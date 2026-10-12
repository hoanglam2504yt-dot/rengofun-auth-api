"""
Admin Routes — RenGoFun Auth API v3.0
Tất cả endpoint đều bảo vệ bởi require_admin dependency (RBAC Guard).

Thiết kế theo chuẩn:
- RBAC Guard: mọi endpoint đều gắn Depends(require_admin)
- Định danh linh hoạt: nhận id / email / username
- Password Reset workflow: List → Approve (sinh mật khẩu + gửi Gmail) → Reject
- Role enum: free | pro_tier_1 | pro_tier_2 | admin
- Đồng bộ cả trường 'plan' mỗi khi cập nhật 'role'
- Ghi audit log mọi thao tác nhạy cảm
"""
import os
import uuid
import smtplib
import logging
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from pymongo.errors import PyMongoError
import jwt

# Import helpers từ auth.py để tránh trùng lặp logic
from auth import get_password_hash, generate_temp_password

from database import (
    users_collection,
    # security_audit_logs_collection là alias của security_logs_collection (xem database.py)
    security_logs_collection,
    user_sessions_collection,
    password_resets_collection,
    db,
)

logger = logging.getLogger("rengofun_auth")

# ─── Cấu hình ─────────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "")
ALGORITHM  = "HS256"

SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM     = os.getenv("SMTP_FROM", SMTP_USER)

router        = APIRouter(prefix="/api/admin", tags=["Admin"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

VALID_ROLES = {"free", "pro_tier_1", "pro_tier_2", "admin"}

# ─── Pydantic Schemas ──────────────────────────────────────────────────────────

class StatusUpdateSchema(BaseModel):
    is_active: bool
    reason: Optional[str] = None


class RoleUpdateSchema(BaseModel):
    role: str  # "free" | "pro_tier_1" | "pro_tier_2" | "admin"


class PlanUpdateSchema(BaseModel):
    plan: str  # "free" | "pro" | "enterprise"
    duration_days: Optional[int] = 30


class BroadcastSchema(BaseModel):
    min_version: Optional[str] = None
    banner_msg: Optional[str] = None
    maintenance_mode: Optional[bool] = None


class RejectResetSchema(BaseModel):
    admin_note: Optional[str] = None


# ─── Admin Guard (RBAC) ────────────────────────────────────────────────────────
async def require_admin(token: str = Depends(oauth2_scheme)) -> dict:
    """Dependency bảo vệ tất cả endpoint admin. Yêu cầu role == 'admin'."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Truy cập bị từ chối: Yêu cầu quyền Quản trị viên (Admin)",
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Phiên đăng nhập đã hết hạn")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token không hợp lệ hoặc đã hết hạn")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _find_user(identifier: str) -> Optional[dict]:
    """Tìm user bằng UUID id, email, hoặc username."""
    return users_collection.find_one({
        "$or": [
            {"id": identifier},
            {"email": identifier},
            {"username": identifier},
        ]
    })


def _write_audit_log(action: str, target: str, performed_by: str, extra: dict = None):
    """Ghi log an ninh vào security_logs."""
    try:
        security_logs_collection.insert_one({
            "action": action,
            "email_attempted": target,
            "performed_by_admin": performed_by,
            "ip_address": "admin_panel",
            "metadata": extra or {},
            "created_at": datetime.now(timezone.utc),
        })
    except Exception:
        pass


def _send_email(to_email: str, subject: str, html_body: str) -> bool:
    """Gửi email qua SMTP Gmail."""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = SMTP_FROM
        msg["To"]      = to_email
        msg.attach(MIMEText(html_body, "html", "utf-8"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, to_email, msg.as_string())
        return True
    except Exception as e:
        logger.error(f"[SMTP Admin] Lỗi gửi mail tới {to_email}: {e}")
        return False


def _format_user_doc(u: dict) -> dict:
    """Chuẩn hóa format user document để trả về cho Client."""
    u["_id"] = str(u.get("_id", ""))
    role = u.get("role", "free")
    
    # Map role -> plan để giao diện frontend tương thích 100%
    if role == "pro_tier_2":
        u["plan"] = "enterprise"
    elif role == "pro_tier_1":
        u["plan"] = "pro"
    else:
        u["plan"] = u.get("plan", "free")

    # Đảm bảo có cả is_active và is_verified
    if "is_active" not in u:
        u["is_active"] = u.get("is_verified", True)

    for field in ("created_at", "updated_at", "plan_expires_at"):
        if isinstance(u.get(field), datetime):
            u[field] = u[field].isoformat()
    return u


# ══════════════════════════════════════════════════════════════════════════════
# 1. METRICS (KPI Dashboard)
# GET /api/admin/metrics
# ══════════════════════════════════════════════════════════════════════════════
@router.get("/metrics")
async def get_metrics(admin: dict = Depends(require_admin)):
    """Chỉ số thống kê tổng quan cho Dashboard KPIs."""
    try:
        total_users    = users_collection.count_documents({})
        active_users   = users_collection.count_documents({"is_active": {"$ne": False}})
        verified_users = users_collection.count_documents({"is_verified": True})

        # Phân bổ role
        role_pipeline = [{"$group": {"_id": "$role", "count": {"$sum": 1}}}]
        role_stats_raw = list(users_collection.aggregate(role_pipeline))
        role_stats = {item["_id"]: item["count"] for item in role_stats_raw}

        # Cảnh báo brute-force: IP > 5 lần login_failed trong 15 phút
        fifteen_min_ago = datetime.now(timezone.utc) - timedelta(minutes=15)
        bf_pipeline = [
            {"$match": {"action": "login_failed", "created_at": {"$gte": fifteen_min_ago}}},
            {"$group": {"_id": "$ip_address", "count": {"$sum": 1}}},
            {"$match": {"count": {"$gte": 5}}},
        ]
        brute_force_ips = list(security_logs_collection.aggregate(bf_pipeline))

        # Sự kiện an ninh hôm nay
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        security_alerts_today = security_logs_collection.count_documents({
            "action": {"$in": ["login_failed", "captcha_failed"]},
            "created_at": {"$gte": today_start},
        })

        pending_resets = password_resets_collection.count_documents({"status": "pending"})

        return {
            "total_users": total_users,
            "active_users": active_users,
            "banned_users": total_users - active_users,
            "verified_users": verified_users,
            "role_distribution": {
                "free":       role_stats.get("free", 0),
                "pro_tier_1": role_stats.get("pro_tier_1", 0),
                "pro_tier_2": role_stats.get("pro_tier_2", 0),
                "admin":      role_stats.get("admin", 0),
            },
            # Map sang plan_distribution cho frontend cũ
            "plan_distribution": {
                "free":       role_stats.get("free", 0),
                "pro":        role_stats.get("pro_tier_1", 0),
                "enterprise": role_stats.get("pro_tier_2", 0),
            },
            "security_alerts_today": security_alerts_today,
            "brute_force_ips": len(brute_force_ips),
            "pending_password_resets": pending_resets,
        }
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# 2. USER MANAGEMENT
# GET /api/admin/users
# ══════════════════════════════════════════════════════════════════════════════
@router.get("/users")
async def list_users(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    plan: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    admin: dict = Depends(require_admin),
):
    """Danh sách người dùng có phân trang, tìm kiếm theo username/email, lọc role/status."""
    try:
        query: dict = {}
        if search:
            query["$or"] = [
                {"email": {"$regex": search, "$options": "i"}},
                {"username": {"$regex": search, "$options": "i"}},
            ]

        # Lọc role hoặc plan
        selected_role = role or plan
        if selected_role and selected_role != "all":
            if selected_role == "pro":
                query["role"] = "pro_tier_1"
            elif selected_role == "enterprise":
                query["role"] = "pro_tier_2"
            else:
                query["role"] = selected_role

        # Lọc trạng thái
        if status_filter == "active":
            query["is_active"] = {"$ne": False}
        elif status_filter == "banned":
            query["is_active"] = False
        elif status_filter == "verified":
            query["is_verified"] = True
        elif status_filter == "unverified":
            query["is_verified"] = False

        total = users_collection.count_documents(query)
        skip  = (page - 1) * limit

        users_cursor = users_collection.find(
            query,
            {"password_hash": 0},
        ).sort("created_at", -1).skip(skip).limit(limit)

        users = [_format_user_doc(u) for u in users_cursor]

        return {
            "users": users,
            "total": total,
            "page": page,
            "limit": limit,
            "total_pages": (total + limit - 1) // limit,
        }
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# 3. CẬP NHẬT TRẠNG THÁI (Khóa / Mở khóa)
# PATCH /api/admin/users/{user_id}/status
# ══════════════════════════════════════════════════════════════════════════════
@router.patch("/users/{user_id}/status")
async def update_user_status(
    user_id: str,
    body: StatusUpdateSchema,
    admin: dict = Depends(require_admin),
):
    """Khóa hoặc mở khóa tài khoản người dùng."""
    try:
        user = _find_user(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Không tìm thấy người dùng")

        now = datetime.now(timezone.utc)
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"is_active": body.is_active, "updated_at": now}}
        )

        # Nếu khóa, thu hồi luôn toàn bộ phiên đăng nhập
        if not body.is_active:
            user_sessions_collection.update_many(
                {"user_id": user.get("id", str(user["_id"])), "is_revoked": False},
                {"$set": {"is_revoked": True}}
            )

        action = "admin_ban_user" if not body.is_active else "admin_unban_user"
        target_name = user.get("email") or user.get("username") or user_id
        _write_audit_log(action, target_name, admin["sub"], {"reason": body.reason})

        verb = "khóa" if not body.is_active else "mở khóa"
        return {"message": f"Đã {verb} tài khoản '{target_name}' thành công."}
    except HTTPException:
        raise
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# 4. CẬP NHẬT ROLE (Gói / Quyền)
# PATCH /api/admin/users/{user_id}/role
# ══════════════════════════════════════════════════════════════════════════════
@router.patch("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    body: RoleUpdateSchema,
    admin: dict = Depends(require_admin),
):
    """Cập nhật role quyền hạn của người dùng (free | pro_tier_1 | pro_tier_2 | admin)."""
    if body.role not in VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Role không hợp lệ. Chọn một trong: {sorted(VALID_ROLES)}",
        )
    try:
        user = _find_user(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Không tìm thấy người dùng")

        now = datetime.now(timezone.utc)
        # Đồng bộ cả field plan
        plan_equiv = "enterprise" if body.role == "pro_tier_2" else ("pro" if body.role == "pro_tier_1" else "free")
        
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"role": body.role, "plan": plan_equiv, "updated_at": now}},
        )

        target_name = user.get("email") or user.get("username") or user_id
        _write_audit_log("admin_change_role", target_name, admin["sub"], {"new_role": body.role})
        return {"message": f"Đã cập nhật role '{body.role}' cho tài khoản thành công."}
    except HTTPException:
        raise
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# 5. CẬP NHẬT GÓI (Tương thích giao diện cũ)
# PATCH /api/admin/users/{user_id}/plan
# ══════════════════════════════════════════════════════════════════════════════
@router.patch("/users/{user_id}/plan")
async def update_user_plan(
    user_id: str,
    body: PlanUpdateSchema,
    admin: dict = Depends(require_admin),
):
    """Tương thích ngược: Cập nhật gói dịch vụ (free | pro | enterprise)."""
    valid_plans = {"free", "pro", "enterprise"}
    if body.plan not in valid_plans:
        raise HTTPException(status_code=400, detail=f"Gói không hợp lệ. Chọn một trong: {sorted(valid_plans)}")
    try:
        user = _find_user(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Không tìm thấy người dùng")

        now = datetime.now(timezone.utc)
        expires_at = None
        if body.plan != "free" and body.duration_days:
            expires_at = now + timedelta(days=body.duration_days)

        role_equiv = "pro_tier_2" if body.plan == "enterprise" else ("pro_tier_1" if body.plan == "pro" else "free")

        update_data = {
            "plan": body.plan,
            "role": role_equiv,
            "updated_at": now,
        }
        if expires_at:
            update_data["plan_expires_at"] = expires_at

        users_collection.update_one({"_id": user["_id"]}, {"$set": update_data})

        target_name = user.get("email") or user.get("username") or user_id
        _write_audit_log("admin_change_plan", target_name, admin["sub"], {"plan": body.plan, "days": body.duration_days})
        return {"message": f"Đã cập nhật gói '{body.plan}' (+{body.duration_days} ngày) thành công."}
    except HTTPException:
        raise
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# 6. REVOKE SESSIONS (Force Logout)
# POST /api/admin/users/{user_id}/revoke-sessions
# ══════════════════════════════════════════════════════════════════════════════
@router.post("/users/{user_id}/revoke-sessions")
async def revoke_user_sessions(
    user_id: str,
    admin: dict = Depends(require_admin),
):
    """Buộc đăng xuất tài khoản khỏi tất cả thiết bị (is_revoked = True)."""
    try:
        user = _find_user(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Không tìm thấy người dùng")

        uid = user.get("id", str(user["_id"]))
        result = user_sessions_collection.update_many(
            {"user_id": uid, "is_revoked": False},
            {"$set": {"is_revoked": True}},
        )
        target_name = user.get("email") or user.get("username") or user_id
        _write_audit_log("admin_revoke_sessions", target_name, admin["sub"], {"sessions_revoked": result.modified_count})
        return {"message": f"Đã thu hồi {result.modified_count} phiên làm việc của '{target_name}'."}
    except HTTPException:
        raise
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# 7. SESSIONS
# GET /api/admin/sessions
# ══════════════════════════════════════════════════════════════════════════════
@router.get("/sessions")
async def list_sessions(
    user_id: Optional[str] = Query(None),
    admin: dict = Depends(require_admin),
):
    """Danh sách phiên đăng nhập đang hoạt động."""
    try:
        query: dict = {"is_revoked": False}
        if user_id:
            user = _find_user(user_id)
            if user:
                query["user_id"] = user.get("id", str(user["_id"]))
            else:
                query["user_id"] = user_id

        sessions = list(
            user_sessions_collection.find(query, {"_id": 0, "refresh_token": 0})
            .sort("created_at", -1)
            .limit(100)
        )
        for s in sessions:
            for f in ("expires_at", "created_at"):
                if isinstance(s.get(f), datetime):
                    s[f] = s[f].isoformat()
        return {"sessions": sessions, "total": len(sessions)}
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# 8. AUDIT LOGS
# GET /api/admin/audit-logs
# ══════════════════════════════════════════════════════════════════════════════
@router.get("/audit-logs")
async def get_audit_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    action_type: Optional[str] = Query(None),
    admin: dict = Depends(require_admin),
):
    """Nhật ký bảo mật và thao tác admin."""
    try:
        query: dict = {}
        if action_type and action_type != "all":
            query["action"] = action_type

        total = security_logs_collection.count_documents(query)
        skip  = (page - 1) * limit

        logs = list(
            security_logs_collection.find(query, {"_id": 0})
            .sort("created_at", -1)
            .skip(skip)
            .limit(limit)
        )
        for log in logs:
            if isinstance(log.get("created_at"), datetime):
                log["created_at"] = log["created_at"].isoformat()
            # Map sang field timestamp cho frontend cũ
            log["timestamp"] = log.get("created_at")

        # Phân tích brute-force
        fifteen_min_ago = datetime.now(timezone.utc) - timedelta(minutes=15)
        bf_pipeline = [
            {"$match": {"action": "login_failed", "created_at": {"$gte": fifteen_min_ago}}},
            {"$group": {"_id": "$ip_address", "count": {"$sum": 1}, "last_seen": {"$max": "$created_at"}}},
            {"$match": {"count": {"$gte": 5}}},
            {"$sort": {"count": -1}},
        ]
        brute_force_alerts = list(security_logs_collection.aggregate(bf_pipeline))
        for alert in brute_force_alerts:
            if isinstance(alert.get("last_seen"), datetime):
                alert["last_seen"] = alert["last_seen"].isoformat()

        return {
            "logs": logs,
            "total": total,
            "page": page,
            "limit": limit,
            "total_pages": (total + limit - 1) // limit,
            "brute_force_alerts": brute_force_alerts,
        }
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# 9. SYSTEM BROADCAST & CONFIG
# ══════════════════════════════════════════════════════════════════════════════
@router.post("/system/broadcast")
async def system_broadcast(
    body: BroadcastSchema,
    admin: dict = Depends(require_admin),
):
    """Cập nhật cấu hình hệ thống: phiên bản tối thiểu, banner, chế độ bảo trì."""
    try:
        config_col  = db["system_config"]
        update_data = {"updated_at": datetime.now(timezone.utc), "updated_by": admin["sub"]}
        if body.min_version is not None:
            update_data["min_version"] = body.min_version
        if body.banner_msg is not None:
            update_data["banner_msg"] = body.banner_msg
        if body.maintenance_mode is not None:
            update_data["maintenance_mode"] = body.maintenance_mode

        config_col.update_one({}, {"$set": update_data}, upsert=True)
        _write_audit_log("admin_system_broadcast", "system", admin["sub"], {"config": update_data})
        return {"message": "Đã cập nhật cấu hình hệ thống thành công.", "config": update_data}
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


@router.get("/system/config")
async def get_system_config(admin: dict = Depends(require_admin)):
    """Lấy cấu hình hệ thống hiện tại."""
    try:
        config = db["system_config"].find_one({}, {"_id": 0})
        if not config:
            return {"min_version": "1.0.0", "banner_msg": None, "maintenance_mode": False}
        if isinstance(config.get("updated_at"), datetime):
            config["updated_at"] = config["updated_at"].isoformat()
        return config
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# 10. PASSWORD RESET REQUESTS
# ══════════════════════════════════════════════════════════════════════════════
@router.get("/password-resets")
async def list_password_resets(
    status_filter: Optional[str] = Query("pending", alias="status"),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    admin: dict = Depends(require_admin),
):
    """Danh sách yêu cầu đặt lại mật khẩu."""
    try:
        query: dict = {}
        if status_filter and status_filter != "all":
            query["status"] = status_filter

        total = password_resets_collection.count_documents(query)
        skip  = (page - 1) * limit

        resets = list(
            password_resets_collection.find(query, {"_id": 0})
            .sort("created_at", -1)
            .skip(skip)
            .limit(limit)
        )

        for r in resets:
            user = users_collection.find_one({"id": r.get("user_id")}, {"email": 1, "username": 1})
            r["user_email"] = user.get("email", "unknown") if user else "unknown"
            r["username"]   = user.get("username", "") if user else ""
            for f in ("created_at", "processed_at"):
                if isinstance(r.get(f), datetime):
                    r[f] = r[f].isoformat()

        return {
            "resets": resets,
            "total": total,
            "page": page,
            "limit": limit,
            "total_pages": (total + limit - 1) // limit,
        }
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


@router.post("/password-resets/{reset_id}/approve")
async def approve_password_reset(
    reset_id: str,
    admin: dict = Depends(require_admin),
):
    """
    Admin phê duyệt yêu cầu cấp lại mật khẩu:
    1. Sinh mật khẩu ngẫu nhiên (12 ký tự)
    2. Băm và lưu vào DB
    3. Thu hồi toàn bộ session
    4. Gửi mail mật khẩu mới về Gmail
    5. Cập nhật trạng thái yêu cầu approved
    """
    try:
        now = datetime.now(timezone.utc)
        reset_doc = password_resets_collection.find_one({"id": reset_id})
        if not reset_doc:
            raise HTTPException(status_code=404, detail="Không tìm thấy yêu cầu")
        if reset_doc.get("status") != "pending":
            raise HTTPException(status_code=400, detail="Yêu cầu này đã được xử lý trước đó")

        user = users_collection.find_one({"id": reset_doc["user_id"]})
        if not user:
            raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản người dùng")

        # Dùng generate_temp_password từ auth.py (single source of truth)
        temp_password = generate_temp_password(12)

        users_collection.update_one(
            {"id": user["id"]},
            {"$set": {"password_hash": get_password_hash(temp_password), "updated_at": now}},
        )

        # Thu hồi toàn bộ session
        user_sessions_collection.update_many(
            {"user_id": user["id"], "is_revoked": False},
            {"$set": {"is_revoked": True}},
        )

        # Gửi mật khẩu mới qua email
        html = f"""
        <h2>RenGoFun — Cấp lại mật khẩu thành công</h2>
        <p>Yêu cầu đặt lại mật khẩu cho tài khoản <strong>{user.get('email')}</strong> đã được Quản trị viên phê duyệt.</p>
        <p>Mật khẩu mới của bạn là:</p>
        <pre style="font-size:18px; font-weight:bold; background:#f4f4f5; padding:14px; border-radius:8px; border:1px solid #e4e4e7;">
{temp_password}
        </pre>
        <p style="color:#ef4444;"><strong>Lưu ý bảo mật:</strong> Vui lòng đăng nhập và đổi mật khẩu ngay sau khi nhận được email này.</p>
        """
        mail_sent = _send_email(user["email"], "[RenGoFun] Mật khẩu mới của bạn", html)

        password_resets_collection.update_one(
            {"id": reset_id},
            {"$set": {
                "status": "approved",
                "admin_id": admin["sub"],
                "processed_at": now,
                "admin_note": "Đã cấp mật khẩu mới qua Gmail.",
            }},
        )

        _write_audit_log(
            "admin_reset_password", user["email"], admin["sub"],
            {"reset_id": reset_id, "mail_sent": mail_sent},
        )

        return {
            "message": f"Đã phê duyệt và cấp mật khẩu mới cho {user['email']}.",
            "mail_sent": mail_sent,
        }
    except HTTPException:
        raise
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


@router.post("/password-resets/{reset_id}/reject")
async def reject_password_reset(
    reset_id: str,
    body: RejectResetSchema,
    admin: dict = Depends(require_admin),
):
    """Admin từ chối yêu cầu đặt lại mật khẩu."""
    try:
        now = datetime.now(timezone.utc)
        reset_doc = password_resets_collection.find_one({"id": reset_id})
        if not reset_doc:
            raise HTTPException(status_code=404, detail="Không tìm thấy yêu cầu")
        if reset_doc.get("status") != "pending":
            raise HTTPException(status_code=400, detail="Yêu cầu này đã được xử lý trước đó")

        password_resets_collection.update_one(
            {"id": reset_id},
            {"$set": {
                "status": "rejected",
                "admin_id": admin["sub"],
                "admin_note": body.admin_note,
                "processed_at": now,
            }},
        )

        user = users_collection.find_one({"id": reset_doc["user_id"]}, {"email": 1, "username": 1})
        target_name = user.get("email") or user.get("username") if user else "unknown"
        _write_audit_log("admin_reject_password_reset", target_name, admin["sub"], {"reset_id": reset_id})
        return {"message": "Đã từ chối yêu cầu đặt lại mật khẩu thành công."}
    except HTTPException:
        raise
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")
