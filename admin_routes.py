"""
Admin & Staff Routes — RenGoFun Auth API v3.1
- Tách bạch `role` ("user" | "moderator" | "admin") và `plan` ("free" | "pro" | "enterprise").
- `require_staff`: Cho phép Admin hoặc Moderator xem hỗ trợ, duyệt đổi mật khẩu và thu hồi phiên.
- `require_admin`: Chỉ Admin được khóa/mở tài khoản, đổi role/plan, cấu hình hệ thống, xem billing & duyệt giao dịch.
"""
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import jwt
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from pymongo.errors import PyMongoError

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")

from auth import (
    VALID_PLANS,
    VALID_ROLES,
    generate_temp_password,
    get_password_hash,
    normalize_user_role_and_plan,
    send_email_unified,
)
from billing_routes import mark_order_paid
from database import (
    billing_transactions_collection,
    db,
    password_resets_collection,
    security_logs_collection,
    telemetry_events_collection,
    user_sessions_collection,
    users_collection,
)

logger = logging.getLogger("rengofun_auth")

SECRET_KEY = os.getenv("SECRET_KEY", "")
ALGORITHM = "HS256"

router = APIRouter(prefix="/api/admin", tags=["Admin"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


class StatusUpdateSchema(BaseModel):
    is_active: bool
    reason: Optional[str] = None


class RoleUpdateSchema(BaseModel):
    role: str  # "user" | "moderator" | "admin"


class PlanUpdateSchema(BaseModel):
    plan: str  # "free" | "pro" | "enterprise"
    duration_days: Optional[int] = 30


class BroadcastSchema(BaseModel):
    min_version: Optional[str] = None
    banner_msg: Optional[str] = None
    maintenance_mode: Optional[bool] = None


class RejectResetSchema(BaseModel):
    admin_note: Optional[str] = None


def _decode_staff_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Phiên đăng nhập đã hết hạn")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token không hợp lệ hoặc đã hết hạn")


async def require_admin(token: str = Depends(oauth2_scheme)) -> dict:
    """Dependency bảo vệ toàn bộ endpoint nhạy cảm. Yêu cầu role == 'admin'."""
    payload = _decode_staff_token(token)
    if payload.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Truy cập bị từ chối: Yêu cầu quyền Quản trị viên (Admin)",
        )
    return payload


async def require_staff(token: str = Depends(oauth2_scheme)) -> dict:
    """Cho phép Admin hoặc Nhân viên CSKH (`moderator`) xem dữ liệu hỗ trợ & reset phiên/mật khẩu."""
    payload = _decode_staff_token(token)
    if payload.get("role") not in ("admin", "moderator"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Truy cập bị từ chối: Yêu cầu quyền Quản trị hoặc CSKH (Moderator)",
        )
    return payload


def _find_user(identifier: str) -> Optional[dict]:
    return users_collection.find_one({
        "$or": [
            {"id": identifier},
            {"email": identifier},
            {"username": identifier},
        ]
    })


def _write_audit_log(action: str, target: str, performed_by: str, extra: dict = None):
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


def _format_user_doc(u: dict) -> dict:
    """Chuẩn hóa và migrate nhẹ format user document để trả về cho Admin Dashboard."""
    u = normalize_user_role_and_plan(u, users_collection)
    u["_id"] = str(u.get("_id", ""))
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
async def get_metrics(staff: dict = Depends(require_staff)):
    """Chỉ số thống kê tổng quan cho Dashboard KPIs (tách riêng role vs plan)."""
    try:
        all_users = list(users_collection.find({}, {"role": 1, "plan": 1, "plan_expires_at": 1, "email": 1, "is_active": 1, "is_verified": 1}))
        role_counts = {"user": 0, "moderator": 0, "admin": 0}
        plan_counts = {"free": 0, "pro": 0, "enterprise": 0}
        active_users = 0
        verified_users = 0

        for u in all_users:
            u_norm = normalize_user_role_and_plan(u, users_collection)
            r = u_norm.get("role", "user")
            p = u_norm.get("plan", "free")
            role_counts[r] = role_counts.get(r, 0) + 1
            plan_counts[p] = plan_counts.get(p, 0) + 1
            if u.get("is_active", True) is not False:
                active_users += 1
            if u.get("is_verified"):
                verified_users += 1

        total_users = len(all_users)

        fifteen_min_ago = datetime.now(timezone.utc) - timedelta(minutes=15)
        bf_pipeline = [
            {"$match": {"action": "login_failed", "created_at": {"$gte": fifteen_min_ago}}},
            {"$group": {"_id": "$ip_address", "count": {"$sum": 1}}},
            {"$match": {"count": {"$gte": 5}}},
        ]
        brute_force_ips = list(security_logs_collection.aggregate(bf_pipeline))

        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        security_alerts_today = security_logs_collection.count_documents({
            "action": {"$in": ["login_failed", "captcha_failed", "login_rate_limited"]},
            "created_at": {"$gte": today_start},
        })
        pending_resets = password_resets_collection.count_documents({"status": "pending"})

        # Billing & Telemetry summary
        paid_orders = list(billing_transactions_collection.find({"status": "PAID"}, {"amount_vnd": 1}))
        pending_orders = billing_transactions_collection.count_documents({"status": "PENDING"})
        total_revenue_vnd = sum(int(o.get("amount_vnd", 0)) for o in paid_orders)
        telemetry_today = telemetry_events_collection.count_documents({"created_at": {"$gte": today_start}})

        return {
            "total_users": total_users,
            "active_users": active_users,
            "banned_users": total_users - active_users,
            "verified_users": verified_users,
            "role_distribution": role_counts,
            "plan_distribution": plan_counts,
            "security_alerts_today": security_alerts_today,
            "brute_force_ips": len(brute_force_ips),
            "pending_password_resets": pending_resets,
            "billing_summary": {
                "total_paid_orders": len(paid_orders),
                "pending_orders": pending_orders,
                "total_revenue_vnd": total_revenue_vnd,
            },
            "telemetry_errors_today": telemetry_today,
        }
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# 2. USER MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════
@router.get("/users")
async def list_users(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    plan: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    staff: dict = Depends(require_staff),
):
    """Danh sách người dùng có phân trang, hỗ trợ lọc cả role (`user|moderator|admin`) và plan (`free|pro|enterprise`)."""
    try:
        query: dict = {}
        and_clauses = []
        if search:
            and_clauses.append({
                "$or": [
                    {"email": {"$regex": search, "$options": "i"}},
                    {"username": {"$regex": search, "$options": "i"}},
                ]
            })

        if role and role != "all":
            if role == "user":
                and_clauses.append({"role": {"$in": ["user", "free", "pro_tier_1", "pro_tier_2", None]}})
            else:
                and_clauses.append({"role": role})

        if plan and plan != "all":
            if plan == "free":
                and_clauses.append({"$or": [{"plan": "free"}, {"plan": {"$exists": False}, "role": {"$in": ["free", "user"]}}]})
            elif plan == "pro":
                and_clauses.append({"$or": [{"plan": "pro"}, {"role": "pro_tier_1"}]})
            elif plan == "enterprise":
                and_clauses.append({"$or": [{"plan": "enterprise"}, {"role": "pro_tier_2"}]})

        if status_filter == "active":
            and_clauses.append({"is_active": {"$ne": False}})
        elif status_filter == "banned":
            and_clauses.append({"is_active": False})
        elif status_filter == "verified":
            and_clauses.append({"is_verified": True})
        elif status_filter == "unverified":
            and_clauses.append({"is_verified": False})

        if and_clauses:
            query = {"$and": and_clauses}

        total = users_collection.count_documents(query)
        skip = (page - 1) * limit

        users_cursor = (
            users_collection.find(query, {"password_hash": 0})
            .sort("created_at", -1)
            .skip(skip)
            .limit(limit)
        )
        users = [_format_user_doc(u) for u in users_cursor]

        return {
            "users": users,
            "total": total,
            "page": page,
            "limit": limit,
            "total_pages": max(1, (total + limit - 1) // limit),
        }
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


@router.patch("/users/{user_id}/status")
async def update_user_status(
    user_id: str,
    body: StatusUpdateSchema,
    admin: dict = Depends(require_admin),
):
    """Khóa hoặc mở khóa tài khoản người dùng (Admin only)."""
    try:
        user = _find_user(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Không tìm thấy người dùng")

        now = datetime.now(timezone.utc)
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"is_active": body.is_active, "updated_at": now}},
        )

        if not body.is_active:
            user_sessions_collection.update_many(
                {"user_id": user.get("id", str(user["_id"])), "is_revoked": False},
                {"$set": {"is_revoked": True}},
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


@router.patch("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    body: RoleUpdateSchema,
    admin: dict = Depends(require_admin),
):
    """Cập nhật vai trò hệ thống (`user` | `moderator` | `admin`) mà KHÔNG ghi đè `plan`."""
    target_role = body.role.strip().lower()
    if target_role not in VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Role không hợp lệ. Chọn một trong: {sorted(VALID_ROLES)}",
        )
    try:
        user = _find_user(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Không tìm thấy người dùng")

        now = datetime.now(timezone.utc)
        user = normalize_user_role_and_plan(user, users_collection)
        update_doc = {"role": target_role, "updated_at": now}
        if target_role == "admin":
            update_doc["plan"] = "enterprise"

        users_collection.update_one({"_id": user["_id"]}, {"$set": update_doc})

        target_name = user.get("email") or user.get("username") or user_id
        _write_audit_log("admin_change_role", target_name, admin["sub"], {"new_role": target_role})
        return {"message": f"Đã cập nhật vai trò '{target_role}' cho '{target_name}' thành công."}
    except HTTPException:
        raise
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


@router.patch("/users/{user_id}/plan")
async def update_user_plan(
    user_id: str,
    body: PlanUpdateSchema,
    admin: dict = Depends(require_admin),
):
    """Cập nhật gói bản quyền thương mại (`free` | `pro` | `enterprise`) mà KHÔNG ghi đè `role`."""
    target_plan = body.plan.strip().lower()
    if target_plan not in VALID_PLANS:
        raise HTTPException(status_code=400, detail=f"Gói không hợp lệ. Chọn một trong: {sorted(VALID_PLANS)}")
    try:
        user = _find_user(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Không tìm thấy người dùng")

        user = normalize_user_role_and_plan(user, users_collection)
        now = datetime.now(timezone.utc)
        expires_at = None
        if target_plan != "free" and body.duration_days:
            expires_at = now + timedelta(days=int(body.duration_days))

        update_data: dict = {
            "plan": target_plan,
            "role": user.get("role", "user"),
            "plan_expires_at": expires_at if target_plan != "free" else None,
            "updated_at": now,
        }
        users_collection.update_one({"_id": user["_id"]}, {"$set": update_data})

        target_name = user.get("email") or user.get("username") or user_id
        _write_audit_log("admin_change_plan", target_name, admin["sub"], {"plan": target_plan, "days": body.duration_days})
        return {"message": f"Đã cập nhật gói '{target_plan}' (+{body.duration_days} ngày) thành công."}
    except HTTPException:
        raise
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


@router.post("/users/{user_id}/revoke-sessions")
async def revoke_user_sessions(
    user_id: str,
    staff: dict = Depends(require_staff),
):
    """Buộc đăng xuất tài khoản khỏi tất cả thiết bị (CSKH Moderator & Admin đều có quyền)."""
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
        _write_audit_log("admin_revoke_sessions", target_name, staff["sub"], {"sessions_revoked": result.modified_count})
        return {"message": f"Đã thu hồi {result.modified_count} phiên làm việc của '{target_name}'."}
    except HTTPException:
        raise
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


@router.get("/sessions")
async def list_sessions(
    user_id: Optional[str] = Query(None),
    staff: dict = Depends(require_staff),
):
    """Danh sách phiên đăng nhập & thiết bị đang hoạt động."""
    try:
        query: dict = {"is_revoked": False}
        if user_id:
            user = _find_user(user_id)
            query["user_id"] = user.get("id", str(user["_id"])) if user else user_id

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
        skip = (page - 1) * limit

        logs = list(
            security_logs_collection.find(query, {"_id": 0})
            .sort("created_at", -1)
            .skip(skip)
            .limit(limit)
        )
        for log in logs:
            if isinstance(log.get("created_at"), datetime):
                log["created_at"] = log["created_at"].isoformat()
            log["timestamp"] = log.get("created_at")

        fifteen_min_ago = datetime.now(timezone.utc) - timedelta(minutes=15)
        bf_pipeline = [
            {"$match": {"action": {"$in": ["login_failed", "login_rate_limited"]}, "created_at": {"$gte": fifteen_min_ago}}},
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
            "total_pages": max(1, (total + limit - 1) // limit),
            "brute_force_alerts": brute_force_alerts,
        }
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


@router.post("/system/broadcast")
async def system_broadcast(
    body: BroadcastSchema,
    admin: dict = Depends(require_admin),
):
    """Cập nhật cấu hình hệ thống: phiên bản tối thiểu, banner, chế độ bảo trì."""
    try:
        config_col = db["system_config"]
        update_data: dict = {"updated_at": datetime.now(timezone.utc), "updated_by": admin["sub"]}
        if body.min_version is not None:
            update_data["min_version"] = body.min_version
        if body.banner_msg is not None:
            update_data["banner_msg"] = body.banner_msg
        if body.maintenance_mode is not None:
            update_data["maintenance_mode"] = body.maintenance_mode

        config_col.update_one({}, {"$set": update_data}, upsert=True)
        _write_audit_log("admin_system_broadcast", "system", admin["sub"], {"config": str(update_data)})
        if isinstance(update_data.get("updated_at"), datetime):
            update_data["updated_at"] = update_data["updated_at"].isoformat()
        return {"message": "Đã cập nhật cấu hình hệ thống thành công.", "config": update_data}
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


@router.get("/system/config")
async def get_system_config(admin: dict = Depends(require_admin)):
    """Lấy cấu hình hệ thống hiện tại."""
    try:
        config = db["system_config"].find_one({}, {"_id": 0})
        if not config:
            return {"min_version": "0.1.0", "banner_msg": None, "maintenance_mode": False}
        if isinstance(config.get("updated_at"), datetime):
            config["updated_at"] = config["updated_at"].isoformat()
        return config
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# 10. PASSWORD RESET REQUESTS (Admin + Moderator)
# ══════════════════════════════════════════════════════════════════════════════
@router.get("/password-resets")
async def list_password_resets(
    status_filter: Optional[str] = Query("pending", alias="status"),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    staff: dict = Depends(require_staff),
):
    try:
        query: dict = {}
        if status_filter and status_filter != "all":
            query["status"] = status_filter

        total = password_resets_collection.count_documents(query)
        skip = (page - 1) * limit
        resets = list(
            password_resets_collection.find(query, {"_id": 0})
            .sort("created_at", -1)
            .skip(skip)
            .limit(limit)
        )
        for r in resets:
            user = users_collection.find_one({"id": r.get("user_id")}, {"email": 1, "username": 1})
            r["user_email"] = user.get("email", "unknown") if user else "unknown"
            r["username"] = user.get("username", "") if user else ""
            for f in ("created_at", "processed_at"):
                if isinstance(r.get(f), datetime):
                    r[f] = r[f].isoformat()

        return {
            "resets": resets,
            "total": total,
            "page": page,
            "limit": limit,
            "total_pages": max(1, (total + limit - 1) // limit),
        }
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


@router.post("/password-resets/{reset_id}/approve")
async def approve_password_reset(
    reset_id: str,
    staff: dict = Depends(require_staff),
):
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

        temp_password = generate_temp_password(12)
        users_collection.update_one(
            {"id": user["id"]},
            {"$set": {"password_hash": get_password_hash(temp_password), "updated_at": now}},
        )
        user_sessions_collection.update_many(
            {"user_id": user["id"], "is_revoked": False},
            {"$set": {"is_revoked": True}},
        )

        html = f"""
        <h2>RenGoFun — Cấp lại mật khẩu thành công</h2>
        <p>Yêu cầu đặt lại mật khẩu cho tài khoản <strong>{user.get('email')}</strong> đã được phê duyệt.</p>
        <p>Mật khẩu mới của bạn là:</p>
        <pre style="font-size:18px; font-weight:bold; background:#f4f4f5; padding:14px; border-radius:8px; border:1px solid #e4e4e7;">
{temp_password}
        </pre>
        <p style="color:#ef4444;"><strong>Lưu ý bảo mật:</strong> Vui lòng đăng nhập và đổi mật khẩu ngay sau khi nhận được email này.</p>
        """
        mail_sent = send_email_unified(user["email"], "[RenGoFun] Mật khẩu mới của bạn", html)

        password_resets_collection.update_one(
            {"id": reset_id},
            {"$set": {
                "status": "approved",
                "admin_id": staff["sub"],
                "processed_at": now,
                "admin_note": "Đã cấp mật khẩu mới qua Gmail.",
            }},
        )
        _write_audit_log(
            "admin_reset_password", user["email"], staff["sub"],
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
    staff: dict = Depends(require_staff),
):
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
                "admin_id": staff["sub"],
                "admin_note": body.admin_note,
                "processed_at": now,
            }},
        )
        user = users_collection.find_one({"id": reset_doc["user_id"]}, {"email": 1, "username": 1})
        target_name = user.get("email") or user.get("username") if user else "unknown"
        _write_audit_log("admin_reject_password_reset", target_name, staff["sub"], {"reset_id": reset_id})
        return {"message": "Đã từ chối yêu cầu đặt lại mật khẩu thành công."}
    except HTTPException:
        raise
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# 11. BILLING MANAGEMENT & TELEMETRY STATS (Giai đoạn 4)
# ══════════════════════════════════════════════════════════════════════════════
@router.get("/billing/orders")
async def admin_list_billing_orders(
    status_filter: Optional[str] = Query("all", alias="status"),
    limit: int = Query(50, ge=1, le=200),
    admin: dict = Depends(require_admin),
):
    """Danh sách đơn hàng nâng cấp gói QR."""
    try:
        query = {} if status_filter in (None, "", "all") else {"status": status_filter.upper()}
        orders = list(
            billing_transactions_collection.find(query, {"_id": 0})
            .sort("created_at", -1)
            .limit(limit)
        )
        for o in orders:
            for k in ("created_at", "expires_at", "paid_at"):
                if isinstance(o.get(k), datetime):
                    o[k] = o[k].isoformat()
        return {"orders": orders, "total": len(orders)}
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


@router.post("/billing/orders/{order_code}/confirm")
async def admin_confirm_billing_order(
    order_code: str,
    admin: dict = Depends(require_admin),
):
    """Admin xác nhận thủ công đơn chuyển khoản QR khi khách đã thanh toán."""
    order_doc = billing_transactions_collection.find_one({"order_code": order_code.strip().upper()})
    if not order_doc:
        raise HTTPException(status_code=404, detail="Không tìm thấy mã đơn hàng.")
    res = mark_order_paid(order_doc, source="admin_confirm", admin_sub=admin["sub"])
    return {
        "message": f"Đã xác nhận thanh toán đơn {order_doc['order_code']} và nâng cấp gói '{res['user']['plan']}'.",
        "order_code": order_doc["order_code"],
        "already_paid": res["already_paid"],
    }


@router.get("/telemetry/stats")
async def get_telemetry_stats(
    limit: int = Query(30, ge=1, le=100),
    staff: dict = Depends(require_staff),
):
    """Thống kê Crash Telemetry ẩn danh theo từng công cụ (TOOL-01 -> TOOL-15)."""
    try:
        by_tool_raw = list(telemetry_events_collection.aggregate([
            {"$group": {
                "_id": "$tool_code",
                "count": {"$sum": 1},
                "last_seen": {"$max": "$created_at"},
            }},
            {"$sort": {"count": -1}},
        ]))
        by_tool = []
        for item in by_tool_raw:
            ls = item.get("last_seen")
            by_tool.append({
                "tool_code": item["_id"] or "UNKNOWN",
                "count": item["count"],
                "last_seen": ls.isoformat() if isinstance(ls, datetime) else ls,
            })

        recent = list(
            telemetry_events_collection.find({}, {"_id": 0})
            .sort("created_at", -1)
            .limit(limit)
        )
        for ev in recent:
            if isinstance(ev.get("created_at"), datetime):
                ev["created_at"] = ev["created_at"].isoformat()

        total_events = telemetry_events_collection.count_documents({})
        return {
            "total_events": total_events,
            "by_tool": by_tool,
            "recent": recent,
        }
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")
