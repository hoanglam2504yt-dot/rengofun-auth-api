"""
Admin Routes — RenGoFun Auth API v2.0
Tất cả endpoint đều bảo vệ bởi require_admin dependency (RBAC Guard).
"""
import os
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from pymongo.errors import PyMongoError
import jwt

from database import (
    users_collection,
    security_audit_logs_collection,
    user_sessions_collection,
    db,
)

# ─── Cấu hình ─────────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "khoa_bi_mat_mac_dinh_rengofun")
ALGORITHM = "HS256"

router = APIRouter(prefix="/api/admin", tags=["Admin"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# ─── Pydantic Schemas ──────────────────────────────────────────────────────────
class StatusUpdateSchema(BaseModel):
    is_active: bool
    reason: Optional[str] = None

class PlanUpdateSchema(BaseModel):
    plan: str  # "free" | "pro" | "enterprise"
    duration_days: Optional[int] = 30

class BroadcastSchema(BaseModel):
    min_version: Optional[str] = None
    banner_msg: Optional[str] = None
    maintenance_mode: Optional[bool] = None

# ─── Admin Guard (Bộ lọc bảo mật RBAC) ───────────────────────────────────────
async def require_admin(token: str = Depends(oauth2_scheme)) -> dict:
    """
    Dependency bảo vệ tất cả endpoint admin.
    Giải mã JWT và kiểm tra role == 'admin'.
    Ném 403 nếu không đủ quyền, 401 nếu token không hợp lệ.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Truy cập bị từ chối: Yêu cầu quyền Quản trị viên"
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Phiên đăng nhập đã hết hạn"
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Phiên đăng nhập không hợp lệ hoặc đã hết hạn"
        )

# ─── Helper: Ghi nhật ký Admin ────────────────────────────────────────────────
def _write_audit_log(action: str, target_user: str, performed_by: str, extra: dict = None):
    """Ghi lại mọi thao tác admin vào security_audit_logs."""
    try:
        log_doc = {
            "action": action,
            "target_user": target_user,
            "performed_by_admin": performed_by,
            "timestamp": datetime.now(timezone.utc),
            **(extra or {})
        }
        security_audit_logs_collection.insert_one(log_doc)
    except Exception:
        pass  # Không để lỗi log block API


# ══════════════════════════════════════════════════════════════════════════════
# 1. METRICS (KPI Dashboard)
# GET /api/admin/metrics
# ══════════════════════════════════════════════════════════════════════════════
@router.get("/metrics")
async def get_metrics(admin: dict = Depends(require_admin)):
    """Lấy các chỉ số thống kê tổng quan cho Dashboard KPIs."""
    try:
        total_users = users_collection.count_documents({})
        active_users = users_collection.count_documents({"is_active": True})

        # Thống kê gói
        plan_pipeline = [
            {"$group": {"_id": "$plan", "count": {"$sum": 1}}}
        ]
        plan_stats_raw = list(users_collection.aggregate(plan_pipeline))
        plan_stats = {item["_id"]: item["count"] for item in plan_stats_raw}

        # Cảnh báo brute-force: IP có >5 lần login_failed trong 15 phút
        fifteen_min_ago = datetime.now(timezone.utc) - timedelta(minutes=15)
        brute_force_pipeline = [
            {"$match": {"action": "login_failed", "timestamp": {"$gte": fifteen_min_ago}}},
            {"$group": {"_id": "$ip_address", "count": {"$sum": 1}}},
            {"$match": {"count": {"$gte": 5}}}
        ]
        brute_force_ips = list(security_audit_logs_collection.aggregate(brute_force_pipeline))

        # Sự kiện an ninh trong ngày
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        security_alerts_today = security_audit_logs_collection.count_documents({
            "action": {"$in": ["login_failed", "admin_action"]},
            "timestamp": {"$gte": today_start}
        })

        return {
            "total_users": total_users,
            "active_users": active_users,
            "banned_users": total_users - active_users,
            "plan_distribution": {
                "free": plan_stats.get("free", 0),
                "pro": plan_stats.get("pro", 0),
                "enterprise": plan_stats.get("enterprise", 0),
            },
            "security_alerts_today": security_alerts_today,
            "brute_force_ips": len(brute_force_ips),
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
    plan: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    admin: dict = Depends(require_admin)
):
    """Lấy danh sách người dùng có phân trang, tìm kiếm và lọc."""
    try:
        query = {}
        if search:
            query["$or"] = [
                {"username": {"$regex": search, "$options": "i"}},
                {"email": {"$regex": search, "$options": "i"}},
            ]
        if plan and plan != "all":
            query["plan"] = plan
        if status_filter == "active":
            query["is_active"] = True
        elif status_filter == "banned":
            query["is_active"] = False

        total = users_collection.count_documents(query)
        skip = (page - 1) * limit

        users_cursor = users_collection.find(
            query,
            {"password_hash": 0}  # Không trả về hash mật khẩu
        ).sort("created_at", -1).skip(skip).limit(limit)

        users = []
        for u in users_cursor:
            u["_id"] = str(u["_id"])
            users.append(u)

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
# 3. PATCH USER STATUS (Khóa / Mở khóa)
# PATCH /api/admin/users/{user_id}/status
# ══════════════════════════════════════════════════════════════════════════════
@router.patch("/users/{username}/status")
async def update_user_status(
    username: str,
    body: StatusUpdateSchema,
    admin: dict = Depends(require_admin)
):
    """Khóa hoặc mở khóa tài khoản người dùng."""
    try:
        result = users_collection.update_one(
            {"username": username},
            {"$set": {"is_active": body.is_active, "updated_at": datetime.now(timezone.utc)}}
        )
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Không tìm thấy người dùng")

        action = "admin_ban_user" if not body.is_active else "admin_unban_user"
        _write_audit_log(action, username, admin["sub"], {"reason": body.reason})

        verb = "khóa" if not body.is_active else "mở khóa"
        return {"message": f"Đã {verb} tài khoản '{username}' thành công."}
    except HTTPException:
        raise
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# 4. PATCH USER PLAN (Nâng / Hạ gói)
# PATCH /api/admin/users/{username}/plan
# ══════════════════════════════════════════════════════════════════════════════
@router.patch("/users/{username}/plan")
async def update_user_plan(
    username: str,
    body: PlanUpdateSchema,
    admin: dict = Depends(require_admin)
):
    """Cập nhật gói dịch vụ bản quyền của người dùng."""
    valid_plans = ["free", "pro", "enterprise"]
    if body.plan not in valid_plans:
        raise HTTPException(status_code=400, detail=f"Gói không hợp lệ. Chọn một trong: {valid_plans}")
    try:
        expires_at = None
        if body.plan != "free" and body.duration_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=body.duration_days)

        update_data = {
            "plan": body.plan,
            "updated_at": datetime.now(timezone.utc)
        }
        if expires_at:
            update_data["plan_expires_at"] = expires_at

        result = users_collection.update_one(
            {"username": username},
            {"$set": update_data}
        )
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Không tìm thấy người dùng")

        _write_audit_log(
            "admin_change_plan", username, admin["sub"],
            {"new_plan": body.plan, "duration_days": body.duration_days}
        )
        return {"message": f"Đã cập nhật gói '{body.plan}' cho tài khoản '{username}' thành công."}
    except HTTPException:
        raise
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# 5. REVOKE ALL SESSIONS (Force Logout)
# POST /api/admin/users/{username}/revoke-sessions
# ══════════════════════════════════════════════════════════════════════════════
@router.post("/users/{username}/revoke-sessions")
async def revoke_user_sessions(
    username: str,
    admin: dict = Depends(require_admin)
):
    """Buộc đăng xuất tài khoản khỏi tất cả thiết bị."""
    try:
        result = user_sessions_collection.delete_many({"username": username})
        _write_audit_log("admin_revoke_sessions", username, admin["sub"],
                         {"sessions_removed": result.deleted_count})
        return {
            "message": f"Đã thu hồi {result.deleted_count} phiên làm việc của '{username}'."
        }
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# 6. SESSIONS (Quản lý phiên & thiết bị)
# GET /api/admin/sessions
# ══════════════════════════════════════════════════════════════════════════════
@router.get("/sessions")
async def list_sessions(
    user_id: Optional[str] = Query(None),
    admin: dict = Depends(require_admin)
):
    """Lấy danh sách các phiên đăng nhập đang hoạt động."""
    try:
        query = {}
        if user_id:
            query["username"] = user_id
        sessions = list(user_sessions_collection.find(query, {"_id": 0}).sort("created_at", -1).limit(100))
        return {"sessions": sessions, "total": len(sessions)}
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# 7. AUDIT LOGS (Nhật ký an ninh)
# GET /api/admin/audit-logs
# ══════════════════════════════════════════════════════════════════════════════
@router.get("/audit-logs")
async def get_audit_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    action_type: Optional[str] = Query(None),
    admin: dict = Depends(require_admin)
):
    """Truy vấn nhật ký an ninh và lịch sử các hành động admin."""
    try:
        query = {}
        if action_type and action_type != "all":
            query["action"] = action_type

        total = security_audit_logs_collection.count_documents(query)
        skip = (page - 1) * limit

        logs = list(
            security_audit_logs_collection.find(query, {"_id": 0})
            .sort("timestamp", -1)
            .skip(skip)
            .limit(limit)
        )
        # Chuyển datetime sang ISO string
        for log in logs:
            if isinstance(log.get("timestamp"), datetime):
                log["timestamp"] = log["timestamp"].isoformat()

        # Phân tích Brute-force: IP > 5 lần thất bại trong 15 phút
        fifteen_min_ago = datetime.now(timezone.utc) - timedelta(minutes=15)
        bf_pipeline = [
            {"$match": {"action": "login_failed", "timestamp": {"$gte": fifteen_min_ago}}},
            {"$group": {"_id": "$ip_address", "count": {"$sum": 1}, "last_seen": {"$max": "$timestamp"}}},
            {"$match": {"count": {"$gte": 5}}},
            {"$sort": {"count": -1}}
        ]
        brute_force_alerts = list(security_audit_logs_collection.aggregate(bf_pipeline))
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
# 8. SYSTEM BROADCAST (Cấu hình từ xa)
# POST /api/admin/system/broadcast
# ══════════════════════════════════════════════════════════════════════════════
@router.post("/system/broadcast")
async def system_broadcast(
    body: BroadcastSchema,
    admin: dict = Depends(require_admin)
):
    """Cập nhật cấu hình hệ thống: phiên bản tối thiểu, banner thông báo, chế độ bảo trì."""
    try:
        config_collection = db["system_config"]
        update_data = {"updated_at": datetime.now(timezone.utc), "updated_by": admin["sub"]}
        if body.min_version is not None:
            update_data["min_version"] = body.min_version
        if body.banner_msg is not None:
            update_data["banner_msg"] = body.banner_msg
        if body.maintenance_mode is not None:
            update_data["maintenance_mode"] = body.maintenance_mode

        config_collection.update_one({}, {"$set": update_data}, upsert=True)
        _write_audit_log("admin_system_broadcast", "system", admin["sub"], {"config": update_data})
        return {"message": "Đã cập nhật cấu hình hệ thống thành công.", "config": update_data}
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")


# ══════════════════════════════════════════════════════════════════════════════
# 9. SYSTEM CONFIG (Lấy cấu hình hiện tại)
# GET /api/admin/system/config
# ══════════════════════════════════════════════════════════════════════════════
@router.get("/system/config")
async def get_system_config(admin: dict = Depends(require_admin)):
    """Lấy cấu hình hệ thống hiện tại."""
    try:
        config_collection = db["system_config"]
        config = config_collection.find_one({}, {"_id": 0})
        if not config:
            return {"min_version": "1.0.0", "banner_msg": None, "maintenance_mode": False}
        if isinstance(config.get("updated_at"), datetime):
            config["updated_at"] = config["updated_at"].isoformat()
        return config
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=f"Lỗi database: {str(e)}")
