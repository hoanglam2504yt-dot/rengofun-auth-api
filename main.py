"""
RenGoFun Auth API — main.py
Kiến trúc: Hybrid (Cloud Auth DB MongoDB Atlas + Local Desktop Licensing)
Phiên bản: 3.1.0 — Tách role/plan, RS256 7-day Offline License, Device HWID Limit, SlowAPI Rate-Limit, Billing & Telemetry
"""
import logging
import os
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from pymongo.errors import DuplicateKeyError, PyMongoError
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# ── Env & Logger (nạp .env trước khi import modules đọc os.getenv) ───────────
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

logger = logging.getLogger("rengofun_auth")
logging.basicConfig(level=logging.INFO)

from admin_routes import router as admin_router
from auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    BOOTSTRAP_ADMIN_EMAIL,
    OFFLINE_GRACE_DAYS,
    REFRESH_TOKEN_EXPIRE_DAYS,
    check_login_bruteforce_locked,
    clear_login_failures,
    create_access_token,
    create_license_token,
    generate_captcha_text,
    generate_otp,
    generate_refresh_token,
    get_device_limit,
    get_password_hash,
    get_rs256_public_key,
    is_bootstrap_admin,
    normalize_user_role_and_plan,
    record_login_failure,
    send_email_unified,
    verify_password,
)
from billing_routes import router as billing_router
from database import (
    client,
    email_verifications_collection,
    init_db,
    password_resets_collection,
    security_logs_collection,
    system_config_collection,
    telemetry_events_collection,
    user_sessions_collection,
    users_collection,
)

# ── Captcha In-Memory Store (TTL = 3 phút) ────────────────────────────────────
_captcha_store: dict[str, dict] = {}
CAPTCHA_TTL_SECONDS = 180
OTP_EXPIRE_MINUTES = 15


def parse_cors_origins(raw_origins: Optional[str] = None) -> list[str]:
    """Phân tách danh sách domain CORS cách nhau bởi dấu phẩy từ biến môi trường."""
    raw = (os.getenv("CORS_ORIGINS", "*") if raw_origins is None else raw_origins).strip()
    if not raw or raw == "*":
        return ["*"]
    origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
    if not origins or "*" in origins:
        return ["*"]
    return origins


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    bootstrap_email = os.getenv("BOOTSTRAP_ADMIN_EMAIL", BOOTSTRAP_ADMIN_EMAIL).strip().lower()
    if bootstrap_email:
        try:
            users_collection.update_many(
                {"email": {"$regex": f"^{re.escape(bootstrap_email)}$", "$options": "i"}},
                {"$set": {"role": "admin", "plan": "enterprise", "updated_at": datetime.now(timezone.utc)}},
            )
        except Exception as exc:
            logger.warning(f"[Bootstrap Admin] Không thể đồng bộ khi khởi động: {exc}")
    yield


limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="RenGoFun Auth & Licensing API",
    version="3.1.0",
    lifespan=lifespan,
)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Thao tác quá nhanh hoặc vượt quá giới hạn an toàn. Vui lòng thử lại sau ít phút."},
    )


cors_origins_list = parse_cors_origins()
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(admin_router)
app.include_router(billing_router)


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def is_system_in_maintenance() -> bool:
    try:
        cfg = system_config_collection.find_one({}, {"_id": 0})
        return bool(cfg and cfg.get("maintenance_mode", False))
    except Exception:
        return False


def _log_security(action: str, email: str, ip: str, metadata: dict = None):
    try:
        security_logs_collection.insert_one({
            "email_attempted": email,
            "ip_address": ip,
            "action": action,
            "metadata": metadata or {},
            "created_at": datetime.now(timezone.utc),
        })
    except Exception:
        pass


def _verify_captcha(captcha_id: str, captcha_text: str) -> bool:
    _now = datetime.now(timezone.utc)
    entry = _captcha_store.pop(captcha_id, None)
    if not entry or _now > entry["expires_at"]:
        return False
    return entry["text"].upper() == captcha_text.upper().strip()


def _get_client_ip(request: Request) -> str:
    return request.client.host if request and request.client else "unknown"


def _sanitize_error_message(msg: str) -> str:
    """Làm sạch đường dẫn cá nhân Windows/Linux/Email khỏi thông báo lỗi trước khi lưu Telemetry."""
    clean = re.sub(r"[A-Za-z]:\\[^\s'\"]+", "<LOCAL_PATH>", str(msg or ""))
    clean = re.sub(r"/(?:Users|home)/[^\s'\"]+", "<HOME_PATH>", clean)
    clean = re.sub(r"[\w.+-]+@[\w-]+\.[\w.-]+", "<EMAIL>", clean)
    return clean[:320]


def _enforce_device_limit(user_id: str, role: str, plan: str, device_hwid: str) -> Optional[int]:
    """
    Giới hạn số thiết bị đồng thời dựa theo `plan`:
    - `free`: MAX_DEVICES_FREE (1)
    - `pro` / `moderator`: MAX_DEVICES_PRO (2)
    - `enterprise` / `admin`: không giới hạn (`None`)
    Khi vượt giới hạn, thu hồi phiên thiết bị cũ nhất để đảm bảo không vượt trần đồng thời.
    """
    limit = get_device_limit(role, plan)
    if limit is None:
        return None

    active_sessions = list(
        user_sessions_collection.find(
            {"user_id": user_id, "is_revoked": False},
            {"session_id": 1, "device_hwid": 1, "created_at": 1},
        ).sort("created_at", 1)
    )

    if device_hwid:
        # Thu hồi các phiên cùng device_hwid cũ (tránh tích tụ trùng lặp trên cùng 1 máy)
        same_hw_ids = [s["session_id"] for s in active_sessions if s.get("device_hwid") == device_hwid]
        if same_hw_ids:
            user_sessions_collection.update_many(
                {"session_id": {"$in": same_hw_ids}},
                {"$set": {"is_revoked": True}},
            )
            active_sessions = [s for s in active_sessions if s.get("device_hwid") != device_hwid]

    # Cần giữ chỗ cho 1 phiên mới sắp chèn -> chỉ giữ tối đa (limit - 1) phiên đang hoạt động
    max_existing = max(0, limit - 1)
    if len(active_sessions) > max_existing:
        excess = active_sessions[: len(active_sessions) - max_existing]
        revoke_ids = [s["session_id"] for s in excess if "session_id" in s]
        if revoke_ids:
            user_sessions_collection.update_many(
                {"session_id": {"$in": revoke_ids}},
                {"$set": {"is_revoked": True}},
            )
    return limit


def _serialize_user_payload(user: dict) -> dict:
    exp_val = user.get("plan_expires_at")
    return {
        "id": user.get("id", str(user.get("_id", ""))),
        "email": user.get("email"),
        "username": user.get("username", user.get("email")),
        "role": user.get("role", "user"),
        "plan": user.get("plan", "free"),
        "plan_expires_at": exp_val.isoformat() if isinstance(exp_val, datetime) else exp_val,
        "preferences": user.get("preferences", {}),
    }


# ══════════════════════════════════════════════════════════════════════════════
# PYDANTIC SCHEMAS
# ══════════════════════════════════════════════════════════════════════════════

class RegisterSchema(BaseModel):
    email: EmailStr
    password: str
    captcha_id: str
    captcha_text: str


class VerifyEmailSchema(BaseModel):
    email: EmailStr
    otp_code: str


class LoginSchema(BaseModel):
    email: str
    password: str
    captcha_id: Optional[str] = None
    captcha_text: Optional[str] = None
    device_hwid: Optional[str] = None
    device_name: Optional[str] = None


class LegacyAuthSchema(BaseModel):
    username: str
    password: str


class RefreshTokenSchema(BaseModel):
    refresh_token: str
    device_hwid: Optional[str] = None


class ForgotPasswordSchema(BaseModel):
    email: EmailStr
    captcha_id: str
    captcha_text: str


class TelemetryReportSchema(BaseModel):
    tool_code: str
    error_code: str = "RUNTIME_ERROR"
    error_message: str = ""
    image_dimensions: Optional[str] = None
    cpu_info: Optional[str] = None
    ram_gb: Optional[float] = None
    gpu_name: Optional[str] = None
    app_version: Optional[str] = None
    os_platform: Optional[str] = None


# ══════════════════════════════════════════════════════════════════════════════
# ROOT / HEALTH / PUBLIC STATUS / PUBLIC KEY
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/")
async def root():
    return {
        "service": "RenGoFun Auth & Licensing API",
        "version": "3.1.0",
        "status": "online",
        "docs": "/docs",
    }


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/health/db")
async def health_check_db():
    try:
        client.admin.command("ping")
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        logger.error(f"MongoDB health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Mất kết nối tới cơ sở dữ liệu MongoDB Atlas",
        )


@app.get("/system/status")
async def get_public_system_status():
    """Kiểm tra công khai: chế độ bảo trì, banner, min_version."""
    try:
        cfg = system_config_collection.find_one({}, {"_id": 0})
        if not cfg:
            return {"maintenance_mode": False, "banner_msg": None, "min_version": "0.1.0"}
        return {
            "maintenance_mode": cfg.get("maintenance_mode", False),
            "banner_msg": cfg.get("banner_msg"),
            "min_version": cfg.get("min_version", "0.1.0"),
        }
    except Exception:
        return {"maintenance_mode": False, "banner_msg": None, "min_version": "0.1.0"}


@app.get("/auth/public-key")
async def get_license_public_key():
    """Trả về Public Key RS256 để đồng bộ xác thực bản quyền offline."""
    return {"algorithm": "RS256", "public_key_pem": get_rs256_public_key()}


# ══════════════════════════════════════════════════════════════════════════════
# 1. CAPTCHA
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/auth/captcha")
@app.post("/auth/captcha")
@limiter.limit("30/minute")
async def get_captcha(request: Request):
    captcha_id = str(uuid.uuid4())
    captcha_text = generate_captcha_text(4)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=CAPTCHA_TTL_SECONDS)
    _captcha_store[captcha_id] = {"text": captcha_text, "expires_at": expires_at}

    _now = datetime.now(timezone.utc)
    for k in [k for k, v in _captcha_store.items() if _now > v["expires_at"]]:
        _captcha_store.pop(k, None)

    return {
        "captcha_id": captcha_id,
        "captcha_text": captcha_text,
        "expires_in_seconds": CAPTCHA_TTL_SECONDS,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 2. ĐĂNG KÝ (Bắt buộc Captcha thật + Giới hạn OTP 5 lần/giờ/IP)
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/hour")
async def register(body: RegisterSchema, request: Request):
    ip = _get_client_ip(request)

    if is_system_in_maintenance():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Hệ thống đang bảo trì. Tạm ngừng tiếp nhận đăng ký mới.",
        )

    if not _verify_captcha(body.captcha_id, body.captcha_text):
        _log_security("captcha_failed", body.email, ip, {"endpoint": "register"})
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mã xác thực (captcha) không đúng hoặc đã hết hạn. Vui lòng thử lại.",
        )

    try:
        if users_collection.find_one({"email": body.email}):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email này đã được đăng ký trên hệ thống.",
            )

        user_id = str(uuid.uuid4())
        default_username = body.email.split("@")[0]

        bootstrap_admin = is_bootstrap_admin(body.email)
        initial_role = "admin" if bootstrap_admin else "user"
        initial_plan = "enterprise" if bootstrap_admin else "free"

        new_user = {
            "id": user_id,
            "email": body.email,
            "username": default_username,
            "password_hash": get_password_hash(body.password),
            "role": initial_role,
            "plan": initial_plan,
            "plan_expires_at": None,
            "preferences": {"theme": "dark", "language": "vi"},
            "is_verified": False,
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
        users_collection.insert_one(new_user)

        otp_code = generate_otp(6)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES)
        email_verifications_collection.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "otp_code": otp_code,
            "expires_at": expires_at,
            "is_used": False,
            "created_at": datetime.now(timezone.utc),
        })

        html = f"""
        <div style="font-family:sans-serif; max-width:500px; margin:auto; padding:24px; border:1px solid #e4e4e7; border-radius:12px;">
            <h2 style="color:#4f46e5; margin-top:0;">Chào mừng đến với RenGoFun!</h2>
            <p>Mã OTP xác thực kích hoạt tài khoản của bạn là:</p>
            <div style="font-size:28px; font-weight:bold; letter-spacing:8px; color:#4f46e5; background:#f4f4f5; padding:16px; border-radius:8px; text-align:center; margin:16px 0;">
                {otp_code}
            </div>
            <p style="color:#71717a; font-size:13px;">Mã này có hiệu lực trong <strong>{OTP_EXPIRE_MINUTES} phút</strong>. Tuyệt đối không chia sẻ mã này với bất kỳ ai.</p>
        </div>
        """
        send_email_unified(body.email, "[RenGoFun] Mã OTP kích hoạt tài khoản", html)

        _log_security("register", body.email, ip)
        return {"message": "Đăng ký thành công! Vui lòng kiểm tra email để lấy mã kích hoạt."}

    except DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Email này đã được đăng ký trên hệ thống.")
    except HTTPException:
        raise
    except PyMongoError as e:
        logger.error(f"MongoDB Error during register: {e}")
        raise HTTPException(status_code=503, detail="Lỗi kết nối cơ sở dữ liệu.")


@app.post("/auth/verify-email")
async def verify_email(body: VerifyEmailSchema):
    try:
        user = users_collection.find_one({"email": body.email})
        if not user:
            raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản.")

        if user.get("is_verified"):
            normalize_user_role_and_plan(user, users_collection)
            return {"message": "Tài khoản đã được kích hoạt trước đó. Bạn có thể đăng nhập ngay."}

        now = datetime.now(timezone.utc)
        otp_doc = email_verifications_collection.find_one({
            "user_id": user["id"],
            "otp_code": body.otp_code.strip(),
            "is_used": False,
            "expires_at": {"$gt": now},
        })

        if not otp_doc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Mã xác thực OTP không đúng hoặc đã hết hạn.",
            )

        email_verifications_collection.update_one(
            {"_id": otp_doc["_id"]},
            {"$set": {"is_used": True}},
        )

        verify_update: dict = {"is_verified": True, "updated_at": now}
        if is_bootstrap_admin(user.get("email")):
            verify_update["role"] = "admin"
            verify_update["plan"] = "enterprise"

        users_collection.update_one({"id": user["id"]}, {"$set": verify_update})
        return {"message": "Kích hoạt tài khoản thành công! Bạn có thể đăng nhập ngay bây giờ."}
    except HTTPException:
        raise
    except PyMongoError as e:
        logger.error(f"MongoDB Error during verify-email: {e}")
        raise HTTPException(status_code=503, detail="Lỗi cơ sở dữ liệu.")


# ══════════════════════════════════════════════════════════════════════════════
# 4. ĐĂNG NHẬP (Brute-Force Lock 5 lần/15p + HWID Device Limit + RS256 License 7 ngày)
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/auth/login")
async def login(body: LoginSchema, request: Request):
    ip = _get_client_ip(request)
    lock_sec = check_login_bruteforce_locked(ip, body.email)
    if lock_sec > 0:
        _log_security("login_rate_limited", body.email, ip, {"retry_after_sec": lock_sec})
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Bạn đã nhập sai quá 5 lần. Vui lòng thử lại sau {max(1, (lock_sec + 59) // 60)} phút.",
        )

    if body.captcha_id:
        if not body.captcha_text or not _verify_captcha(body.captcha_id, body.captcha_text):
            _log_security("captcha_failed", body.email, ip, {"endpoint": "login"})
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Mã xác thực (captcha) không đúng hoặc đã hết hạn.",
            )

    try:
        user = users_collection.find_one({
            "$or": [
                {"email": body.email},
                {"username": body.email},
            ]
        })

        if not user or not verify_password(body.password, user.get("password_hash", "")):
            fails = record_login_failure(ip, body.email)
            _log_security("login_failed", body.email, ip, {"reason": "wrong_credentials", "attempt": fails})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Tài khoản/email hoặc mật khẩu không chính xác.",
            )

        clear_login_failures(ip, body.email)
        user = normalize_user_role_and_plan(user, users_collection)

        if not user.get("is_verified", False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tài khoản chưa được kích hoạt. Vui lòng kiểm tra email và nhập mã OTP.",
            )

        if user.get("is_active") is False:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tài khoản của bạn đã bị khóa. Vui lòng liên hệ quản trị viên.",
            )

        role = user.get("role", "user")
        plan = user.get("plan", "free")

        if is_system_in_maintenance() and role != "admin":
            _log_security("login_blocked_maintenance", body.email, ip)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Hệ thống đang trong chế độ bảo trì nâng cấp. Chỉ Quản trị viên mới có thể truy cập.",
            )

        user_id = user.get("id", str(user["_id"]))
        device_hwid = (body.device_hwid or "").strip()
        device_limit = _enforce_device_limit(user_id, role, plan, device_hwid)

        access_token = create_access_token({
            "sub": user_id,
            "role": role,
            "plan": plan,
            "username": user.get("username", user.get("email")),
        })
        license_token = create_license_token(
            user_id=user_id,
            role=role,
            plan=plan,
            device_hwid=device_hwid,
            plan_expires_at=user.get("plan_expires_at"),
            grace_days=OFFLINE_GRACE_DAYS,
        )

        refresh_token = generate_refresh_token()
        expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

        user_sessions_collection.insert_one({
            "session_id": str(uuid.uuid4()),
            "user_id": user_id,
            "device_hwid": device_hwid or None,
            "refresh_token": refresh_token,
            "device_info": {
                "ip_address": ip,
                "user_agent": request.headers.get("user-agent", "unknown"),
                "device_name": (body.device_name or "")[:100],
            },
            "expires_at": expires_at,
            "is_revoked": False,
            "created_at": datetime.now(timezone.utc),
        })

        _log_security("login_success", body.email, ip, {"hwid_bound": bool(device_hwid)})
        user_payload = _serialize_user_payload(user)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "license_token": license_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "device_limit": device_limit,
            "offline_grace_days": OFFLINE_GRACE_DAYS,
            "username": user_payload["username"],
            "role": role,
            "plan": plan,
            "user": user_payload,
        }

    except HTTPException:
        raise
    except PyMongoError as e:
        logger.error(f"MongoDB Error during login: {e}")
        raise HTTPException(status_code=503, detail="Lỗi kết nối cơ sở dữ liệu.")


# ══════════════════════════════════════════════════════════════════════════════
# 5. LÀM MỚI ACCESS TOKEN & LICENSE TOKEN
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/auth/refresh")
async def refresh_token(body: RefreshTokenSchema):
    try:
        now = datetime.now(timezone.utc)
        session = user_sessions_collection.find_one({
            "refresh_token": body.refresh_token,
            "is_revoked": False,
            "expires_at": {"$gt": now},
        })

        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh Token không hợp lệ hoặc đã hết hạn. Vui lòng đăng nhập lại.",
            )

        bound_hwid = (session.get("device_hwid") or "").strip()
        req_hwid = (body.device_hwid or "").strip()
        if bound_hwid and req_hwid and bound_hwid != req_hwid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Phiên đăng nhập không khớp mã phần cứng thiết bị.",
            )

        user = users_collection.find_one({"id": session["user_id"]})
        if not user or not user.get("is_verified"):
            raise HTTPException(status_code=401, detail="Tài khoản không tồn tại hoặc chưa kích hoạt.")
        if user.get("is_active") is False:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tài khoản của bạn đã bị khóa. Vui lòng liên hệ quản trị viên.",
            )

        user = normalize_user_role_and_plan(user, users_collection)
        role = user.get("role", "user")
        plan = user.get("plan", "free")
        uid = user.get("id", str(user["_id"]))
        active_hwid = req_hwid or bound_hwid

        access_token = create_access_token({
            "sub": uid,
            "role": role,
            "plan": plan,
            "username": user.get("username", user.get("email")),
        })
        license_token = create_license_token(
            user_id=uid,
            role=role,
            plan=plan,
            device_hwid=active_hwid,
            plan_expires_at=user.get("plan_expires_at"),
            grace_days=OFFLINE_GRACE_DAYS,
        )
        user_payload = _serialize_user_payload(user)

        return {
            "access_token": access_token,
            "license_token": license_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "role": role,
            "plan": plan,
            "user": user_payload,
        }

    except HTTPException:
        raise
    except PyMongoError as e:
        logger.error(f"MongoDB Error during refresh: {e}")
        raise HTTPException(status_code=503, detail="Lỗi cơ sở dữ liệu.")


@app.post("/auth/logout")
async def logout(body: RefreshTokenSchema):
    try:
        user_sessions_collection.update_one(
            {"refresh_token": body.refresh_token},
            {"$set": {"is_revoked": True}},
        )
        return {"message": "Đăng xuất thành công."}
    except PyMongoError as e:
        logger.error(f"MongoDB Error during logout: {e}")
        raise HTTPException(status_code=503, detail="Lỗi cơ sở dữ liệu.")


@app.post("/auth/forgot-password", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("3/hour")
async def forgot_password(body: ForgotPasswordSchema, request: Request):
    ip = _get_client_ip(request)

    if not _verify_captcha(body.captcha_id, body.captcha_text):
        _log_security("captcha_failed", body.email, ip, {"endpoint": "forgot-password"})
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mã xác thực không đúng hoặc đã hết hạn.",
        )

    try:
        user = users_collection.find_one({"email": body.email})
        if not user or not user.get("is_verified"):
            _log_security("password_reset_request", body.email, ip, {"result": "user_not_found_or_unverified"})
            return {
                "message": "Nếu email tồn tại và đã kích hoạt, yêu cầu đặt lại mật khẩu đã được ghi nhận."
            }

        password_resets_collection.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": user["id"],
            "status": "pending",
            "admin_id": None,
            "admin_note": None,
            "processed_at": None,
            "created_at": datetime.now(timezone.utc),
        })

        _log_security("password_reset_request", body.email, ip, {"result": "request_created"})
        return {
            "message": "Yêu cầu đặt lại mật khẩu đã được ghi nhận. Quản trị viên sẽ phê duyệt và gửi mật khẩu mới qua email của bạn."
        }
    except HTTPException:
        raise
    except PyMongoError as e:
        logger.error(f"MongoDB Error during forgot-password: {e}")
        raise HTTPException(status_code=503, detail="Lỗi cơ sở dữ liệu.")


# ══════════════════════════════════════════════════════════════════════════════
# 8. PRIVACY-FIRST CRASH TELEMETRY
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/telemetry/report", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("30/minute")
async def report_crash_telemetry(body: TelemetryReportSchema, request: Request):
    """Nhận báo cáo lỗi ẩn danh (tuyệt đối không lưu ảnh hay đường dẫn cá nhân)."""
    try:
        telemetry_events_collection.insert_one({
            "tool_code": body.tool_code[:32].upper(),
            "error_code": body.error_code[:64],
            "error_message": _sanitize_error_message(body.error_message),
            "image_dimensions": (body.image_dimensions or "")[:40],
            "cpu_info": (body.cpu_info or "")[:80],
            "ram_gb": body.ram_gb,
            "gpu_name": (body.gpu_name or "")[:80],
            "app_version": (body.app_version or "")[:24],
            "os_platform": (body.os_platform or "")[:40],
            "created_at": datetime.now(timezone.utc),
        })
        return {"status": "recorded"}
    except Exception:
        return {"status": "ignored"}


# ══════════════════════════════════════════════════════════════════════════════
# 9. LEGACY ROUTE PROTECTION (/register khóa hẳn chống vượt Captcha, /login giữ tương thích)
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/login")
async def legacy_login(body: LegacyAuthSchema, request: Request):
    login_obj = LoginSchema(email=body.username, password=body.password)
    return await login(login_obj, request)


@app.post("/register")
async def legacy_register_disabled():
    """Đã khóa endpoint /register cũ không có Captcha để chặn spam tài khoản tự động."""
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="Endpoint /register cũ đã bị vô hiệu hóa vì lý do bảo mật. Vui lòng sử dụng /auth/register kèm Captcha.",
    )
