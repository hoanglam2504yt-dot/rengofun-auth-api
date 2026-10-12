"""
RenGoFun Auth API — main.py
Kiến trúc: Hybrid (Cloud Auth DB MongoDB Atlas + Local SQLite)
Phiên bản: 3.0.0 — Cập nhật bảo mật toàn diện theo Update_Auth_Database_Design.md
"""
import logging
import os
import smtplib
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from pymongo.errors import DuplicateKeyError, PyMongoError

from admin_routes import router as admin_router
from auth import (
    create_access_token,
    generate_captcha_text,
    generate_otp,
    generate_refresh_token,
    get_password_hash,
    verify_password,
)
from database import (
    client,
    email_verifications_collection,
    password_resets_collection,
    security_logs_collection,
    system_config_collection,
    user_sessions_collection,
    users_collection,
    init_db,
)

# ── Env & Logger ──────────────────────────────────────────────────────────────
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

logger = logging.getLogger("rengofun_auth")
logging.basicConfig(level=logging.INFO)

# ── SMTP Config ───────────────────────────────────────────────────────────────
SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM     = os.getenv("SMTP_FROM", SMTP_USER)

# ── Captcha In-Memory Store (TTL = 3 phút) ────────────────────────────────────
_captcha_store: dict[str, dict] = {}
CAPTCHA_TTL_SECONDS = 180

# ── Tham số bảo mật ───────────────────────────────────────────────────────────
OTP_EXPIRE_MINUTES        = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


# ── FastAPI App ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="RenGoFun Auth API",
    version="3.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(admin_router)


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def is_system_in_maintenance() -> bool:
    """Kiểm tra cờ maintenance_mode trong system_config."""
    try:
        cfg = system_config_collection.find_one({}, {"_id": 0})
        return bool(cfg and cfg.get("maintenance_mode", False))
    except Exception:
        return False


def _log_security(action: str, email: str, ip: str, metadata: dict = None):
    """Ghi nhật ký bảo mật vào security_logs (không gây nghẽn luồng chính)."""
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


def _send_email(to_email: str, subject: str, html_body: str) -> bool:
    """Gửi email qua SMTP (Gmail)."""
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
        logger.error(f"[SMTP] Gửi email tới {to_email} thất bại: {e}")
        return False


def _verify_captcha(captcha_id: str, captcha_text: str) -> bool:
    """
    Xác thực captcha:
    - Xóa ngay sau khi kiểm tra để chống replay attack.
    - So sánh không phân biệt hoa/thường.
    """
    _now = datetime.now(timezone.utc)
    entry = _captcha_store.pop(captcha_id, None)
    if not entry:
        return False
    if _now > entry["expires_at"]:
        return False
    return entry["text"].upper() == captcha_text.upper().strip()


def _get_client_ip(request: Request) -> str:
    return request.client.host if request and request.client else "unknown"


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
    email: str  # Chấp nhận cả email hoặc username
    password: str
    captcha_id: Optional[str] = None
    captcha_text: Optional[str] = None


class LegacyAuthSchema(BaseModel):
    username: str
    password: str


class RefreshTokenSchema(BaseModel):
    refresh_token: str


class ForgotPasswordSchema(BaseModel):
    email: EmailStr
    captcha_id: str
    captcha_text: str


# ══════════════════════════════════════════════════════════════════════════════
# ROOT / HEALTH / STATUS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/")
async def root():
    return {
        "service": "RenGoFun Auth API",
        "version": "3.0.0",
        "status": "online",
        "docs": "/docs",
    }


@app.get("/health")
def health_check():
    """Liveness check — kiểm tra máy chủ hoạt động."""
    return {"status": "ok"}


@app.get("/health/db")
async def health_check_db():
    """Readiness check — kiểm tra kết nối MongoDB Atlas."""
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
            return {"maintenance_mode": False, "banner_msg": None, "min_version": "1.0.0"}
        return {
            "maintenance_mode": cfg.get("maintenance_mode", False),
            "banner_msg": cfg.get("banner_msg"),
            "min_version": cfg.get("min_version", "1.0.0"),
        }
    except Exception:
        return {"maintenance_mode": False, "banner_msg": None, "min_version": "1.0.0"}


# ══════════════════════════════════════════════════════════════════════════════
# 1. CAPTCHA (Bắt buộc theo thiết kế 3.1)
# POST /auth/captcha
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/auth/captcha")
async def get_captcha():
    """
    Sinh Captcha 4 ký tự ngẫu nhiên (lọc bỏ ký tự dễ nhầm lẫn).
    TTL 3 phút, lưu in-memory / cache.
    """
    captcha_id   = str(uuid.uuid4())
    captcha_text = generate_captcha_text(4)
    expires_at   = datetime.now(timezone.utc) + timedelta(seconds=CAPTCHA_TTL_SECONDS)
    _captcha_store[captcha_id] = {"text": captcha_text, "expires_at": expires_at}

    # Dọn dẹp key hết hạn
    _now = datetime.now(timezone.utc)
    expired_keys = [k for k, v in _captcha_store.items() if _now > v["expires_at"]]
    for k in expired_keys:
        _captcha_store.pop(k, None)

    return {
        "captcha_id": captcha_id,
        "captcha_text": captcha_text,
        "expires_in_seconds": CAPTCHA_TTL_SECONDS,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 2. ĐĂNG KÝ (Theo thiết kế 3.2: OTP gửi về Gmail)
# POST /auth/register
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
async def register(body: RegisterSchema, request: Request):
    """
    Luồng đăng ký:
    1. Kiểm tra bảo trì & xác thực Captcha
    2. Tạo user với is_verified = False
    3. Sinh OTP 6 số lưu email_verifications và gửi Gmail
    """
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
        # Trích username mặc định từ email
        default_username = body.email.split("@")[0]

        new_user = {
            "id": user_id,
            "email": body.email,
            "username": default_username,
            "password_hash": get_password_hash(body.password),
            "role": "free",
            "plan": "free",
            "preferences": {"theme": "dark", "language": "vi"},
            "is_verified": False,
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
        users_collection.insert_one(new_user)

        # Sinh OTP 6 số (15 phút)
        otp_code   = generate_otp(6)
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
        _send_email(body.email, "[RenGoFun] Mã OTP kích hoạt tài khoản", html)

        _log_security("register", body.email, ip)
        return {"message": "Đăng ký thành công! Vui lòng kiểm tra email để lấy mã kích hoạt."}

    except DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Email này đã được đăng ký trên hệ thống.")
    except HTTPException:
        raise
    except PyMongoError as e:
        logger.error(f"MongoDB Error during register: {e}")
        raise HTTPException(status_code=503, detail="Lỗi kết nối cơ sở dữ liệu.")


# ══════════════════════════════════════════════════════════════════════════════
# 3. XÁC THỰC EMAIL (Kích hoạt tài khoản)
# POST /auth/verify-email
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/auth/verify-email")
async def verify_email(body: VerifyEmailSchema):
    """Kích hoạt tài khoản bằng mã OTP 6 số."""
    try:
        user = users_collection.find_one({"email": body.email})
        if not user:
            raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản.")

        if user.get("is_verified"):
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

        # Đánh dấu OTP đã dùng
        email_verifications_collection.update_one(
            {"_id": otp_doc["_id"]},
            {"$set": {"is_used": True}},
        )

        # Kích hoạt user
        users_collection.update_one(
            {"id": user["id"]},
            {"$set": {"is_verified": True, "updated_at": now}},
        )

        return {"message": "Kích hoạt tài khoản thành công! Bạn có thể đăng nhập ngay bây giờ."}

    except HTTPException:
        raise
    except PyMongoError as e:
        logger.error(f"MongoDB Error during verify-email: {e}")
        raise HTTPException(status_code=503, detail="Lỗi cơ sở dữ liệu.")


# ══════════════════════════════════════════════════════════════════════════════
# 4. ĐĂNG NHẬP (Access Token 15p + Refresh Token 7 ngày)
# POST /auth/login
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/auth/login")
async def login(body: LoginSchema, request: Request):
    """
    Luồng đăng nhập chuẩn v3.0:
    1. Kiểm tra captcha (nếu gửi)
    2. Xác thực email/username và mật khẩu
    3. Bắt buộc is_verified = True
    4. Cấp Access Token JWT (15 phút) và Refresh Token (7 ngày)
    """
    ip = _get_client_ip(request)

    # Nếu có gửi captcha thì bắt buộc xác thực
    if body.captcha_id:
        if not body.captcha_text or not _verify_captcha(body.captcha_id, body.captcha_text):
            _log_security("captcha_failed", body.email, ip, {"endpoint": "login"})
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Mã xác thực (captcha) không đúng hoặc đã hết hạn.",
            )

    try:
        # Tìm theo email hoặc username
        user = users_collection.find_one({
            "$or": [
                {"email": body.email},
                {"username": body.email},
            ]
        })

        if not user or not verify_password(body.password, user["password_hash"]):
            _log_security("login_failed", body.email, ip, {"reason": "wrong_credentials"})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Tài khoản/email hoặc mật khẩu không chính xác.",
            )

        # Kiểm tra tài khoản đã kích hoạt chưa
        if not user.get("is_verified", False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tài khoản chưa được kích hoạt. Vui lòng kiểm tra email và nhập mã OTP.",
            )

        # Kiểm tra tài khoản có bị khóa không
        if user.get("is_active") is False:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tài khoản của bạn đã bị khóa. Vui lòng liên hệ quản trị viên.",
            )

        # Kiểm tra chế độ bảo trì
        if is_system_in_maintenance() and user.get("role") != "admin":
            _log_security("login_blocked_maintenance", body.email, ip)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Hệ thống đang trong chế độ bảo trì nâng cấp. Chỉ Quản trị viên mới có thể truy cập.",
            )

        # Access Token JWT sống 15 phút
        user_id = user.get("id", str(user["_id"]))
        role    = user.get("role", "free")
        access_token = create_access_token({
            "sub": user_id,
            "role": role,
            "username": user.get("username", user.get("email")),
        })

        # Refresh Token sống 7 ngày
        refresh_token = generate_refresh_token()
        expires_at    = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

        user_sessions_collection.insert_one({
            "session_id": str(uuid.uuid4()),
            "user_id": user_id,
            "refresh_token": refresh_token,
            "device_info": {
                "ip_address": ip,
                "user_agent": request.headers.get("user-agent", "unknown"),
            },
            "expires_at": expires_at,
            "is_revoked": False,
            "created_at": datetime.now(timezone.utc),
        })

        _log_security("login_success", body.email, ip)

        # Map plan để tương thích với app cũ
        plan_equiv = "enterprise" if role == "pro_tier_2" else ("pro" if role == "pro_tier_1" else "free")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": 15 * 60,
            "username": user.get("username", user.get("email")),
            "role": role,
            "plan": user.get("plan", plan_equiv),
            "user": {
                "id": user_id,
                "email": user.get("email"),
                "username": user.get("username"),
                "role": role,
                "plan": user.get("plan", plan_equiv),
                "preferences": user.get("preferences", {}),
            },
        }

    except HTTPException:
        raise
    except PyMongoError as e:
        logger.error(f"MongoDB Error during login: {e}")
        raise HTTPException(status_code=503, detail="Lỗi kết nối cơ sở dữ liệu.")


# ══════════════════════════════════════════════════════════════════════════════
# 5. LÀM MỚI ACCESS TOKEN
# POST /auth/refresh
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/auth/refresh")
async def refresh_token(body: RefreshTokenSchema):
    """Cấp Access Token mới khi còn Refresh Token hợp lệ."""
    try:
        now     = datetime.now(timezone.utc)
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

        user = users_collection.find_one({"id": session["user_id"]})
        if not user or not user.get("is_verified"):
            raise HTTPException(status_code=401, detail="Tài khoản không tồn tại hoặc chưa kích hoạt.")

        access_token = create_access_token({
            "sub": user["id"],
            "role": user.get("role", "free"),
            "username": user.get("username", user.get("email")),
        })

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": 15 * 60,
        }

    except HTTPException:
        raise
    except PyMongoError as e:
        logger.error(f"MongoDB Error during refresh: {e}")
        raise HTTPException(status_code=503, detail="Lỗi cơ sở dữ liệu.")


# ══════════════════════════════════════════════════════════════════════════════
# 6. ĐĂNG XUẤT
# POST /auth/logout
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/auth/logout")
async def logout(body: RefreshTokenSchema):
    """Thu hồi Refresh Token hiện tại (is_revoked = True)."""
    try:
        user_sessions_collection.update_one(
            {"refresh_token": body.refresh_token},
            {"$set": {"is_revoked": True}},
        )
        return {"message": "Đăng xuất thành công."}
    except PyMongoError as e:
        logger.error(f"MongoDB Error during logout: {e}")
        raise HTTPException(status_code=503, detail="Lỗi cơ sở dữ liệu.")


# ══════════════════════════════════════════════════════════════════════════════
# 7. QUÊN MẬT KHẨU (Tạo yêu cầu chờ Admin duyệt)
# POST /auth/forgot-password
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/auth/forgot-password", status_code=status.HTTP_202_ACCEPTED)
async def forgot_password(body: ForgotPasswordSchema, request: Request):
    """Luồng quên mật khẩu: kiểm tra captcha -> tạo yêu cầu pending chờ Admin duyệt."""
    ip = _get_client_ip(request)

    if not _verify_captcha(body.captcha_id, body.captcha_text):
        _log_security("captcha_failed", body.email, ip, {"endpoint": "forgot-password"})
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mã xác thực không đúng hoặc đã hết hạn.",
        )

    try:
        user = users_collection.find_one({"email": body.email})

        # Phản hồi trung lập chống email enumeration
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
# 8. LEGACY COMPATIBILITY ROUTE ALIASES (/login, /register)
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/login")
async def legacy_login(body: LegacyAuthSchema, request: Request):
    """Endpoint tương thích ngược với client cũ gọi /login với {username, password}."""
    login_obj = LoginSchema(email=body.username, password=body.password)
    return await login(login_obj, request)


@app.post("/register", status_code=status.HTTP_201_CREATED)
async def legacy_register(body: LegacyAuthSchema, request: Request):
    """Endpoint tương thích ngược cho client cũ chưa có Captcha."""
    # Nếu client cũ gọi mà chưa có captcha, sinh tự động nội bộ để không vỡ client cũ
    captcha_text = generate_captcha_text(4)
    captcha_id = str(uuid.uuid4())
    _captcha_store[captcha_id] = {
        "text": captcha_text,
        "expires_at": datetime.now(timezone.utc) + timedelta(seconds=60)
    }
    email_equiv = body.username if "@" in body.username else f"{body.username}@rengofun.com"
    reg_obj = RegisterSchema(
        email=email_equiv,
        password=body.password,
        captcha_id=captcha_id,
        captcha_text=captcha_text
    )
    return await register(reg_obj, request)