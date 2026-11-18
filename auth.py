import json
import logging
import os
import secrets
import smtplib
import ssl
import string
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

import bcrypt
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv

try:
    import certifi
except ImportError:
    certifi = None

env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

logger = logging.getLogger("rengofun_auth")


def _safe_int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


SECRET_KEY = os.getenv("SECRET_KEY", "")
ALGORITHM = "HS256"

# ── RBAC & Plan Constants (Tách bạch role vs plan) ────────────────────────────
VALID_ROLES = {"user", "moderator", "admin"}
VALID_PLANS = {"free", "pro", "enterprise"}

ACCESS_TOKEN_EXPIRE_MINUTES = _safe_int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"), 15)
REFRESH_TOKEN_EXPIRE_DAYS = _safe_int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"), 7)
BOOTSTRAP_ADMIN_EMAIL = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()

MAX_DEVICES_FREE = max(1, _safe_int(os.getenv("MAX_DEVICES_FREE", "1"), 1))
MAX_DEVICES_PRO = max(1, _safe_int(os.getenv("MAX_DEVICES_PRO", "2"), 2))
OFFLINE_GRACE_DAYS = max(1, _safe_int(os.getenv("OFFLINE_GRACE_DAYS", "7"), 7))

# ── RSA-2048 Key Management cho License Token (RS256 Offline 7 ngày) ─────────
_EPHEMERAL_PRIVATE_PEM: Optional[str] = None
_EPHEMERAL_PUBLIC_PEM: Optional[str] = None


def _ensure_ephemeral_rsa_pair() -> tuple[str, str]:
    global _EPHEMERAL_PRIVATE_PEM, _EPHEMERAL_PUBLIC_PEM
    if _EPHEMERAL_PRIVATE_PEM and _EPHEMERAL_PUBLIC_PEM:
        return _EPHEMERAL_PRIVATE_PEM, _EPHEMERAL_PUBLIC_PEM
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _EPHEMERAL_PRIVATE_PEM = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    _EPHEMERAL_PUBLIC_PEM = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    logger.warning("[RS256] Chưa cấu hình JWT_RS256_PRIVATE_KEY trong .env — đang dùng khóa tạm thời cho tiến trình hiện tại.")
    return _EPHEMERAL_PRIVATE_PEM, _EPHEMERAL_PUBLIC_PEM


def get_rs256_private_key() -> str:
    raw = os.getenv("JWT_RS256_PRIVATE_KEY", "").strip()
    if raw:
        return raw.strip('"').strip("'").replace("\\n", "\n")
    priv, _ = _ensure_ephemeral_rsa_pair()
    return priv


def get_rs256_public_key() -> str:
    raw = os.getenv("JWT_RS256_PUBLIC_KEY", "").strip()
    if raw:
        return raw.strip('"').strip("'").replace("\\n", "\n")
    priv_raw = os.getenv("JWT_RS256_PRIVATE_KEY", "").strip()
    if priv_raw:
        priv = serialization.load_pem_private_key(
            priv_raw.strip('"').strip("'").replace("\\n", "\n").encode("ascii"),
            password=None,
        )
        return priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
    _, pub = _ensure_ephemeral_rsa_pair()
    return pub


def is_bootstrap_admin(email: Optional[str]) -> bool:
    """Kiểm tra email có trùng khớp BOOTSTRAP_ADMIN_EMAIL trong .env hay không."""
    configured = os.getenv("BOOTSTRAP_ADMIN_EMAIL", BOOTSTRAP_ADMIN_EMAIL).strip().lower()
    if not configured or not email:
        return False
    return email.strip().lower() == configured


def _parse_utc_dt(val) -> Optional[datetime]:
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    if isinstance(val, str) and val.strip():
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def normalize_user_role_and_plan(user_doc: Optional[dict], users_col=None) -> Optional[dict]:
    """
    Chuẩn hóa & migrate nhẹ dữ liệu phân quyền cũ trong MongoDB:
    - `role` chỉ nhận: "user" | "moderator" | "admin"
    - `plan` chỉ nhận: "free" | "pro" | "enterprise"
    - Chuyển đổi các role legacy ("free", "pro_tier_1", "pro_tier_2", "support") sang chuẩn mới.
    - Kiểm tra hạn `plan_expires_at` cho tài khoản trả phí (nếu hết hạn hạ về "free").
    - Bảo đảm email khớp BOOTSTRAP_ADMIN_EMAIL luôn mang role="admin" và plan="enterprise".
    """
    if not isinstance(user_doc, dict):
        return user_doc

    raw_role = str(user_doc.get("role") or "").strip().lower()
    raw_plan = str(user_doc.get("plan") or "").strip().lower()
    now = datetime.now(timezone.utc)

    if is_bootstrap_admin(user_doc.get("email")):
        norm_role = "admin"
        norm_plan = "enterprise"
    elif raw_role == "admin":
        norm_role = "admin"
        norm_plan = raw_plan if raw_plan in VALID_PLANS else "enterprise"
    elif raw_role in ("moderator", "support"):
        norm_role = "moderator"
        norm_plan = raw_plan if raw_plan in VALID_PLANS else "pro"
    else:
        norm_role = "user"
        if raw_plan in VALID_PLANS and not (raw_plan == "free" and raw_role in ("pro_tier_1", "pro_tier_2")):
            norm_plan = raw_plan
        elif raw_role == "pro_tier_2":
            norm_plan = "enterprise"
        elif raw_role == "pro_tier_1":
            norm_plan = "pro"
        else:
            norm_plan = "free"

    # Kiểm tra hết hạn gói Pro/Enterprise (trừ Admin)
    exp_dt = _parse_utc_dt(user_doc.get("plan_expires_at"))
    expired_downgrade = False
    if norm_role != "admin" and norm_plan in ("pro", "enterprise") and exp_dt is not None and now > exp_dt:
        norm_plan = "free"
        expired_downgrade = True

    needs_update = (
        user_doc.get("role") != norm_role
        or user_doc.get("plan") != norm_plan
        or expired_downgrade
    )

    if needs_update and users_col is not None and "_id" in user_doc:
        try:
            update_fields: dict = {
                "role": norm_role,
                "plan": norm_plan,
                "updated_at": now,
            }
            if expired_downgrade:
                update_fields["plan_expires_at"] = None
            users_col.update_one({"_id": user_doc["_id"]}, {"$set": update_fields})
        except Exception as exc:
            logger.warning(f"[RBAC Normalize] Không thể cập nhật DB cho {user_doc.get('email')}: {exc}")

    user_doc["role"] = norm_role
    user_doc["plan"] = norm_plan
    if expired_downgrade:
        user_doc["plan_expires_at"] = None
    return user_doc


def ensure_bootstrap_admin_user(user_doc: Optional[dict], users_col=None) -> Optional[dict]:
    """Alias tương thích ngược gọi chuẩn hóa Bootstrap Admin & RBAC role/plan."""
    return normalize_user_role_and_plan(user_doc, users_col)


def get_device_limit(role: str, plan: str) -> Optional[int]:
    """Trả về giới hạn số thiết bị đồng thời (`None` = không giới hạn cho Enterprise/Admin)."""
    if role == "admin" or plan == "enterprise":
        return None
    if plan == "pro" or role == "moderator":
        return max(1, _safe_int(os.getenv("MAX_DEVICES_PRO", str(MAX_DEVICES_PRO)), MAX_DEVICES_PRO))
    return max(1, _safe_int(os.getenv("MAX_DEVICES_FREE", str(MAX_DEVICES_FREE)), MAX_DEVICES_FREE))


# ── Login Failed Attempt Sliding-Window Lockout (5 lần sai / 15 phút) ─────────
_LOGIN_FAIL_LOCK = threading.Lock()
_LOGIN_FAIL_BUCKETS: dict[str, list[float]] = {}
_LOGIN_FAIL_MAX = 5
_LOGIN_FAIL_WINDOW_SEC = 15 * 60


def check_login_bruteforce_locked(ip: str, identifier: str) -> int:
    """Kiểm tra khóa đăng nhập sai theo (ip, email). Trả về số giây cần đợi còn lại (`0` nếu hợp lệ)."""
    key = f"{ip.strip()}:{(identifier or '').strip().lower()}"
    now_ts = time.time()
    cutoff = now_ts - _LOGIN_FAIL_WINDOW_SEC
    with _LOGIN_FAIL_LOCK:
        stamps = [ts for ts in _LOGIN_FAIL_BUCKETS.get(key, []) if ts > cutoff]
        if stamps:
            _LOGIN_FAIL_BUCKETS[key] = stamps
        else:
            _LOGIN_FAIL_BUCKETS.pop(key, None)
        if len(stamps) >= _LOGIN_FAIL_MAX:
            retry_after = max(1, int(round(_LOGIN_FAIL_WINDOW_SEC - (now_ts - stamps[0]))))
            return retry_after
    return 0


def record_login_failure(ip: str, identifier: str) -> int:
    """Ghi nhận 1 lần đăng nhập thất bại và trả về tổng số lần thất bại trong 15 phút qua."""
    key = f"{ip.strip()}:{(identifier or '').strip().lower()}"
    now_ts = time.time()
    cutoff = now_ts - _LOGIN_FAIL_WINDOW_SEC
    with _LOGIN_FAIL_LOCK:
        stamps = [ts for ts in _LOGIN_FAIL_BUCKETS.get(key, []) if ts > cutoff]
        stamps.append(now_ts)
        _LOGIN_FAIL_BUCKETS[key] = stamps
        return len(stamps)


def clear_login_failures(ip: str, identifier: str) -> None:
    key = f"{ip.strip()}:{(identifier or '').strip().lower()}"
    with _LOGIN_FAIL_LOCK:
        _LOGIN_FAIL_BUCKETS.pop(key, None)


def send_email_unified(to_email: str, subject: str, html_body: str) -> bool:
    """
    Gửi OTP / thông báo qua email:
    1. Ưu tiên gọi Resend HTTP API (RESEND_API_KEY) để tránh bị Render chặn cổng SMTP 587.
    2. Fallback về SMTP (Gmail) khi chạy local hoặc khi chưa cấu hình Resend API key thật.
    """
    resend_api_key = os.getenv("RESEND_API_KEY", "").strip()
    mail_from = os.getenv(
        "MAIL_FROM",
        os.getenv("SMTP_FROM", "RenGoFun <onboarding@resend.dev>"),
    ).strip()

    has_real_resend_key = (
        bool(resend_api_key)
        and not resend_api_key.startswith("re_xxxx")
        and resend_api_key != "your_resend_api_key"
    )

    if has_real_resend_key:
        payload = json.dumps({
            "from": mail_from,
            "to": [to_email],
            "subject": subject,
            "html": html_body,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=payload,
            headers={
                "Authorization": f"Bearer {resend_api_key}",
                "Content-Type": "application/json",
                "User-Agent": "RenGoFun-Auth-API/3.0",
            },
            method="POST",
        )
        ssl_ctx = (
            ssl.create_default_context(cafile=certifi.where())
            if certifi is not None
            else ssl.create_default_context()
        )
        try:
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as resp:
                if 200 <= getattr(resp, "status", 200) < 300:
                    return True
                logger.warning(f"[Resend API] Trả về status {resp.status}, chuyển sang fallback SMTP.")
        except Exception as exc:
            logger.warning(f"[Resend API] Gửi email tới {to_email} thất bại ({exc}), chuyển sang fallback SMTP.")

    # Fallback SMTP (Local Dev)
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com").strip()
    smtp_port = _safe_int(os.getenv("SMTP_PORT", "587"), 587)
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
    smtp_from = os.getenv("SMTP_FROM", smtp_user).strip() or smtp_user

    if (
        not smtp_user
        or not smtp_password
        or smtp_user == "your_gmail_address@gmail.com"
        or smtp_password == "your_16_char_gmail_app_password"
    ):
        logger.warning(f"[Email] Chưa cấu hình RESEND_API_KEY hoặc SMTP hợp lệ để gửi tới {to_email}.")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = smtp_from
        msg["To"] = to_email
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_from, to_email, msg.as_string())
        return True
    except Exception as exc:
        logger.error(f"[SMTP] Gửi email tới {to_email} thất bại: {exc}")
        return False


# ── Mật khẩu ──────────────────────────────────────────────────────────────────

def get_password_hash(password: str) -> str:
    """Băm mật khẩu bằng bcrypt native."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """So khớp mật khẩu nhập vào với chuỗi hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


# ── JWT Access Token & RS256 Offline License Token ────────────────────────────

def create_access_token(data: dict) -> str:
    """Tạo Access Token JWT (HS256) sống ngắn hạn (mặc định 15 phút)."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Giải mã và xác thực Access Token JWT."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def create_license_token(
    user_id: str,
    role: str,
    plan: str,
    device_hwid: Optional[str] = None,
    plan_expires_at=None,
    grace_days: Optional[int] = None,
) -> str:
    """
    Tạo Offline License Token ký bất đối xứng RS256 cho phép Desktop App & Python Engine
    xác thực bản quyền ngoại tuyến tối đa `OFFLINE_GRACE_DAYS` (mặc định 7 ngày).
    """
    now = datetime.now(timezone.utc)
    days = grace_days or _safe_int(os.getenv("OFFLINE_GRACE_DAYS", str(OFFLINE_GRACE_DAYS)), OFFLINE_GRACE_DAYS)
    grace_exp = now + timedelta(days=days)

    plan_exp_dt = _parse_utc_dt(plan_expires_at)
    # Nếu gói trả phí sắp hết hạn sớm hơn grace period (trừ admin), giới hạn exp theo ngày hết hạn
    effective_exp = grace_exp
    if role != "admin" and plan in ("pro", "enterprise") and plan_exp_dt is not None and plan_exp_dt < grace_exp:
        effective_exp = max(now + timedelta(minutes=5), plan_exp_dt)

    payload = {
        "sub": str(user_id),
        "role": role,
        "plan": plan,
        "hwid": (device_hwid or "").strip(),
        "plan_expires_at": plan_exp_dt.isoformat() if plan_exp_dt else None,
        "iat": int(now.timestamp()),
        "exp": int(effective_exp.timestamp()),
        "iss": "rengofun-auth",
        "typ": "license_rs256",
    }
    return jwt.encode(payload, get_rs256_private_key(), algorithm="RS256")


def decode_license_token(token: str) -> dict:
    """Giải mã và xác thực chữ ký RS256 của License Token."""
    return jwt.decode(token, get_rs256_public_key(), algorithms=["RS256"])


# ── Chuỗi ngẫu nhiên an toàn ──────────────────────────────────────────────────

_CAPTCHA_CHARS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"


def generate_captcha_text(length: int = 4) -> str:
    """Sinh chuỗi captcha N ký tự ngẫu nhiên bằng module secrets."""
    return "".join(secrets.choice(_CAPTCHA_CHARS) for _ in range(length))


def generate_otp(length: int = 6) -> str:
    """Sinh mã OTP N chữ số ngẫu nhiên."""
    return "".join(secrets.choice(string.digits) for _ in range(length))


def generate_temp_password(length: int = 12) -> str:
    """Sinh mật khẩu tạm thời an toàn (chữ hoa + thường + số + ký tự đặc biệt)."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.isupper() for c in pwd)
            and any(c.islower() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in "!@#$%^&*" for c in pwd)
        ):
            return pwd


def generate_refresh_token() -> str:
    """Sinh Refresh Token dạng hex ngẫu nhiên 64 bytes."""
    return secrets.token_hex(64)
