import os
import secrets
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bcrypt
import jwt
from dotenv import load_dotenv

env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

SECRET_KEY = os.getenv("SECRET_KEY", "")
ALGORITHM  = "HS256"

# Access Token sống 15 phút theo thiết kế bảo mật
ACCESS_TOKEN_EXPIRE_MINUTES = 15


# ── Mật khẩu ─────────────────────────────────────────────────────────────────

def get_password_hash(password: str) -> str:
    """Băm mật khẩu bằng bcrypt native."""
    salt   = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """So khớp mật khẩu nhập vào với chuỗi hash."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8")
    )


# ── JWT ───────────────────────────────────────────────────────────────────────

def create_access_token(data: dict) -> str:
    """
    Tạo Access Token JWT sống 15 phút.
    Payload chỉ chứa user_id và role (không chứa thông tin nhạy cảm).
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Giải mã và xác thực Access Token JWT. Ném jwt.PyJWTError nếu không hợp lệ."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


# ── Chuỗi ngẫu nhiên an toàn ─────────────────────────────────────────────────

# Bộ ký tự captcha: lọc bỏ ký tự dễ nhầm lẫn (0, O, 1, I, l)
_CAPTCHA_CHARS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

def generate_captcha_text(length: int = 4) -> str:
    """Sinh chuỗi captcha N ký tự ngẫu nhiên bằng module secrets (cryptographically secure)."""
    return "".join(secrets.choice(_CAPTCHA_CHARS) for _ in range(length))


def generate_otp(length: int = 6) -> str:
    """Sinh mã OTP N chữ số ngẫu nhiên."""
    return "".join(secrets.choice(string.digits) for _ in range(length))


def generate_temp_password(length: int = 12) -> str:
    """
    Sinh mật khẩu tạm thời an toàn (chữ hoa + chữ thường + số + ký tự đặc biệt).
    Đảm bảo có ít nhất 1 ký tự mỗi loại.
    """
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