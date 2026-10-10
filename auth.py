import os
from datetime import datetime, timedelta, timezone
import bcrypt
import jwt
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "khoa_bi_mat_mac_dinh_rengofun")
ALGORITHM = "HS256"

def get_password_hash(password: str) -> str:
    """Băm mật khẩu trực tiếp bằng bcrypt native."""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """So khớp mật khẩu nhập vào với chuỗi hash."""
    plain_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(plain_bytes, hashed_bytes)

def create_access_token(data: dict, expires_delta_hours: int = 24) -> str:
    """Tạo chuỗi JWT Token có thời hạn sử dụng."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(hours=expires_delta_hours)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)