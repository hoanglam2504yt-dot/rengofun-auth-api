
import os
from pathlib import Path
from pymongo import MongoClient, ASCENDING
from dotenv import load_dotenv
# pyrefly: ignore [missing-import]
import certifi

# Xác định đường dẫn tuyệt đối đến file .env cùng cấp
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

MONGO_URI = os.getenv("MONGO_URI")

# Khởi tạo kết nối đến MongoDB Atlas với thiết lập tối ưu
client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=5000,
    maxPoolSize=50,
    minPoolSize=5,
    tlsCAFile=certifi.where()
)

db = client["rengofun_auth"]

# ── Collections (theo thiết kế mới) ──────────────────────────────────────────
users_collection                 = db["users"]
user_sessions_collection         = db["user_sessions"]
email_verifications_collection   = db["email_verifications"]
password_resets_collection       = db["password_reset_requests"]
security_logs_collection         = db["security_logs"]
system_config_collection         = db["system_config"]

# Alias cũ (để admin_routes không bị lỗi import ngay)
security_audit_logs_collection   = security_logs_collection


def init_db():
    """Khởi tạo và đảm bảo các Index cần thiết trên MongoDB Atlas."""
    try:
        client.admin.command('ping')

        # ── users ─────────────────────────────────────────────────────────────
        users_collection.create_index("email", unique=True)
        users_collection.create_index("role")

        # ── user_sessions ─────────────────────────────────────────────────────
        user_sessions_collection.create_index("user_id")
        user_sessions_collection.create_index(
            [("refresh_token", ASCENDING)], unique=True, sparse=True
        )
        user_sessions_collection.create_index("expires_at")

        # ── email_verifications ───────────────────────────────────────────────
        email_verifications_collection.create_index("user_id")
        email_verifications_collection.create_index("expires_at")

        # ── password_reset_requests ───────────────────────────────────────────
        password_resets_collection.create_index("user_id")
        password_resets_collection.create_index("status")
        password_resets_collection.create_index("created_at")

        # ── security_logs ─────────────────────────────────────────────────────
        security_logs_collection.create_index("created_at")
        security_logs_collection.create_index("ip_address")
        security_logs_collection.create_index("email_attempted")

        # ── system_config ─────────────────────────────────────────────────────
        # Không cần index đặc biệt — chỉ có 1 document

        print(">>> Ket noi MongoDB Atlas THANH CONG! Da dam bao cac Index theo schema moi.")
        return True
    except Exception as e:
        print(f">>> Loi khi ket noi hoac thiet lap index tren MongoDB: {e}")
        return False


if __name__ == "__main__":
    init_db()