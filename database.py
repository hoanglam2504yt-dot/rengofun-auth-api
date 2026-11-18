import os
from pathlib import Path
from pymongo import MongoClient, ASCENDING, DESCENDING
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
    tz_aware=True,
    tlsCAFile=certifi.where(),
)

db = client["rengofun_auth"]

# ── Collections ───────────────────────────────────────────────────────────────
users_collection                 = db["users"]
user_sessions_collection         = db["user_sessions"]
email_verifications_collection   = db["email_verifications"]
password_resets_collection       = db["password_reset_requests"]
security_logs_collection         = db["security_logs"]
system_config_collection         = db["system_config"]
billing_transactions_collection  = db["billing_transactions"]
telemetry_events_collection      = db["telemetry_events"]

# Alias cũ (để tương thích ngược nếu code ngoài tham chiếu)
security_audit_logs_collection   = security_logs_collection


def init_db():
    """Khởi tạo và đảm bảo toàn bộ Index trên MongoDB Atlas."""
    try:
        client.admin.command("ping")

        # ── users ─────────────────────────────────────────────────────────────
        users_collection.create_index("email", unique=True)
        users_collection.create_index("role")
        users_collection.create_index("plan")

        # ── user_sessions (Hỗ trợ Device HWID Limit) ─────────────────────────
        user_sessions_collection.create_index("user_id")
        user_sessions_collection.create_index([("user_id", ASCENDING), ("device_hwid", ASCENDING)])
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

        # ── billing_transactions ──────────────────────────────────────────────
        billing_transactions_collection.create_index("order_code", unique=True)
        billing_transactions_collection.create_index([("user_id", ASCENDING), ("created_at", DESCENDING)])
        billing_transactions_collection.create_index("status")

        # ── telemetry_events ──────────────────────────────────────────────────
        telemetry_events_collection.create_index([("tool_code", ASCENDING), ("created_at", DESCENDING)])
        telemetry_events_collection.create_index("created_at")

        print(">>> Ket noi MongoDB Atlas THANH CONG! Da dam bao cac Index & Collections san xuat.")
        return True
    except Exception as e:
        print(f">>> Loi khi ket noi hoac thiet lap index tren MongoDB: {e}")
        return False


if __name__ == "__main__":
    init_db()
