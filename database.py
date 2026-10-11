
import os
from pathlib import Path
from pymongo import MongoClient
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
users_collection = db["users"]

def init_db():
    """Khởi tạo và đảm bảo chỉ mục (Unique Index) trên MongoDB Atlas."""
    try:
        client.admin.command('ping')
        users_collection.create_index("username", unique=True)
        print(">>> Ket noi MongoDB Atlas THANH CONG! Da dam bao Unique Index tren field 'username'.")
        return True
    except Exception as e:
        print(f">>> Loi khi ket noi hoac thiet lap index tren MongoDB: {e}")
        return False

if __name__ == "__main__":
    init_db()