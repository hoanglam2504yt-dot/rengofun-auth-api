import os
from pathlib import Path
from pymongo import MongoClient
from dotenv import load_dotenv

# Xác định đường dẫn tuyệt đối đến file .env cùng cấp
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

MONGO_URI = os.getenv("MONGO_URI")

# In kiểm tra xem biến môi trường đã được đọc chưa
print(f">>> Kiem tra MONGO_URI: {MONGO_URI}")

# Khởi tạo kết nối đến MongoDB Atlas
client = MongoClient(MONGO_URI)
db = client["rengofun_auth"]
users_collection = db["users"]

if __name__ == "__main__":
    try:
        # Gửi ping kiểm tra kết nối
        client.admin.command('ping')
        print(">>> Ket noi MongoDB Atlas THANH CONG! San sang luu tru du lieu.")
    except Exception as e:
        print(">>> Ket noi THAT BAI. Loi chi tiet:")
        print(e)