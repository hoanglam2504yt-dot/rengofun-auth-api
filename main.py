import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from pymongo.errors import PyMongoError, DuplicateKeyError
from database import client, users_collection, init_db
from auth import get_password_hash, verify_password, create_access_token
from fastapi.middleware.cors import CORSMiddleware

logger = logging.getLogger("rengofun_auth")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Khởi động và kiểm tra kết nối MongoDB Atlas
    init_db()
    yield

app = FastAPI(
    title="RenGoFun Auth API",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class UserAuthSchema(BaseModel):
    username: str
    password: str

@app.get("/")
async def root():
    return {
        "service": "RenGoFun Auth API",
        "status": "online",
        "docs": "/docs"
    }

@app.get("/health")
def health_check():
    """Kiểm tra phản hồi nhanh (Liveness check)."""
    return {"status": "ok"}

@app.get("/health/db")
async def health_check_db():
    """Kiểm tra tình trạng kết nối đến MongoDB Atlas (Readiness check)."""
    try:
        client.admin.command('ping')
        return {
            "status": "healthy",
            "database": "connected"
        }
    except Exception as e:
        logger.error(f"MongoDB health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Mất kết nối tới cơ sở dữ liệu MongoDB Atlas"
        )

@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user_data: UserAuthSchema):
    # 1. Kiểm tra tài khoản đã tồn tại trong MongoDB chưa
    try:
        existing_user = users_collection.find_one({"username": user_data.username})
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Tài khoản này đã tồn tại trên hệ thống"
            )

        # 2. Băm mật khẩu và chuẩn bị Document
        new_user = {
            "username": user_data.username,
            "password_hash": get_password_hash(user_data.password),
            "plan": "free",
            "created_at": datetime.now(timezone.utc),
            "is_active": True
        }

        # 3. Ghi vào MongoDB Atlas
        users_collection.insert_one(new_user)
        return {"message": "Đăng ký tài khoản thành công!"}
    except DuplicateKeyError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tài khoản này đã tồn tại trên hệ thống"
        )
    except HTTPException:
        raise
    except PyMongoError as e:
        logger.error(f"MongoDB Error during register: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Lỗi kết nối cơ sở dữ liệu. Vui lòng thử lại sau giây lát."
        )

@app.post("/login")
async def login(user_data: UserAuthSchema):
    try:
        # 1. Tìm người dùng theo username
        user = users_collection.find_one({"username": user_data.username})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Tài khoản hoặc mật khẩu không chính xác"
            )

        # 2. Kiểm tra mật khẩu
        if not verify_password(user_data.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Tài khoản hoặc mật khẩu không chính xác"
            )

        # 3. Tạo thẻ bài JWT chứa định danh và gói quyền
        token_payload = {
            "sub": user["username"],
            "plan": user.get("plan", "free")
        }
        access_token = create_access_token(token_payload)

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "username": user["username"],
            "plan": user.get("plan", "free")
        }
    except HTTPException:
        raise
    except PyMongoError as e:
        logger.error(f"MongoDB Error during login: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Lỗi kết nối cơ sở dữ liệu. Vui lòng thử lại sau giây lát."
        )