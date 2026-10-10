from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from database import users_collection
from auth import get_password_hash, verify_password, create_access_token
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="RenGoFun Auth API", version="1.0.0")

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

@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user_data: UserAuthSchema):
    # 1. Kiểm tra tài khoản đã tồn tại trong MongoDB chưa
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

@app.post("/login")
async def login(user_data: UserAuthSchema):
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