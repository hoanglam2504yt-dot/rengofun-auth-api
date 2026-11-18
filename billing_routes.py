"""
Billing Routes — RenGoFun Auth API v3.1
Quản lý tạo đơn thanh toán VietQR / SePay / PayOS và xác nhận Webhook tự động.
"""
import hashlib
import hmac
import logging
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from pymongo.errors import PyMongoError

from auth import (
    create_access_token,
    create_license_token,
    decode_access_token,
    normalize_user_role_and_plan,
)
from database import (
    billing_transactions_collection,
    security_logs_collection,
    users_collection,
)

logger = logging.getLogger("rengofun_auth")

router = APIRouter(prefix="/api/billing", tags=["Billing"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

PLAN_CATALOG = {
    "pro_monthly": {
        "sku": "pro_monthly",
        "plan": "pro",
        "duration_days": 30,
        "amount_vnd": 199000,
        "label": "Pro Tháng (30 ngày)",
    },
    "pro_yearly": {
        "sku": "pro_yearly",
        "plan": "pro",
        "duration_days": 365,
        "amount_vnd": 1790000,
        "label": "Pro Năm (365 ngày - Tiết kiệm 25%)",
    },
    "enterprise_yearly": {
        "sku": "enterprise_yearly",
        "plan": "enterprise",
        "duration_days": 365,
        "amount_vnd": 4990000,
        "label": "Enterprise Chuỗi Xưởng (365 ngày)",
    },
}


class CreateOrderSchema(BaseModel):
    plan_sku: str = "pro_monthly"
    device_hwid: Optional[str] = None


async def get_current_user_payload(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        return decode_access_token(token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Phiên đăng nhập không hợp lệ hoặc đã hết hạn.",
        )


def _generate_order_code() -> str:
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    suffix = "".join(secrets.choice(chars) for _ in range(6))
    return f"RGF-{suffix}"


def _build_vietqr_url(order_code: str, amount_vnd: int) -> tuple[str, dict]:
    bank_id = os.getenv("VIETQR_BANK_ID", "MB").strip() or "MB"
    account_no = os.getenv("VIETQR_ACCOUNT_NO", "000000000000").strip() or "000000000000"
    account_name = os.getenv("VIETQR_ACCOUNT_NAME", "RENGOFUN STUDIO").strip() or "RENGOFUN STUDIO"
    qr_url = (
        f"https://img.vietqr.io/image/{quote(bank_id)}-{quote(account_no)}-compact2.png"
        f"?amount={int(amount_vnd)}&addInfo={quote(order_code)}&accountName={quote(account_name)}"
    )
    bank_info = {
        "bank_id": bank_id,
        "account_no": account_no,
        "account_name": account_name,
        "transfer_content": order_code,
        "amount_vnd": int(amount_vnd),
    }
    return qr_url, bank_info


def mark_order_paid(order_doc: dict, source: str = "webhook", admin_sub: Optional[str] = None) -> dict:
    """
    Xử lý idempotent khi đơn hàng thanh toán thành công:
    1. Chuyển trạng thái đơn sang PAID.
    2. Nâng cấp `user.plan` và cộng thêm `duration_days` từ max(now, plan_expires_at hiện tại).
    3. Ghi audit log vào `security_logs`.
    """
    now = datetime.now(timezone.utc)
    if order_doc.get("status") == "PAID":
        user = users_collection.find_one({"id": order_doc["user_id"]})
        user = normalize_user_role_and_plan(user, users_collection) if user else None
        return {"already_paid": True, "order": order_doc, "user": user}

    user = users_collection.find_one({"id": order_doc["user_id"]})
    if not user:
        raise HTTPException(status_code=404, detail="Không tìm thấy chủ sở hữu đơn hàng.")

    user = normalize_user_role_and_plan(user, users_collection)
    target_plan = order_doc.get("target_plan", "pro")
    days = int(order_doc.get("duration_days", 30))

    cur_exp = user.get("plan_expires_at")
    if isinstance(cur_exp, str):
        try:
            cur_exp = datetime.fromisoformat(cur_exp.replace("Z", "+00:00"))
        except ValueError:
            cur_exp = None
    if isinstance(cur_exp, datetime) and cur_exp.tzinfo is None:
        cur_exp = cur_exp.replace(tzinfo=timezone.utc)

    base_time = cur_exp if (isinstance(cur_exp, datetime) and cur_exp > now and user.get("plan") == target_plan) else now
    new_exp = base_time + timedelta(days=days)

    users_collection.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "plan": target_plan,
                "plan_expires_at": new_exp,
                "updated_at": now,
            }
        },
    )
    user["plan"] = target_plan
    user["plan_expires_at"] = new_exp

    billing_transactions_collection.update_one(
        {"order_code": order_doc["order_code"]},
        {
            "$set": {
                "status": "PAID",
                "paid_at": now,
                "confirmed_by": admin_sub or source,
                "updated_at": now,
            }
        },
    )
    order_doc["status"] = "PAID"
    order_doc["paid_at"] = now

    try:
        security_logs_collection.insert_one({
            "action": "billing_order_paid",
            "email_attempted": user.get("email", order_doc["user_id"]),
            "ip_address": source,
            "metadata": {
                "order_code": order_doc["order_code"],
                "plan": target_plan,
                "duration_days": days,
                "amount_vnd": order_doc.get("amount_vnd", 0),
                "confirmed_by": admin_sub or source,
            },
            "created_at": now,
        })
    except Exception:
        pass

    return {"already_paid": False, "order": order_doc, "user": user}


@router.get("/plans")
async def list_billing_plans():
    """Trả về danh sách gói nâng cấp hỗ trợ thanh toán QR."""
    return {"plans": list(PLAN_CATALOG.values())}


@router.post("/create-order")
async def create_billing_order(
    body: CreateOrderSchema,
    caller: dict = Depends(get_current_user_payload),
):
    """Tạo đơn hàng thanh toán QR (PENDING) & sinh URL mã VietQR."""
    sku_info = PLAN_CATALOG.get(body.plan_sku)
    if not sku_info:
        raise HTTPException(
            status_code=400,
            detail=f"Gói thanh toán không hợp lệ. Chọn một trong: {list(PLAN_CATALOG.keys())}",
        )

    user_id = caller.get("sub")
    user = users_collection.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản người dùng.")
    user = normalize_user_role_and_plan(user, users_collection)

    try:
        now = datetime.now(timezone.utc)
        order_code = _generate_order_code()
        qr_url, bank_info = _build_vietqr_url(order_code, sku_info["amount_vnd"])

        order_doc = {
            "order_code": order_code,
            "user_id": user_id,
            "user_email": user.get("email"),
            "plan_sku": sku_info["sku"],
            "target_plan": sku_info["plan"],
            "duration_days": sku_info["duration_days"],
            "amount_vnd": sku_info["amount_vnd"],
            "label": sku_info["label"],
            "status": "PENDING",
            "qr_url": qr_url,
            "bank_info": bank_info,
            "device_hwid": (body.device_hwid or "").strip(),
            "created_at": now,
            "expires_at": now + timedelta(minutes=30),
            "paid_at": None,
        }
        billing_transactions_collection.insert_one(order_doc)
        return {
            "order_code": order_code,
            "status": "PENDING",
            "plan_sku": sku_info["sku"],
            "target_plan": sku_info["plan"],
            "duration_days": sku_info["duration_days"],
            "amount_vnd": sku_info["amount_vnd"],
            "label": sku_info["label"],
            "qr_url": qr_url,
            "bank_info": bank_info,
            "expires_in_seconds": 1800,
        }
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail=f"Lỗi tạo đơn hàng: {exc}")


@router.get("/order/{order_code}")
async def check_order_status(
    order_code: str,
    device_hwid: Optional[str] = None,
    caller: dict = Depends(get_current_user_payload),
):
    """Kiểm tra trạng thái đơn hàng (Client polling mỗi 3s); trả về license_token mới nếu đã PAID."""
    order = billing_transactions_collection.find_one({"order_code": order_code.strip().upper()}, {"_id": 0})
    if not order:
        raise HTTPException(status_code=404, detail="Không tìm thấy mã đơn hàng.")

    if order.get("user_id") != caller.get("sub") and caller.get("role") not in ("admin", "moderator"):
        raise HTTPException(status_code=403, detail="Bạn không có quyền truy cập đơn hàng này.")

    resp: dict = {
        "order_code": order["order_code"],
        "status": order.get("status", "PENDING"),
        "target_plan": order.get("target_plan"),
        "amount_vnd": order.get("amount_vnd"),
        "paid_at": order["paid_at"].isoformat() if isinstance(order.get("paid_at"), datetime) else order.get("paid_at"),
    }

    if order.get("status") == "PAID":
        user = users_collection.find_one({"id": order["user_id"]})
        if user:
            user = normalize_user_role_and_plan(user, users_collection)
            uid = user.get("id", str(user["_id"]))
            role = user["role"]
            plan = user["plan"]
            exp_val = user.get("plan_expires_at")
            hwid = (device_hwid or order.get("device_hwid") or "").strip()

            resp["access_token"] = create_access_token({
                "sub": uid,
                "role": role,
                "plan": plan,
                "username": user.get("username", user.get("email")),
            })
            resp["license_token"] = create_license_token(
                user_id=uid,
                role=role,
                plan=plan,
                device_hwid=hwid,
                plan_expires_at=exp_val,
            )
            resp["user"] = {
                "id": uid,
                "email": user.get("email"),
                "username": user.get("username"),
                "role": role,
                "plan": plan,
                "plan_expires_at": exp_val.isoformat() if isinstance(exp_val, datetime) else exp_val,
                "preferences": user.get("preferences", {}),
            }
    return resp


@router.get("/my-orders")
async def list_my_orders(caller: dict = Depends(get_current_user_payload)):
    """Lịch sử giao dịch của tài khoản hiện tại."""
    orders = list(
        billing_transactions_collection.find({"user_id": caller.get("sub")}, {"_id": 0})
        .sort("created_at", -1)
        .limit(25)
    )
    for o in orders:
        for k in ("created_at", "expires_at", "paid_at"):
            if isinstance(o.get(k), datetime):
                o[k] = o[k].isoformat()
    return {"orders": orders}


@router.post("/webhook")
async def payment_webhook(request: Request):
    """
    Webhook nhận tín hiệu chuyển khoản từ SePay / PayOS / Cổng thanh toán:
    - Xác thực chữ ký HMAC-SHA256 (X-Webhook-Signature) hoặc Secret Header (X-Payment-Secret / Authorization: Apikey ...)
    - Tự động tìm mã đơn `RGF-XXXXXX` và nâng cấp tài khoản sang Pro/Enterprise.
    """
    secret = os.getenv("PAYMENT_WEBHOOK_SECRET", "").strip()
    if not secret:
        raise HTTPException(status_code=503, detail="Chưa cấu hình PAYMENT_WEBHOOK_SECRET trên máy chủ.")

    raw_body = await request.body()
    sig_hdr = (request.headers.get("X-Webhook-Signature") or "").strip()
    sec_hdr = (request.headers.get("X-Payment-Secret") or "").strip()
    auth_hdr = (request.headers.get("Authorization") or "").strip()

    authorized = False
    if sig_hdr:
        expected_sig = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
        sig_clean = sig_hdr.removeprefix("sha256=").strip().lower()
        authorized = hmac.compare_digest(sig_clean, expected_sig.lower())
    elif sec_hdr:
        authorized = hmac.compare_digest(sec_hdr, secret)
    elif auth_hdr:
        token_part = auth_hdr.split(" ", 1)[-1].strip()
        authorized = hmac.compare_digest(token_part, secret)

    if not authorized:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Chữ ký Webhook không hợp lệ.")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Payload JSON không hợp lệ.")

    order_code = str(payload.get("order_code") or "").strip().upper()
    if not order_code:
        search_text = f"{payload.get('content', '')} {payload.get('description', '')}".upper()
        m = re.search(r"RGF-[A-Z0-9]{6}", search_text)
        if m:
            order_code = m.group(0)

    if not order_code:
        raise HTTPException(status_code=400, detail="Không tìm thấy mã đơn hàng RGF-XXXXXX trong Webhook.")

    order_doc = billing_transactions_collection.find_one({"order_code": order_code})
    if not order_doc:
        raise HTTPException(status_code=404, detail=f"Đơn hàng {order_code} không tồn tại.")

    paid_amount = payload.get("transferAmount") or payload.get("amount")
    if paid_amount is not None:
        try:
            if int(float(paid_amount)) < int(order_doc.get("amount_vnd", 0)):
                raise HTTPException(status_code=400, detail="Số tiền chuyển khoản chưa đủ giá trị đơn hàng.")
        except (TypeError, ValueError):
            pass

    res = mark_order_paid(order_doc, source="webhook")
    return {
        "status": "ok",
        "order_code": order_code,
        "already_paid": res["already_paid"],
        "new_plan": res["user"]["plan"] if res.get("user") else None,
    }
