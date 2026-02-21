from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from passlib.context import CryptContext
from app.dependencies import get_database, get_current_admin
from app.utils.jwt_handler import create_access_token
from app.config import settings

router = APIRouter(prefix="/auth", tags=["Auth"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/login")
async def login(request: LoginRequest, db = Depends(get_database)):
    user = await db.admin_users.find_one({"username": request.username})
    if not user or not pwd_context.verify(request.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token({"sub": user["username"], "role": user["role"]})
    await db.admin_users.update_one({"_id": user["_id"]}, {"$set": {"last_login": datetime.now(timezone.utc)}})
    return {"access_token": token, "token_type": "bearer", "role": user["role"], "username": user["username"]}

@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_admin)):
    return {"username": current_user.get("sub"), "role": current_user.get("role")}
