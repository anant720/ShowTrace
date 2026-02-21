from fastapi import Header, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.database import get_db
from app.config import settings
from app.utils.jwt_handler import verify_token

security = HTTPBearer()

async def get_database() -> AsyncIOMotorDatabase:
    return get_db()

async def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> str:
    if x_api_key != settings.API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    return x_api_key

async def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    payload = verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return payload

async def require_admin(current_user: dict = Depends(get_current_admin)) -> dict:
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin required")
    return current_user

async def require_analyst(current_user: dict = Depends(get_current_admin)) -> dict:
    if current_user.get("role") not in ("admin", "analyst"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Analyst required")
    return current_user
