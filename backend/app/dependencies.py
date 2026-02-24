from fastapi import Header, HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.database import get_db
from app.config import settings
from app.utils.jwt_handler import verify_token

security = HTTPBearer()

async def get_database() -> AsyncIOMotorDatabase:
    return get_db()

async def get_current_org_id(request: Request) -> str:
    org_id = getattr(request.state, "org_id", "community")
    return org_id

async def get_current_user_email(request: Request) -> str:
    """Return the authenticated user's email (set by middleware from JWT or Google token)."""
    return getattr(request.state, "user_email", None) or getattr(request.state, "user_id", None) or "anonymous"

def build_org_query(org_id: str, user_email: str | None = None) -> dict:
    """
    Build the 'ownership' filter for MongoDB scan_logs queries.

    - Real org  (org_id != "community"): filter by org_id only — the whole
      org shares its data, that is intentional for enterprise dashboards.
    - Community (X-API-Key fallback, no org):  also filter by user_email so
      one anonymous user cannot see another anonymous user's browsing data.
    """
    if org_id != "community":
        return {"org_id": org_id}
    if user_email and user_email not in ("anonymous", "anonymous@shadowtrace.local"):
        return {"org_id": "community", "user_email": user_email}
    # Truly anonymous — show only this session's scans (no saved history)
    return {"org_id": "community", "user_email": user_email or "anonymous@shadowtrace.local"}

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
