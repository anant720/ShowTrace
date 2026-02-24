"""
ShadowTrace — Auth Middleware (Fixed)

Auth priority:
  1. Bearer JWT (dashboard users)    → org_id from JWT payload
  2. Bearer Google OAuth (SSO)       → org_id from DB lookup
  3. X-API-Key (extension)           → org_id = "community"
  4. No auth on exempt paths
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from app.config import settings
from app.utils.jwt_handler import verify_token
import logging

logger = logging.getLogger("shadowtrace.middleware.auth")

EXEMPT_PATHS = {"/docs", "/openapi.json", "/redoc", "/health", "/favicon.ico"}
EXEMPT_PREFIXES = ("/auth/", "/organizations/activate/")


class OAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip exempt paths and prefixes
        if path in EXEMPT_PATHS or path.startswith(EXEMPT_PREFIXES):
            return await call_next(request)

        # Skip CORS preflight
        if request.method == "OPTIONS":
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")

        # ── Branch 1: Bearer token ──────────────────────────────────
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]

            # 1a. Try ShadowTrace JWT first (dashboard login)
            payload = verify_token(token)
            if payload:
                request.state.org_id  = payload.get("org_id", "community")
                request.state.user_id = payload.get("sub", "")
                request.state.role    = payload.get("role", "member")
                return await call_next(request)

            # 1b. Fall through to Google OAuth (enterprise SSO)
            try:
                from google.oauth2 import id_token as google_id_token
                from google.auth.transport import requests as google_requests
                idinfo = google_id_token.verify_oauth2_token(
                    token,
                    google_requests.Request(),
                    audience=settings.GOOGLE_CLIENT_ID,
                )
                email = idinfo.get("email")
                request.state.user_email = email

                from app.database import get_db
                from bson import ObjectId
                db = get_db()
                user = await db.admin_users.find_one({"email": email})
                if not user:
                    request.state.org_id = "community"
                    return await call_next(request)

                request.state.user_id = str(user["_id"])

                # Honour X-Org-ID header if member
                requested_org = request.headers.get("X-Org-ID")
                if requested_org and requested_org != "community":
                    membership = await db.memberships.find_one(
                        {"user_id": str(user["_id"]), "org_id": requested_org}
                    )
                    request.state.org_id = requested_org if membership else user.get("org_id", "community")
                else:
                    request.state.org_id = user.get("org_id", "community")

                return await call_next(request)

            except Exception as e:
                logger.warning(f"Token verification failed: {e}")
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid authentication token"},
                )

        # ── Branch 2: X-Member-Key (extension with org key) ─────────
        member_key = request.headers.get("X-Member-Key")
        if member_key:
            try:
                from app.database import get_db
                db = get_db()
                record = await db.member_keys.find_one({"key": member_key, "active": True})
                if record:
                    request.state.org_id     = record["org_id"]
                    request.state.user_email = record["email"]
                    return await call_next(request)
            except Exception as e:
                logger.warning(f"Member key lookup failed: {e}")
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or revoked member key"},
            )

        # ── Branch 3: X-API-Key (extension without org key) ──────────
        api_key = request.headers.get("X-API-Key")
        if api_key == settings.API_KEY:
            request.state.org_id = "community"
            return await call_next(request)

        # ── Branch 3: No auth ─────────────────────────────────────────
        return JSONResponse(
            status_code=401,
            content={"detail": "Missing Authorization header"},
        )
