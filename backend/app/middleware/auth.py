"""
ShadowTrace — API Key Authentication Middleware

Validates X-API-Key header on all requests except
docs, health, and OpenAPI schema endpoints.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from google.oauth2 import id_token
from google.auth.transport import requests
from app.config import settings
import logging

logger = logging.getLogger("shadowtrace.middleware.auth")

# Paths exempt from authentication
EXEMPT_PATHS = {"/docs", "/openapi.json", "/redoc", "/health", "/favicon.ico"}
EXEMPT_PREFIXES = ("/auth/", "/analytics/")

class OAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip exempt paths and prefixes
        if path in EXEMPT_PATHS or path.startswith(EXEMPT_PREFIXES):
            return await call_next(request)

        # Skip OPTIONS (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)

        # Extract Bearer token from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            # Fallback for old extension versions using X-API-Key for now
            api_key = request.headers.get("X-API-Key")
            if api_key == settings.API_KEY:
                return await call_next(request)
            
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing Authorization header"},
            )

        token = auth_header.split(" ")[1]

        try:
            # Verify the ID token using Google's public keys
            # Note: We need the GOOGLE_CLIENT_ID in settings
                token, 
                requests.Request(), 
                audience=settings.GOOGLE_CLIENT_ID
            )

            # Store user info in request state if needed
            request.state.user_email = idinfo.get('email')
            
        except ValueError as e:
            logger.warning(f"Invalid Google ID Token: {e}")
            return JSONResponse(
                status_code=401,
                content={"detail": f"Invalid authentication token: {str(e)}"},
            )

        return await call_next(request)
