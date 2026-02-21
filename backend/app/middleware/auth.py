"""
ShadowTrace — API Key Authentication Middleware

Validates X-API-Key header on all requests except
docs, health, and OpenAPI schema endpoints.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from app.config import settings

# Paths exempt from API key check
EXEMPT_PATHS = {"/docs", "/openapi.json", "/redoc", "/health", "/favicon.ico"}

# Prefixes exempt from API key check (JWT-protected routes)
EXEMPT_PREFIXES = ("/auth/", "/analytics/")


class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip exempt paths
        if path in EXEMPT_PATHS or path.startswith(EXEMPT_PREFIXES):
            return await call_next(request)

        # Skip OPTIONS (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)

        # Validate API key
        api_key = request.headers.get("X-API-Key")
        if not api_key or api_key != settings.API_KEY:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing API key"},
            )

        return await call_next(request)
