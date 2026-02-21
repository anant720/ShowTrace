"""
ShadowTrace — Rate Limiting Middleware

In-memory sliding window rate limiter keyed by client IP.
Sufficient for single-instance deployment; swap to Redis
for horizontal scaling.
"""

import time
from collections import defaultdict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from app.config import settings

# Paths exempt from rate limiting
EXEMPT_PATHS = {"/docs", "/openapi.json", "/redoc", "/health"}


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.requests: dict[str, list[float]] = defaultdict(list)
        self.rpm = settings.RATE_LIMIT_RPM
        self.window = 60.0  # 1 minute window

    async def dispatch(self, request: Request, call_next):
        # Skip exempt paths
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        # Skip OPTIONS
        if request.method == "OPTIONS":
            return await call_next(request)

        # Get client IP
        client_ip = self._get_client_ip(request)
        now = time.time()

        # Clean expired entries
        self.requests[client_ip] = [
            ts for ts in self.requests[client_ip]
            if now - ts < self.window
        ]

        # Check rate limit
        if len(self.requests[client_ip]) >= self.rpm:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after_seconds": int(
                        self.window - (now - self.requests[client_ip][0])
                    ),
                },
            )

        # Record request
        self.requests[client_ip].append(now)

        return await call_next(request)

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """Extract client IP, respecting X-Forwarded-For for proxied requests."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
