"""
Endpoint-scoped rate limiter for sensitive actions.

Used in addition to the global middleware rate limiter to
protect:
  - Incident creation
  - Evidence export
  - Device key rotation
"""

import time
from collections import defaultdict
from typing import Dict, Tuple

from fastapi import HTTPException, Request, status


class InMemoryActionRateLimiter:
    def __init__(self) -> None:
        # key: (ip, action_key) → list[timestamps]
        self._requests: Dict[Tuple[str, str], list[float]] = defaultdict(list)

    def check(self, ip: str, action_key: str, limit: int, window_seconds: int) -> None:
        now = time.time()
        key = (ip, action_key)

        window = self._requests[key]
        # prune old
        self._requests[key] = [ts for ts in window if now - ts < window_seconds]

        if len(self._requests[key]) >= limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded for action '{action_key}'",
            )

        self._requests[key].append(now)


_limiter = InMemoryActionRateLimiter()


async def rate_limit_action(
    request: Request,
    action_key: str,
    limit: int = 10,
    window_seconds: int = 60,
) -> None:
    """
    Dependency to enforce per-action rate limiting.

    Example:
        await rate_limit_action(request, "incident.create", limit=5, window_seconds=60)
    """

    ip = request.client.host if request.client else "unknown"
    _limiter.check(ip, action_key, limit, window_seconds)

