import logging
from datetime import datetime, timezone
from typing import Any, Optional, Dict

from fastapi import Request
from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger("shadowtrace.utils.audit")


async def log_admin_action(
    db: AsyncIOMotorDatabase,
    request: Request,
    *,
    org_id: str,
    actor: Dict[str, Any],
    action: str,
    resource_type: str,
    resource_id: str,
    old_value: Optional[Dict[str, Any]] = None,
    new_value: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Write a tamper-evident admin audit log entry.

    Required by governance for:
      - Key rotations
      - Incident status changes
      - Note edits
      - Evidence exports
      - Device policy changes
    """

    try:
        ip = request.client.host if request.client else "unknown"
        entry = {
            "org_id": org_id,
            "actor_id": actor.get("sub") or actor.get("user_id") or actor.get("id"),
            "actor_email": actor.get("email"),
            "actor_role": actor.get("role"),
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "ip": ip,
            "timestamp": datetime.now(timezone.utc),
            "old_value": old_value,
            "new_value": new_value,
            "metadata": metadata or {},
        }
        await db.admin_audit_logs.insert_one(entry)
    except Exception as e:
        # Audit logging must never break the primary control flow,
        # but failures are always logged server-side.
        logger.error(f"Failed to write admin audit log for action={action}: {e}")

