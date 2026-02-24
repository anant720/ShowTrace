import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from app.dependencies import get_database, get_current_org_id, require_analyst, require_admin
from app.services.device_integrity import compute_device_snapshot
from app.utils.audit import log_admin_action
from app.utils.rate_limiter import rate_limit_action

logger = logging.getLogger("shadowtrace.routers.devices")

router = APIRouter(prefix="/devices", tags=["Devices & Endpoints"])


@router.get("/", summary="List devices/endpoints for the current organization")
async def list_devices(
    db: AsyncIOMotorDatabase = Depends(get_database),
    org_id: str = Depends(get_current_org_id),
    _user: dict = Depends(require_analyst),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
) -> Dict[str, Any]:
    """
    Device Aggregation Engine.

    Groups scan/log data per installation_id and surfaces:
      - last_seen
      - integrity_status
      - sequence_gap_count
      - replay_attempt_count
      - tamper_flag
      - key_rotation_count
      - risk_score
      - offline
    """
    skip = (page - 1) * page_size

    # Use materialized device_integrity collection when available
    cursor = (
        db.device_integrity.find({"org_id": org_id})
        .sort("last_seen", -1)
        .skip(skip)
        .limit(page_size)
    )

    devices: List[Dict[str, Any]] = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        if isinstance(doc.get("last_seen"), datetime):
            doc["last_seen"] = doc["last_seen"].isoformat()
        if isinstance(doc.get("offline_since"), datetime) and doc.get("offline_since"):
            doc["offline_since"] = doc["offline_since"].isoformat()
        devices.append(doc)

    # If no materialized records exist yet, fall back to on-demand computation
    if not devices:
        installation_ids = await db.scan_logs.distinct("installation_id", {"org_id": org_id})
        installation_ids = installation_ids[skip : skip + page_size]
        for installation_id in installation_ids:
            snapshot = await compute_device_snapshot(db, org_id, installation_id)
            if not snapshot:
                continue
            if isinstance(snapshot.get("last_seen"), datetime):
                snapshot["last_seen"] = snapshot["last_seen"].isoformat()
            if isinstance(snapshot.get("offline_since"), datetime) and snapshot.get(
                "offline_since"
            ):
                snapshot["offline_since"] = snapshot["offline_since"].isoformat()
            devices.append(snapshot)

    total = await db.device_integrity.count_documents({"org_id": org_id})
    if total == 0:
        # Fallback to approximate count via distinct installation_ids
        total = len(await db.scan_logs.distinct("installation_id", {"org_id": org_id}))

    return {
        "items": devices,
        "page": page,
        "page_size": page_size,
        "total": total,
    }


@router.get("/{installation_id}", summary="Get a single device with full integrity context")
async def get_device(
    installation_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
    org_id: str = Depends(get_current_org_id),
    _user: dict = Depends(require_analyst),
) -> Dict[str, Any]:
    snapshot = await compute_device_snapshot(db, org_id, installation_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="Device not found for this organization")

    # Attach gap details & replay attempts for this device
    gaps_cursor = db.integrity_gaps.find(
        {"org_id": org_id, "installation_id": installation_id}
    ).sort("detected_at", -1)
    gaps: List[Dict[str, Any]] = []
    async for g in gaps_cursor:
        g["_id"] = str(g["_id"])
        if isinstance(g.get("detected_at"), datetime):
            g["detected_at"] = g["detected_at"].isoformat()
        gaps.append(g)

    replay_attempts = await db.tamper_alerts.count_documents(
        {"org_id": org_id, "installation_id": installation_id, "type": "REPLAY_ATTACK"}
    )

    if isinstance(snapshot.get("last_seen"), datetime):
        snapshot["last_seen"] = snapshot["last_seen"].isoformat()
    if isinstance(snapshot.get("offline_since"), datetime) and snapshot.get("offline_since"):
        snapshot["offline_since"] = snapshot["offline_since"].isoformat()

    snapshot["integrity_gaps"] = gaps
    snapshot["replay_attempt_count"] = replay_attempts

    return snapshot


@router.patch(
    "/organizations/devices/{installation_id}/rotate-key",
    summary="Rotate device integrity key and reset nonce tracker",
)
async def rotate_device_key(
    installation_id: str,
    request: Request,
    db: AsyncIOMotorDatabase = Depends(get_database),
    org_id: str = Depends(get_current_org_id),
    admin: dict = Depends(require_admin),
) -> Dict[str, Any]:
    """
    Rotate the device-level integrity key.

    This operation:
      - Invalidates previous key record for this device/org
      - Generates a new hardware-bound key identifier
      - Resets nonce tracker by purging historical nonces for this device
      - Logs the operation to admin_audit_logs
      - Records a KEY_ROTATION forensic event for the device
    """
    await rate_limit_action(request, "device.rotate_key", limit=3, window_seconds=60)

    # Simulated hardware-bound secret; in a real deployment this would be
    # exchanged securely with the endpoint agent.
    import secrets

    new_key = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)

    # Fetch previous key record for audit
    old_record = await db.device_keys.find_one(
        {"org_id": org_id, "installation_id": installation_id, "active": True}
    )

    # Invalidate previous keys
    await db.device_keys.update_many(
        {"org_id": org_id, "installation_id": installation_id, "active": True},
        {"$set": {"active": False, "deactivated_at": now}},
    )

    new_record = {
        "org_id": org_id,
        "installation_id": installation_id,
        "active": True,
        "key": new_key,
        "created_at": now,
        "created_by": admin.get("sub"),
    }
    result = await db.device_keys.insert_one(new_record)
    new_record_id = str(result.inserted_id)

    # Reset nonce tracker for this device
    await db.nonce_registry.delete_many({"installation_id": installation_id})

    # Record device forensic event
    await db.device_events.insert_one(
        {
            "org_id": org_id,
            "installation_id": installation_id,
            "event_type": "KEY_ROTATION",
            "actor_id": admin.get("sub"),
            "timestamp": now,
            "old_key_id": str(old_record["_id"]) if old_record else None,
            "new_key_id": new_record_id,
        }
    )

    # Admin audit log
    await log_admin_action(
        db,
        request,
        org_id=org_id,
        actor=admin,
        action="device.key.rotate",
        resource_type="device",
        resource_id=installation_id,
        old_value={"device_key": str(old_record["_id"])} if old_record else None,
        new_value={"device_key": new_record_id},
        metadata={},
    )

    return {
        "status": "ok",
        "installation_id": installation_id,
        "new_key_id": new_record_id,
        "rotated_at": now.isoformat(),
    }

