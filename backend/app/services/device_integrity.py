import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger("shadowtrace.services.device_integrity")


DEFAULT_OFFLINE_MINUTES = 30


async def _get_offline_threshold_minutes(db: AsyncIOMotorDatabase) -> int:
    """
    Read organization-wide offline detection threshold from settings collection if present,
    otherwise fall back to a sane default.
    """
    try:
        # Global settings document (optional)
        doc = await db.system_settings.find_one({"key": "device_offline_threshold_minutes"})
        if doc and isinstance(doc.get("value"), int) and doc["value"] > 0:
            return doc["value"]
    except Exception:
        pass
    return DEFAULT_OFFLINE_MINUTES


def _compute_device_risk(
    *,
    gap_count: int,
    replay_count: int,
    tamper_events: int,
    anomaly_events: int,
    key_resets: int,
) -> float:
    """
    Risk Score Engine for devices.

    All weights are server-side and never exposed as client-controlled inputs.
    """
    # Tunable weights (can later move to DB-backed config if needed)
    GAP_WEIGHT = 1.5
    REPLAY_WEIGHT = 8.0
    TAMPER_WEIGHT = 10.0
    ANOMALY_WEIGHT = 0.5
    KEY_RESET_WEIGHT = 3.0

    score = (
        gap_count * GAP_WEIGHT
        + replay_count * REPLAY_WEIGHT
        + tamper_events * TAMPER_WEIGHT
        + anomaly_events * ANOMALY_WEIGHT
        + key_resets * KEY_RESET_WEIGHT
    )
    # Clamp to [0, 100]
    return max(0.0, min(100.0, float(score)))


def _classify_integrity(
    *,
    gap_count: int,
    replay_count: int,
    tamper_events: int,
    key_resets: int,
    offline: bool,
) -> str:
    """
    Map raw metrics to a coarse integrity state.
    """
    if tamper_events > 0 or replay_count > 0 or key_resets > 3:
        return "COMPROMISED"
    if gap_count > 0 or offline:
        return "DEGRADED"
    return "HEALTHY"


async def compute_device_snapshot(
    db: AsyncIOMotorDatabase,
    org_id: str,
    installation_id: str,
) -> Optional[Dict[str, Any]]:
    """
    Compute an integrity snapshot for a single device (installation_id).

    This function is intentionally read-only and uses indexed lookups only.
    """
    # Latest scan timestamp (authoritative last_seen)
    latest_scan = await db.scan_logs.find_one(
        {"org_id": org_id, "installation_id": installation_id},
        sort=[("timestamp", -1)],
        projection={"timestamp": 1, "id_tier": 1},
    )

    # Fallback to forensic_chain timestamp if no scan log is present
    latest_chain = await db.forensic_chain.find_one(
        {"org_id": org_id, "installation_id": installation_id},
        sort=[("timestamp", -1)],
        projection={"timestamp": 1, "seq": 1, "agent_version": 1},
    )

    if not latest_scan and not latest_chain:
        return None

    last_seen = None
    if latest_scan and latest_scan.get("timestamp"):
        last_seen = latest_scan["timestamp"]
    if latest_chain and latest_chain.get("timestamp"):
        if not last_seen or latest_chain["timestamp"] > last_seen:
            last_seen = latest_chain["timestamp"]

    # Sequence metrics
    gap_count = await db.integrity_gaps.count_documents(
        {"org_id": org_id, "installation_id": installation_id}
    )

    # Replay attempts
    replay_count = await db.tamper_alerts.count_documents(
        {
            "org_id": org_id,
            "installation_id": installation_id,
            "type": "REPLAY_ATTACK",
        }
    )

    # Tamper / signature failures
    tamper_events = await db.tamper_alerts.count_documents(
        {
            "org_id": org_id,
            "installation_id": installation_id,
            "type": {"$in": ["HMAC_MISMATCH", "CHAIN_BROKEN", "GENESIS_HASH_MISMATCH"]},
        }
    )

    # General anomalies (frequency of anomalies)
    anomaly_events = await db.anomalies.count_documents(
        {"org_id": org_id, "installation_id": installation_id}
    )

    # Key reset patterns (admin-driven rotations)
    key_resets = await db.device_events.count_documents(
        {
            "org_id": org_id,
            "installation_id": installation_id,
            "event_type": "KEY_ROTATION",
        }
    )

    # Offline detection
    offline_threshold_min = await _get_offline_threshold_minutes(db)
    now = datetime.now(timezone.utc)
    offline = False
    offline_since: Optional[datetime] = None
    if last_seen:
        delta = now - last_seen.replace(tzinfo=timezone.utc)
        if delta > timedelta(minutes=offline_threshold_min):
            offline = True
            offline_since = last_seen

    risk_score = _compute_device_risk(
        gap_count=gap_count,
        replay_count=replay_count,
        tamper_events=tamper_events,
        anomaly_events=anomaly_events,
        key_resets=key_resets,
    )

    integrity_status = _classify_integrity(
        gap_count=gap_count,
        replay_count=replay_count,
        tamper_events=tamper_events,
        key_resets=key_resets,
        offline=offline,
    )

    snapshot: Dict[str, Any] = {
        "installation_id": installation_id,
        "org_id": org_id,
        "last_seen": last_seen,
        "integrity_status": integrity_status,
        "sequence_gap_count": gap_count,
        "replay_attempt_count": replay_count,
        "tamper_flag": tamper_events > 0 or replay_count > 0,
        "key_rotation_count": key_resets,
        "risk_score": risk_score,
        "offline": offline,
        "offline_since": offline_since,
        "agent_version": (latest_chain or {}).get("agent_version") or (latest_scan or {}).get(
            "id_tier"
        ),
    }

    return snapshot


async def recompute_all_devices(db: AsyncIOMotorDatabase, org_id: Optional[str] = None) -> int:
    """
    Background-friendly batch recomputation of device_integrity documents.

    If org_id is provided, the recomputation is scoped to that organization.
    Returns the number of devices processed.
    """
    match: Dict[str, Any] = {}
    if org_id:
        match["org_id"] = org_id

    # Distinct installation_ids scoped to (optional) org
    installation_ids = await db.scan_logs.distinct("installation_id", match)
    processed = 0

    for installation_id in installation_ids:
        if not installation_id:
            continue
        # Determine orgs for this installation_id
        org_ids = await db.scan_logs.distinct(
            "org_id", {"installation_id": installation_id, **match}
        )
        for oid in org_ids:
            snapshot = await compute_device_snapshot(db, oid, installation_id)
            if not snapshot:
                continue
            await db.device_integrity.update_one(
                {"org_id": oid, "installation_id": installation_id},
                {"$set": snapshot},
                upsert=True,
            )
            processed += 1

    logger.info(f"Recomputed device integrity for {processed} device-org pairs")
    return processed

