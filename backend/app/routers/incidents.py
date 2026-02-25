import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.dependencies import get_database, get_current_org_id, require_analyst, require_admin
from app.utils.audit import log_admin_action
from app.utils.rate_limiter import rate_limit_action
from app.routers.integrity import verify_envelope_hmac
from app.config import settings

logger = logging.getLogger("shadowtrace.routers.incidents")

router = APIRouter(prefix="/incidents", tags=["Incidents"])


ALLOWED_TRANSITIONS: Dict[str, List[str]] = {
    "OPEN": ["INVESTIGATING"],
    "INVESTIGATING": ["CONTAINED"],
    "CONTAINED": ["RESOLVED"],
    "RESOLVED": ["CLOSED"],
    "CLOSED": [],
}


def _derive_severity(risk_score: float, has_tamper: bool, replay_count: int) -> str:
    """
    Server-side severity classification.
    """
    if has_tamper or replay_count > 0:
        return "CRITICAL"
    if risk_score >= 80:
        return "HIGH"
    if risk_score >= 50:
        return "MEDIUM"
    return "LOW"


@router.get("/", summary="List incidents")
async def list_incidents(
    db: AsyncIOMotorDatabase = Depends(get_database),
    org_id: str = Depends(get_current_org_id),
    _user: dict = Depends(require_analyst),
    status_filter: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
) -> Dict[str, Any]:
    query: Dict[str, Any] = {"org_id": org_id}
    if status_filter:
        query["status"] = status_filter

    skip = (page - 1) * page_size
    cursor = (
        db.incidents.find(query)
        .sort("created_at", -1)
        .skip(skip)
        .limit(page_size)
    )
    items: List[Dict[str, Any]] = []
    async for doc in cursor:
        doc["id"] = str(doc["_id"])
        del doc["_id"]
        if isinstance(doc.get("created_at"), datetime):
            doc["created_at"] = doc["created_at"].isoformat()
        if isinstance(doc.get("updated_at"), datetime):
            doc["updated_at"] = doc["updated_at"].isoformat()
        items.append(doc)

    total = await db.incidents.count_documents(query)
    return {"items": items, "page": page, "page_size": page_size, "total": total}


@router.post("/", summary="Create a new incident from an event")
async def create_incident(
    body: Dict[str, Any],
    request: Request,
    db: AsyncIOMotorDatabase = Depends(get_database),
    org_id: str = Depends(get_current_org_id),
    analyst: dict = Depends(require_analyst),
) -> Dict[str, Any]:
    """
    Create an incident pointing at an underlying event.

    Required invariants:
      - Event exists
      - Event belongs to current org
      - installation_id, anomaly_type, risk_score, linked_event_ids, severity are server-derived
    """
    await rate_limit_action(request, "incident.create", limit=10, window_seconds=60)

    event_id = body.get("event_id")
    if not event_id:
        raise HTTPException(status_code=400, detail="event_id is required")

    try:
        oid = ObjectId(event_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid event_id format")

    # For now we treat scan_logs as primary event source
    event = await db.scan_logs.find_one({"_id": oid, "org_id": org_id})
    if not event:
        raise HTTPException(
            status_code=404, detail="Event not found for this organization"
        )

    installation_id = event.get("installation_id")
    risk_score = float(event.get("final_risk_score", 0.0))

    # Link anomaly / chain context
    replay_count = await db.tamper_alerts.count_documents(
        {"org_id": org_id, "installation_id": installation_id, "type": "REPLAY_ATTACK"}
    )
    has_tamper = await db.tamper_alerts.count_documents(
        {
            "org_id": org_id,
            "installation_id": installation_id,
            "type": {"$in": ["HMAC_MISMATCH", "CHAIN_BROKEN", "GENESIS_HASH_MISMATCH"]},
        }
    ) > 0

    severity = _derive_severity(
        risk_score=risk_score, has_tamper=has_tamper, replay_count=replay_count
    )

    now = datetime.now(timezone.utc)
    incident_doc: Dict[str, Any] = {
        "org_id": org_id,
        "installation_id": installation_id,
        "status": "OPEN",
        "created_at": now,
        "updated_at": now,
        "created_by": analyst.get("sub"),
        "updated_by": analyst.get("sub"),
        "version": 1,
        "anomaly_type": event.get("risk_level"),
        "risk_score": risk_score,
        "linked_event_ids": [event_id],
        "initial_severity": severity,
        "notes": body.get("notes") or "",
    }

    result = await db.incidents.insert_one(incident_doc)
    incident_id = str(result.inserted_id)

    await log_admin_action(
        db,
        request,
        org_id=org_id,
        actor=analyst,
        action="incident.create",
        resource_type="incident",
        resource_id=incident_id,
        old_value=None,
        new_value={"status": "OPEN", "risk_score": risk_score, "severity": severity},
        metadata={"event_id": event_id},
    )

    incident_doc["id"] = incident_id
    del incident_doc["_id"]
    incident_doc["created_at"] = incident_doc["created_at"].isoformat()
    incident_doc["updated_at"] = incident_doc["updated_at"].isoformat()
    return incident_doc


@router.get("/{incident_id}", summary="Get incident with event chain slice")
async def get_incident(
    incident_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
    org_id: str = Depends(get_current_org_id),
    _user: dict = Depends(require_analyst),
) -> Dict[str, Any]:
    try:
        oid = ObjectId(incident_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid incident id")

    incident = await db.incidents.find_one({"_id": oid, "org_id": org_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    installation_id = incident.get("installation_id")

    # Pull chain slice around the linked events (bounded window)
    linked_ids = [ObjectId(eid) for eid in incident.get("linked_event_ids", []) if eid]
    events_cursor = db.scan_logs.find(
        {"_id": {"$in": linked_ids}, "org_id": org_id}
    ).sort("timestamp", 1)
    events: List[Dict[str, Any]] = []
    seq_values: List[int] = []
    async for e in events_cursor:
        if isinstance(e.get("timestamp"), datetime):
            e["timestamp"] = e["timestamp"].isoformat()
        e["_id"] = str(e["_id"])
        seq = e.get("seq")
        if isinstance(seq, int):
            seq_values.append(seq)
        events.append(e)

    chain: List[Dict[str, Any]] = []
    replay_attempts: List[Dict[str, Any]] = []

    if installation_id and seq_values:
        start_seq = max(min(seq_values) - 25, 1)
        end_seq = max(seq_values) + 25

        chain_cursor = db.forensic_chain.find(
            {
                "org_id": org_id,
                "installation_id": installation_id,
                "seq": {"$gte": start_seq, "$lte": end_seq},
            }
        ).sort("seq", 1)
        async for c in chain_cursor:
            c["_id"] = str(c["_id"])
            if isinstance(c.get("timestamp"), datetime):
                c["timestamp"] = c["timestamp"].isoformat()
            if isinstance(c.get("stored_at"), datetime):
                c["stored_at"] = c["stored_at"].isoformat()
            chain.append(c)

        # Replay attempts in incident window
        replay_cursor = db.tamper_alerts.find(
            {
                "org_id": org_id,
                "installation_id": installation_id,
                "type": "REPLAY_ATTACK",
            }
        ).sort("timestamp", -1)
        async for r in replay_cursor:
            r["_id"] = str(r["_id"])
            if isinstance(r.get("timestamp"), datetime):
                r["timestamp"] = r["timestamp"].isoformat()
            replay_attempts.append(r)

    incident["id"] = str(incident["_id"])
    del incident["_id"]
    if isinstance(incident.get("created_at"), datetime):
        incident["created_at"] = incident["created_at"].isoformat()
    if isinstance(incident.get("updated_at"), datetime):
        incident["updated_at"] = incident["updated_at"].isoformat()

    return {
        "incident": incident,
        "events": events,
        "chain": chain,
        "replay_attempts": replay_attempts,
    }


@router.patch("/{incident_id}", summary="Update incident status or notes (state machine enforced)")
async def update_incident(
    incident_id: str,
    body: Dict[str, Any],
    request: Request,
    db: AsyncIOMotorDatabase = Depends(get_database),
    org_id: str = Depends(get_current_org_id),
    analyst: dict = Depends(require_analyst),
) -> Dict[str, Any]:
    try:
        oid = ObjectId(incident_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid incident id")

    # Optimistic locking via version field
    expected_version = body.get("version")
    if not isinstance(expected_version, int):
        raise HTTPException(status_code=400, detail="version (int) is required for updates")

    update_fields: Dict[str, Any] = {}
    status_update = body.get("status")
    notes_update = body.get("notes")

    incident = await db.incidents.find_one({"_id": oid, "org_id": org_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    current_status = incident.get("status", "OPEN")
    old_value = {
        "status": current_status,
        "notes": incident.get("notes", ""),
        "version": incident.get("version"),
    }

    if status_update:
        status_update = status_update.upper()
        allowed = ALLOWED_TRANSITIONS.get(current_status, [])
        if status_update not in allowed:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid transition {current_status} → {status_update}",
            )
        update_fields["status"] = status_update

    if notes_update is not None:
        update_fields["notes"] = str(notes_update)

    if not update_fields:
        raise HTTPException(status_code=400, detail="No updatable fields provided")

    update_fields["updated_at"] = datetime.now(timezone.utc)
    update_fields["updated_by"] = analyst.get("sub")

    result = await db.incidents.find_one_and_update(
        {"_id": oid, "org_id": org_id, "version": expected_version},
        {"$set": update_fields, "$inc": {"version": 1}},
        return_document=True,
    )
    if not result:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Incident update conflict (stale version)",
        )

    new_value = {
        "status": result.get("status"),
        "notes": result.get("notes", ""),
        "version": result.get("version"),
    }
    await log_admin_action(
        db,
        request,
        org_id=org_id,
        actor=analyst,
        action="incident.update",
        resource_type="incident",
        resource_id=incident_id,
        old_value=old_value,
        new_value=new_value,
        metadata={},
    )

    result["id"] = str(result["_id"])
    del result["_id"]
    if isinstance(result.get("created_at"), datetime):
        result["created_at"] = result["created_at"].isoformat()
    if isinstance(result.get("updated_at"), datetime):
        result["updated_at"] = result["updated_at"].isoformat()

    return result


@router.get("/{incident_id}/export", summary="Export legally-defensible incident evidence bundle")
async def export_incident(
    incident_id: str,
    request: Request,
    db: AsyncIOMotorDatabase = Depends(get_database),
    org_id: str = Depends(get_current_org_id),
    analyst: dict = Depends(require_analyst),
) -> Dict[str, Any]:
    """
    Export full event chain, hash-chain proof, and integrity verification for an incident.

    Before export, signatures are re-verified using stored canonical envelopes and
    org-level integrity keys.
    """
    await rate_limit_action(request, "incident.export", limit=5, window_seconds=60)

    try:
        oid = ObjectId(incident_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid incident id")

    incident = await db.incidents.find_one({"_id": oid, "org_id": org_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    installation_id = incident.get("installation_id")
    if not installation_id:
        raise HTTPException(
            status_code=400,
            detail="Incident is missing installation_id; cannot construct chain",
        )

    linked_ids = [ObjectId(eid) for eid in incident.get("linked_event_ids", []) if eid]
    events_cursor = db.scan_logs.find(
        {"_id": {"$in": linked_ids}, "org_id": org_id}
    ).sort("timestamp", 1)

    events: List[Dict[str, Any]] = []
    seq_values: List[int] = []
    async for e in events_cursor:
        seq = e.get("seq")
        if isinstance(seq, int):
            seq_values.append(seq)
        e_copy = {
            **e,
            "_id": str(e["_id"]),
            "timestamp": e["timestamp"].isoformat() if isinstance(e.get("timestamp"), datetime) else e.get("timestamp"),
        }
        events.append(e_copy)

    if not seq_values:
        raise HTTPException(
            status_code=400,
            detail="Incident has no bounded event sequence for export",
        )

    start_seq = max(min(seq_values) - 25, 1)
    end_seq = max(seq_values) + 25

    chain_cursor = db.forensic_chain.find(
        {
            "org_id": org_id,
            "installation_id": installation_id,
            "seq": {"$gte": start_seq, "$lte": end_seq},
        }
    ).sort("seq", 1)

    chain: List[Dict[str, Any]] = []
    verification_results: List[Dict[str, Any]] = []

    async for c in chain_cursor:
        seq = c.get("seq")
        canonical_envelope = c.get("canonical_envelope")
        hmac_hex = c.get("hmac")

        record_export = {
            **c,
            "_id": str(c["_id"]),
            "timestamp": c["timestamp"].isoformat() if isinstance(c.get("timestamp"), datetime) else c.get("timestamp"),
            "stored_at": c["stored_at"].isoformat() if isinstance(c.get("stored_at"), datetime) else c.get("stored_at"),
        }
        chain.append(record_export)

        # Re-verify HMAC over stored canonical envelope, when available
        if canonical_envelope and hmac_hex:
            try:
                envelope_dict = {
                    "header": {
                        "seq": seq,
                        "installation_id": installation_id,
                        "hmac": hmac_hex,
                    },
                    "payload": {},  # not needed for re-verification as canonical_envelope is stored
                }
                # verify_envelope_hmac expects envelope structure; we temporarily
                # patch in the stored canonical JSON by bypassing the serializer.
                # For re-verification we recompute based on canonical string.
                # Here we rely on the fact that canonical_envelope is the same
                # string that was used at ingest.
                import hmac as _hmac
                import hashlib

                org = await db.organizations.find_one({"_id": org_id})
                if not org:
                    import bson

                    try:
                        org = await db.organizations.find_one({"_id": bson.ObjectId(org_id)})
                    except Exception:
                        org = None
                integrity_key = (org or {}).get(
                    "integrity_secret", settings.DEFAULT_INTEGRITY_SECRET
                )
                message = canonical_envelope.encode("utf-8")
                calc = _hmac.new(
                    integrity_key.encode("utf-8"), message, hashlib.sha256
                ).hexdigest()
                valid_sig = _hmac.compare_digest(calc, hmac_hex)
            except Exception as e:
                logger.error(f"Export signature re-verification failed for seq={seq}: {e}")
                valid_sig = False
        else:
            valid_sig = False

        verification_results.append(
            {
                "seq": seq,
                "signature_valid": valid_sig,
            }
        )

    # Nonce verification: ensure no replay alerts in chain window
    replay_alerts_cursor = db.tamper_alerts.find(
        {
            "org_id": org_id,
            "installation_id": installation_id,
            "type": "REPLAY_ATTACK",
        }
    )
    replay_alerts: List[Dict[str, Any]] = []
    async for r in replay_alerts_cursor:
        r["_id"] = str(r["_id"])
        if isinstance(r.get("timestamp"), datetime):
            r["timestamp"] = r["timestamp"].isoformat()
        replay_alerts.append(r)

    export_payload = {
        "incident_id": incident_id,
        "org_id": org_id,
        "installation_id": installation_id,
        "incident": {
            "status": incident.get("status"),
            "risk_score": incident.get("risk_score"),
            "initial_severity": incident.get("initial_severity"),
        },
        "events": events,
        "chain": chain,
        "signature_verification": verification_results,
        "nonce_verification": {
            "replay_alert_count": len(replay_alerts),
            "alerts": replay_alerts,
        },
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }

    import json
    import hashlib as _hashlib
    import hmac as _hmac

    serialized = json.dumps(export_payload, sort_keys=True).encode("utf-8")
    export_hash = _hashlib.sha256(serialized).hexdigest()

    signing_key = getattr(settings, "EXPORT_SIGNING_KEY", settings.JWT_SECRET)
    signature = _hmac.new(
        signing_key.encode("utf-8"), export_hash.encode("utf-8"), _hashlib.sha256
    ).hexdigest()

    await log_admin_action(
        db,
        request,
        org_id=org_id,
        actor=analyst,
        action="incident.export",
        resource_type="incident",
        resource_id=incident_id,
        old_value=None,
        new_value=None,
        metadata={
            "export_hash": export_hash,
        },
    )

    return {
        "bundle": export_payload,
        "sha256": export_hash,
        "signature": signature,
    }

