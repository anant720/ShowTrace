"""
ShadowTrace — Integrity Router  (Phase 1.5)

Endpoints:
  POST /integrity/check   — nonce dedup + HMAC + hash-chain validation
  GET  /integrity/chain/{installation_id}  — audit chain view
  GET  /integrity/gaps/{installation_id}   — sequence gap analysis

Called internally by risk_scorer.evaluate() before analysis and directly
by the SOC dashboard for chain-of-custody queries.

Sequence Gap Severity Model:
  1–5   missing: LOW    — log only
  6–50  missing: MEDIUM — dashboard badge
  51+   missing: HIGH   — SOC webhook + alert
  reset (seq < last): CRITICAL — suspend installation_id
"""

import logging
import hmac as _hmac
import hashlib
import json
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo.errors import DuplicateKeyError

from app.dependencies import get_database, get_current_org_id

logger = logging.getLogger("shadowtrace.routers.integrity")
router = APIRouter(prefix="/integrity", tags=["Integrity"])

# ── Canonical JSON (server-side mirror of extension utils/canonicalize.js) ───
def _canonical(value) -> str:
    """
    RFC 8785 / JCS canonical JSON serializer.
    MUST produce byte-for-byte identical output to the JS canonicalize() in
    extension_dist/utils/canonicalize.js for the same logical object.

    Rules:
      • Object keys sorted by unicode code-point (Python's default str sort).
      • Arrays preserve element order.
      • Uses json.dumps for leaf types (handles Unicode escaping consistently).
      • No whitespace.
    """
    if value is None or not isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    if isinstance(value, list):
        return '[' + ','.join(_canonical(v) for v in value) + ']'
    # dict — sort keys
    sorted_keys = sorted(value.keys())
    members = [
        json.dumps(k, ensure_ascii=False) + ':' + _canonical(value[k])
        for k in sorted_keys
    ]
    return '{' + ','.join(members) + '}'


def canonical_bytes(value: dict) -> bytes:
    return _canonical(value).encode('utf-8')


# ── HMAC Verification ────────────────────────────────────────────────────────
async def verify_envelope_hmac(envelope_dict: dict, db, org_id: str) -> bool:
    """
    Reconstruct the canonical form of (envelope minus hmac field) and
    verify the HMAC-SHA-256.  The integrity key is the org-level secret
    stored in the organizations collection.
    """
    org = await db.organizations.find_one({"_id": org_id})
    if not org:
        # Try string ObjectId lookup
        import bson
        try:
            org = await db.organizations.find_one({"_id": bson.ObjectId(org_id)})
        except Exception:
            pass
    integrity_key = (org or {}).get("integrity_secret", "shadowtrace_test_integrity_key_2025")

    # Deep-copy header and pop hmac
    header_data = {k: v for k, v in envelope_dict.get("header", {}).items()}
    provided_hmac = header_data.pop("hmac", "")

    envelope_sans_hmac = {
        "header": header_data,
        "payload": envelope_dict.get("payload", {})
    }

    message = canonical_bytes(envelope_sans_hmac)
    calculated = _hmac.new(integrity_key.encode("utf-8"), message, hashlib.sha256).hexdigest()

    return _hmac.compare_digest(provided_hmac, calculated)


# ── Envelope Hash (chain link) ───────────────────────────────────────────────
def compute_envelope_hash(canonical: bytes, hmac_hex: str) -> str:
    """
    envelope_hash = SHA-256( canonical_bytes ‖ hmac_bytes )
    Mirrors signer.js signEnvelope() on the extension side.
    """
    combined = canonical + hmac_hex.encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


# ── Nonce Deduplication ──────────────────────────────────────────────────────
async def check_and_record_nonce(
    nonce: str,
    installation_id: str,
    db,
    ttl_hours: int = 24,
) -> bool:
    """
    Atomically insert the nonce.  Returns True if fresh, False if replayed.
    MongoDB unique index on 'nonce' ensures atomic dedup without a read-then-write race.
    TTL index on 'expires_at' auto-purges records after ttl_hours.
    """
    now = datetime.now(timezone.utc)
    try:
        await db.nonce_registry.insert_one({
            "nonce": nonce,
            "installation_id": installation_id,
            "received_at": now,
            "expires_at": now + timedelta(hours=ttl_hours),
        })
        return True
    except DuplicateKeyError:
        return False


# ── Hash Chain Verification ──────────────────────────────────────────────────
async def verify_hash_chain(
    installation_id: str,
    seq: int,
    prev_hash: str,
    genesis: bool,
    db,
) -> dict:
    """
    Returns {"valid": bool, "reason": str | None}.
    Checks that prev_hash matches the stored envelope_hash of (seq - 1).
    """
    if seq == 1:
        if prev_hash != "GENESIS":
            return {"valid": False, "reason": "GENESIS_HASH_MISMATCH"}
        # Check no prior chain exists (reinstall / identity reset)
        prior = await db.forensic_chain.find_one({"installation_id": installation_id})
        if prior and not genesis:
            return {"valid": False, "reason": "GENESIS_WITHOUT_FLAG"}
        return {"valid": True, "reason": None}

    prev_record = await db.forensic_chain.find_one(
        {"installation_id": installation_id, "seq": seq - 1}
    )
    if not prev_record:
        return {"valid": False, "reason": "PREV_EVENT_MISSING"}

    expected = prev_record.get("envelope_hash", "")
    if not _hmac.compare_digest(prev_hash, expected):
        return {"valid": False, "reason": "CHAIN_BROKEN"}

    return {"valid": True, "reason": None}


# ── Sequence Gap Analysis ────────────────────────────────────────────────────
async def analyze_sequence_gap(
    installation_id: str,
    org_id: str,
    seq: int,
    db,
) -> dict:
    """
    Determines if the incoming seq represents a gap, reset, or normal increment.
    Logs anomaly records accordingly and persists explicit integrity_gaps entries
    for forensic-grade analysis.
    """
    last_record = await db.forensic_chain.find_one(
        {"installation_id": installation_id},
        sort=[("seq", -1)]
    )
    if not last_record:
        return {"state": "NORMAL", "gap": 0}

    last_seq = last_record["seq"]

    # Counter reset
    if seq < last_seq:
        gap_info = {
            "state": "RESET_DETECTED",
            "gap": last_seq - seq,
            "severity": "CRITICAL",
        }
        await _log_anomaly(installation_id, org_id, seq, last_seq, gap_info, db)
        return gap_info

    # Expected
    if seq == last_seq + 1:
        return {"state": "NORMAL", "gap": 0}

    # Gap
    gap = seq - last_seq - 1
    # Original anomaly severity model
    severity = "LOW" if gap <= 5 else ("MEDIUM" if gap <= 50 else "HIGH")
    # Integrity gap severity model: more than 1 consecutive missing event is HIGH
    integrity_severity = "HIGH" if gap > 1 else "LOW"

    gap_info = {
        "state": "GAP_DETECTED",
        "gap": gap,
        "severity": severity,
        "integrity_severity": integrity_severity,
        "expected_seq": last_seq + 1,
        "received_seq": seq,
    }
    await _log_anomaly(installation_id, org_id, seq, last_seq, gap_info, db)
    return gap_info


async def _log_anomaly(installation_id, org_id, seq, last_seq, gap_info, db):
    now = datetime.now(timezone.utc)
    gap_size = gap_info.get("gap", 0)
    expected_seq = last_seq + 1

    # Behavioral anomaly record (existing dashboard model)
    await db.anomalies.insert_one({
        "anomaly_type": "SEQUENCE_GAP",
        "installation_id": installation_id,
        "org_id": org_id,
        "expected_seq": expected_seq,
        "received_seq": seq,
        "gap_size": gap_size,
        "severity": gap_info.get("severity", "UNKNOWN"),
        "state": gap_info.get("state"),
        "detected_at": now,
        "acknowledged": False,
    })

    # Integrity gaps collection for device / incident engines
    missing_sequences = list(range(expected_seq, seq)) if gap_size > 0 and gap_size <= 500 else []
    await db.integrity_gaps.insert_one({
        "installation_id": installation_id,
        "org_id": org_id,
        "last_known_seq": last_seq,
        "first_missing_seq": expected_seq,
        "observed_seq": seq,
        "gap_size": gap_size,
        "missing_sequences": missing_sequences,
        "severity": gap_info.get("integrity_severity", gap_info.get("severity", "UNKNOWN")),
        "state": gap_info.get("state"),
        "detected_at": now,
    })


# ── Internal: Full Integrity Pipeline ────────────────────────────────────────
async def run_integrity_pipeline(
    envelope_dict: dict,
    org_id: str,
    db,
) -> dict:
    """
    Runs all four integrity checks in order:
      1. Nonce dedup      (replay immunity)
      2. HMAC verify      (tamper detection)
      3. Hash chain       (deletion detection)
      4. Sequence gap     (dropping / reset detection)

    Returns a result dict with keys: valid, violation_type, gap_info, envelope_hash.
    Also records the chain entry in forensic_chain for valid envelopes.
    """
    header = envelope_dict.get("header", {})
    nonce           = header.get("nonce", "")
    installation_id = header.get("installation_id", "")
    seq             = header.get("seq", 0)
    prev_hash       = header.get("prev_hash", "GENESIS")
    genesis         = header.get("genesis", False)
    hmac_hex        = header.get("hmac", "")

    # 1. Replay check
    is_fresh = await check_and_record_nonce(nonce, installation_id, db)
    if not is_fresh:
        await db.tamper_alerts.insert_one({
            "org_id": org_id,
            "installation_id": installation_id,
            "nonce": nonce,
            "seq": seq,
            "type": "REPLAY_ATTACK",
            "timestamp": datetime.now(timezone.utc),
        })
        return {"valid": False, "violation_type": "REPLAY", "gap_info": None, "envelope_hash": None}

    # 2. HMAC
    hmac_valid = await verify_envelope_hmac(envelope_dict, db, org_id)
    if not hmac_valid:
        await db.tamper_alerts.insert_one({
            "org_id": org_id,
            "installation_id": installation_id,
            "header": header,
            "type": "HMAC_MISMATCH",
            "timestamp": datetime.now(timezone.utc),
        })
        return {"valid": False, "violation_type": "HMAC_MISMATCH", "gap_info": None, "envelope_hash": None}

    # 3. Hash chain
    chain_result = await verify_hash_chain(installation_id, seq, prev_hash, genesis, db)
    if not chain_result["valid"]:
        await db.tamper_alerts.insert_one({
            "org_id": org_id,
            "installation_id": installation_id,
            "seq": seq,
            "type": chain_result["reason"],
            "timestamp": datetime.now(timezone.utc),
        })
        return {"valid": False, "violation_type": chain_result["reason"], "gap_info": None, "envelope_hash": None}

    # 4. Sequence gap
    gap_info = await analyze_sequence_gap(installation_id, org_id, seq, db)

    # Compute this envelope's hash for chain storage
    header_sans_hmac = {k: v for k, v in header.items()}
    header_sans_hmac.pop("hmac", None)
    canonical = canonical_bytes({"header": header_sans_hmac, "payload": envelope_dict.get("payload", {})})
    env_hash = compute_envelope_hash(canonical, hmac_hex)

    # Persist chain record
    now = datetime.now(timezone.utc)
    await db.forensic_chain.insert_one({
        "installation_id": installation_id,
        "org_id": org_id,
        "seq": seq,
        "nonce": nonce,
        "timestamp": now,
        "envelope_hash": env_hash,
        "prev_hash": prev_hash,
        "gap_state": gap_info.get("state", "NORMAL"),
        "id_tier": header.get("id_tier", "derived"),
        "agent_version": header.get("version"),
        "stored_at": now,
        # For export-time re-verification of signatures
        "canonical_envelope": canonical.decode("utf-8"),
        "hmac": hmac_hex,
    })

    return {
        "valid": True,
        "violation_type": None,
        "gap_info": gap_info,
        "envelope_hash": env_hash,
    }


# ── REST Endpoints ────────────────────────────────────────────────────────────

@router.get("/chain/{installation_id}", summary="Audit forensic chain for an installation")
async def get_chain(
    installation_id: str,
    limit: int = 100,
    db: AsyncIOMotorDatabase = Depends(get_database),
    org_id: str = Depends(get_current_org_id),
):
    """Returns the stored forensic chain records for the given installation_id,
    sorted ascending by seq.  SOC analysts use this to verify continuity."""
    cursor = db.forensic_chain.find(
        {"installation_id": installation_id, "org_id": org_id}
    ).sort("seq", 1).limit(limit)

    records = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        if "timestamp" in doc:
            doc["timestamp"] = doc["timestamp"].isoformat()
        if "stored_at" in doc:
            doc["stored_at"] = doc["stored_at"].isoformat()
        records.append(doc)

    return {
        "installation_id": installation_id,
        "count": len(records),
        "records": records,
    }


@router.get("/gaps/{installation_id}", summary="Sequence gap analysis for an installation")
async def get_gaps(
    installation_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
    org_id: str = Depends(get_current_org_id),
):
    """Returns sequence gap anomalies recorded for the given installation_id."""
    cursor = db.anomalies.find(
        {"installation_id": installation_id, "org_id": org_id, "anomaly_type": "SEQUENCE_GAP"}
    ).sort("detected_at", -1).limit(50)

    gaps = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        if "detected_at" in doc:
            doc["detected_at"] = doc["detected_at"].isoformat()
        gaps.append(doc)

    return {"installation_id": installation_id, "gaps": gaps}
