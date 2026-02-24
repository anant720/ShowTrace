import logging
import hmac
import hashlib
import json
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.models.schemas import AnalyzeEnvelope, AnalyzeResponse, AnalyzeRequest
from app.ml.features import FeatureEngineer
from app.ml.ensemble_engine import EnsembleScorer
from app.ml.whitelist_manager import WhitelistManager
from app.ml.normalization import Normalizer
from app.ml.security_auditor import SecurityAuditor
from app.utils.scrubber import CredentialScrubber
from app.routers.integrity import run_integrity_pipeline

# ── Tier config (inlined to avoid app/config.py vs app/config/ conflict) ──
_TIER_LIMITS = {
    "community":  {"features": {"ml_explainability": False, "forensic_reasoning": False}},
    "pro":        {"features": {"ml_explainability": False, "forensic_reasoning": True}},
    "enterprise": {"features": {"ml_explainability": True,  "forensic_reasoning": True}},
    "guardian":   {"features": {"ml_explainability": True,  "forensic_reasoning": True}},
}
def get_tier_config(tier: str) -> dict:
    return _TIER_LIMITS.get((tier or "community").lower(), _TIER_LIMITS["community"])


logger = logging.getLogger("shadowtrace.services.risk_scorer")
scorer = EnsembleScorer()
whitelist = WhitelistManager()

def classify_risk(score: float) -> str:
    if score <= 30: return "Safe"
    elif score <= 60: return "Suspicious"
    return "Dangerous"


async def evaluate(envelope_data: dict, db: AsyncIOMotorDatabase, org_id: str = "community") -> AnalyzeResponse:
    now = datetime.now(timezone.utc)
    try:
        # 0. Parse envelope schema
        envelope = AnalyzeEnvelope(**envelope_data)

        # ── PHASE 1.5: Full Integrity Pipeline ─────────────────────────
        # Runs in order: nonce dedup → canonical HMAC → hash chain → gap detection
        integrity = await run_integrity_pipeline(envelope_data, org_id, db)

        if not integrity["valid"]:
            violation = integrity.get("violation_type", "UNKNOWN")
            logger.warning(
                f"[ShadowTrace] Forensic Integrity VIOLATION ({violation}) "
                f"for Org={org_id} seq={envelope.header.seq}"
            )
            return AnalyzeResponse(
                risk_score=100.0,
                risk_level="Dangerous",
                reasons=[f"Forensic Integrity Chain BROKEN — type={violation}. Signal rejected."],
                confidence=1.0
            )

        # Log gap warning if present (but still process event)
        gap_info = integrity.get("gap_info") or {}
        if gap_info.get("state") not in (None, "NORMAL"):
            logger.warning(
                f"[ShadowTrace] Sequence gap detected: {gap_info} "
                f"for installation={envelope.header.installation_id}"
            )

        request = AnalyzeRequest(**envelope.payload)

        # 0. Normalization
        original_url = request.fullURL or request.domain.fullURL
        normalized_url = Normalizer.normalize_url(original_url)
        
        # 1. Whitelist Check (Database + Static)
        domain_name = request.domain.hostname
        
        # Check DB for analyst-confirmed safe domains (scoped to Org)
        analyst_override = await db.trusted_domains.find_one({
            "org_id": org_id,
            "domain": domain_name, 
            "manual_override": True
        })
        
        if analyst_override or whitelist.is_trusted(domain_name):
            source = "analyst_override" if analyst_override else "whitelist"
            return AnalyzeResponse(
                risk_score=0.0,
                risk_level="Safe",
                reasons=[f"Domain confirmed SAFE by {source} layer"],
                confidence=1.0,
                source=source,
                security_score=100.0
            )

        # 2. ML Inference
        raw_payload = request.model_dump()
        raw_payload["full_url"] = normalized_url
        features = FeatureEngineer.extract_all(raw_payload)
        analysis = await scorer.calculate_ensemble_score(features)
        
        # 3. Security Audit (Passive)
        network_reqs = raw_payload.get("network_requests", [])
        
        # Try to find main page response headers (first request usually)
        main_headers = []
        if network_reqs:
            main_headers = network_reqs[0].get("responseHeaders", [])
            
        audit = SecurityAuditor.audit_headers(main_headers)
        vulns = SecurityAuditor.detect_vulnerabilities(network_reqs)
        
        combined_findings = audit["findings"] + vulns
        security_score = audit["score"]

        final_score = analysis["risk_score"]
        risk_level = classify_risk(final_score)
        
        # 4. Persistence
        try:
            # Scrub sensitive data before persisting logs
            scrubbed_requests = CredentialScrubber.scrub_requests(network_reqs)
            user_email = request.meta.user_email if request.meta else "anonymous@shadowtrace.local"
            
            log_entry = {
                "org_id": org_id,
                "domain": domain_name,
                "user_email": user_email,
                "full_url": normalized_url,
                "original_url": original_url,
                "confidence": analysis["confidence"],
                "final_risk_score": final_score,
                "risk_level": risk_level,
                "reasons": analysis["reasons"],
                "engine_scores": analysis["layer_scores"],
                "security_score": security_score,
                "security_findings": combined_findings,
                "explainability": analysis["explainability"],
                "network_requests": scrubbed_requests,
                "timestamp": now,
                # ── Phase 1.5: Forensic chain-of-custody fields ──────────
                "installation_id": envelope.header.installation_id,
                "id_tier": envelope.header.id_tier,
                "seq": envelope.header.seq,
                "envelope_hash": integrity.get("envelope_hash"),
                "gap_state": gap_info.get("state", "NORMAL"),
            }
            await db.scan_logs.insert_one(log_entry)
        except Exception as e:
            logger.error(f"Log failed: {e}")

        # 5. Tier-Based Feature Masking
        org = await db.organizations.find_one({"_id": bson.ObjectId(org_id)}) if org_id != "community" else None
        tier = org.get("subscription_tier", "community") if org else "community"
        tier_config = get_tier_config(tier)
        features_allowed = tier_config.get("features", {})

        response_data = {
            "risk_score": final_score,
            "risk_level": risk_level,
            "confidence": analysis["confidence"]
        }

        # Pro & Enterprise: Reasoning and Forensic Findings
        if features_allowed.get("forensic_reasoning") or tier == "enterprise":
            response_data["reasons"] = analysis["reasons"]
            response_data["security_score"] = security_score
            response_data["security_findings"] = combined_findings
        else:
            response_data["reasons"] = [f"Phishing analysis complete. Upgrade to Professional for behavioral reasoning."]
            response_data["security_score"] = None
            response_data["security_findings"] = []

        # Enterprise: Full XAI Explainability
        if features_allowed.get("ml_explainability"):
            response_data["engine_scores"] = analysis["layer_scores"]
            response_data["explainability"] = analysis["explainability"]

        # Intelligence Policy for Extension (DLP/Behavioral)
        response_data["intelligence_policy"] = {
            "blockExfiltration": features_allowed.get("dlp_exfiltration_blocking", False),
            "warningOnly": features_allowed.get("dlp_exfiltration_warning", False),
            "captureBehavioral": features_allowed.get("behavioral_fingerprinting", False)
        }
        
        # 6. Autonomous Remediation (Phase 5)
        if final_score > 75:
            # We pass a dict for easier processing in remediation service
            scan_context = {
                "org_id": org_id,
                "domain": request.domain.hostname,
                "risk_score": final_score,
                "risk_level": risk_level
            }
            # Background task would be better, but we'll await for now to ensure policy sync
            try:
                await analyze_and_remediate(org_id, scan_context, db)
            except Exception as e:
                logger.error(f"Auto-remediation failed: {e}")

        return AnalyzeResponse(**response_data)

    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        return AnalyzeResponse(
            risk_score=0,
            risk_level="Safe",
            reasons=["Internal ML analysis failure"],
            confidence=0.0
        )
