import logging
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.models.schemas import AnalyzeRequest, AnalyzeResponse
from app.ml.features import FeatureEngineer
from app.ml.ensemble_engine import EnsembleScorer
from app.ml.whitelist_manager import WhitelistManager
from app.ml.normalization import Normalizer
from app.ml.security_auditor import SecurityAuditor
from app.utils.scrubber import CredentialScrubber

logger = logging.getLogger("shadowtrace.services.risk_scorer")
scorer = EnsembleScorer()
whitelist = WhitelistManager()

def classify_risk(score: float) -> str:
    if score <= 30: return "Safe"
    elif score <= 60: return "Suspicious"
    return "Dangerous"

async def evaluate(request: AnalyzeRequest, db: AsyncIOMotorDatabase) -> AnalyzeResponse:
    now = datetime.now(timezone.utc)
    try:
        # 0. Normalization
        original_url = request.fullURL or request.domain.fullURL
        normalized_url = Normalizer.normalize_url(original_url)
        
        # 1. Whitelist Check (Database + Static)
        domain_name = request.domain.hostname
        
        # Check DB for analyst-confirmed safe domains
        analyst_override = await db.trusted_domains.find_one({"domain": domain_name, "manual_override": True})
        
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
            }
            await db.scan_logs.insert_one(log_entry)
        except Exception as e:
            logger.error(f"Log failed: {e}")

        return AnalyzeResponse(
            risk_score=final_score,
            risk_level=risk_level,
            reasons=analysis["reasons"],
            confidence=analysis["confidence"],
            engine_scores=analysis["layer_scores"],
            explainability=analysis["explainability"],
            security_score=security_score,
            security_findings=combined_findings
        )

    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        return AnalyzeResponse(
            risk_score=0,
            risk_level="Safe",
            reasons=["Internal ML analysis failure"],
            confidence=0.0
        )
