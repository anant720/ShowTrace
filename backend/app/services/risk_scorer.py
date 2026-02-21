import asyncio
import logging
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.engines.base import EngineResult
from app.engines import domain_similarity, ssl_protocol, behavioral, threat_intel
from app.models.schemas import AnalyzeRequest, AnalyzeResponse

logger = logging.getLogger("shadowtrace.services.risk_scorer")

WEIGHTS = {
    "domain_similarity": 0.30,
    "behavioral":        0.30,
    "ssl_protocol":      0.10,
    "threat_intel":      0.30,
}

def classify_risk(score: int) -> str:
    if score <= 30: return "Safe"
    elif score <= 60: return "Suspicious"
    return "Dangerous"

async def evaluate(request: AnalyzeRequest, db: AsyncIOMotorDatabase) -> AnalyzeResponse:
    results = await asyncio.gather(
        domain_similarity.analyze(request, db),
        behavioral.analyze(request, db),
        ssl_protocol.analyze(request, db),
        threat_intel.analyze(request, db),
        return_exceptions=True,
    )

    engine_results = {}
    all_reasons = []
    total_weighted_score = 0.0

    for result in results:
        if isinstance(result, Exception):
            logger.error(f"Engine failed: {result}")
            continue
        engine_results[result.engine_name] = {
            "score": round(result.score, 1),
            "max_score": result.max_score,
            "normalized": round(result.normalized, 3),
        }
        weight = WEIGHTS.get(result.engine_name, 0.0)
        total_weighted_score += result.normalized * weight * 100
        all_reasons.extend(result.reasons)

    final_score = min(round(total_weighted_score), 100)
    risk_level = classify_risk(final_score)
    unique_reasons = list(dict.fromkeys(all_reasons))

    try:
        d = request.domain
        now = datetime.now(timezone.utc)
        await db.scan_logs.insert_one({
            "domain": d.hostname,
            "full_url": d.fullURL,
            "engine_scores": engine_results,
            "final_risk_score": final_score,
            "risk_level": risk_level,
            "reasons": unique_reasons,
            "timestamp": now,
        })
        await db.risk_history.insert_one({
            "domain": d.hostname,
            "risk_score": final_score,
            "risk_level": risk_level,
            "engine_scores": engine_results,
            "timestamp": now,
        })
    except Exception as e:
        logger.error(f"Log failed: {e}")

    return AnalyzeResponse(
        risk_score=final_score,
        risk_level=risk_level,
        reasons=unique_reasons,
        engine_scores=engine_results,
    )
