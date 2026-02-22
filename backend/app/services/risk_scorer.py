import logging
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.models.schemas import AnalyzeRequest, AnalyzeResponse
from app.ml.features import FeatureEngineer
from app.ml.ensemble_engine import EnsembleScorer

logger = logging.getLogger("shadowtrace.services.risk_scorer")
scorer = EnsembleScorer()

def classify_risk(score: float) -> str:
    if score <= 30: return "Safe"
    elif score <= 60: return "Suspicious"
    return "Dangerous"

async def evaluate(request: AnalyzeRequest, db: AsyncIOMotorDatabase) -> AnalyzeResponse:
    try:
        # 1. Pipeline: Feature Engineering
        # Convert Pydantic model to dict for transparency in processing
        raw_payload = request.model_dump()
        features = FeatureEngineer.extract_all(raw_payload)
        
        # 2. Pipeline: ML Ensemble Inference
        analysis = await scorer.calculate_ensemble_score(features)
        
        final_score = analysis["final_score"]
        risk_level = classify_risk(final_score)
        
        # 3. Log results to MongoDB
        try:
            d = request.domain
            now = datetime.now(timezone.utc)
            log_entry = {
                "domain": d.hostname,
                "full_url": request.fullURL or d.fullURL,
                "confidence": analysis["confidence"],
                "final_risk_score": final_score,
                "risk_level": risk_level,
                "reasons": analysis["reasons"],
                "engine_scores": analysis["layer_scores"],
                "explainability": analysis["explainability"],
                "network_requests": raw_payload.get("network_requests", []),
                "timestamp": now,
            }
            await db.scan_logs.insert_one(log_entry)
            await db.risk_history.insert_one({
                "domain": d.hostname,
                "risk_score": final_score,
                "risk_level": risk_level,
                "layer_scores": analysis["layer_scores"],
                "timestamp": now,
            })
        except Exception as e:
            logger.error(f"Log failed: {e}")

        return AnalyzeResponse(
            risk_score=final_score,
            risk_level=risk_level,
            reasons=analysis["reasons"],
            confidence=analysis["confidence"],
            engine_scores=analysis["layer_scores"],
            explainability=analysis["explainability"]
        )

    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        return AnalyzeResponse(
            risk_score=0,
            risk_level="Safe",
            reasons=["Internal ML analysis failure"],
            confidence=0.0
        )
