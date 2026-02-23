import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.dependencies import get_database, require_analyst
from app.models.schemas import CorrectionRequest

logger = logging.getLogger("shadowtrace.routers.feedback")
router = APIRouter(prefix="/feedback", tags=["Continuous Learning"])

@router.post("/correct", summary="Submit analyst correction for ML model refinement")
async def submit_correction(
    request: CorrectionRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
    _user: dict = Depends(require_analyst)
):
    """
    Records an analyst's manual label for a domain to retrain the model.
    This feedback loop prevents model drift and reduces false positives.
    """
    logger.info(f"Analyst correction received for {request.domain}: {request.actual_risk}")
    
    # 1. Store in feedback collection for retraining
    feedback_entry = {
        "domain": request.domain,
        "actual_risk": request.actual_risk,
        "analyst_notes": request.analyst_notes,
        "submitted_by": _user.get("username"),
        "timestamp": datetime.now(timezone.utc),
        "processed": False
    }
    
    await db.model_feedback.insert_one(feedback_entry)
    
    # 2. Proactively update whitelist/blacklist if needed
    if request.actual_risk == "Safe":
        await db.trusted_domains.update_one(
            {"domain": request.domain},
            {"$set": {"manual_override": True, "source": "analyst_feedback"}},
            upsert=True
        )
    
    return {"status": "ok", "message": "Feedback recorded for next training cycle."}

@router.get("/pending", summary="Get un-processed feedback items")
async def get_pending_feedback(
    db: AsyncIOMotorDatabase = Depends(get_database),
    _user: dict = Depends(require_analyst)
):
    cursor = db.model_feedback.find({"processed": False}).sort("timestamp", -1)
    results = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        results.append(doc)
    return {"feedback": results}
