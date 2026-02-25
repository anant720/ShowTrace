"""
ShadowTrace — Analyze Router
POST /analyze
"""

import logging
from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.dependencies import get_database, verify_api_key, get_current_org_id
from app.models.schemas import AnalyzeRequest, AnalyzeResponse
from app.services import risk_scorer

logger = logging.getLogger("shadowtrace.routers.analyze")
router = APIRouter(tags=["Analysis"])


@router.post("/analyze", response_model=AnalyzeResponse, summary="Analyze page signals for phishing risk")
async def analyze_url(
    request_data: dict,
    db: AsyncIOMotorDatabase = Depends(get_database),
    # ... other deps
    org_id: str = Depends(get_current_org_id),
) -> AnalyzeResponse:
    # Pass raw dict to evaluate for envelope parsing
    domain_hostname = request_data.get("domain", {}).get("hostname")
    logger.info(f"Analyzing domain: {domain_hostname} for Org: {org_id}")
    result = await risk_scorer.evaluate(request_data, db, org_id)
    return result
