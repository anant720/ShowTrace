"""
ShadowTrace — Analyze Router
POST /analyze
"""

import logging
from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.dependencies import get_database, verify_api_key
from app.models.schemas import AnalyzeRequest, AnalyzeResponse
from app.services import risk_scorer

logger = logging.getLogger("shadowtrace.routers.analyze")
router = APIRouter(tags=["Analysis"])


@router.post("/analyze", response_model=AnalyzeResponse, summary="Analyze page signals for phishing risk")
async def analyze_page(
    request: AnalyzeRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
    _api_key: str = Depends(verify_api_key),
) -> AnalyzeResponse:
    logger.info(f"Analyzing domain: {request.domain.hostname}")
    return await risk_scorer.evaluate(request, db)
