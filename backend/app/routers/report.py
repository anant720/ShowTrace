"""
ShadowTrace — Report Router
POST /report
"""

import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.dependencies import get_database, verify_api_key
from app.models.schemas import ReportRequest, ReportResponse

logger = logging.getLogger("shadowtrace.routers.report")
router = APIRouter(tags=["Reporting"])


@router.post("/report", response_model=ReportResponse, summary="Report a suspicious domain")
async def report_domain(
    request: ReportRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
    _api_key: str = Depends(verify_api_key),
) -> ReportResponse:
    logger.info(f"Received report for domain: {request.domain}")

    # Insert report
    await db.reports.insert_one({
        "domain": request.domain,
        "reason": request.reason,
        "timestamp": datetime.now(timezone.utc),
    })

    # Count reports
    report_count = await db.reports.count_documents({"domain": request.domain})

    # Auto-promote after 3 reports
    if report_count >= 3:
        existing = await db.malicious_domains.find_one({"domain": request.domain})
        if not existing:
            await db.malicious_domains.insert_one({
                "domain": request.domain,
                "source": "user_reports",
                "threat_level": "medium",
                "detected_at": datetime.now(timezone.utc),
            })
            logger.info(f"Domain {request.domain} promoted to malicious_domains")
            return ReportResponse(
                status="reported",
                message=f"Domain reported and flagged as malicious ({report_count} reports total)",
            )

    return ReportResponse(
        status="reported",
        message=f"Report logged successfully ({report_count} report(s) for this domain)",
    )
