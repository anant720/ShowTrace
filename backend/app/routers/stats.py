"""
ShadowTrace — Stats Router
GET /stats
"""

import logging
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.dependencies import get_database, verify_api_key
from app.models.schemas import StatsResponse

logger = logging.getLogger("shadowtrace.routers.stats")
router = APIRouter(tags=["Admin"])


@router.get("/stats", response_model=StatsResponse, summary="Get scan statistics")
async def get_stats(
    db: AsyncIOMotorDatabase = Depends(get_database),
    _api_key: str = Depends(verify_api_key),
) -> StatsResponse:
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    seven_days_ago = now - timedelta(days=7)
    one_day_ago = now - timedelta(hours=24)

    total_scans = await db.scan_logs.count_documents({})
    scans_today = await db.scan_logs.count_documents({"timestamp": {"$gte": today_start}})

    # Risk distribution
    pipeline_risk = [
        {"$group": {"_id": "$risk_level", "count": {"$sum": 1}}}
    ]
    risk_dist = {}
    async for doc in db.scan_logs.aggregate(pipeline_risk):
        if doc["_id"]:
            risk_dist[doc["_id"]] = doc["count"]

    # Top risky domains (last 7 days)
    pipeline_top = [
        {"$match": {"timestamp": {"$gte": seven_days_ago}}},
        {"$group": {
            "_id": "$domain",
            "avg_score": {"$avg": "$final_risk_score"},
            "scan_count": {"$sum": 1},
            "max_score": {"$max": "$final_risk_score"},
        }},
        {"$sort": {"avg_score": -1}},
        {"$limit": 10},
    ]
    top_risky = []
    async for doc in db.scan_logs.aggregate(pipeline_top):
        top_risky.append({
            "domain": doc["_id"],
            "avg_score": round(doc["avg_score"], 1),
            "scan_count": doc["scan_count"],
            "max_score": doc["max_score"],
        })

    recent_reports = await db.reports.count_documents({"timestamp": {"$gte": one_day_ago}})

    return StatsResponse(
        total_scans=total_scans,
        scans_today=scans_today,
        risk_distribution=risk_dist,
        top_risky_domains=top_risky,
        recent_reports=recent_reports,
    )
