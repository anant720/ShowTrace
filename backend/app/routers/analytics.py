import logging
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.dependencies import get_database, require_analyst

logger = logging.getLogger("shadowtrace.routers.analytics")
router = APIRouter(prefix="/analytics", tags=["Analytics"])

@router.get("/summary")
async def get_summary(db: AsyncIOMotorDatabase = Depends(get_database), _user: dict = Depends(require_analyst)):
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = today_start - timedelta(days=1)
    
    total_scans = await db.scan_logs.count_documents({})
    scans_today = await db.scan_logs.count_documents({"timestamp": {"$gte": today_start}})
    scans_yesterday = await db.scan_logs.count_documents({"timestamp": {"$gte": yesterday_start, "$lt": today_start}})

    risk_dist = {}
    async for doc in db.scan_logs.aggregate([{"$group": {"_id": "$risk_level", "count": {"$sum": 1}}}]):
        if doc["_id"]: risk_dist[doc["_id"]] = doc["count"]

    growth = 0
    if scans_yesterday > 0: growth = round(((scans_today - scans_yesterday) / scans_yesterday) * 100, 1)

    return {
        "total_scans": total_scans,
        "scans_today": scans_today,
        "growth_rate": growth,
        "risk_distribution": risk_dist,
        "total_reports": await db.reports.count_documents({}),
        "reports_today": await db.reports.count_documents({"timestamp": {"$gte": today_start}}),
        "active_anomalies": await db.anomalies.count_documents({"acknowledged": False}),
        "unique_domains": len(await db.scan_logs.distinct("domain")),
    }

@router.get("/trends")
async def get_trends(days: int = 30, db: AsyncIOMotorDatabase = Depends(get_database), _user: dict = Depends(require_analyst)):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    pipeline = [
        {"$match": {"timestamp": {"$gte": cutoff}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
            "total_scans": {"$sum": 1},
            "avg_risk": {"$avg": "$final_risk_score"},
        }},
        {"$sort": {"_id": 1}},
    ]
    trends = []
    async for doc in db.scan_logs.aggregate(pipeline):
        trends.append({"date": doc["_id"], "total_scans": doc["total_scans"], "avg_risk": round(doc["avg_risk"], 1)})
    return {"days": days, "trends": trends}

@router.get("/top-domains")
async def get_top_domains(limit: int = 20, days: int = 7, db: AsyncIOMotorDatabase = Depends(get_database), _user: dict = Depends(require_analyst)):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    pipeline = [
        {"$match": {"timestamp": {"$gte": cutoff}}},
        {"$group": {
            "_id": "$domain",
            "avg_score": {"$avg": "$final_risk_score"},
            "scan_count": {"$sum": 1},
            "last_scan": {"$max": "$timestamp"},
            "risk_levels": {"$push": "$risk_level"},
        }},
        {"$sort": {"avg_score": -1}},
        {"$limit": limit},
    ]
    domains = []
    async for doc in db.scan_logs.aggregate(pipeline):
        from collections import Counter
        domains.append({
            "domain": doc["_id"],
            "avg_score": round(doc["avg_score"], 1),
            "scan_count": doc["scan_count"],
            "last_scan": doc["last_scan"].isoformat(),
            "risk_breakdown": dict(Counter(doc["risk_levels"]))
        })
    return {"domains": domains}

@router.get("/anomalies")
async def get_anomalies(limit: int = 50, db: AsyncIOMotorDatabase = Depends(get_database), _user: dict = Depends(require_analyst)):
    cursor = db.anomalies.find({}).sort("detected_at", -1).limit(limit)
    anomalies = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        if "detected_at" in doc: doc["detected_at"] = doc["detected_at"].isoformat()
        anomalies.append(doc)
    return {"anomalies": anomalies}

@router.post("/anomalies/{anomaly_id}/acknowledge")
async def acknowledge_anomaly(anomaly_id: str, db: AsyncIOMotorDatabase = Depends(get_database), _user: dict = Depends(require_analyst)):
    from bson import ObjectId
    await db.anomalies.update_one({"_id": ObjectId(anomaly_id)}, {"$set": {"acknowledged": True}})
    return {"status": "ok"}

@router.get("/tld-distribution")
async def get_tld_dist(days: int = 30, db: AsyncIOMotorDatabase = Depends(get_database), _user: dict = Depends(require_analyst)):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    pipeline = [
        {"$match": {"timestamp": {"$gte": cutoff}}},
        {"$project": {"tld": {"$arrayElemAt": [{"$split": ["$domain", "."]}, -1]}}},
        {"$group": {"_id": "$tld", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    tlds = []
    async for doc in db.scan_logs.aggregate(pipeline):
        tlds.append({"tld": "."+doc["_id"], "suspicious_scans": doc["count"]})
    return {"tlds": tlds}

@router.get("/engine-breakdown")
async def get_engine_breakdown(db: AsyncIOMotorDatabase = Depends(get_database), _user: dict = Depends(require_analyst)):
    pipeline = [
        {"$match": {"engine_scores": {"$exists": True}}},
        {"$group": {
            "_id": None,
            "sim": {"$avg": "$engine_scores.domain_similarity.score"},
            "beh": {"$avg": "$engine_scores.behavioral.score"},
            "ssl": {"$avg": "$engine_scores.ssl_protocol.score"},
            "int": {"$avg": "$engine_scores.threat_intel.score"},
        }}
    ]
    res = None
    async for doc in db.scan_logs.aggregate(pipeline): res = doc
    if not res: return {"engines": {}}
    return {"engines": {
        "similarity": {"avg_score": round(res["sim"] or 0, 1), "max_score": 30, "weight": "30%"},
        "behavioral": {"avg_score": round(res["beh"] or 0, 1), "max_score": 30, "weight": "30%"},
        "ssl": {"avg_score": round(res["ssl"] or 0, 1), "max_score": 10, "weight": "10%"},
        "intel": {"avg_score": round(res["int"] or 0, 1), "max_score": 30, "weight": "30%"}
    }}
