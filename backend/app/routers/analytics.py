import logging
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.dependencies import get_database, require_analyst, get_current_org_id, get_current_user_email, build_org_query

logger = logging.getLogger("shadowtrace.routers.analytics")
router = APIRouter(prefix="/analytics", tags=["Analytics"])

@router.get("/summary")
async def get_summary(
    domain: str = Query(None), 
    db: AsyncIOMotorDatabase = Depends(get_database), 
    org_id: str = Depends(get_current_org_id),
    user_email: str = Depends(get_current_user_email),
    _user: dict = Depends(require_analyst)
):
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    
    match_query = build_org_query(org_id, user_email)
    if domain:
        match_query["domain"] = domain
    
    total_scans = await db.scan_logs.count_documents(match_query)
    scans_today = await db.scan_logs.count_documents({**match_query, "timestamp": {"$gte": today_start}})

    risk_dist = {}
    pipeline_risk = [
        {"$match": match_query},
        {"$group": {"_id": "$risk_level", "count": {"$sum": 1}}}
    ]
    async for doc in db.scan_logs.aggregate(pipeline_risk):
        if doc["_id"]: risk_dist[doc["_id"]] = doc["count"]

    yesterday_start = today_start - timedelta(days=1)
    scans_yesterday = await db.scan_logs.count_documents({**match_query, "timestamp": {"$gte": yesterday_start, "$lt": today_start}})
    
    growth = 0
    if scans_yesterday > 0: growth = round(((scans_today - scans_yesterday) / scans_yesterday) * 100, 1)

    return {
        "total_scans": total_scans,
        "scans_today": scans_today,
        "growth_rate": growth,
        "risk_distribution": risk_dist,
        "total_reports": await db.reports.count_documents(build_org_query(org_id, user_email)),
        "reports_today": await db.reports.count_documents({**build_org_query(org_id, user_email), "timestamp": {"$gte": today_start}}),
        "active_anomalies": await db.anomalies.count_documents({**build_org_query(org_id, user_email), "acknowledged": False}),
        "unique_domains": len(await db.scan_logs.distinct("domain", build_org_query(org_id, user_email))),
    }

@router.get("/trends")
async def get_trends(
    domain: str = Query(None), 
    days: int = 30, 
    db: AsyncIOMotorDatabase = Depends(get_database), 
    org_id: str = Depends(get_current_org_id),
    _user: dict = Depends(require_analyst)
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    match_stage = {"org_id": org_id, "timestamp": {"$gte": cutoff}}
    if domain: match_stage["domain"] = domain
    
    pipeline = [
        {"$match": match_stage},
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
async def get_top_domains(
    limit: int = 20, 
    days: int = 7, 
    db: AsyncIOMotorDatabase = Depends(get_database), 
    org_id: str = Depends(get_current_org_id),
    _user: dict = Depends(require_analyst)
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    pipeline = [
        {"$match": {"org_id": org_id, "timestamp": {"$gte": cutoff}}},
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
            "last_scan": doc["last_scan"].isoformat() if doc["last_scan"] else None,
            "risk_breakdown": dict(Counter(doc["risk_levels"]))
        })
    return {"domains": domains}

@router.get("/anomalies")
async def get_anomalies(
    limit: int = 50, 
    db: AsyncIOMotorDatabase = Depends(get_database), 
    org_id: str = Depends(get_current_org_id),
    _user: dict = Depends(require_analyst)
):
    cursor = db.anomalies.find({"org_id": org_id}).sort("detected_at", -1).limit(limit)
    anomalies = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        if "detected_at" in doc: doc["detected_at"] = doc["detected_at"].isoformat()
        anomalies.append(doc)
    return {"anomalies": anomalies}

@router.post("/anomalies/{anomaly_id}/acknowledge")
async def acknowledge_anomaly(
    anomaly_id: str, 
    db: AsyncIOMotorDatabase = Depends(get_database), 
    org_id: str = Depends(get_current_org_id),
    _user: dict = Depends(require_analyst)
):
    from bson import ObjectId
    await db.anomalies.update_one(
        {"_id": ObjectId(anomaly_id), "org_id": org_id}, 
        {"$set": {"acknowledged": True}}
    )
    return {"status": "ok"}

@router.get("/tld-distribution")
async def get_tld_dist(
    days: int = 30, 
    db: AsyncIOMotorDatabase = Depends(get_database), 
    org_id: str = Depends(get_current_org_id),
    _user: dict = Depends(require_analyst)
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    pipeline = [
        {"$match": {
            "org_id": org_id,
            "timestamp": {"$gte": cutoff},
            "risk_level": {"$in": ["Suspicious", "Dangerous"]}
        }},
        {"$project": {"tld": {"$arrayElemAt": [{"$split": ["$domain", "."]}, -1]}}},
        {"$group": {"_id": "$tld", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    tlds = []
    async for doc in db.scan_logs.aggregate(pipeline):
        tlds.append({"tld": "."+doc["_id"], "suspicious_scans": doc["count"]})
    return {"tlds": tlds}

@router.get("/recent-scans")
async def get_recent_scans(
    limit: int = 10, 
    db: AsyncIOMotorDatabase = Depends(get_database), 
    org_id: str = Depends(get_current_org_id),
    _user: dict = Depends(require_analyst)
):
    cursor = db.scan_logs.find({"org_id": org_id}).sort("timestamp", -1).limit(limit)
    scans = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        if "timestamp" in doc: doc["timestamp"] = doc["timestamp"].isoformat()
        scans.append(doc)
    return {"scans": scans}


@router.get("/engine-breakdown")
async def get_engine_breakdown(
    domain: str = Query(None), 
    db: AsyncIOMotorDatabase = Depends(get_database), 
    org_id: str = Depends(get_current_org_id),
    _user: dict = Depends(require_analyst)
):
    match_stage = {"org_id": org_id, "layer_scores": {"$exists": True}}
    if domain: match_stage["domain"] = domain
    
    pipeline = [
        {"$match": match_stage},
        {"$group": {
            "_id": None,
            "l1": {"$avg": "$layer_scores.L1"},
            "l2": {"$avg": "$layer_scores.L2"},
            "l3": {"$avg": "$layer_scores.L3"},
            "l4": {"$avg": "$layer_scores.L4"},
        }}
    ]
    res = None
    async for doc in db.scan_logs.aggregate(pipeline): res = doc
    if not res: return {"engines": {}}
    return {"engines": {
        "L1": {"avg_score": round(res["l1"] or 0, 1), "max_score": 100, "weight": "20%"},
        "L2": {"avg_score": round(res["l2"] or 0, 1), "max_score": 100, "weight": "30%"},
        "L3": {"avg_score": round(res["l3"] or 0, 1), "max_score": 100, "weight": "40%"},
        "L4": {"avg_score": round(res["l4"] or 0, 1), "max_score": 100, "weight": "10%"}
    }}

@router.get("/domain-posture/{domain}")
async def get_domain_posture(
    domain: str, 
    db: AsyncIOMotorDatabase = Depends(get_database), 
    org_id: str = Depends(get_current_org_id),
    _user: dict = Depends(require_analyst)
):
    # Get the latest scan for this specific domain (scoped to Org)
    doc = await db.scan_logs.find_one({"org_id": org_id, "domain": domain}, sort=[("timestamp", -1)])
    if not doc:
        return {"status": "no_data", "message": f"No scan data found for domain: {domain}"}
    
    return {
        "domain": doc["domain"],
        "security_score": doc.get("security_score", 0),
        "security_findings": doc.get("security_findings", []),
        "timestamp": doc["timestamp"].isoformat() if "timestamp" in doc else None,
        "engine_scores": doc.get("engine_scores", {})
    }
