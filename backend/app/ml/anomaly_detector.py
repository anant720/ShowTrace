import logging
import math
from datetime import datetime, timezone, timedelta
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.config import settings

logger = logging.getLogger("shadowtrace.ml.anomaly_detector")

class AnomalyDetector:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.zscore_threshold = settings.ANOMALY_ZSCORE_THRESHOLD

    async def run_full_scan(self):
        results = []
        try: results.extend(await self._detect_zscore_anomalies())
        except Exception as e: logger.error(f"Z-score failed: {e}")
        try: results.extend(await self._detect_volume_spikes())
        except Exception as e: logger.error(f"Spike failed: {e}")
        try: results.extend(await self._detect_domain_clusters())
        except Exception as e: logger.error(f"Cluster failed: {e}")

        one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
        stored = 0
        for anomaly in results:
            existing = await self.db.anomalies.find_one({
                "type": anomaly["type"],
                "domain": anomaly.get("domain", ""),
                "detected_at": {"$gte": one_hour_ago},
            })
            if not existing:
                anomaly["acknowledged"] = False
                anomaly["detected_at"] = datetime.now(timezone.utc)
                await self.db.anomalies.insert_one(anomaly)
                stored += 1
        return stored

    async def _detect_zscore_anomalies(self) -> list:
        anomalies = []
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        pipeline = [
            {"$match": {"timestamp": {"$gte": cutoff}}},
            {"$group": {
                "_id": None,
                "global_avg": {"$avg": "$final_risk_score"},
                "scores": {"$push": "$final_risk_score"},
            }},
        ]
        stats = None
        async for doc in self.db.scan_logs.aggregate(pipeline): stats = doc
        if not stats or not stats["scores"]: return anomalies

        mean = stats["global_avg"]
        variance = sum((s - mean) ** 2 for s in stats["scores"]) / len(stats["scores"])
        std_dev = math.sqrt(variance) if variance > 0 else 1.0

        domain_pipeline = [
            {"$match": {"timestamp": {"$gte": cutoff}}},
            {"$group": {"_id": "$domain", "avg": {"$avg": "$final_risk_score"}, "count": {"$sum": 1}}},
        ]
        async for doc in self.db.scan_logs.aggregate(domain_pipeline):
            z = (doc["avg"] - mean) / std_dev
            if z > self.zscore_threshold:
                anomalies.append({
                    "type": "zscore",
                    "severity": "high" if z > 3 else "medium",
                    "domain": doc["_id"],
                    "details": f"Risk deviation: {z:.1f}σ",
                    "metadata": {"z": round(z, 2), "avg": round(doc["avg"], 1)}
                })
        return anomalies

    async def _detect_volume_spikes(self) -> list:
        anomalies = []
        now = datetime.now(timezone.utc)
        hour_start = now.replace(minute=0, second=0, microsecond=0)
        current = await self.db.scan_logs.count_documents({"timestamp": {"$gte": hour_start}})
        total_24h = await self.db.scan_logs.count_documents({"timestamp": {"$gte": now - timedelta(hours=24)}})
        avg = total_24h / 24

        if avg > 0 and current > max(avg * 3, 10):
            anomalies.append({
                "type": "spike",
                "severity": "high" if (current / avg) > 5 else "medium",
                "details": f"Volume spike: {current} scans/hr (avg: {avg:.1f})",
                "metadata": {"current": current, "avg": round(avg, 1)}
            })
        return anomalies

    async def _detect_domain_clusters(self) -> list:
        anomalies = []
        cutoff = datetime.now(timezone.utc) - timedelta(hours=6)
        pipeline = [
            {"$match": {"timestamp": {"$gte": cutoff}, "final_risk_score": {"$gte": 60}}},
            {"$group": {"_id": "$domain", "count": {"$sum": 1}}},
        ]
        risky = []
        async for doc in self.db.scan_logs.aggregate(pipeline): risky.append(doc["_id"])
        
        from collections import Counter
        tlds = Counter(d.split(".")[-1] for d in risky if "." in d)
        for tld, count in tlds.items():
            if count >= 3:
                anomalies.append({
                    "type": "cluster",
                    "severity": "high" if count >= 5 else "medium",
                    "domain": f"*.{tld}",
                    "details": f"Cluster: {count} risky domains in .{tld}",
                    "metadata": {"tld": tld, "count": count}
                })
        return anomalies
