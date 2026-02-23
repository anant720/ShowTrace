import logging
import numpy as np
from datetime import datetime, timedelta, timezone
from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger("shadowtrace.ml.drift")

class ModelDriftMonitor:
    """
    ShadowTrace Model Drift Monitor.
    Detects if the live model's prediction distribution deviates significantly
    from the expected baseline, signaling a need for retraining or recalibration.
    """
    
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        # Expected baseline distribution (Safe/Suspicious/Dangerous)
        # These would ideally be derived from the training set distribution
        self.baseline = {
            "Safe": 0.85,
            "Suspicious": 0.10,
            "Dangerous": 0.05
        }
        self.threshold = 0.15 # Max 15% divergence before alert

    async def check_drift(self, sample_size: int = 100) -> dict:
        """
        Analyzes the last N scans to check for distribution drift.
        """
        try:
            cursor = self.db.scan_logs.find().sort("timestamp", -1).limit(sample_size)
            logs = await cursor.to_list(length=sample_size)
            
            if len(logs) < sample_size // 2:
                return {"status": "insufficient_data", "samples": len(logs)}

            # Count distributions
            counts = {"Safe": 0, "Suspicious": 0, "Dangerous": 0}
            for log in logs:
                level = log.get("risk_level", "Safe")
                if level in counts:
                    counts[level] += 1
            
            total = sum(counts.values())
            distribution = {k: v/total for k, v in counts.items()}
            
            # Calculate divergence (Mean Absolute Error)
            divergence = sum(abs(distribution[k] - self.baseline[k]) for k in self.baseline) / len(self.baseline)
            
            has_drift = divergence > self.threshold
            
            result = {
                "status": "monitored",
                "divergence": round(divergence, 3),
                "has_drift": has_drift,
                "current_distribution": distribution,
                "samples": total,
                "timestamp": datetime.now(timezone.utc)
            }
            
            if has_drift:
                logger.warning(f"Model Drift Detected! Divergence: {divergence}. Distribution: {distribution}")
                # Store drift event for dashboard/analyst
                await self.db.system_events.insert_one({
                    "type": "MODEL_DRIFT",
                    "severity": "high",
                    "details": result,
                    "timestamp": datetime.now(timezone.utc)
                })
            
            return result
            
        except Exception as e:
            logger.error(f"Drift check failed: {e}")
            return {"status": "error", "message": str(e)}
