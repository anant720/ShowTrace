import asyncio
import logging
from app.config import settings
from app.services.device_integrity import recompute_all_devices
from app.ml.anomaly_detector import AnomalyDetector
from app.ml.trainer import EnterpriseTrainer
from app.services.retention_service import retention_scheduler

logger = logging.getLogger("shadowtrace.services.background_tasks")
_tasks = []

async def anomaly_detection_loop(db):
    interval = settings.ANOMALY_INTERVAL_MINUTES * 60
    detector = AnomalyDetector(db)
    await asyncio.sleep(30)
    while True:
        try:
            await detector.run_full_scan()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Anomaly task failed: {e}")
        await asyncio.sleep(interval)

async def continuous_learning_loop(db):
    """
    Autonomous Retraining Scheduler
    Checks for analyst feedback and updates the ensemble models.
    Also monitors for model drift.
    """
    from app.ml.drift_monitor import ModelDriftMonitor
    trainer = EnterpriseTrainer()
    drift_monitor = ModelDriftMonitor(db)
    
    while True:
        try:
            # 1. Check for Model Drift
            drift_status = await drift_monitor.check_drift(sample_size=100)
            if drift_status.get("has_drift"):
                logger.warning("Model drift detected. Initiating emergency recalibration...")
                trainer.train_all()
                logger.info("Recalibration complete.")

            # 2. Check for Analyst Feedback
            count = await db.model_feedback.count_documents({"processed": False})
            if count >= 10: # Threshold for autonomous retraining
                logger.info(f"Retraining triggered: {count} new feedback items detected")
                trainer.train_all()
                await db.model_feedback.update_many({"processed": False}, {"$set": {"processed": True}})
                logger.info("Retraining complete. New model weights deployed.")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Learning loop failure: {e}")
        
        await asyncio.sleep(3600) # Check hourly


async def integrity_maintenance_loop(db):
    """
    Nightly integrity maintenance:
      - Recompute device integrity snapshots
      - Ensure silent / offline devices are reflected in dashboards
      - Leverage TTL indexes for nonce expiry (no manual work required)
    """
    # Stagger initial run
    await asyncio.sleep(60)
    while True:
        try:
            await recompute_all_devices(db)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Integrity maintenance task failed: {e}")
        # Run once per 24 hours
        await asyncio.sleep(86400)

def start_background_tasks(db):
    global _tasks
    _tasks.append(asyncio.create_task(anomaly_detection_loop(db)))
    _tasks.append(asyncio.create_task(continuous_learning_loop(db)))
    _tasks.append(asyncio.create_task(retention_scheduler(db)))
    _tasks.append(asyncio.create_task(integrity_maintenance_loop(db)))

async def stop_background_tasks():
    global _tasks
    for t in _tasks:
        if not t.done():
            t.cancel()
    if _tasks:
        await asyncio.gather(*_tasks, return_exceptions=True)
    _tasks = []
