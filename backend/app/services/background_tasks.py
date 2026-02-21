import asyncio
import logging
from app.config import settings
from app.ml.anomaly_detector import AnomalyDetector

logger = logging.getLogger("shadowtrace.services.background_tasks")
_task = None

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
            logger.error(f"Task failed: {e}")
        await asyncio.sleep(interval)

def start_background_tasks(db):
    global _task
    _task = asyncio.create_task(anomaly_detection_loop(db))

async def stop_background_tasks():
    global _task
    if _task and not _task.done():
        _task.cancel()
        try: await _task
        except asyncio.CancelledError: pass
