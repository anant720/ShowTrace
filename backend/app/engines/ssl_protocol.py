from motor.motor_asyncio import AsyncIOMotorDatabase
from app.engines.base import EngineResult
from app.models.schemas import AnalyzeRequest

async def analyze(request: AnalyzeRequest, db: AsyncIOMotorDatabase) -> EngineResult:
    score = 0.0
    reasons = []
    
    if not request.domain.isHTTPS:
        score += 10.0
        reasons.append("Page served over insecure HTTP")
    
    if request.domain.isIPBased:
        score += 10.0
        reasons.append("URL uses raw IP instead of domain")

    return EngineResult(engine_name="ssl_protocol", score=min(score, 10.0), max_score=10.0, reasons=reasons)
