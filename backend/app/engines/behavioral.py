from motor.motor_asyncio import AsyncIOMotorDatabase
from app.engines.base import EngineResult
from app.models.schemas import AnalyzeRequest

async def analyze(request: AnalyzeRequest, db: AsyncIOMotorDatabase) -> EngineResult:
    score = 0.0
    reasons = []
    behavior = request.behavior

    if behavior.externalFetchDetected:
        score += 20.0
        reasons.append("JavaScript cross-domain fetch detected")
    
    if behavior.externalXHRDetected:
        score += 15.0
        reasons.append("JavaScript cross-domain XHR detected")

    if behavior.suspiciousSubmissions:
        cred_bearing = [s for s in behavior.suspiciousSubmissions if s.get("type") == "credential_bearing"]
        if cred_bearing:
            score += 30.0
            reasons.append(f"Credential-bearing request to external domain")

    return EngineResult(engine_name="behavioral", score=min(score, 30.0), max_score=30.0, reasons=reasons)
