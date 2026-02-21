from motor.motor_asyncio import AsyncIOMotorDatabase
from app.engines.base import EngineResult
from app.models.schemas import AnalyzeRequest

async def analyze(request: AnalyzeRequest, db: AsyncIOMotorDatabase) -> EngineResult:
    score = 0.0
    reasons = []
    hostname = request.domain.hostname

    malicious = await db.malicious_domains.find_one({"domain": hostname})
    if malicious:
        score += 30.0
        reasons.append("Match found in global threat database")

    reports_count = await db.reports.count_documents({"domain": hostname})
    if reports_count >= 5:
        score += 20.0
        reasons.append(f"Community flagged this domain ({reports_count} reports)")
    elif reports_count > 0:
        score += 10.0
        reasons.append("Domain has active user-submitted reports")

    return EngineResult(engine_name="threat_intel", score=min(score, 30.0), max_score=30.0, reasons=reasons)
