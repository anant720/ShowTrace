"""
ShadowTrace Backend — Pydantic Request/Response Schemas

Input validation and response serialization models.
All external data passes through these schemas.
"""

from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
from datetime import datetime
import re


# ── Request Models ───────────────────────────────────────────────────

class DomainSignals(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=253)
    protocol: str = Field(default="https", max_length=10)
    isHTTPS: bool = False
    isIPBased: bool = False
    isPunycode: bool = False
    tld: str = Field(default="", max_length=20)
    isSuspiciousTLD: bool = False
    fullURL: Optional[str] = Field(default=None, max_length=2048)

    @field_validator("hostname")
    @classmethod
    def sanitize_hostname(cls, v: str) -> str:
        # Strip whitespace, lowercase, basic injection prevention
        v = v.strip().lower()
        if not re.match(r'^[a-z0-9\.\-\[\]:]+$', v) and not v.startswith("xn--"):
            # Allow punycode and standard hostnames only
            v = re.sub(r'[^a-z0-9\.\-\[\]:]', '', v)
        return v


class FormSignals(BaseModel):
    hasLoginForm: bool = False
    formCount: int = Field(default=0, ge=0, le=500)
    standalonePasswordFields: int = Field(default=0, ge=0)
    forms: Optional[List[dict]] = Field(default_factory=list)


class BehaviorSignals(BaseModel):
    externalFetchDetected: bool = False
    externalXHRDetected: bool = False
    suspiciousSubmissions: Optional[List[dict]] = Field(default_factory=list)


class MLBehaviorSignals(BaseModel):
    scriptCount: int = 0
    totalScriptSize: int = 0
    evalCount: int = 0
    largeHexCount: int = 0
    hasSuspiciousFunctions: bool = False


class InteractionSignals(BaseModel):
    inputCount: int = 0
    suspiciousHandlerCount: int = 0
    hasGlobalKeylogger: bool = False


class TrapSignals(BaseModel):
    hiddenFormCount: int = 0
    offscreenElementCount: int = 0


class NetworkRequest(BaseModel):
    id: str
    url: str
    method: str
    type: str
    timestamp: int
    headers: Optional[List[dict]] = Field(default_factory=list)
    responseHeaders: Optional[List[dict]] = Field(default_factory=list)
    statusCode: Optional[int] = None


class MetaInfo(BaseModel):
    extensionVersion: Optional[str] = None
    userAgent: Optional[str] = Field(default=None, max_length=512)


class AnalyzeRequest(BaseModel):
    timestamp: Optional[str] = None
    fullURL: Optional[str] = None
    domain: DomainSignals
    forms: Optional[FormSignals] = Field(default_factory=FormSignals)
    behavior: Optional[BehaviorSignals] = Field(default_factory=BehaviorSignals)
    ml_behavior: Optional[MLBehaviorSignals] = Field(default_factory=MLBehaviorSignals)
    interaction: Optional[InteractionSignals] = Field(default_factory=InteractionSignals)
    traps: Optional[TrapSignals] = Field(default_factory=TrapSignals)
    network_requests: Optional[List[NetworkRequest]] = Field(default_factory=list)
    meta: Optional[MetaInfo] = None

    class Config:
        # Limit total request size via max content length in middleware
        json_schema_extra = {
            "example": {
                "domain": {
                    "hostname": "g00gle.com",
                    "protocol": "http",
                    "isHTTPS": False,
                    "isIPBased": False,
                    "isPunycode": False,
                    "tld": "com",
                    "isSuspiciousTLD": False,
                },
                "forms": {
                    "hasLoginForm": True,
                    "formCount": 1,
                },
                "behavior": {
                    "externalFetchDetected": True,
                },
            }
        }


class ReportRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)
    reason: str = Field(..., min_length=1, max_length=1000)


class CorrectionRequest(BaseModel):
    domain: str
    actual_risk: str  # Safe / Dangerous
    analyst_notes: Optional[str] = None


# ── Response Models ──────────────────────────────────────────────────

class AnalyzeResponse(BaseModel):
    risk_score: float = Field(..., ge=0, le=100)
    risk_level: str = Field(...)  # Safe / Suspicious / Dangerous
    reasons: List[str] = Field(default_factory=list)
    confidence: float = 1.0
    engine_scores: Optional[dict] = None
    explainability: Optional[dict] = None
    security_score: Optional[float] = None
    security_findings: Optional[List[dict]] = Field(default_factory=list)
    source: Optional[str] = None


class ReportResponse(BaseModel):
    status: str
    message: str


class StatsResponse(BaseModel):
    total_scans: int
    scans_today: int
    risk_distribution: dict  # {"Safe": N, "Suspicious": N, "Dangerous": N}
    top_risky_domains: List[dict]
    recent_reports: int


class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
