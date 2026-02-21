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


class MetaInfo(BaseModel):
    extensionVersion: Optional[str] = None
    userAgent: Optional[str] = Field(default=None, max_length=512)


class AnalyzeRequest(BaseModel):
    timestamp: Optional[str] = None
    domain: DomainSignals
    forms: Optional[FormSignals] = Field(default_factory=FormSignals)
    behavior: Optional[BehaviorSignals] = Field(default_factory=BehaviorSignals)
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

    @field_validator("domain")
    @classmethod
    def sanitize_domain(cls, v: str) -> str:
        return v.strip().lower()


# ── Response Models ──────────────────────────────────────────────────

class AnalyzeResponse(BaseModel):
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str = Field(...)  # Safe / Suspicious / Dangerous
    reasons: List[str] = Field(default_factory=list)
    engine_scores: Optional[dict] = None


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
