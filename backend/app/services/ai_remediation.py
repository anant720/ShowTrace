"""
ShadowTrace — AI Triage & Autonomous Remediation
Automated risk decision orchestration for Enterprise+ (Guardian).
"""

import logging
from motor.motor_asyncio import AsyncIOMotorDatabase
from datetime import datetime, timezone


# Inline tier config (app/config/ directory was removed to fix package conflict)
_TIER_LIMITS = {
    "community":  {"features": {"autonomous_remediation": False}},
    "pro":        {"features": {"autonomous_remediation": False}},
    "enterprise": {"features": {"autonomous_remediation": True}},
    "guardian":   {"features": {"autonomous_remediation": True}},
}
def get_tier_config(tier: str) -> dict:
    return _TIER_LIMITS.get((tier or "community").lower(), _TIER_LIMITS["community"])
from app.routers.policies import update_org_policy
from app.models.schemas import PolicyUpdate

logger = logging.getLogger("shadowtrace.services.ai_remediation")

async def analyze_and_remediate(org_id: str, scan_result: dict, db: AsyncIOMotorDatabase):
    """
    Evaluates a scan result and automatically updates fleet policies if risk is critical.
    ONLY for Enterprise+ (Guardian) users with autonomous_remediation enabled.
    """
    # 1. Check Tier & Feature
    org = await db.organizations.find_one({"_id": scan_result.get("org_id")})
    if not org: return
    
    tier = org.get("subscription_tier", "community")
    tier_config = get_tier_config(tier)
    
    if not tier_config["features"].get("autonomous_remediation"):
        return

    # 2. Critical Risk Logic
    risk_score = scan_result.get("risk_score", 0)
    domain = scan_result.get("domain")
    
    if risk_score > 90:
        logger.warning(f"[AI TRIAGE] High-criticality threat detected: {domain}. Initiating auto-remediation.")
        
        # 3. Update Fleet Policy (Auto-Block)
        current_policy = await db.fleet_policies.find_one({"org_id": org_id})
        blocked = current_policy.get("blocked_domains", []) if current_policy else []
        
        if domain not in blocked:
            blocked.append(domain)
            await db.fleet_policies.update_one(
                {"org_id": org_id},
                {"$set": {
                    "blocked_domains": blocked,
                    "updated_at": datetime.now(timezone.utc)
                }},
                upsert=True
            )
            logger.info(f"[AI TRIAGE] Domain {domain} has been added to the fleet-wide block list for Org {org_id}.")
            
            # 4. Notify SIEM (Placeholder for Connector pipe)
            # await pipe_to_siem(org_id, {"event": "auto_block", "domain": domain}, db)

    elif risk_score > 75:
        # Medium-High: Add to watchlist or generate alert
        logger.info(f"[AI TRIAGE] Moderate threat detected ({domain}). Monitoring for repeat patterns.")
