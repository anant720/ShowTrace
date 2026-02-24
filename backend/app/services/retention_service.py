"""
ShadowTrace — Tiered Retention Service
Prunes scan logs based on organization subscription tiers.
"""

import logging
import asyncio
from datetime import datetime, timedelta, timezone
from motor.motor_asyncio import AsyncIOMotorDatabase

# Inline tier limits (app/config/ directory was removed to fix package conflict)
TIER_LIMITS = {
    "community": {"retention_days": 7},
    "pro":       {"retention_days": 90},
    "enterprise":{"retention_days": 365},
    "guardian":  {"retention_days": -1},  # -1 = permanent
}

logger = logging.getLogger("shadowtrace.services.retention")

async def run_retention_policy(db: AsyncIOMotorDatabase):
    """
    Periodic task to delete logs exceeding tier-based retention limits.
    """
    logger.info("Starting tiered retention pruning cycle...")
    
    try:
        # Get all organizations
        orgs = await db.organizations.find().to_list(length=1000)
        
        # Add community org (it's implicit but its logs are tagged)
        orgs.append({"_id": "community", "subscription_tier": "community"})
        
        for org in orgs:
            org_id = str(org["_id"])
            tier = org.get("subscription_tier", "community")
            
            # Get retention limit for this tier
            limit_days = TIER_LIMITS.get(tier, TIER_LIMITS["community"])["retention_days"]
            
            if limit_days == -1:
                # Unlimited retention for enterprise
                continue
                
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=limit_days)
            
            # Delete old logs for this org
            result = await db.scan_logs.delete_many({
                "org_id": org_id,
                "timestamp": {"$lt": cutoff_date}
            })
            
            if result.deleted_count > 0:
                logger.info(f"Pruned {result.deleted_count} logs for Org {org_id} (Tier: {tier}, Retention: {limit_days} days)")
                
    except Exception as e:
        logger.error(f"Retention policy execution failed: {e}")

async def retention_scheduler(db: AsyncIOMotorDatabase):
    """
    Runs the retention policy every 24 hours.
    """
    while True:
        await run_retention_policy(db)
        # Sleep for 24 hours
        await asyncio.sleep(24 * 3600)
