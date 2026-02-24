import logging
from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from app.dependencies import get_database, require_admin, get_current_org_id, get_current_admin
from app.models.schemas import (
    OrganizationCreate, OrganizationResponse,
    InvitationCreate, InvitationResponse, Member
)

logger = logging.getLogger("shadowtrace.routers.organizations")
router = APIRouter(prefix="/organizations", tags=["Organization Management"])

@router.get("/", response_model=List[OrganizationResponse])
async def list_my_orgs(
    db: AsyncIOMotorDatabase = Depends(get_database),
    user: dict = Depends(get_current_admin)
):
    """
    List all organizations the current user is a member of.
    """
    user_email = user.get("email")
    user_record = await db.admin_users.find_one({"email": user_email})
    
    if not user_record:
        return []

    user_id = str(user_record["_id"])
    
    # 1. Primary Org
    primary_org_id = user_record.get("org_id", "community")
    org_ids = {primary_org_id}
    
    # 2. Other memberships
    memberships = await db.memberships.find({
        "user_id": user_id
    }).to_list(length=100)
    
    for m in memberships:
        org_ids.add(m["org_id"])
    
    # 3. Fetch Org details
    org_list = []
    for oid in org_ids:
        if oid == "community":
            org_list.append({
                "id": "community",
                "name": "Community",
                "slug": "community",
                "subscription_tier": "community",
                "created_at": datetime.min
            })
            continue
            
        try:
            org = await db.organizations.find_one({"_id": ObjectId(oid)})
            if org:
                org["id"] = str(org["_id"])
                org_list.append(org)
        except:
            continue
            
    return org_list

@router.post("/invite", status_code=status.HTTP_201_CREATED)
async def invite_member(
    request: InvitationCreate,
    db: AsyncIOMotorDatabase = Depends(get_database),
    org_id: str = Depends(get_current_org_id),
    _admin: dict = Depends(require_admin)
):
    """
    Invite a new member to the current organization.
    """
    if org_id == "community":
        raise HTTPException(status_code=400, detail="Cannot invite to community org")
        
    import secrets
    from datetime import timedelta
    
    token = secrets.token_urlsafe(32)
    invitation = {
        "email": request.email,
        "role": request.role,
        "org_id": org_id,
        "token": token,
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7)
    }
    
    try:
        await db.invitations.insert_one(invitation)
    except:
        raise HTTPException(status_code=400, detail="User already invited to this organization")
        
    # In a real app, we would send an email here.
    return {"status": "success", "invite_token": token}

@router.get("/members", response_model=List[Member])
async def list_members(
    db: AsyncIOMotorDatabase = Depends(get_database),
    org_id: str = Depends(get_current_org_id),
    _user: dict = Depends(require_admin)
):
    """
    List all members of the current organization.
    """
    if org_id == "community":
        return []
        
    # Get primary users
    primary_users = await db.admin_users.find({"org_id": org_id}).to_list(length=500)
    members = []
    for u in primary_users:
        members.append({
            "user_id": str(u["_id"]),
            "email": u["email"],
            "role": u.get("role", "member"),
            "joined_at": u.get("created_at", datetime.now(timezone.utc))
        })
        
    # Get secondary members via memberships
    secondary_memberships = await db.memberships.find({"org_id": org_id}).to_list(length=500)
    for m in secondary_memberships:
        u = await db.admin_users.find_one({"_id": ObjectId(m["user_id"])})
        if u:
             members.append({
                "user_id": str(u["_id"]),
                "email": u["email"],
                "role": m.get("role", "member"),
                "joined_at": m.get("created_at", datetime.now(timezone.utc))
            })
            
    return members

@router.get("/invitations", response_model=List[InvitationResponse])
async def list_invitations(
    db: AsyncIOMotorDatabase = Depends(get_database),
    org_id: str = Depends(get_current_org_id),
    _user: dict = Depends(require_admin)
):
    """
    List all pending invitations for the current organization.
    """
    if org_id == "community":
        return []
        
    invites = await db.invitations.find({"org_id": org_id}).to_list(length=100)
    for invite in invites:
        invite["id"] = str(invite["_id"])
        
    return invites


# ── Member Key (Extension Integration) ──────────────────────────────────────
@router.post("/member-key", summary="Generate an extension key for a member")
async def generate_member_key(
    email: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
    org_id: str = Depends(get_current_org_id),
    _admin: dict = Depends(require_admin)
):
    """
    Admin generates a unique key for a specific user's email.
    The user pastes this key into the extension settings once.
    From that point on, all their scans are attributed to this org.
    """
    if org_id == "community":
        raise HTTPException(status_code=400, detail="Community org does not support member keys")

    import secrets
    key = "st_mk_" + secrets.token_urlsafe(32)

    await db.member_keys.update_one(
        {"org_id": org_id, "email": email},
        {"$set": {
            "org_id": org_id,
            "email": email,
            "key": key,
            "created_at": datetime.now(timezone.utc),
            "active": True
        }},
        upsert=True
    )

    return {
        "member_key": key,
        "email": email,
        "org_id": org_id,
        "instructions": (
            "Share this key with the member. They should paste it in "
            "the ShadowTrace extension → Settings → Organization Key."
        )
    }


@router.get("/activate/{key}", summary="Validate a member key (called by extension)")
async def activate_member_key(
    key: str,
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    The extension calls this once after the user pastes their key.
    Returns the org context so the extension can display org name.
    Exempt from auth middleware — this IS the auth step.
    """
    record = await db.member_keys.find_one({"key": key, "active": True})
    if not record:
        raise HTTPException(status_code=404, detail="Invalid or revoked member key")

    # Fetch org name for display
    try:
        org = await db.organizations.find_one({"_id": ObjectId(record["org_id"])})
        org_name = org.get("name", "Unknown Org") if org else "Unknown Org"
    except Exception:
        org_name = "Unknown Org"

    return {
        "valid": True,
        "org_id": record["org_id"],
        "org_name": org_name,
        "email": record["email"]
    }
