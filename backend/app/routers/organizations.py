import logging
from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from app.dependencies import get_database, require_admin, get_current_org_id, get_current_admin
from app.models.schemas import (
    OrganizationCreate, OrganizationResponse,
    InvitationCreate, InvitationResponse, Member
)
from app.utils.audit import log_admin_action
from app.utils.rate_limiter import rate_limit_action
from app.services.mailer import send_email_sendgrid, MailerError
from app.config import settings

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
    http_request: Request,
    db: AsyncIOMotorDatabase = Depends(get_database),
    org_id: str = Depends(get_current_org_id),
    admin: dict = Depends(require_admin)
):
    """
    Invite a new member to the current organization.
    """
    if org_id == "community":
        raise HTTPException(status_code=400, detail="Cannot invite to community org")

    await rate_limit_action(http_request, "org.invite", limit=10, window_seconds=60)
        
    import secrets
    from datetime import timedelta
    
    token = secrets.token_urlsafe(32)
    invitation = {
        "email": request.email,
        "role": request.role,
        "org_id": org_id,
        "token": token,
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
        "email_status": "PENDING",
    }
    
    try:
        await db.invitations.insert_one(invitation)
    except:
        raise HTTPException(status_code=400, detail="User already invited to this organization")

    # Generate (or rotate) extension member key for this invitee
    member_key = "st_mk_" + secrets.token_urlsafe(32)
    await db.member_keys.update_one(
        {"org_id": org_id, "email": request.email},
        {"$set": {
            "org_id": org_id,
            "email": request.email,
            "key": member_key,
            "created_at": datetime.now(timezone.utc),
            "active": True
        }},
        upsert=True
    )

    # Fetch org name for email body
    org_doc = await db.organizations.find_one({"_id": ObjectId(org_id)})
    org_name = (org_doc or {}).get("name", "ShadowTrace Organization")

    dashboard_url = getattr(settings, "DASHBOARD_BASE_URL", "http://localhost:3000")
    invite_link = f"{dashboard_url}/login"

    subject = f"You’ve been invited to {org_name} on ShadowTrace"
    text = (
        f"You have been invited to ShadowTrace.\n\n"
        f"Organization: {org_name}\n"
        f"Role: {request.role}\n\n"
        f"Dashboard login: {invite_link}\n\n"
        f"Extension Member Key (paste into ShadowTrace extension → Settings → Organization Key):\n"
        f"{member_key}\n\n"
        f"Invite token (internal reference): {token}\n"
        f"This invite expires at: {invitation['expires_at'].isoformat()}\n"
    )
    html = (
        f"<p>You have been invited to <b>ShadowTrace</b>.</p>"
        f"<p><b>Organization:</b> {org_name}<br/>"
        f"<b>Role:</b> {request.role}</p>"
        f"<p><b>Dashboard login:</b> <a href=\"{invite_link}\">{invite_link}</a></p>"
        f"<p><b>Extension Member Key</b> (paste into ShadowTrace extension → Settings → Organization Key):</p>"
        f"<pre style=\"padding:12px;background:#f5f5f5;border-radius:8px;\">{member_key}</pre>"
        f"<p style=\"color:#666;font-size:12px;\">Invite token (internal reference): {token}<br/>"
        f"Expires: {invitation['expires_at'].isoformat()}</p>"
    )

    try:
        send_email_sendgrid(
            to_email=request.email,
            subject=subject,
            text=text,
            html=html,
        )
        await db.invitations.update_one(
            {"org_id": org_id, "email": request.email},
            {"$set": {"email_status": "SENT", "sent_at": datetime.now(timezone.utc)}},
        )
    except MailerError as e:
        await db.invitations.update_one(
            {"org_id": org_id, "email": request.email},
            {"$set": {"email_status": "FAILED", "email_error": str(e)}},
        )
        raise HTTPException(
            status_code=502,
            detail=f"Invitation created but email delivery failed: {e}",
        )

    await log_admin_action(
        db,
        http_request,
        org_id=org_id,
        actor=admin,
        action="org.invite",
        resource_type="invitation",
        resource_id=request.email,
        old_value=None,
        new_value={"email": request.email, "role": request.role},
        metadata={"email_status": "SENT"},
    )

    return {"status": "success", "invite_token": token, "member_key": member_key, "email_status": "SENT"}


@router.post("/invite/resend", summary="Resend invitation email (admin only)")
async def resend_invite(
    email: str,
    http_request: Request,
    db: AsyncIOMotorDatabase = Depends(get_database),
    org_id: str = Depends(get_current_org_id),
    admin: dict = Depends(require_admin),
):
    await rate_limit_action(http_request, "org.invite.resend", limit=10, window_seconds=60)

    invite = await db.invitations.find_one({"org_id": org_id, "email": email})
    if not invite:
        raise HTTPException(status_code=404, detail="Invitation not found")

    mk = await db.member_keys.find_one({"org_id": org_id, "email": email, "active": True})
    if not mk:
        raise HTTPException(status_code=400, detail="No active member key exists for this email")

    org_doc = await db.organizations.find_one({"_id": ObjectId(org_id)})
    org_name = (org_doc or {}).get("name", "ShadowTrace Organization")
    dashboard_url = getattr(settings, "DASHBOARD_BASE_URL", "http://localhost:3000")
    invite_link = f"{dashboard_url}/login"

    subject = f"ShadowTrace invite for {org_name} (resend)"
    text = (
        f"Resent invitation to ShadowTrace.\n\n"
        f"Organization: {org_name}\n"
        f"Role: {invite.get('role')}\n\n"
        f"Dashboard login: {invite_link}\n\n"
        f"Extension Member Key:\n{mk['key']}\n\n"
        f"Invite token (internal reference): {invite.get('token')}\n"
        f"Expires: {invite.get('expires_at')}\n"
    )

    try:
        send_email_sendgrid(to_email=email, subject=subject, text=text)
        await db.invitations.update_one(
            {"_id": invite["_id"]},
            {"$set": {"email_status": "SENT", "resent_at": datetime.now(timezone.utc)}},
        )
    except MailerError as e:
        await db.invitations.update_one(
            {"_id": invite["_id"]},
            {"$set": {"email_status": "FAILED", "email_error": str(e)}},
        )
        raise HTTPException(status_code=502, detail=f"Email delivery failed: {e}")

    await log_admin_action(
        db,
        http_request,
        org_id=org_id,
        actor=admin,
        action="org.invite.resend",
        resource_type="invitation",
        resource_id=email,
        old_value=None,
        new_value={"email": email},
        metadata={},
    )

    return {"status": "ok", "email": email, "email_status": "SENT"}

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
