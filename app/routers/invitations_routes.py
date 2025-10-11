"""Invitation management routes for multi-tenant accounts."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone, timedelta
from uuid import uuid4
import os

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status, Header

from app.models import AuditAction, AuditStatus, MessageResponse
from app.models.invitations import (
    InvitationCreateRequest,
    InvitationResponse, 
    InvitationListResponse,
    PendingInvitationInfo,
    InvitationRole,
    InvitationCreateResponse,
)
from app.utils.audit import log_audit_event
from app.utils.dependencies import get_supabase_async
from app.utils.auth import require_auth
from app.utils.database import insert_data, query_data, query_one, update_data
from pydantic import BaseModel
from app.models.members import AccountMember, AccountMembersResponse


router = APIRouter(prefix="/v1/accounts/{account_id}/invitations", tags=["invitations"])


async def _generate_invitation_token() -> str:
    """Generate a secure random token for invitations."""
    return f"inv_{secrets.token_urlsafe(32)}"


@router.post(
    "",
    response_model=InvitationCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_invitation(
    account_id: str = Path(..., description="Account ID"),
    request: InvitationCreateRequest = ...,
    auth: AuthContext = Depends(require_auth(require_privileged=True, require_user=True)),
    supabase=Depends(get_supabase_async),
):
    """Create a new invitation to join the account.
    
    Only account admins can invite new users.
    Invited users will receive an email with a secure link to accept.
    """
    # Enforce account access and admin role
    if auth.account_id != account_id:
        raise HTTPException(status_code=403, detail="account_mismatch")
    # Ensure the caller is an authenticated Supabase user (not just an API token)
    if auth.user_id is None:
        raise HTTPException(status_code=403, detail="supabase_session_required")
    
    # Check member limits before proceeding
    from app.utils.database import query_one as db_query_one
    account = await db_query_one(supabase, "accounts", match={"id": auth.account_id})
    if account:
        from app.utils.plans import enforce_member_limits, resolve_plan_name
        current_plan = await resolve_plan_name(supabase, account)
        await enforce_member_limits(supabase, auth.account_id, current_plan)
    
    # Check if user already exists in the account
    existing_user = await query_one(
        supabase,
        "users",
        match={"account_id": auth.account_id, "email": request.email}
    )
    if existing_user:
        raise HTTPException(status_code=409, detail="user_already_in_account")
    
    # Check if there's already a pending invitation
    existing_invitation = await query_one(
        supabase,
        "invitations", 
        match={"account_id": auth.account_id, "email": request.email, "accepted_at": ("is", "null")}
    )
    if existing_invitation:
        raise HTTPException(status_code=409, detail="invitation_already_exists")
    
    # Generate secure invitation token
    invitation_token = await _generate_invitation_token()
    invitation_id = str(uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    
    # Create invitation
    await insert_data(
        supabase,
        "invitations",
        {
            "id": invitation_id,
            "account_id": auth.account_id,
            "email": request.email,
            "role": request.role.value,
            "invited_by_user_id": auth.user_id,
            "invitation_token": invitation_token,
            "expires_at": expires_at.isoformat(),
        }
    )
    
    # Audit log the invitation
    await log_audit_event(
        supabase,
        action=AuditAction.invitation_create,
        actor_id=account_id,
        status=AuditStatus.success,
        user_id=auth.user_id,
        resource_type="invitation",
        resource_id=invitation_id,
        metadata={
            "email": request.email,
            "role": request.role.value,
        },
    )
    
    # Build URL for front-end invitation acceptance page
    from app import settings
    base_url = os.getenv("FRONTEND_ORIGIN") or settings.ALLOWED_ORIGINS[0]
    invitation_url = f"{base_url.rstrip('/')}/v1/invitations/accept?token={invitation_token}"

    # TODO: send email with invitation_url

    return InvitationCreateResponse(
        message=f"invitation_sent_to_{request.email}",
        invitation_url=invitation_url,
    )


@router.get("", response_model=InvitationListResponse)
async def list_invitations(
    account_id: str = Path(..., description="Account ID"),
    include_accepted: bool = Query(False, description="Include accepted invitations"),
    auth: AuthContext = Depends(require_auth(require_privileged=True, require_user=True)),
    supabase=Depends(get_supabase_async),
):
    """List all invitations for the account with user name attribution."""
    # Enforce account access
    if auth.account_id != account_id:
        raise HTTPException(status_code=403, detail="account_mismatch")
    
    # Build query filters
    filters = {"account_id": auth.account_id}
    if not include_accepted:
        # Supabase/PostgREST requires the special operator ("is", "null") for NULL comparisons
        filters["accepted_at"] = ("is", "null")
    
    # Query invitations
    resp = await query_data(
        supabase,
        "invitations",
        filters=filters,
        select_fields="id,email,role,invited_by_user_id,expires_at,accepted_at,created_at,invitation_token"
    )
    
    invitations_data = getattr(resp, "data", []) or []
    
    # Get user names for attribution
    user_ids = [inv["invited_by_user_id"] for inv in invitations_data if inv.get("invited_by_user_id")]
    user_names = {}
    
    if user_ids:
        user_resp = await query_data(
            supabase,
            "users",
            filters={"user_id": ("in", user_ids)},
            select_fields="user_id,display_name,full_name,email"
        )
        user_data = getattr(user_resp, "data", []) or []
        for u in user_data:
            user_names[u["user_id"]] = u.get("display_name") or u.get("full_name") or u.get("email") or "Unknown User"
    
    # Format response with user names
    invitations = [
        InvitationResponse(
            id=inv["id"],
            email=inv["email"],
            role=inv["role"],
            invited_by_user_id=inv["invited_by_user_id"],
            invited_by_name=user_names.get(inv["invited_by_user_id"]),
            expires_at=inv["expires_at"],
            accepted_at=inv.get("accepted_at"),
            created_at=inv["created_at"],
            invitation_token=inv.get("invitation_token"),
        )
        for inv in invitations_data
    ]
    
    return InvitationListResponse(invitations=invitations)


@router.delete("/{invitation_id}")
async def cancel_invitation(
    account_id: str = Path(..., description="Account ID"),
    invitation_id: str = Path(..., description="Invitation ID to cancel"),
    auth: AuthContext = Depends(require_auth(require_privileged=True, require_user=True)),
    supabase=Depends(get_supabase_async),
):
    """Cancel a pending invitation."""
    # Enforce account access
    if auth.account_id != account_id:
        raise HTTPException(status_code=403, detail="account_mismatch")
    
    # Find invitation
    invitation = await query_one(
        supabase,
        "invitations",
        match={"id": invitation_id, "account_id": auth.account_id}
    )
    if not invitation:
        raise HTTPException(status_code=404, detail="invitation_not_found")
    
    if invitation.get("accepted_at"):
        raise HTTPException(status_code=400, detail="invitation_already_accepted")
    
    # Delete invitation
    await supabase.table("invitations").delete().eq("id", invitation_id).execute()
    
    # Audit log the cancellation
    await log_audit_event(
        supabase,
        action=AuditAction.invitation_cancel,
        actor_id=account_id,
        status=AuditStatus.success,
        user_id=auth.user_id,
        resource_type="invitation",
        resource_id=invitation_id,
        metadata={
            "email": invitation.get("email"),
            "role": invitation.get("role"),
        },
    )
    
    return MessageResponse(message="invitation_cancelled")


# Public endpoint for invitation acceptance (no auth required)
invitation_public_router = APIRouter(prefix="/v1/invitations", tags=["invitations"])

@invitation_public_router.get("/info/{invitation_token}")
async def get_invitation_info(
    invitation_token: str = Path(..., description="Invitation token from email"),
    supabase=Depends(get_supabase_async),
):
    """Get information about a pending invitation (for the accept page)."""
    # Find invitation by token
    invitation = await query_one(
        supabase,
        "invitations",
        match={"invitation_token": invitation_token}
    )
    
    if not invitation:
        raise HTTPException(status_code=404, detail="invitation_not_found")
    
    # Check if expired
    expires_at = datetime.fromisoformat(invitation["expires_at"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(status_code=410, detail="invitation_expired")
    
    # Check if already accepted
    if invitation.get("accepted_at"):
        raise HTTPException(status_code=409, detail="invitation_already_accepted")
    
    # Get account info
    account = await query_one(
        supabase,
        "accounts",
        match={"id": invitation["account_id"]}
    )
    
    # Get inviter info  
    inviter = await query_one(
        supabase,
        "users",
        match={"user_id": invitation["invited_by_user_id"]}
    )
    
    return PendingInvitationInfo(
        account_name=account.get("name", "Unknown Account"),
        invited_by_name=inviter.get("display_name") or inviter.get("full_name") or "Unknown User",
        role=invitation["role"],
        expires_at=expires_at
    )


@invitation_public_router.get("/accept")
async def get_accept_invitation_page(
    token: str = Query(..., description="Invitation token from email link"),
    supabase=Depends(get_supabase_async),
):
    """Get invitation acceptance page info (what user sees when they click the link)."""
    # Find invitation by token (same logic as info endpoint)
    invitation = await query_one(
        supabase,
        "invitations",
        match={"invitation_token": token}
    )
    
    if not invitation:
        raise HTTPException(status_code=404, detail="invitation_not_found")
    
    # Check if invitation is expired
    expires_at = datetime.fromisoformat(invitation["expires_at"]).astimezone(timezone.utc)
    if datetime.now(timezone.utc) >= expires_at:
        raise HTTPException(status_code=410, detail="invitation_expired")
    
    # Check if already accepted
    if invitation.get("accepted_at"):
        raise HTTPException(status_code=409, detail="invitation_already_accepted")
    
    # Get inviter's name
    inviter = await query_one(
        supabase,
        "users",
        match={"user_id": invitation["invited_by_user_id"]}
    )
    
    # Fetch account name for display (authoritative)
    account = await query_one(
        supabase,
        "accounts",
        match={"id": invitation["account_id"]}
    )
    account_name = (account or {}).get("name") or invitation.get("account_name", "Unknown")
    
    # Return invitation details for the acceptance page
    return PendingInvitationInfo(
        account_name=account_name,
        invited_by_name=inviter.get("display_name") or inviter.get("full_name") or "Unknown User",
        role=invitation["role"],
        expires_at=expires_at
    )


@invitation_public_router.post("/accept")
async def accept_invitation(
    token: str = Query(..., description="Invitation token from email link"),
    authorization: str | None = Header(None),  # Supabase session required
    supabase=Depends(get_supabase_async),
):
    """Accept an invitation and join the account.
    
    User must be authenticated with Supabase (just signed up/in).
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="supabase_session_required")
    
    # Find invitation
    invitation = await query_one(
        supabase,
        "invitations",
        match={"invitation_token": token}
    )
    
    if not invitation:
        raise HTTPException(status_code=404, detail="invitation_not_found")
    
    # Validate invitation
    expires_at = datetime.fromisoformat(invitation["expires_at"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(status_code=410, detail="invitation_expired")
    
    if invitation.get("accepted_at"):
        raise HTTPException(status_code=409, detail="invitation_already_accepted")
    
    # Get user info from Supabase Auth
    bearer = (authorization or "").split(" ")[-1]
    user_response = await supabase.auth.get_user(bearer)
    user = getattr(user_response, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="invalid_session")
    
    user_email = getattr(user, "email", "").lower()
    if user_email != invitation["email"].lower():
        raise HTTPException(status_code=400, detail="email_mismatch")
    
    # Check if user is already in some account
    existing_user = await query_one(
        supabase,
        "users",
        match={"user_id": getattr(user, "id", None)}
    )
    
    if existing_user:
        raise HTTPException(status_code=409, detail="user_already_has_account")
    
    # Check member limits before adding user to account
    # This is critical - we need to check limits at acceptance time, not just invitation time
    # because the plan could have changed or other users might have been added
    account = await query_one(supabase, "accounts", match={"id": invitation["account_id"]})
    if account:
        from app.utils.plans import enforce_member_limits, resolve_plan_name
        current_plan = await resolve_plan_name(supabase, account)
        await enforce_member_limits(supabase, invitation["account_id"], current_plan)
    
    # Add user to the account
    await insert_data(
        supabase,
        "users",
        {
            "user_id": getattr(user, "id", None),
            "account_id": invitation["account_id"],
            "email": user_email,
            "role": invitation["role"],
            "display_name": getattr(user, "user_metadata", {}).get("name", user_email.split("@")[0]),
            "full_name": getattr(user, "user_metadata", {}).get("full_name"),
        }
    )
    
    # Mark invitation as accepted
    await update_data(
        supabase,
        "invitations",
        {"id": invitation["id"]},
        {
            "accepted_at": datetime.now(timezone.utc).isoformat(),
            "accepted_by_user_id": getattr(user, "id", None)
        }
    )
    
    # Audit log acceptance
    await log_audit_event(
        supabase,
        action=AuditAction.invitation_accept,
        actor_id=invitation["account_id"],
        status=AuditStatus.success,
        user_id=getattr(user, "id", None),
        resource_type="invitation",
        resource_id=invitation["id"],
        metadata={
            "email": user_email, 
            "role": invitation["role"],
            "invited_by": invitation.get("invited_by_user_id"),
        }
    )
    
    return MessageResponse(message="invitation_accepted")


@router.get("/members", response_model=AccountMembersResponse)
async def list_account_members(
    account_id: str = Path(..., description="Account ID"),
    auth: AuthContext = Depends(require_auth(require_privileged=True, require_user=True)),
    supabase=Depends(get_supabase_async),
):
    """List all users who belong to the given account (admin-only)."""

    # Enforce account access
    if auth.account_id != account_id:
        raise HTTPException(status_code=403, detail="account_mismatch")

    resp = await query_data(
        supabase,
        "users",
        filters={"account_id": account_id},
        select_fields="user_id,email,full_name,display_name,role,created_at",
    )

    rows = getattr(resp, "data", []) or []

    members = [
        AccountMember(
            user_id=row["user_id"],
            email=row.get("email"),
            full_name=row.get("full_name"),
            display_name=row.get("display_name"),
            role=row.get("role"),
            created_at=row.get("created_at"),
        )
        for row in rows
    ]

    return AccountMembersResponse(members=members)
