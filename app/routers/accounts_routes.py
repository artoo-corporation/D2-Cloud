from __future__ import annotations

"""Tenant provisioning endpoints.

This router replaces the old /v1/signup path.  It creates an *accounts* row but
*does not* issue any API tokens – callers subsequently create their first token
via POST /v1/accounts/{account_id}/tokens (see tokens_routes.py).
"""


from fastapi import APIRouter, Depends, Path, HTTPException, status

from app.utils.dependencies import get_supabase_async

router = APIRouter(prefix="/v1/accounts", tags=["accounts"])
# ---------------------------------------------------------------------------
# /v1/accounts/me  – details & quotas for the current account
# ---------------------------------------------------------------------------


import os  # placed here to avoid polluting top-matter
from fastapi import Header, HTTPException

from app.models import AuthContext, MeResponse
from app.utils.plans import effective_plan, get_plan_limit
from app.utils.database import query_one
from app.utils.require_scope import require_scope


@router.get("/me", response_model=MeResponse)
async def get_me(
    auth: AuthContext = Depends(require_scope("policy.read")),
    supabase=Depends(get_supabase_async),
):
    """Return plan, quotas and misc account metadata for the caller."""

    account = await query_one(supabase, "accounts", match={"id": auth.account_id})
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    plan = effective_plan(account)
    _prefix_map = {
        "pro": "PRO",
        "enterprise": "ENTERPRISE",
        "essentials": "ESSENTIALS",
        "free": "FREE",
    }
    plan_prefix = _prefix_map.get(plan, "FREE")

    def _env_int(key: str, default: int | None = None) -> int:  # noqa: D401
        val = os.getenv(key)
        if val is None:
            return default if default is not None else 0
        try:
            return int(val)
        except ValueError:
            return default if default is not None else 0

    quotas = {
        "poll_sec": _env_int(
            f"{plan_prefix}_POLL_SEC",
            get_plan_limit(plan, "min_poll", account.get("poll_seconds", 60)),
        ),
        "event_batch": _env_int(f"{plan_prefix}_EVENT_BATCH", 1000),
        "max_tools": get_plan_limit(plan, "max_tools"),
        "event_payload_max_bytes": get_plan_limit(plan, "max_batch_bytes"),
    }

    return MeResponse(
        plan=plan,
        trial_expires=account.get("trial_expires"),
        quotas=quotas,
        metrics_enabled=account.get("metrics_enabled", False),
        poll_seconds=quotas["poll_sec"],
    )

# ---------------------------------------------------------------------------
# User role management – promote / demote users (admin-only)
# ---------------------------------------------------------------------------

from pydantic import BaseModel, Field
from app.models.invitations import InvitationRole
from app.utils.dependencies import require_actor_admin, Actor
from app.utils.database import update_data, query_one
from app.models import MessageResponse, AuditAction, AuditStatus
from app.utils.audit import log_audit_event


class UserRoleUpdateRequest(BaseModel):
    """Request body to change a user's role within the account."""

    role: InvitationRole = Field(..., description="New role for the user")

    # Restrict allowed roles – cannot assign owner via API
    @classmethod
    def __get_validators__(cls):
        yield cls.validate_role

    @classmethod
    def validate_role(cls, v: InvitationRole):  # noqa: D401
        if v not in {InvitationRole.admin, InvitationRole.dev, InvitationRole.member}:
            raise ValueError("Role must be admin, dev or member")
        return v


@router.patch("/{account_id}/users/{user_id}/role", response_model=MessageResponse)
async def update_user_role(
    account_id: str = Path(..., description="Account ID"),
    user_id: str = Path(..., description="User ID whose role is being updated"),
    request: UserRoleUpdateRequest = ...,
    user: Actor = Depends(require_actor_admin),
    supabase=Depends(get_supabase_async),
):
    """Update the role of an existing user in the account.

    Only account admins can modify roles. *owner* role cannot be assigned via this
    endpoint to safeguard against privilege escalation.
    """

    # Enforce Supabase session and account match
    if user.user_id is None:
        raise HTTPException(status_code=403, detail="supabase_session_required")
    if user.account_id != account_id:
        raise HTTPException(status_code=403, detail="account_mismatch")

    # Make sure target user exists in this account
    target_user = await query_one(
        supabase,
        "users",
        match={"user_id": user_id, "account_id": account_id},
    )
    if not target_user:
        raise HTTPException(status_code=404, detail="user_not_found")

    # Disallow changing owner role via API
    if target_user.get("role") == InvitationRole.owner.value:
        raise HTTPException(status_code=400, detail="cannot_modify_owner")
    if request.role == InvitationRole.owner:
        raise HTTPException(status_code=400, detail="cannot_assign_owner")

    # Update role
    await update_data(
        supabase,
        "users",
        {"user_id": user_id},
        {"role": request.role.value},
    )

    # Audit log
    await log_audit_event(
        supabase,
        action=AuditAction.user_role_update,
        actor_id=account_id,
        status=AuditStatus.success,
        user_id=user.user_id,
        resource_type="user",
        resource_id=user_id,
        metadata={
            "target_user_id": user_id, 
            "new_role": request.role.value,
            "old_role": target_user.get("role"),
        },
    )

    return MessageResponse(message="role_updated") 