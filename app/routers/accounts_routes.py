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
import json
from fastapi import Header, HTTPException

from app.models import AuthContext, MeResponse, AuditAction, AuditStatus
from app.utils.plans import effective_plan, get_plan_limit
from app.utils.database import query_one, update_data
from app.utils.auth import require_auth
from pydantic import BaseModel, Field
from app.utils.audit import log_audit_event


@router.get("/me", response_model=MeResponse)
async def get_me(
    auth: AuthContext = Depends(require_auth("policy.read")),
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

    # Get current member count
    from app.utils.database import query_many
    try:
        current_members = await query_many(
            supabase,
            "users",
            match={"account_id": auth.account_id},
            select_fields="user_id",
            limit=None
        )
        member_count = len(current_members)
    except Exception:
        # If we can't count members, default to 1 (assume at least the owner exists)
        member_count = 1

    quotas = {
        "poll_sec": _env_int(
            f"{plan_prefix}_POLL_SEC",
            get_plan_limit(plan, "min_poll", account.get("poll_seconds", 60)),
        ),
        "event_batch": _env_int(f"{plan_prefix}_EVENT_BATCH", 1000),
        "max_tools": get_plan_limit(plan, "max_tools"),
        "max_members": get_plan_limit(plan, "max_members"),
        "current_members": member_count,
        "event_payload_max_bytes": get_plan_limit(plan, "max_batch_bytes"),
    }

    # -------------------------------------------------------------------
    # Event sampling configuration (server-driven SDK sampling)
    #
    # Merge strategy (in priority order):
    #   1) Account-level JSON column `event_sample` (if present)
    #   2) Env override `EVENT_SAMPLE_JSON` (JSON object)
    #   3) Hard-coded defaults (below)
    # Unknown keys are preserved; values are clamped to [0.0, 1.0].
    #
    # Semantics:
    # - Values are sampling probabilities used by SDKs when deciding whether to
    #   emit a raw telemetry event of a given type. They DO NOT affect the
    #   underlying authorization decision itself – only whether the event is
    #   sent to the control plane.
    # - 1.0  ⇒ always send (no sampling)
    # - 0.0  ⇒ never send (fully suppressed)
    # - 0.5  ⇒ ~50% of events emitted (client-side randomised)
    #
    # Keys (initial set):
    # - "authz_decision": Decision outcome for an authorization check. Keep at
    #   1.0 for accurate allow/deny metrics and troubleshooting. Lowering this
    #   will reduce fidelity of metrics.
    # - "tool_invoked": Tool-level invocation events around decisions. Useful
    #   for debugging and attribution; can be reduced (<1.0) to cut noise.
    # - "policy_poll_interval": Periodic/heartbeat style events from bundle
    #   polling. Safe to downsample aggressively (e.g., 0.1) to limit chatter.
    # - "missing_policy": Emitted when a policy is missing. Can be spiky during
    #   incidents; downsample to avoid bursts while retaining visibility.
    #
    # Behaviour & propagation:
    # - Merge precedence: account.event_sample > ENV(EVENT_SAMPLE_JSON) > defaults
    # - Non-numeric values are ignored; numeric values are clamped into [0,1].
    # - Unknown keys are passed through untouched for forward-compat (SDKs may
    #   ignore keys they don’t understand).
    # - SDKs cache /v1/accounts/me for ~5 minutes; changes typically take effect
    #   within that window on clients.
    # -------------------------------------------------------------------

    defaults = {
        "authz_decision": 1.0,
        "tool_invoked": 1.0,
        "policy_poll_interval": 0.1,
        "missing_policy": 0.5,
    }

    merged: dict[str, float] = {}

    # Start with defaults
    merged.update(defaults)

    # Env JSON override (optional)
    env_json = os.getenv("EVENT_SAMPLE_JSON")
    if env_json:
        try:
            env_obj = json.loads(env_json)
            if isinstance(env_obj, dict):
                for k, v in env_obj.items():
                    try:
                        fv = float(v)
                        merged[k] = fv
                    except Exception:
                        # ignore non-numeric env values
                        pass
        except Exception:
            # ignore bad env JSON
            pass

    # Account-level per-tenant config (preferred)
    acct_cfg = account.get("event_sample")
    if isinstance(acct_cfg, dict):
        for k, v in acct_cfg.items():
            try:
                merged[k] = float(v)
            except Exception:
                # ignore non-numeric account values
                pass

    # Clamp to [0,1]
    for k, v in list(merged.items()):
        if not isinstance(v, (int, float)):
            del merged[k]
            continue
        if v < 0.0:
            merged[k] = 0.0
        elif v > 1.0:
            merged[k] = 1.0

    return MeResponse(
        plan=plan,
        trial_expires=account.get("trial_expires"),
        quotas=quotas,
        metrics_enabled=account.get("metrics_enabled", False),
        poll_seconds=quotas["poll_sec"],
        event_sample=merged,
        account_id=auth.account_id,
    )


class AccountNameUpdateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200, description="New organization name")


@router.patch("/{account_id}/name", status_code=status.HTTP_200_OK)
async def update_account_name(
    account_id: str = Path(..., description="Account ID to update"),
    payload: AccountNameUpdateRequest = ...,  # Provided by FastAPI from JSON body
    auth: AuthContext = Depends(require_auth(require_privileged=True, require_user=True)),
    supabase=Depends(get_supabase_async),
):
    """Update the organization's display name.

    Security:
    - Caller must be an OAuth user (require_user=True)
    - Caller must be owner/dev of the same account (require_privileged=True + account match)
    """

    if auth.account_id != account_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="account_mismatch")

    # Fetch current to detect no-op
    current = await query_one(supabase, "accounts", match={"id": account_id})
    if not current:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="account_not_found")

    new_name = payload.name.strip()
    if not new_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_account_name")

    if current.get("name") == new_name:
        # Idempotent no-op
        return {"message": "account_name_unchanged", "name": new_name}

    await update_data(
        supabase,
        "accounts",
        update_values={"name": new_name},
        filters={"id": account_id},
        error_message="account_update_failed",
    )

    # Audit
    await log_audit_event(
        supabase,
        action=AuditAction.account_update,
        actor_id=auth.account_id,
        status=AuditStatus.success,
        token_id=auth.token_id,
        user_id=auth.user_id,
        resource_type="account",
        resource_id=account_id,
        metadata={
            "field": "name",
            "old": current.get("name"),
            "new": new_name,
        },
    )

    return {"message": "account_name_updated", "name": new_name}
