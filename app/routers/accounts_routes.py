from __future__ import annotations

"""Tenant provisioning endpoints.

This router replaces the old /v1/signup path.  It creates an *accounts* row but
*does not* issue any API tokens – callers subsequently create their first token
via POST /v1/accounts/{account_id}/tokens (see tokens_routes.py).
"""


from fastapi import APIRouter, Depends

from app.utils.dependencies import get_supabase_async

router = APIRouter(prefix="/v1/accounts", tags=["accounts"])
# ---------------------------------------------------------------------------
# /v1/accounts/me  – details & quotas for the current account
# ---------------------------------------------------------------------------


import os  # placed here to avoid polluting top-matter
from fastapi import Header, HTTPException

from app.models import MeResponse
from app.utils.plans import effective_plan, get_plan_limit
from app.utils.database import query_one
from app.utils.require_scope import require_scope


@router.get("/me", response_model=MeResponse)
async def get_me(
    account_id: str = Depends(require_scope("read")),
    supabase=Depends(get_supabase_async),
):
    """Return plan, quotas and misc account metadata for the caller."""

    account = await query_one(supabase, "accounts", match={"id": account_id})
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