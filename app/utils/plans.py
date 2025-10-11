from __future__ import annotations

"""Subscription plan constants and helpers.

This module centralises quota tables so other packages can enforce
limits consistently (trial locking, tool counts, poll windows, etc.).
"""

from datetime import datetime, timezone
from typing import Dict, Any

# Exports
__all__ = [
    "effective_plan",
    "get_plan_limit_db",
    "get_plan_limits_db",
    "enforce_event_limits",
    "enforce_bundle_poll",
    # legacy get_plan_limit removed – use async helpers instead
]

# ---------------------------------------------------------------------------
# In-process stores for simple throttling
# ---------------------------------------------------------------------------

_last_events_ts: Dict[str, float] = {}
_last_bundle_poll_ts: Dict[str, float] = {}


# ---------------------------------------------------------------------------
# No in-code plan quotas – all limits come from the database table.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Enforcement helpers (moved from old plan_limits.py)
# ---------------------------------------------------------------------------


async def enforce_event_limits(supabase, account_id: str, plan: str, payload_size: int) -> None:
    """Raise HTTPException if the event ingest exceeds plan quotas."""

    from fastapi import HTTPException, status  # local import to avoid heavy deps
    import time

    # 1) Batch size cap (DB-driven, fallback to constants)
    max_batch_bytes = await get_plan_limit_db(supabase, plan, "max_batch_bytes", 0)
    if payload_size > max_batch_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="event_batch_too_large",
        )

    # 2) Determine allowed interval (None => not allowed)
    interval = (await get_plan_limits_db(supabase, plan)).get("ingest_interval", 60)
    if interval is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="plan_no_ingest")

    # 3) Token-bucket: one request every <interval>
    now = time.time()
    last = _last_events_ts.get(account_id, 0.0)
    if now - last < interval:
        retry_after = int(interval - (now - last)) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="ingest_rate_limit",
            headers={"Retry-After": str(retry_after)},
        )

    _last_events_ts[account_id] = now


def enforce_bundle_poll(account_id: str, poll_seconds: int, token_scopes: list[str] | None = None) -> None:
    """Server-side throttle for policy bundle fetches.
    
    Developer-friendly polling:
    - Dev tokens (scope='dev'): No polling restrictions for local development
    - Server tokens (scope='server'): Full polling restrictions apply
    - Privileged tokens (admin scope): No polling restrictions
    """

    from fastapi import HTTPException, status  # local import
    import time

    # Skip polling restrictions for dev and privileged (admin-scope) tokens
    if token_scopes:
        if "dev" in token_scopes or "admin" in token_scopes:
            return  # No restrictions for developers and admins

    now = time.time()
    last = _last_bundle_poll_ts.get(account_id, 0.0)
    if now - last < poll_seconds:
        retry_after = int(poll_seconds - (now - last)) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="bundle_poll_rate_limit",
            headers={"Retry-After": str(retry_after)},
        )

    _last_bundle_poll_ts[account_id] = now


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def utc_now() -> datetime:  # small util to avoid duplicating imports
    """Return a timezone-aware UTC *datetime* object."""
    return datetime.now(timezone.utc)


def effective_plan(account: Dict[str, Any]) -> str:  # noqa: WPS231 (simple logic)
    """Return the **current** plan name taking trial expiry into account.

    `accounts.plan` remains the source of truth but we transparently treat
    expired trials as *locked* for quota enforcement so callers don't need
    to duplicate the date-math.
    """

    # Prefer plan_id (FK to plans.name) if present; fallback to legacy 'plan' column
    plan = (account or {}).get("plan_id") or (account or {}).get("plan", "free")

    if plan == "trial":
        expires_iso = account.get("trial_expires")
        if expires_iso:
            if isinstance(expires_iso, str):
                expires_dt = datetime.fromisoformat(expires_iso).astimezone(timezone.utc)
            else:
                expires_dt = expires_iso

            if expires_dt < utc_now():
                return "locked"

        # Active trial behaves like free
        return "free"

    return plan


async def get_plan_limits_db(supabase, plan: str) -> Dict[str, int]:
    """Fetch plan limits from database `plans` table.

    Table schema expected (plans):
      name text primary key,
      max_tools int, max_apps int, max_members int,
      min_poll int, ingest_interval int,
      max_batch_bytes int, max_bundle_bytes int
    """
    try:
        from app.utils.database import query_one  # local import
        row = await query_one(supabase, "plans", match={"name": plan})
        if not row:
            return {}
        # Coerce to ints and return
        limits: Dict[str, int] = {}
        for k in ("max_tools","max_apps","max_members","min_poll","ingest_interval","max_batch_bytes","max_bundle_bytes"):
            if row.get(k) is not None:
                limits[k] = int(row.get(k))
        return limits
    except Exception:
        # On any DB error, return empty dict so callers fall back to defaults
        return {}


async def get_plan_limit_db(supabase, plan: str, key: str, default: int | None = None) -> int:
    limits = await get_plan_limits_db(supabase, plan)
    if key in limits:
        return int(limits[key])
    # Fallback to caller-provided default (or 0)
    return int(default or 0)


async def enforce_member_limits(supabase, account_id: str, plan: str) -> None:
    """Raise HTTPException if adding a new member would exceed plan quotas."""
    
    from fastapi import HTTPException, status  # local import to avoid heavy deps
    from app.utils.database import query_many
    
    # Get current member count
    try:
        current_members = await query_many(
            supabase,
            "users",
            match={"account_id": account_id},
            select_fields="user_id",
            limit=None
        )
        current_count = len(current_members)
    except Exception:
        # If we can't count members, be conservative and allow the invitation
        # This prevents database issues from blocking legitimate invitations
        return
    
    # Get plan limit (DB-driven, fallback to constants)
    max_members = await get_plan_limit_db(supabase, plan, "max_members", 1)
    
    # Check if adding one more member would exceed the limit
    if current_count >= max_members:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="quota_members_exceeded",
            headers={
                "X-Current-Members": str(current_count),
                "X-Max-Members": str(max_members)
            }
        )

# ---------------------------------------------------------------------------
# Async helper to resolve plan name via plan_id FK
# ---------------------------------------------------------------------------


async def resolve_plan_name(supabase, account: Dict[str, Any]) -> str:  # noqa: WPS231
    """Return the plan *name* for given account row.

    Handles both legacy ``accounts.plan`` text column and new ``accounts.plan_id``
    foreign-key to ``plans.id``.
    """

    # Prefer FK lookup
    plan_id = (account or {}).get("plan_id")
    if plan_id:
        try:
            from app.utils.database import query_one  # local import to avoid heavy deps

            row = await query_one(supabase, "plans", match={"id": plan_id}, select_fields="name")
            if row and row.get("name"):
                plan = row["name"]
            else:
                plan = "free"  # fallback if FK broken
        except Exception:
            plan = "free"
    else:
        plan = (account or {}).get("plan", "free")

    # Trial expiry logic (same as effective_plan)
    if plan == "trial":
        expires_iso = account.get("trial_expires")
        if expires_iso:
            if isinstance(expires_iso, str):
                expires_dt = datetime.fromisoformat(expires_iso).astimezone(timezone.utc)
            else:
                expires_dt = expires_iso
            if expires_dt < utc_now():
                return "locked"
        return "free"

    return plan

__all__.append("resolve_plan_name")