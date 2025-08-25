from __future__ import annotations

"""Subscription plan constants and helpers.

This module centralises quota tables so other packages can enforce
limits consistently (trial locking, tool counts, poll windows, etc.).
"""

from datetime import datetime, timezone
from typing import Dict, Any

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

PLANS: Dict[str, Dict[str, Any]] = {
    "free": { # $0
        "max_tools": 5,
        "min_poll": 300,
        "ingest_interval": 60,
        "max_batch_bytes": 32 * 1024,  # 32 KiB (events)
        "max_bundle_bytes": int(0.5 * 1024 * 1024),  # 0.5 MiB
    },
    "essentials": { # $99
        "max_tools": 25,
        "min_poll": 60,
        "ingest_interval": 60,
        "max_batch_bytes": 128 * 1024,
        "max_bundle_bytes": int(2 * 1024 * 1024),  # 2 MiB
    },
    "pro": { # $250
        "max_tools": 250,
        "min_poll": 30,
        "ingest_interval": 30,
        "max_batch_bytes": 512 * 1024,
        "max_bundle_bytes": int(5 * 1024 * 1024),  # 5 MiB
    },
    "enterprise": { # $CUSTOM
        "max_tools": 1000,
        "min_poll": 15,
        "ingest_interval": 10,
        "max_batch_bytes": 1024 * 1024,
        "max_bundle_bytes": int(20 * 1024 * 1024),  # 20 MiB
    },
    "locked": {
        "max_tools": 0,
        "min_poll": 100000,
        "ingest_interval": 60,  # disallow ingest
        "max_batch_bytes": 32 * 1024,
        "max_bundle_bytes": int(0.5 * 1024 * 1024),
    },
}

__all__ = [
    "PLANS",
    "effective_plan",
    "get_plan_limit",
    "enforce_event_limits",
    "enforce_bundle_poll",
]

# ---------------------------------------------------------------------------
# In-process stores for simple throttling
# ---------------------------------------------------------------------------

_last_events_ts: Dict[str, float] = {}
_last_bundle_poll_ts: Dict[str, float] = {}


# ---------------------------------------------------------------------------
# Enforcement helpers (moved from old plan_limits.py)
# ---------------------------------------------------------------------------


def enforce_event_limits(account_id: str, plan: str, payload_size: int) -> None:
    """Raise HTTPException if the event ingest exceeds plan quotas."""

    from fastapi import HTTPException, status  # local import to avoid heavy deps
    import time

    # 1) Batch size cap
    if payload_size > get_plan_limit(plan, "max_batch_bytes"):
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="event_batch_too_large",
        )

    # 2) Determine allowed interval (None => not allowed)
    interval = PLANS.get(plan, {}).get("ingest_interval", 60)
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


def enforce_bundle_poll(account_id: str, poll_seconds: int) -> None:
    """Server-side throttle for policy bundle fetches."""

    from fastapi import HTTPException, status  # local import
    import time

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

    plan = (account or {}).get("plan", "free")

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


def get_plan_limit(plan: str, key: str, default: int | None = None) -> int:
    """Return a numeric limit for *plan* with optional fallback."""
    return int(PLANS.get(plan, {}).get(key, default or 0))