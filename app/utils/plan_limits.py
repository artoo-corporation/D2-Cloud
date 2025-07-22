from __future__ import annotations

import time
from typing import Dict

from fastapi import HTTPException, status

# ---- Static limits ---------------------------------------------------------
_PLAN_RATE_LIMIT_SECONDS: Dict[str, float | None] = {
    "free": None,         # not allowed
    "starter": 60.0,      # one batch per minute
    "team": 30.0,
    "enterprise": 10.0,
}

MAX_BATCH_BYTES = 1 * 1024 * 1024  # 1 MiB universal cap

# In-memory store (cold-start resets on Vercel serverless; acceptable MVP)
_last_events_ts: Dict[str, float] = {}


def enforce_event_limits(account_id: str, plan: str, payload_size: int) -> None:
    """Raise HTTPException if the request exceeds plan quotas."""

    # 1. Batch size
    if payload_size > MAX_BATCH_BYTES:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Event batch exceeds 1 MiB cap")

    # 2. Plan allows ingest?
    interval = _PLAN_RATE_LIMIT_SECONDS.get(plan, 60.0)
    if interval is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Current plan does not include event ingest")

    # 3. Simple token-bucket (one request every <interval>)
    now = time.time()
    last = _last_events_ts.get(account_id, 0)
    if now - last < interval:
        retry_after = int(interval - (now - last)) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Event ingest rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )

    _last_events_ts[account_id] = now 

# ---- Added bundle polling limits ------------------------------------------
# Uses per-account memory store similar to events ingest. Enforces that SDKs
# do not hit /v1/policy/bundle more often than the poll window dictated by
# the customer plan (or an explicit per-account override).

_last_bundle_poll_ts: Dict[str, float] = {}


def enforce_bundle_poll(account_id: str, poll_seconds: int) -> None:
    """Server-side throttle for policy bundle fetches.

    If the same *account_id* calls this endpoint again before ``poll_seconds``
    have elapsed we raise **429 Too Many Requests** and include a
    ``Retry-After`` header so well-behaved SDKs can back-off gracefully.

    For the MVP we keep timestamps in process memory. Cold-starts on Vercel
    reset the dictionary which is acceptable because the SDK will still obey
    the client-side header.
    """

    import time

    now = time.time()
    last = _last_bundle_poll_ts.get(account_id, 0.0)
    if now - last < poll_seconds:
        retry_after = int(poll_seconds - (now - last)) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Bundle poll rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )

    _last_bundle_poll_ts[account_id] = now 