from __future__ import annotations

"""Metrics endpoints for the dashboard (Supabase-backed).

All endpoints require explicit `metrics.read` via strict scope check and
`accounts.metrics_enabled = true` for the caller's account.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.models import (
    AuthContext,
    MetricsSummaryResponse,
    MetricsTimeseriesResponse,
    TimeseriesPoint,
    MetricsTopResponse,
    TopItem,
)
from app.utils.dependencies import get_supabase_async
from app.utils.auth import require_auth
from app.utils.database import query_one, query_many


router = APIRouter(prefix="/v1/metrics", tags=["metrics"])


async def _ensure_metrics_enabled(supabase, account_id: str, auth_context: AuthContext) -> dict:
    account = await query_one(supabase, "accounts", match={"id": account_id})
    if not account:
        raise HTTPException(status_code=404, detail="account_not_found")
    
    # Admin users can always access metrics (bypass metrics_enabled check)
    if "admin" in auth_context.scopes or "metrics.read" in auth_context.scopes:
        return account
        
    if not account.get("metrics_enabled", False):
        raise HTTPException(status_code=403, detail="metrics_disabled")
    return account


def _parse_timerange(
    start: datetime | None,
    end: datetime | None,
    default_days: int,
) -> Tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    if end is None:
        end = now
    if start is None:
        start = end - timedelta(days=default_days)
    # normalize to timezone-aware UTC
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    if start >= end:
        raise HTTPException(status_code=400, detail="invalid_time_range")
    return start, end


def _is_allowed_event(row: dict) -> bool:
    e = (row.get("event_type") or "").lower()
    payload = row.get("payload") or {}
    # Primary: tool_invoked with decision allowed/denied
    if e == "tool_invoked":
        decision = (payload.get("decision") or payload.get("allowed"))
        return bool(decision is True or decision == "allowed")
    # Fallback: authz_decision events
    if e == "authz_decision":
        decision = (payload.get("decision") or payload.get("allowed"))
        return bool(decision is True or decision == "allowed")
    return False


def _is_denied_event(row: dict) -> bool:
    e = (row.get("event_type") or "").lower()
    payload = row.get("payload") or {}
    if e == "tool_invoked":
        decision = (payload.get("decision") or payload.get("allowed"))
        return bool(decision is False or decision == "denied")
    if e == "authz_decision":
        decision = (payload.get("decision") or payload.get("allowed"))
        return bool(decision is False or decision == "denied")
    return False


def _extract_tool_id(row: dict) -> str | None:
    payload = row.get("payload") or {}
    return payload.get("tool_id") or payload.get("resource")


def _extract_decision_ms(row: dict) -> float | None:
    payload = row.get("payload") or {}
    # Look for likely latency fields the SDK may send
    for key in ("decision_ms", "decision_time_ms", "latency_ms", "duration_ms"):
        val = payload.get(key)
        if isinstance(val, (int, float)):
            return float(val)
    return None


@router.get("/summary", response_model=MetricsSummaryResponse)
async def get_summary(
    start: datetime | None = Query(None, description="UTC start time"),
    end: datetime | None = Query(None, description="UTC end time"),
    auth: AuthContext = Depends(require_auth("metrics.read", strict=True, admin_only=True)),
    supabase=Depends(get_supabase_async),
):
    """Overall month-style summary (configurable range)."""
    start, end = _parse_timerange(start, end, default_days=30)

    # Gate by account setting
    await _ensure_metrics_enabled(supabase, auth.account_id, auth)

    # Pull relevant events within range
    rows = await query_many(
        supabase,
        "events",
        match={
            "account_id": auth.account_id,
            "occurred_at": ("gte", start.isoformat()),
        },
        select_fields="event_type,payload,occurred_at,ingested_at",
        limit=None,
    )
    rows = [r for r in rows if r.get("occurred_at") <= end.isoformat()]

    total_authorizations = sum(1 for r in rows if (r.get("event_type") or "").lower() in {"tool_invoked", "authz_decision"})
    total_denied = sum(1 for r in rows if _is_denied_event(r))
    deny_rate = (total_denied / total_authorizations) if total_authorizations else 0.0

    # Unique tools/resources invoked
    tools: set[str] = set()
    resources: set[str] = set()
    decision_times: List[float] = []
    ingest_lags: List[float] = []

    for r in rows:
        if (r.get("event_type") or "").lower() in {"tool_invoked", "authz_decision"}:
            tool_id = _extract_tool_id(r)
            if tool_id:
                tools.add(str(tool_id))
                resources.add(str(tool_id))
            ms = _extract_decision_ms(r)
            if ms is not None:
                decision_times.append(ms)
            # ingest lag: ingested_at - occurred_at (ms)
            try:
                occ = datetime.fromisoformat(r.get("occurred_at"))
                ing = datetime.fromisoformat(r.get("ingested_at"))
                ingest_lags.append((ing - occ).total_seconds() * 1000.0)
            except Exception:
                pass

    avg_decision_ms = (sum(decision_times) / len(decision_times)) if decision_times else None
    avg_ingest_lag_ms = (sum(ingest_lags) / len(ingest_lags)) if ingest_lags else None

    return MetricsSummaryResponse(
        start=start,
        end=end,
        total_authorizations=total_authorizations,
        total_denied=total_denied,
        deny_rate=round(deny_rate, 4),
        unique_tools=len(tools),
        unique_resources=len(resources),
        avg_decision_ms=avg_decision_ms,
        avg_ingest_lag_ms=avg_ingest_lag_ms,
    )


@router.get("/timeseries", response_model=MetricsTimeseriesResponse)
async def get_timeseries(
    bucket: str = Query("day", pattern="^(hour|day)$"),
    days: int = Query(7, ge=1, le=90),
    auth: AuthContext = Depends(require_auth("metrics.read", strict=True, admin_only=True)),
    supabase=Depends(get_supabase_async),
):
    """Allowed vs denied over a recent window (default past week)."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    await _ensure_metrics_enabled(supabase, auth.account_id, auth)

    rows = await query_many(
        supabase,
        "events",
        match={
            "account_id": auth.account_id,
            "occurred_at": ("gte", start.isoformat()),
        },
        select_fields="event_type,payload,occurred_at",
        limit=None,
    )

    # Prepare buckets
    points: Dict[str, Dict[str, Any]] = {}
    def _bucket_start(dt: datetime) -> datetime:
        if bucket == "hour":
            return dt.replace(minute=0, second=0, microsecond=0)
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)

    for r in rows:
        try:
            occ = datetime.fromisoformat(r.get("occurred_at"))
        except Exception:
            continue
        if occ > end:
            continue
        b = _bucket_start(occ).isoformat()
        if b not in points:
            points[b] = {"allowed": 0, "denied": 0}
        if _is_denied_event(r):
            points[b]["denied"] += 1
        elif _is_allowed_event(r):
            points[b]["allowed"] += 1

    # Convert to sorted list
    series: List[TimeseriesPoint] = []
    for b_iso in sorted(points.keys()):
        ts = datetime.fromisoformat(b_iso)
        allowed = points[b_iso]["allowed"]
        denied = points[b_iso]["denied"]
        total = allowed + denied
        series.append(TimeseriesPoint(ts=ts, allowed=allowed, denied=denied, total=total))

    return MetricsTimeseriesResponse(
        bucket=bucket,
        start=start,
        end=end,
        points=series,
    )


@router.get("/top", response_model=MetricsTopResponse)
async def get_top(
    dimension: str = Query("tools", pattern="^(tools|resources|event_type)$"),
    days: int = Query(30, ge=1, le=180),
    n: int = Query(10, ge=1, le=100),
    auth: AuthContext = Depends(require_auth("metrics.read", strict=True, admin_only=True)),
    supabase=Depends(get_supabase_async),
):
    """Top N by tools/resources/event_type for the period."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    await _ensure_metrics_enabled(supabase, auth.account_id, auth)

    select_fields = "event_type,payload,occurred_at"
    rows = await query_many(
        supabase,
        "events",
        match={
            "account_id": auth.account_id,
            "occurred_at": ("gte", start.isoformat()),
        },
        select_fields=select_fields,
        limit=None,
    )

    from collections import Counter

    counter: Counter[str] = Counter()
    for r in rows:
        key: str | None
        if dimension == "event_type":
            key = (r.get("event_type") or "").lower()
        else:
            key = _extract_tool_id(r)
        if key:
            counter[str(key)] += 1

    total = sum(counter.values())
    top_items = counter.most_common(n)

    return MetricsTopResponse(
        dimension=dimension,
        start=start,
        end=end,
        total=total,
        items=[TopItem(key=k, count=c) for k, c in top_items],
    )


