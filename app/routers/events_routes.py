"""Usage events ingest – streams batches to ClickHouse via Logflare HTTP."""

from __future__ import annotations

import os

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, status, Request, Query
from fastapi.responses import JSONResponse

from app.models import AuthContext, EventRecord, MessageResponse
from app.models.events import EventIngest
from app.utils.database import query_one
from app.utils.dependencies import get_supabase_async
from app.utils.plans import effective_plan, enforce_event_limits
from app.utils.auth import require_auth
from datetime import datetime, timezone

router = APIRouter(prefix="/v1", tags=["events"])

LOGFLARE_ENDPOINT = os.getenv("LOGFLARE_HTTP_ENDPOINT", "https://api.logflare.app")
LOGFLARE_API_KEY = os.getenv("LOGFLARE_API_KEY")

# NOTE: SDK telemetry events are kept separate from audit logs.
# Events table = customer telemetry data from SDKs
# Audit logs table = cloud operations by company personnel (keys, policies, tokens, etc.)
# No mixing between the two systems.


# REMOVED: SDK events are no longer converted to audit logs.
# SDK telemetry stays in events table only.


@router.post("/events/ingest", response_model=MessageResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_events(
    request: Request,
    batch: EventIngest,  # Now expects batched events
    auth: AuthContext = Depends(require_auth("event.ingest")),
    supabase=Depends(get_supabase_async),
):
    # auth.account_id is provided by dependency

    # ---------------------------------------------------------------------
    # Payload size guard – reject anything above 32 KiB before doing any
    # heavier work (like DB look-ups).
    # ---------------------------------------------------------------------
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 32 * 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Payload too large")

    # Serialise once so we can cheaply measure the actual bytes on the wire
    batch_json = batch.model_dump_json().encode()
    if not content_length and len(batch_json) > 32 * 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Payload too large")

    # ---------------------------------------------------------------------
    # Auth & plan enforcement
    # ---------------------------------------------------------------------
    # Fetch account plan & enforce limits
    account = await query_one(supabase, "accounts", match={"id": auth.account_id})
    plan = effective_plan(account)
    enforce_event_limits(auth.account_id, plan, payload_size=len(batch_json))

    # Optional downstream export to Logflare → ClickHouse. If no API key is
    # configured we simply store the events in Supabase and rely on the cron
    # job (app.cron.event_rollup) to ship them later.

    if LOGFLARE_API_KEY:
        async with httpx.AsyncClient(timeout=3) as client:
            try:
                await client.post(
                    f"{LOGFLARE_ENDPOINT}/logs?source={auth.account_id}",
                    headers={"X-API-KEY": LOGFLARE_API_KEY},
                    json={"events": [event.model_dump() for event in batch.events]},
                )
            except httpx.HTTPError as exc:
                # Best-effort – don't fail the ingest if Logflare is down; events are still
                # persisted locally and will be picked up by the ClickHouse roll-up.
                pass

    # ------------------------------------------------------------------
    # Enrich with request metadata and process each event
    # ------------------------------------------------------------------
    source_host = request.headers.get("x-d2-host") or request.headers.get("host")
    source_ip = request.client.host if request.client else None

    # Process each event in the batch
    for event in batch.events:
        # Insert individual event to database
        await supabase.table("events").insert(  # type: ignore[attr-defined]
            {
                "account_id": auth.account_id,
                "occurred_at": event.occurred_at.isoformat(),
                "event_type": event.event_type,
                "payload": event.payload,
                "host": source_host,
                "source_ip": source_ip,
                "ingested_at": datetime.now(timezone.utc).isoformat(),
            }
        ).execute()

        # SDK events stay in events table only - no audit log mixing

    return MessageResponse(message=f"Accepted {len(batch.events)} events")


@router.get("/events", response_model=list[EventRecord])
async def list_events(
    limit: int = Query(100, ge=1, le=1000),
    cursor: str | None = Query(None, description="Cursor of form '<iso>,<uuid>' from X-Next-Cursor header"),
    auth: AuthContext = Depends(require_auth("metrics.read")),
    supabase=Depends(get_supabase_async),
):
    # Build query manually to support compound cursor
    tbl = supabase.table("events").select(
        "id,occurred_at,event_type,payload,ingested_at,host,source_ip"
    ).eq("account_id", auth.account_id)

    if cursor:
        try:
            ts_str, id_cursor = cursor.split(",", 1)
            ts_val = datetime.fromisoformat(ts_str)
        except Exception:
            raise HTTPException(status_code=400, detail="invalid_cursor")

        iso = ts_val.isoformat()
        tbl = tbl.or_(f"ingested_at.lt.{iso},and(ingested_at.eq.{iso},id.lt.{id_cursor})")

    tbl = tbl.order("ingested_at", desc=True).order("id", desc=True).limit(limit)

    resp = await tbl.execute()
    rows = getattr(resp, "data", None) or []

    # Compute next cursor (oldest ingested_at in this page)
    if rows:
        next_cursor = f"{rows[-1]['ingested_at']},{rows[-1]['id']}"
    else:
        next_cursor = None

    return JSONResponse(
        content=[EventRecord(**r).model_dump(mode="json") for r in rows],
        headers={"X-Next-Cursor": str(next_cursor) if next_cursor else ""},
    ) 