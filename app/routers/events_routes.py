"""Usage events ingest – streams batches to ClickHouse via Logflare HTTP."""

from __future__ import annotations

import os

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, status, Request

from app.models import MessageResponse
from app.models.events import EventIngest
from app.utils.dependencies import get_supabase_async
from app.utils.require_scope import require_scope
from app.utils.plans import enforce_event_limits, effective_plan
from app.utils.database import query_one
from datetime import datetime, timezone

router = APIRouter(prefix="/v1", tags=["events"])

LOGFLARE_ENDPOINT = os.getenv("LOGFLARE_HTTP_ENDPOINT", "https://api.logflare.app")
LOGFLARE_API_KEY = os.getenv("LOGFLARE_API_KEY")


@router.post("/events/ingest", response_model=MessageResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_events(
    request: Request,
    event: EventIngest,
    account_id: str = Depends(require_scope("policy.read")),
    supabase=Depends(get_supabase_async),
):
    # account_id is provided by dependency

    # ---------------------------------------------------------------------
    # Payload size guard – reject anything above 32 KiB before doing any
    # heavier work (like DB look-ups).
    # ---------------------------------------------------------------------
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 32 * 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Payload too large")

    # Serialise once so we can cheaply measure the actual bytes on the wire
    event_json = event.model_dump_json().encode()
    if not content_length and len(event_json) > 32 * 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Payload too large")

    # ---------------------------------------------------------------------
    # Auth & plan enforcement
    # ---------------------------------------------------------------------
    # Fetch account plan & enforce limits
    account = await query_one(supabase, "accounts", match={"id": account_id})
    plan = effective_plan(account)
    enforce_event_limits(account_id, plan, payload_size=len(event_json))

    # Optional downstream export to Logflare → ClickHouse. If no API key is
    # configured we simply store the events in Supabase and rely on the cron
    # job (app.cron.event_rollup) to ship them later.

    if LOGFLARE_API_KEY:
        async with httpx.AsyncClient(timeout=3) as client:
            try:
                await client.post(
                    f"{LOGFLARE_ENDPOINT}/logs?source={account_id}",
                    headers={"X-API-KEY": LOGFLARE_API_KEY},
                    json={"events": [event.model_dump()]},
                )
            except httpx.HTTPError as exc:
                # Best-effort – don't fail the ingest if Logflare is down; events are still
                # persisted locally and will be picked up by the ClickHouse roll-up.
                pass

    # ------------------------------------------------------------------
    # Enrich with request metadata
    # ------------------------------------------------------------------
    source_host = request.headers.get("x-d2-host") or request.headers.get("host")
    source_ip = request.client.host if request.client else None

    await supabase.table("events").insert(  # type: ignore[attr-defined]
        {
            "account_id": account_id,
            "occurred_at": event.occurred_at.isoformat() if hasattr(event, "occurred_at") else None,
            "event_type": event.event_type,
            "payload": event.payload,
            "host": source_host,
            "source_ip": source_ip,
            "ingested_at": datetime.now(timezone.utc).isoformat(),
        }
    ).execute()

    return MessageResponse(message="Events accepted") 