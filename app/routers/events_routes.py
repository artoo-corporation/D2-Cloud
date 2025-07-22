"""Usage events ingest – streams batches to ClickHouse via Logflare HTTP."""

from __future__ import annotations

import os

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, status, Request

from app.schemas import MessageResponse
from app.schemas.events import EventIngest
from app.utils.dependencies import get_supabase_async
from app.utils.plan_limits import enforce_event_limits
from app.utils.database import query_one
from app.utils.security_utils import verify_api_token

router = APIRouter(prefix="/v1", tags=["events"])

LOGFLARE_ENDPOINT = os.getenv("LOGFLARE_HTTP_ENDPOINT", "https://api.logflare.app")
LOGFLARE_API_KEY = os.getenv("LOGFLARE_API_KEY")


@router.post("/events/ingest", response_model=MessageResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_events(
    request: Request,
    event: EventIngest,
    authorization: str = Header(...),
    supabase=Depends(get_supabase_async),
):
    token = authorization.split(" ")[-1]

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
    account_id = await verify_api_token(token, supabase)

    # Fetch account plan & enforce limits
    account = await query_one(supabase, "accounts", match={"id": account_id})
    plan = (account or {}).get("plan", "free")
    enforce_event_limits(account_id, plan, payload_size=len(event_json))

    async with httpx.AsyncClient(timeout=3) as client:
        try:
            await client.post(
                f"{LOGFLARE_ENDPOINT}/logs?source={account_id}",
                headers={"X-API-KEY": LOGFLARE_API_KEY or ""},
                json={"events": [event.model_dump()]},
            )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=503, detail="Log ingest unavailable") from exc

    return MessageResponse(message="Events accepted") 