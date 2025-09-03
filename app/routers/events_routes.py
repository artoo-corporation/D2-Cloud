"""Usage events ingest – streams batches to ClickHouse via Logflare HTTP."""

from __future__ import annotations

import os

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, status, Request, Query
from fastapi.responses import JSONResponse

from app.models import AuditAction, AuditStatus, AuthContext, EventRecord, MessageResponse
from app.models.events import EventIngest
from app.utils.audit import log_audit_event
from app.utils.database import query_one
from app.utils.dependencies import get_supabase_async
from app.utils.plans import effective_plan, enforce_event_limits
from app.utils.require_scope import require_scope
from datetime import datetime, timezone

router = APIRouter(prefix="/v1", tags=["events"])

LOGFLARE_ENDPOINT = os.getenv("LOGFLARE_HTTP_ENDPOINT", "https://api.logflare.app")
LOGFLARE_API_KEY = os.getenv("LOGFLARE_API_KEY")

# SDK event type mapping to audit actions
SDK_EVENT_TO_AUDIT_MAP = {
    "tool_invoked": AuditAction.tool_invocation,  # Match exact SDK event type
    "authz_decision": AuditAction.auth_decision,
    "policy_poll": AuditAction.policy_poll,
    "policy_load": AuditAction.policy_load,
    "jwks_fetch": AuditAction.jwks_fetch,
    "context_leak": AuditAction.context_leak,
    "missing_policy": AuditAction.missing_policy,
    "sync_in_async_denied": AuditAction.sync_in_async_denied,
    
    # Threading security events (NEW 2025-08-28)
    "context_submission": AuditAction.context_submission,
    "context_missing_actor": AuditAction.context_missing_actor,
    "context_leak_detected": AuditAction.context_leak_detected,
    "context_actor_override": AuditAction.context_actor_override,
    "thread_entrypoint": AuditAction.thread_entrypoint,
    "d2_no_context_error": AuditAction.context_no_context_error,
}


async def _create_audit_from_sdk_event(supabase, account_id: str, single_event, user_id: str = None) -> None:
    """
    Convert SDK telemetry events into audit log entries for comprehensive tracking.
    
    This captures authorization decisions, tool invocations, and other SDK behaviors
    in the unified audit log for frontend display.
    """
    try:
        # Map SDK event types to audit actions
        audit_action = SDK_EVENT_TO_AUDIT_MAP.get(single_event.event_type)
        if not audit_action:
            return  # Not a trackable SDK event
        
        payload = single_event.payload or {}
        
        # Determine status from event payload (matching SDK telemetry structure)
        status = AuditStatus.success
        if single_event.event_type == "tool_invoked":
            # For tool invocations, check the decision field
            decision = payload.get("decision")
            if decision == "denied":
                status = AuditStatus.denied
            elif decision == "allowed":
                status = AuditStatus.allowed
        elif single_event.event_type == "authz_decision":
            # For auth decisions, check if access was allowed/denied
            decision = payload.get("decision") or payload.get("allowed")
            if decision is False or decision == "denied":
                status = AuditStatus.denied
            elif decision is True or decision == "allowed":
                status = AuditStatus.allowed
        # Threading security event status mapping (NEW 2025-08-28)
        elif single_event.event_type in ["context_missing_actor", "d2_no_context_error"]:
            status = AuditStatus.context_violation  # Security violation - no context
        elif single_event.event_type == "context_actor_override":
            status = AuditStatus.security_override  # Potential confused deputy
        elif single_event.event_type in ["context_leak_detected", "context_leak"]:
            status = AuditStatus.context_hygiene  # Context cleanup issues
        elif single_event.event_type in ["context_submission", "thread_entrypoint"]:
            # These are informational tracking events
            status = AuditStatus.success
        elif "error" in payload or "failure" in payload or payload.get("status") == "error":
            status = AuditStatus.failure
        
        # Extract SDK telemetry metadata for audit context
        metadata = {
            "tool_id": payload.get("tool_id"),
            "resource": payload.get("resource"),
            "service": payload.get("service"),  # App name from policy bundle metadata.name (authoritative source)
            "host": payload.get("host"),
            "pid": payload.get("pid"),
            "policy_etag": payload.get("policy_etag"),
        }
        
        # Threading security specific metadata (NEW 2025-08-28)
        if single_event.event_type in ["context_submission", "context_missing_actor", "context_leak_detected", 
                                       "context_actor_override", "thread_entrypoint", "d2_no_context_error"]:
            threading_metadata = {
                "thread_name": payload.get("thread_name"),
                "method": payload.get("method"),  # explicit_actor, ambient_snapshot
                "require_actor": payload.get("require_actor"),
                "ambient_user": payload.get("ambient_user"),
                "explicit_user": payload.get("explicit_user"),
            }
            # Add non-None threading metadata
            metadata.update({k: v for k, v in threading_metadata.items() if v is not None})
        
        # Remove None values
        metadata = {k: v for k, v in metadata.items() if v is not None}
        
        # Log to audit table with enhanced metadata
        await log_audit_event(
            supabase,
            action=audit_action,
            actor_id=account_id,
            status=status,
            user_id=user_id,
            resource_type="tool" if single_event.event_type == "tool_invoked" else None,
            resource_id=payload.get("tool_id") or payload.get("resource"),
            metadata=metadata if metadata else None,
        )
        
    except Exception:
        # Never let audit logging break event ingestion
        # In production, you might want to log this error to monitoring
        pass


@router.post("/events/ingest", response_model=MessageResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_events(
    request: Request,
    batch: EventIngest,  # Now expects batched events
    auth: AuthContext = Depends(require_scope("event.ingest")),
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

        # Create audit log entry for this event
        await _create_audit_from_sdk_event(supabase, auth.account_id, event, auth.user_id)

    return MessageResponse(message=f"Accepted {len(batch.events)} events")


@router.get("/events", response_model=list[EventRecord])
async def list_events(
    limit: int = Query(100, ge=1, le=1000),
    cursor: str | None = Query(None, description="Cursor of form '<iso>,<uuid>' from X-Next-Cursor header"),
    auth: AuthContext = Depends(require_scope("metrics.read")),
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