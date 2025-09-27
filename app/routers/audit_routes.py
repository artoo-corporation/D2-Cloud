from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import JSONResponse

from app.models import AuditLogRecord, AuthContext
from app.utils.dependencies import get_supabase_async
from app.utils.auth import require_auth
from app.utils.database import query_many

router = APIRouter(prefix="/v1/audit", tags=["audit"])

AUDIT_TABLE = "audit_logs"

@router.get("", response_model=list[AuditLogRecord])
async def list_audit_logs(
    limit: int = Query(100, ge=1, le=1000),
    cursor: str | None = Query(None, description="Cursor '<iso>,<id>' from X-Next-Cursor header"),
    auth: AuthContext = Depends(require_auth(require_privileged=True)),
    supabase=Depends(get_supabase_async),
):
    """Paginated audit log list (newest first) with user name attribution."""

    match = {"actor_id": auth.account_id}
    or_filter = None
    if cursor:
        try:
            ts_str, id_cursor = cursor.split(",", 1)
            ts_val = datetime.fromisoformat(ts_str)
        except Exception:
            raise HTTPException(status_code=400, detail="invalid_cursor")

        iso = ts_val.isoformat()
        or_filter = f"created_at.lt.{iso},and(created_at.eq.{iso},id.lt.{id_cursor})"

    rows_raw = await query_many(
        supabase,
        AUDIT_TABLE,
        match=match,
        or_filter=or_filter,
        order_by=("created_at", "desc"),
        select_fields="id,actor_id,token_id,user_id,action,key_id,version,status,resource_type,resource_id,metadata,created_at",
        limit=limit,
    )

    rows = rows_raw if isinstance(rows_raw, list) else getattr(rows_raw, "data", [])

    # Get user names for attribution
    user_ids = {row["user_id"] for row in rows if row.get("user_id")}
    user_names = {}
    
    if user_ids:
        from app.utils.database import query_data
        user_resp = await query_data(
            supabase,
            "users",
            filters={"user_id": ("in", list(user_ids))},
            select_fields="user_id,display_name,full_name,email"
        )
        user_data = getattr(user_resp, "data", []) or []
        for u in user_data:
            user_names[u["user_id"]] = u.get("display_name") or u.get("full_name") or u.get("email")

    # Add user names to audit records
    enriched_rows = []
    for row in rows:
        actor_name = "System"  # Default for API token actions
        user_id = row.get("user_id")
        if user_id:
            actor_name = user_names.get(user_id, f"Unknown User ({user_id[:8]}...)")
        
        # Create a new dict for the response model to avoid sending raw IDs
        enriched_rows.append(
            AuditLogRecord(
                id=row["id"],
                actor_name=actor_name,
                token_id=row.get("token_id"),
                action=row["action"],
                key_id=row.get("key_id"),
                version=row.get("version"),
                status=row.get("status"),
                resource_type=row.get("resource_type"),
                resource_id=row.get("resource_id"),
                metadata=row.get("metadata"),
                created_at=row["created_at"],
            )
        )

    next_cursor = f"{rows[-1]['created_at']},{rows[-1]['id']}" if rows else None

    return JSONResponse(
        content=[r.model_dump(mode="json") for r in enriched_rows],
        headers={"X-Next-Cursor": next_cursor or ""},
    )
