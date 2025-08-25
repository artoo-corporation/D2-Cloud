from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import JSONResponse

from app.models import AuditLogRecord
from app.utils.dependencies import get_supabase_async
from app.utils.require_scope import require_scope
from app.utils.database import query_many

router = APIRouter(prefix="/v1/audit", tags=["audit"])

AUDIT_TABLE = "audit_logs"

@router.get("", response_model=list[AuditLogRecord])
async def list_audit_logs(
    limit: int = Query(100, ge=1, le=1000),
    cursor: str | None = Query(None, description="Cursor '<iso>,<id>' from X-Next-Cursor header"),
    account_id: str = Depends(require_scope("admin")),
    supabase=Depends(get_supabase_async),
):
    """Paginated audit log list (newest first)."""

    match = {"actor_id": account_id}
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
        select_fields="id,actor_id,token_id,user_id,action,key_id,version,created_at",
        limit=limit,
    )

    rows = rows_raw if isinstance(rows_raw, list) else getattr(rows_raw, "data", [])

    next_cursor = f"{rows[-1]['created_at']},{rows[-1]['id']}" if rows else None

    return JSONResponse(
        content=[AuditLogRecord(**r).model_dump(mode="json") for r in rows],
        headers={"X-Next-Cursor": next_cursor or ""},
    )
