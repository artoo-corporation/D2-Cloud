from __future__ import annotations

"""Public Ed25519 key management endpoints (per-tenant)."""

import base64
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status, Query
from app.utils.require_scope import require_scope

from app.models import AuditAction, AuditStatus, AuthContext, MessageResponse, PublicKeyAddRequest, PublicKeyResponse, TokenScopeError
from app.utils.audit import log_audit_event
from app.utils.dependencies import get_supabase_async, require_token_admin
from app.utils.database import insert_data, update_data, query_data

router = APIRouter(prefix="/v1/keys", tags=["keys"])

PUBLIC_KEYS_TABLE = "public_keys"


@router.post(
    "",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    responses={403: {"model": TokenScopeError}},
)
async def add_public_key(
    request: Request,
    payload: PublicKeyAddRequest,
    auth: AuthContext = Depends(require_scope("key.upload")),
    supabase=Depends(get_supabase_async),
):
    # auth.account_id supplied by dependency – admin scope replaced by key.upload capability

    # Validate base64 public key
    try:
        key_bytes = base64.b64decode(payload.public_key)
        print(f"key_bytes: {key_bytes}")
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="invalid_public_key")

    key_id = payload.key_id or str(uuid.uuid4())

    result = await insert_data(
        supabase,
        PUBLIC_KEYS_TABLE,
        {
            "account_id": auth.account_id,
            "key_id": key_id,
            "algo": "ed25519",
            "public_key": "\\x" + key_bytes.hex(),  # bytea hex format for PostgREST
            "user_id": auth.user_id,  # Track which user uploaded this key
        },
    )

    if result == "duplicate":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="key_already_exists")

    # Audit log key upload with user attribution
    await log_audit_event(
        supabase,
        action=AuditAction.key_upload,
        actor_id=auth.account_id,
        status=AuditStatus.success,
        token_id=auth.token_id,
        user_id=auth.user_id,
        key_id=key_id,
    )

    return MessageResponse(message="key_added")


@router.delete("/{key_id}", response_model=MessageResponse, status_code=status.HTTP_202_ACCEPTED)
async def revoke_key(
    key_id: str,
    auth: AuthContext = Depends(require_scope("key.upload")),
    supabase=Depends(get_supabase_async),
):
    await update_data(
        supabase,
        PUBLIC_KEYS_TABLE,
        update_values={"revoked_at": datetime.now(timezone.utc)},
        filters={"account_id": auth.account_id, "key_id": key_id},
        error_message="key_revoke_failed",
    )

    # Audit log key revocation
    await log_audit_event(
        supabase,
        action=AuditAction.key_revoke,
        actor_id=auth.account_id,
        status=AuditStatus.success,
        token_id=auth.token_id,
        user_id=auth.user_id,
        key_id=key_id,
    )

    return MessageResponse(message="key_revoked")


@router.get("", response_model=list[PublicKeyResponse])
async def list_keys(
    include_revoked: int = Query(0, ge=0, le=1),
    auth: AuthContext = Depends(require_scope("key.upload")),
    supabase=Depends(get_supabase_async),
):
    # Build query with user name join
    query = supabase.table(PUBLIC_KEYS_TABLE).select(
        "key_id,algo,public_key,created_at,revoked_at,user_id,users:user_id(display_name,full_name)"
    ).eq("account_id", auth.account_id)
    
    if not include_revoked:
        query = query.is_("revoked_at", "null")
    
    resp = await query.execute()
    rows = getattr(resp, "data", None) or []
    
    # Convert public keys from hex format back to base64 and format user names
    result = []
    for row in rows:
        public_key_raw = row["public_key"]
        if isinstance(public_key_raw, str) and public_key_raw.startswith("\\x"):
            # Convert hex back to base64
            try:
                key_bytes = bytes.fromhex(public_key_raw[2:])
                row["public_key"] = base64.b64encode(key_bytes).decode()
            except ValueError:
                # Skip malformed keys
                continue
        
        # Extract user name from join
        user_info = row.get("users")
        uploaded_by_name = None
        if user_info:
            # Prefer display_name, fallback to full_name
            uploaded_by_name = user_info.get("display_name") or user_info.get("full_name")
        
        # Clean up the row for response model
        row.pop("users", None)  # Remove the join data
        row["uploaded_by_name"] = uploaded_by_name
        
        result.append(PublicKeyResponse(**row))
    
    return result 