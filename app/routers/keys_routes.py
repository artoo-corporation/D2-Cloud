from __future__ import annotations

"""Public Ed25519 key management endpoints (per-tenant)."""

import base64
import uuid
import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status, Query
from app.utils.auth import require_auth

from app.models import AuditAction, AuditStatus, AuthContext, MessageResponse, PublicKeyAddRequest, PublicKeyResponse, TokenScopeError
from app.utils.audit import log_audit_event
from app.utils.dependencies import get_supabase_async
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
    auth: AuthContext = Depends(require_auth("key.upload")),
    supabase=Depends(get_supabase_async),
):
    # auth.account_id supplied by dependency – admin scope replaced by key.upload capability

    # Validate base64 public key
    try:
        key_bytes = base64.b64decode(payload.public_key)
        print(f"key_bytes: {key_bytes}")
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="invalid_public_key")

    # Generate system-controlled key ID (SECURITY: Never use user input for key IDs)
    # Format: ed_<12-char-hex> based on key content + timestamp for uniqueness
    key_hash = hashlib.sha256(key_bytes + datetime.now(timezone.utc).isoformat().encode()).hexdigest()
    key_id = f"ed_{key_hash[:12]}"

    # Build insert data - only include user_id if it exists (server tokens have None)
    insert_data_dict = {
        "account_id": auth.account_id,
        "key_id": key_id,
        "algo": "ed25519",
        "public_key": "\\x" + key_bytes.hex(),  # bytea hex format for PostgREST
    }
    
    # Only add user_id if it's not None (server tokens don't have user_id)
    if auth.user_id is not None:
        insert_data_dict["user_id"] = auth.user_id
    
    result = await insert_data(
        supabase,
        PUBLIC_KEYS_TABLE,
        insert_data_dict,
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
        resource_type="key",
        resource_id=key_id,
        metadata={
            "algorithm": "ed25519",
        },
    )

    return MessageResponse(message=f"key_added: {key_id}")


@router.delete("/{key_id}", response_model=MessageResponse, status_code=status.HTTP_202_ACCEPTED)
async def revoke_key(
    key_id: str,
    auth: AuthContext = Depends(require_auth("key.upload")),
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
        resource_type="key",
        resource_id=key_id,
    )

    return MessageResponse(message="key_revoked")


@router.get("", response_model=list[PublicKeyResponse])
async def list_keys(
    include_revoked: int = Query(0, ge=0, le=1),
    auth: AuthContext = Depends(require_auth(require_privileged=True, require_user=True)),  # OAuth users (frontend) can list keys
    supabase=Depends(get_supabase_async),
):
    # Get public keys for the account
    query = supabase.table(PUBLIC_KEYS_TABLE).select(
        "key_id,algo,public_key,created_at,revoked_at,user_id"
    ).eq("account_id", auth.account_id)
    
    if not include_revoked:
        query = query.is_("revoked_at", "null")
    
    resp = await query.execute()
    rows = getattr(resp, "data", None) or []
    
    # Get user names for attribution
    user_ids = [row["user_id"] for row in rows if row.get("user_id")]
    user_names = {}
    
    if user_ids:
        user_resp = await query_data(
            supabase,
            "users",
            filters={"user_id": ("in", user_ids)},
            select_fields="user_id,display_name,full_name,email"
        )
        user_data = getattr(user_resp, "data", []) or []
        for u in user_data:
            user_names[u["user_id"]] = u.get("display_name") or u.get("full_name") or u.get("email") or "Unknown User"
    
    # Convert public keys from hex format back to base64 and add user names
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
        
        # Set uploaded_by_name with actual user name lookup
        if row.get("user_id") is None:
            # Key was uploaded by a server token (no user_id)
            uploaded_by_name = "Server Token"
        else:
            # Look up actual user name
            uploaded_by_name = user_names.get(row["user_id"], "Unknown User")
        
        row["uploaded_by_name"] = uploaded_by_name
        
        result.append(PublicKeyResponse(**row))
    
    return result 