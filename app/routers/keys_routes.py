from __future__ import annotations

"""Public Ed25519 key management endpoints (per-tenant)."""

import base64
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, status, Query
from app.utils.require_scope import require_scope

from app.models import MessageResponse, PublicKeyAddRequest, PublicKeyResponse, TokenScopeError
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
    payload: PublicKeyAddRequest,
    supabase=Depends(get_supabase_async),
    account_id: str = Depends(require_scope("key.upload")),
):
    # account_id supplied by dependency – admin scope replaced by key.upload capability

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
            "account_id": account_id,
            "key_id": key_id,
            "algo": "ed25519",
            "public_key": "\\x" + key_bytes.hex(),  # bytea hex format for PostgREST
        },
    )

    if result == "duplicate":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="key_already_exists")

    return MessageResponse(message="key_added")


@router.delete("/{key_id}", response_model=MessageResponse, status_code=status.HTTP_202_ACCEPTED)
async def revoke_key(
    key_id: str,
    account_id: str = Depends(require_token_admin),
    supabase=Depends(get_supabase_async),
):
    await update_data(
        supabase,
        PUBLIC_KEYS_TABLE,
        update_values={"revoked_at": datetime.now(timezone.utc)},
        filters={"account_id": account_id, "key_id": key_id},
        error_message="key_revoke_failed",
    )

    return MessageResponse(message="key_revoked")


@router.get("", response_model=list[PublicKeyResponse])
async def list_keys(
    include_revoked: int = Query(0, ge=0, le=1),
    account_id: str = Depends(require_token_admin),
    supabase=Depends(get_supabase_async),
):
    filters = {"account_id": account_id}
    if not include_revoked:
        filters["revoked_at"] = ("is", "null")

    resp = await query_data(
        supabase,
        PUBLIC_KEYS_TABLE,
        filters=filters,
        select_fields="key_id,algo,public_key,created_at,revoked_at",
    )
    rows = getattr(resp, "data", None) or []
    
    # Convert public keys from hex format back to base64
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
        result.append(PublicKeyResponse(**row))
    
    return result 