from __future__ import annotations

"""API token management endpoints nested under /v1/accounts/{account_id}.

If an account has **no** tokens yet, the *create* endpoint allows anonymous
access and forcibly issues an ``["admin"]`` token.  Once at least one token
exists, all further operations require an existing admin token in the
Authorization header.
"""

import secrets
from uuid import uuid4
from hashlib import sha256
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Path, status

from app.models import (
    APITokenResponse,
    MessageResponse,
    TokenCreateRequest,
    TokenCreateResponse,
)
from app.utils.dependencies import get_supabase_async, require_token_admin
from app.utils.database import insert_data, query_data, update_data
from app.utils.security_utils import hash_token

API_TOKEN_TABLE = "api_tokens"
TOKEN_PREFIX = "d2_"

router = APIRouter(prefix="/v1/accounts/{account_id}", tags=["tokens"])


async def _token_count(supabase, account_id: str) -> int:
    resp = await query_data(
        supabase,
        API_TOKEN_TABLE,
        filters={"account_id": account_id},
        select_fields="id",
    )
    return len(getattr(resp, "data", []) or [])


# ---------------------------------------------------------------------------
# Create token (admin-only *after* bootstrap)
# ---------------------------------------------------------------------------


@router.post(
    "/tokens",
    response_model=TokenCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_token(
    account_id: str = Path(..., description="Target account ID"),
    payload: TokenCreateRequest | None = None,
    admin_account: str | None = Depends(require_token_admin),  # None during bootstrap
    supabase=Depends(get_supabase_async),
):
    """Issue a new API token.

    Behaviour:
    • If the account currently has **zero** tokens we allow unauthenticated
      creation and force ``scopes=["admin"]``.
    • Otherwise the caller must present an existing *admin* token.
    """

    existing = await _token_count(supabase, account_id)

    if existing:
        # must have passed require_token_admin so admin_account equals account_id
        if admin_account != account_id:
            raise HTTPException(status_code=403, detail="account_mismatch")
        scopes = ["admin"]  # enforce admin scope regardless of payload
    else:
        # Bootstrap path – first token is READ ONLY
        scopes = ["read"]

    # Generate token & identifiers
    raw_token = f"{TOKEN_PREFIX}{secrets.token_urlsafe(32)}"
    token_id = str(uuid4())
    token_sha = sha256(raw_token.encode()).hexdigest()
    token_sha_hashed = await hash_token(token_sha)

    await insert_data(
        supabase,
        API_TOKEN_TABLE,
        {
            "token_id": token_id,
            "token_sha256": token_sha_hashed,
            "account_id": account_id,
            "scopes": scopes,
            "expires_at": payload.expires_at if payload else None,
        },
    )

    return TokenCreateResponse(
        token_id=token_id,
        token=raw_token,
        scopes=scopes,
        expires_at=payload.expires_at if payload else None,
    )


# ---------------------------------------------------------------------------
# List tokens (admin-only)
# ---------------------------------------------------------------------------


@router.get("/tokens", response_model=list[APITokenResponse])
async def list_tokens(
    account_id: str = Path(...),
    caller_account: str = Depends(require_token_admin),
    supabase=Depends(get_supabase_async),
):
    if caller_account != account_id:
        raise HTTPException(status_code=403, detail="account_mismatch")

    resp = await query_data(
        supabase,
        API_TOKEN_TABLE,
        filters={"account_id": account_id},
        select_fields="token_id,scopes,expires_at,revoked_at",
    )

    rows = getattr(resp, "data", None) or []
    return [APITokenResponse(**row) for row in rows]


# ---------------------------------------------------------------------------
# Revoke token (admin-only)
# ---------------------------------------------------------------------------


@router.delete(
    "/tokens/{token_id}",
    response_model=MessageResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def revoke_token(
    account_id: str = Path(...),
    token_id: str = Path(..., description="Token ID to revoke"),
    caller_account: str = Depends(require_token_admin),
    supabase=Depends(get_supabase_async),
):
    if caller_account != account_id:
        raise HTTPException(status_code=403, detail="account_mismatch")

    await update_data(
        supabase,
        API_TOKEN_TABLE,
        update_values={"revoked_at": datetime.now(timezone.utc)},
        filters={"account_id": account_id, "token_id": token_id},
        error_message="token_revoke_failed",
    )

    return MessageResponse(message="token_revoked") 