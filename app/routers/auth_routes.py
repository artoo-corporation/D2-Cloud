"""Authentication & token management endpoints."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, status

from uuid import uuid4
import secrets
from hashlib import sha256

from app.schemas import (
    MessageResponse,
    MeResponse,
    TokenCreateRequest,
    TokenCreateResponse,
    APITokenResponse,
)
from app.utils.database import query_one, update_data, query_data, insert_data
from app.utils.dependencies import get_supabase_async
from app.utils.security_utils import verify_api_token, hash_token

router = APIRouter(prefix="/v1", tags=["auth"])

API_TOKEN_TABLE = "api_tokens"


@router.get("/me", response_model=MeResponse)
async def get_me(authorization: str = Header(...), supabase=Depends(get_supabase_async)):
    token = authorization.split(" ")[-1]
    account_id = await verify_api_token(token, supabase)

    account = await query_one(supabase, "accounts", match={"id": account_id})
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    return MeResponse(
        plan=account["plan"],
        metrics_enabled=account.get("metrics_enabled", False),
        poll_seconds=account.get("poll_seconds", 60),
    )


@router.post("/token/revoke", response_model=MessageResponse, status_code=status.HTTP_202_ACCEPTED)
async def revoke_token(
    token_id: str,
    authorization: str = Header(...),
    supabase=Depends(get_supabase_async),
):
    admin_token = authorization.split(" ")[-1]
    account_id = await verify_api_token(admin_token, supabase, admin_only=True)

    row = await query_one(supabase, API_TOKEN_TABLE, match={"token_id": token_id, "account_id": account_id})
    if not row:
        raise HTTPException(status_code=404, detail="Token not found")

    await update_data(
        supabase,
        API_TOKEN_TABLE,
        update_values={"revoked_at": datetime.now(timezone.utc)},
        filters={"id": row["id"]},
        error_message="Token revoke failed",
    )
    return MessageResponse(message="Token revoked")


# ---------------------------------------------------------------------------
# New: create API token
# ---------------------------------------------------------------------------


@router.post(
    "/token",
    response_model=TokenCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_token(
    payload: TokenCreateRequest,
    authorization: str = Header(...),
    supabase=Depends(get_supabase_async),
):
    """Issue a new API token (admin-only). Returns the plaintext token exactly once."""
    admin_token = authorization.split(" ")[-1]
    account_id = await verify_api_token(admin_token, supabase, admin_only=True)

    # Generate token & identifiers
    raw_token = secrets.token_urlsafe(32)
    token_id = str(uuid4())
    token_sha = sha256(raw_token.encode()).hexdigest()
    # Extra bcrypt hashing for at-rest secrecy
    token_sha_hashed = await hash_token(token_sha)

    await insert_data(
        supabase,
        API_TOKEN_TABLE,
        {
            "token_id": token_id,
            "token_sha256": token_sha_hashed,
            "account_id": account_id,
            "scopes": payload.scopes or ["read"],
            "expires_at": payload.expires_at.isoformat() if payload.expires_at else None,
        },
    )

    return TokenCreateResponse(
        token_id=token_id,
        token=raw_token,
        scopes=payload.scopes or ["read"],
        expires_at=payload.expires_at,
    )


# ---------------------------------------------------------------------------
# New: list tokens for the current account (admin)
# ---------------------------------------------------------------------------


@router.get("/tokens", response_model=list[APITokenResponse])
async def list_tokens(
    authorization: str = Header(...),
    supabase=Depends(get_supabase_async),
):
    admin_token = authorization.split(" ")[-1]
    account_id = await verify_api_token(admin_token, supabase, admin_only=True)

    resp = await query_data(
        supabase,
        API_TOKEN_TABLE,
        filters={"account_id": account_id},
        select_fields="token_id,scopes,expires_at,revoked_at",
    )

    rows = getattr(resp, "data", None) or []
    return [
        APITokenResponse(**row)  # type: ignore[arg-type]
        for row in rows
    ] 