from __future__ import annotations

"""API token management endpoints nested under /v1/accounts/{account_id}.

Creation of tokens is restricted to authenticated dashboard users (Supabase
session). All other token operations still require an admin token.

First-token behavior: The very first token for an account is forced to
["read"]. All subsequent tokens default to ["admin"] unless narrowed.
"""

import secrets
from uuid import uuid4
from hashlib import sha256
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Path, status

from app.models import (
    APITokenResponse,
    MessageResponse,
    TokenCreateRequest,
    TokenCreateResponse,
)
from app.models.scopes import Scope
from app.utils.dependencies import get_supabase_async, require_token_admin, require_actor_admin, Actor
from app.utils.database import insert_data, query_data, update_data
from app.utils.security_utils import hash_token, compute_token_lookup
from app.utils.logger import logger
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
# Create token (Supabase session required)
# ---------------------------------------------------------------------------


@router.post(
    "/tokens",
    response_model=TokenCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_token(
    account_id: str = Path(..., description="Target account ID"),
    payload: TokenCreateRequest | None = None,
    actor: Actor = Depends(require_actor_admin),  # Must be Supabase session (user_id present)
    supabase=Depends(get_supabase_async),
):
    """Issue a new API token.

    Behaviour:
    • Caller must be an authenticated Supabase user for the same account.
    • If this is the first token for the account, scopes are forced to ["read"].
    • Otherwise, scopes default to ["read"] unless explicitly narrowed by payload.

    Allowed scopes:
    • "read"            – bundle download, event ingest
    • "policy.publish"  – upload & publish policy bundles (requires signature header)
    • "key.upload"      – upload developer public keys
    • "event.ingest"    – send usage events
    • "metrics.read"    – read-only metrics endpoint (future)
    • "server"          – read-only role (policy.read + event.ingest)
    • "dev"             – shorthand for policy.read + policy.publish + key.upload + event.ingest
    • "admin"           – full wildcard (admin-only; includes all above)
    """

    # Enforce Supabase session and account match
    if actor.user_id is None:
        raise HTTPException(status_code=403, detail="supabase_session_required")
    if actor.account_id != account_id:
        raise HTTPException(status_code=403, detail="account_mismatch")

    existing = await _token_count(supabase, account_id)

    if existing == 0:
        scopes = ["policy.read"]
    else:
        scopes = ["policy.read"]
        if payload and payload.scopes:
            requested = {
                s.value if isinstance(s, Scope) else str(s)
                for s in payload.scopes
            }
            if "admin" in requested:
                scopes = ["admin"]
            elif "dev" in requested or requested == {"policy.read", "policy.publish", "key.upload", "event.ingest"}:
                scopes = ["dev"]
            elif "server" in requested or requested == {"policy.read", "event.ingest"}:
                scopes = ["server"]
            else:
                _non_admin = {s.value for s in Scope if s.value not in {"admin", "dev", "server"}}
                scopes = ["admin"] if requested.issuperset(_non_admin) else list(requested or {"read"})

    # Generate token & identifiers
    raw_token = f"{TOKEN_PREFIX}{secrets.token_urlsafe(32)}"
    token_id = str(uuid4())
    token_sha = sha256(raw_token.encode()).hexdigest()
    token_sha_hashed = await hash_token(token_sha)
    token_lookup = compute_token_lookup(raw_token)

    await insert_data(
        supabase,
        API_TOKEN_TABLE,
        {
            "token_id": token_id,
            "token_sha256": token_sha_hashed,
            "token_name": payload.token_name if payload and payload.token_name else None,
            **({"token_lookup": token_lookup} if token_lookup is not None else {}),
            "account_id": account_id,
            "scopes": scopes,
            "expires_at": None,
            "created_by_user_id": actor.user_id,
        },
    )

    return TokenCreateResponse(
        token_id=token_id,
        token=raw_token,
        scopes=scopes,
        expires_at=None,
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
        select_fields="token_id,token_name,scopes,expires_at,revoked_at,created_by_user_id,created_at",
    )

    rows = getattr(resp, "data", None) or []

    # Map created_by_user_id → email via public.users table if present
    user_ids = [row["created_by_user_id"] for row in rows if row.get("created_by_user_id")]
    name_map: dict[str, str] = {}
    if user_ids:
        email_resp = await query_data(
            supabase,
            "users",
            filters={"user_id": ("in", user_ids)},
            select_fields="user_id,display_name,full_name",
        )
        for u in getattr(email_resp, "data", []) or []:
            name_map[u["user_id"]] = u.get("display_name") or u.get("full_name", "")

    enriched = []
    for row in rows:
        row["created_by_name"] = name_map.get(row.get("created_by_user_id", ""))
        enriched.append(APITokenResponse(**row))

    return enriched


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