from __future__ import annotations

"""API token management endpoints nested under /v1/accounts/{account_id}.

Creation of tokens is restricted to authenticated dashboard users (Supabase
session). All other token operations still require a privileged token (admin scope).

Token types: Only two token roles are supported – "dev" and "server".
"""

from uuid import uuid4
from hashlib import sha256
from datetime import datetime, timezone
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Path, status

from app.models import (
    APITokenResponse,
    AuditAction,
    AuditStatus,
    MessageResponse,
    ServerTokenRequest,
    TokenCreateRequest,
    TokenCreateResponse,
)
from app.models.scopes import Scope
from app.utils.audit import log_audit_event
from app.utils.dependencies import get_supabase_async
from app.utils.auth import require_auth
from app.utils.database import insert_data, query_data, query_one, update_data
from app.utils.security_utils import hash_token, compute_token_lookup, verify_api_token
from app.utils.utils import normalize_app_name

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
    auth: AuthContext = Depends(require_auth(require_privileged=True, require_user=True)),  # Must be Supabase session (user_id present)
    supabase=Depends(get_supabase_async),
):
    """Issue a new API token.

    Behaviour:
    • Caller must be an authenticated Supabase user for the same account.
    • If this is the first token for the account, scopes are forced to ["read"].
    • Otherwise, scopes default to ["read"] unless explicitly narrowed by payload.

    Token roles:
    • "dev"             – developer token (policy.read + policy.publish + key.upload + event.ingest)
    • "server"          – service token (policy.read + event.ingest)
    """

    # Enforce account match (user_id is guaranteed by require_user=True)
    if auth.account_id != account_id:
        raise HTTPException(status_code=403, detail="account_mismatch")


    # Determine token role (only 'dev' or 'server' allowed)
    scopes: list[str]
    requested = set()
    if payload and payload.scopes:
        requested = {
            s.value if isinstance(s, Scope) else str(s)
            for s in payload.scopes
        }
    if not requested or "dev" in requested:
        scopes = ["dev"]
    elif "server" in requested:
        scopes = ["server"]
    else:
        raise HTTPException(status_code=400, detail="invalid_token_role")

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
            "account_id": auth.account_id,
            "scopes": scopes,
            "expires_at": None,
            "created_by_user_id": auth.user_id,  # Who created the token
            "app_name": normalize_app_name(payload.app_name) if payload and payload.app_name else None,
        },
    )

    # Audit log token creation
    await log_audit_event(
        supabase,
        action=AuditAction.token_create,
        actor_id=auth.account_id,
        status=AuditStatus.success,
        token_id=token_id,
        user_id=auth.user_id,
        resource_type="token",
        resource_id=token_id,
        metadata={
            "token_name": payload.token_name if payload else None,
            "scopes": scopes,
            "app_name": normalize_app_name(payload.app_name) if payload and payload.app_name else None,
        },
    )

    return TokenCreateResponse(
        token_id=token_id,
        token=raw_token,
        scopes=scopes,
        expires_at=None,
    )


# ---------------------------------------------------------------------------
# Create server token (account-level, not user-assigned)
# ---------------------------------------------------------------------------


@router.post(
    "/tokens/server",
    response_model=TokenCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_server_token(
    account_id: str = Path(..., description="Target account ID"),
    payload: ServerTokenRequest | None = None,
    auth: AuthContext = Depends(require_auth(require_privileged=True)),  # Must be account admin (can be token or user)
    supabase=Depends(get_supabase_async),
):
    """Issue a new server API token.
    
    Server tokens are designed for server-to-server communication:
    • Fixed scopes: ["server"] (policy.read + event.ingest)
    • Not assigned to individual users
    • Survive user departures/role changes
    • Intended for production services
    """
    
    # Ensure caller has admin access to the account
    if auth.account_id != account_id:
        raise HTTPException(status_code=403, detail="account_mismatch")
    
    # Server tokens always get "server" scope (policy.read + event.ingest)
    scopes = [Scope.server]
    
    # Generate token
    token_id = str(uuid4())
    raw_token = f"d2_{secrets.token_urlsafe(32)}"
    token_sha = sha256(raw_token.encode()).hexdigest()
    hashed_token = await hash_token(token_sha)
    
    # Insert into database
    await insert_data(
        supabase,
        "api_tokens",
        {
            "token_id": token_id,
            "account_id": auth.account_id,
            "token_sha256": hashed_token,  # Column is token_sha256, not token_hash
            "token_lookup": compute_token_lookup(raw_token),  # Column is token_lookup, not lookup
            "scopes": [s.value for s in scopes],
            "token_name": payload.token_name if payload else "Server Token",
            "app_name": payload.app_name if payload else None,
            "created_by_user_id": auth.user_id,  # Track who created the server token
            "expires_at": None,  # Server tokens don't expire by default
        },
    )
    
    # Log audit event
    await log_audit_event(
        supabase,
        action=AuditAction.token_create,
        actor_id=auth.account_id,
        status=AuditStatus.success,
        token_id=token_id,
        user_id=auth.user_id,  # Will be None for server tokens, which is fine
        resource_type="token",
        resource_id=token_id,
        metadata={
            "token_name": payload.token_name if payload else "Server Token",
            "token_type": "server",
            "app_name": payload.app_name if payload else None,
        },
    )
    
    return TokenCreateResponse(
        token_id=token_id,
        token=raw_token,  # Return plaintext token (only time it's visible)
        scopes=[s.value for s in scopes],
        expires_at=None,
    )


# ---------------------------------------------------------------------------
# List tokens (owner/dev only)
# ---------------------------------------------------------------------------


@router.get("/tokens", response_model=list[APITokenResponse])
async def list_tokens(
    account_id: str = Path(...),
    auth: AuthContext = Depends(require_auth(require_privileged=True)),
    supabase=Depends(get_supabase_async),
):
    if auth.account_id != account_id:
        raise HTTPException(status_code=403, detail="account_mismatch")

    resp = await query_data(
        supabase,
        API_TOKEN_TABLE,
        filters={"account_id": auth.account_id},
        select_fields="token_id,token_name,app_name,scopes,expires_at,revoked_at,created_by_user_id,created_at",
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
    auth: AuthContext = Depends(require_auth(require_privileged=True)),
    supabase=Depends(get_supabase_async),
):
    if auth.account_id != account_id:
        raise HTTPException(status_code=403, detail="account_mismatch")

    await update_data(
        supabase,
        API_TOKEN_TABLE,
        update_values={"revoked_at": datetime.now(timezone.utc)},
        filters={"account_id": auth.account_id, "token_id": token_id},
        error_message="token_revoke_failed",
    )

    # Audit log token revocation with user attribution
    await log_audit_event(
        supabase,
        action=AuditAction.token_revoke,
        actor_id=auth.account_id,
        status=AuditStatus.success,
        token_id=token_id,
        user_id=auth.user_id,
        resource_type="token",
        resource_id=token_id,
    )

    return MessageResponse(message="token_revoked")


# ---------------------------------------------------------------------------
# Token rotation
# ---------------------------------------------------------------------------


@router.post(
    "/tokens/{token_id}/rotate",
    response_model=TokenCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def rotate_token(
    account_id: str = Path(...),
    token_id: str = Path(..., description="Token ID to rotate"),
    auth: AuthContext = Depends(require_auth(require_privileged=True, require_user=True)),
    supabase=Depends(get_supabase_async),
):
    """Rotate a token: create new token with same settings, revoke old one."""
    
    if auth.account_id != account_id:
        raise HTTPException(status_code=403, detail="account_mismatch")

    # Get existing token details
    existing_token = await query_one(
        supabase,
        API_TOKEN_TABLE,
        match={"account_id": auth.account_id, "token_id": token_id},
    )
    
    if not existing_token:
        raise HTTPException(status_code=404, detail="token_not_found")
    
    if existing_token.get("revoked_at"):
        raise HTTPException(status_code=410, detail="token_already_revoked")

    # Generate new token with same properties
    new_token_id = str(uuid4())
    raw_token = f"{TOKEN_PREFIX}{secrets.token_urlsafe(32)}"
    token_sha = sha256(raw_token.encode()).hexdigest()
    token_sha_hashed = await hash_token(token_sha)
    token_lookup = compute_token_lookup(raw_token)

    # Create new token
    await insert_data(
        supabase,
        API_TOKEN_TABLE,
        {
            "token_id": new_token_id,
            "token_sha256": token_sha_hashed,
            "token_name": existing_token.get("token_name"),
            **({"token_lookup": token_lookup} if token_lookup is not None else {}),
            "account_id": auth.account_id,
            "scopes": existing_token.get("scopes", []),
            "expires_at": None,
            "created_by_user_id": existing_token.get("created_by_user_id"),
            "app_name": existing_token.get("app_name"),
        },
    )

    # Revoke old token
    await update_data(
        supabase,
        API_TOKEN_TABLE,
        update_values={"revoked_at": datetime.now(timezone.utc)},
        filters={"account_id": auth.account_id, "token_id": token_id},
        error_message="token_revoke_failed",
    )

    # Audit log token rotation with user attribution
    await log_audit_event(
        supabase,
        action=AuditAction.token_rotate,
        actor_id=auth.account_id,
        status=AuditStatus.success,
        token_id=new_token_id,  # New token ID
        user_id=existing_token.get("created_by_user_id"),
        resource_type="token",
        resource_id=token_id,  # Original token being rotated
        metadata={
            "old_token_id": token_id,
            "new_token_id": new_token_id,
            "token_name": existing_token.get("token_name"),
        },
    )

    return TokenCreateResponse(
        token_id=new_token_id,
        token=raw_token,
        scopes=existing_token.get("scopes", []),
        expires_at=None,
    )


# ---------------------------------------------------------------------------
# Token scopes (for frontend dropdown)
# ---------------------------------------------------------------------------


@router.get("/scopes", response_model=list[dict])
async def list_available_scopes():
    """Return available token role scopes with descriptions (for token creation dropdown)."""
    
    # Token roles with their descriptions
    role_scopes = {
        Scope.dev: {
            "label": "Developer", 
            "description": "Policy read/write, key upload, event ingest"
        },
        Scope.server: {
            "label": "Server",
            "description": "Policy read, event ingest"
        }
    }
    
    return [
        {
            "value": scope.value,
            "label": info["label"],
            "description": info["description"]
        }
        for scope, info in role_scopes.items()
    ]


# ---------------------------------------------------------------------------
# User listing for token assignment (Frontend only)
# ---------------------------------------------------------------------------

from typing import Dict

@router.get("/users")
async def list_account_users(
    account_id: str = Path(..., description="Account ID"),
    auth: AuthContext = Depends(require_auth(require_privileged=True, require_user=True)),
    supabase=Depends(get_supabase_async),
):
    """List all users in the account for token assignment dropdown.
    
    Returns:
        List of users with basic info for frontend dropdowns
    """
    # Enforce account match (user_id is guaranteed by require_user=True)
    if auth.account_id != account_id:
        raise HTTPException(status_code=403, detail="account_mismatch")

    # Query users in the account
    resp = await query_data(
        supabase,
        "users",
        filters={"account_id": auth.account_id},
        select_fields="user_id,email,display_name,full_name"
    )
    
    users_data = getattr(resp, "data", []) or []
    
    # Format for frontend dropdown
    users = []
    for user in users_data:
        display_name = user.get("display_name") or user.get("full_name") or user.get("email") or "Unknown User"
        users.append({
            "user_id": user["user_id"],
            "display_name": display_name,
            "email": user.get("email"),
            "full_name": user.get("full_name")
        })
    
    return {"users": users} 