"""JWKS endpoint – serves public keys for SDK verification."""

from __future__ import annotations

import uuid
from typing import Dict, Any

from fastapi import APIRouter, Depends, Header, Query, status, Response, Request
# Rate limiter exported by main.py
from app.main import limiter

from app.schemas import MessageResponse
from app.utils.security_utils import generate_rsa_jwk, verify_api_token, encrypt_private_jwk
from app.utils.database import insert_data, query_many
from app.utils.dependencies import get_supabase_async

router = APIRouter(prefix="/.well-known", tags=["jwks"])

# Secondary router for admin actions
rotate_router = APIRouter(prefix="/v1/jwks", tags=["jwks"])


@router.get("/jwks.json", response_model=Dict[str, Any])
@limiter.limit("60/minute")
async def get_jwks(
    request: Request,
    response: Response,
    supabase=Depends(get_supabase_async),
    account_id: str | None = Query(None),
):
    """Return either all public keys or a subset for a given tenant."""
    filters = {"account_id": account_id} if account_id else {}
    try:
        rows = await query_many(supabase, "jwks_keys", match=filters)
    except Exception:  # noqa: BLE001
        rows = []  # Supabase unavailable – return empty set

    keys = [row["public_jwk"] for row in rows if row.get("public_jwk")]
    # Strong public caching – 5 minute TTL, immutable
    response.headers["Cache-Control"] = "public, max-age=300, immutable"
    return {"keys": keys}


# ---------------------------------------------------------------------------
# Admin-only: rotate RSA key-pair for the tenant
# ---------------------------------------------------------------------------


@rotate_router.post("/rotate", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def rotate_jwk(
    authorization: str = Header(...),
    supabase=Depends(get_supabase_async),
):
    admin_token = authorization.split(" ")[-1]
    account_id = await verify_api_token(admin_token, supabase, admin_only=True)

    jwk_pair = generate_rsa_jwk()
    kid = str(uuid.uuid4())

    await insert_data(
        supabase,
        "jwks_keys",
        {
            "account_id": account_id,
            "kid": kid,
            "public_jwk": jwk_pair["public"],
            # Store encrypted private key (or plain JSON in dev if no key)
            "private_jwk": encrypt_private_jwk(jwk_pair["private"]),
        },
    )

    return MessageResponse(message="JWKS rotated")


# Re-export for main.py
__all__ = ["router", "rotate_router"] 