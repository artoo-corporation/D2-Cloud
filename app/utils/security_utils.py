"""Authentication, authorization & signing helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, Union

import base64
import json
import os
import bcrypt
import hmac

from fastapi import HTTPException, status
from jose import jwk as jose_jwk
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.utils.dependencies import get_supabase_async
from app.utils.database import query_one, query_data
from app.main import APP_ENV

API_TOKEN_TABLE = "api_tokens"
JWKS_TABLE = "jwks_keys"
autoerror = False if APP_ENV == "development" else True

# ---------------------------------------------------------------------------
# Supabase Auth JWT verification helpers
# ---------------------------------------------------------------------------

async def verify_supabase_jwt(token: str, admin_only: bool = False) -> str:
    """Validate a Supabase Auth JWT and return the caller's account_id.

    Admin enforcement:
    - If the users row contains either `is_admin` (truthy) or `role` in {"admin","owner"},
      we enforce that when `admin_only=True`. If neither field exists, we treat
      the user as admin for backward compatibility.
    """
    try:
        # Acquire a supabase client via the same factory used by dependencies
        agen = get_supabase_async()
        supabase = await agen.__anext__()  # get first (and only) yield
        try:
            user_response = await supabase.auth.get_user(token)
            supabase_user = getattr(user_response, "user", None)
            if not supabase_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_supabase_token")

            user_auth_id = getattr(supabase_user, "id", None)
            if not user_auth_id:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_supabase_token")

            resp = await query_data(
                supabase,
                table_name="users",
                filters={"user_id": user_auth_id},
                select_fields="*",
            )
            rows = getattr(resp, "data", None) or []
            if not rows:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user_not_found")

            row = rows[0]
            account_id = row.get("account_id") or row.get("org_id")
            if not account_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="account_mapping_not_found")

            if admin_only:
                role = row.get("role")
                if role is not None and role not in {"admin", "owner"}:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin_required")

            return str(account_id)
        finally:
            close_coro = getattr(supabase, "aclose", None)
            if callable(close_coro):
                await close_coro()
    except HTTPException as http_exc:
        raise http_exc
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="supabase_verification_error")


# (helper removed – logic folded into verify_supabase_jwt)


async def hash_token(raw: str) -> str:
    return bcrypt.hashpw(raw.encode(), bcrypt.gensalt()).decode()


def _verify_hash(raw: str, hashed: str) -> bool:
    return bcrypt.checkpw(raw.encode(), hashed.encode())

# ---------------------------------------------------------------------------
# Scalable token lookup helper (reuse JWK_AES_KEY as pepper)
# ---------------------------------------------------------------------------

_JWK_AES_KEY_ENV = "JWK_AES_KEY"


def compute_token_lookup(raw_token: str) -> str | None:
    """Return HMAC(pepper, sha256(raw_token)) using JWK_AES_KEY as pepper.

    If JWK_AES_KEY is not configured (e.g., local dev), return None so callers
    can skip the indexed lookup and fall back to the legacy path.
    """
    key_b64 = os.getenv(_JWK_AES_KEY_ENV)
    if not key_b64:
        return None
    try:
        pepper = base64.urlsafe_b64decode(key_b64)
    except Exception:  # noqa: BLE001
        return None
    token_sha = sha256(raw_token.encode()).hexdigest()
    return hmac.new(pepper, token_sha.encode(), sha256).hexdigest()


async def verify_api_token(
    token: str,
    supabase,
    admin_only: bool = False,
    *,
    return_scopes: bool = False,
    return_details: bool = False,
) -> str | tuple[str, list[str]] | dict:
    """Validate a bearer token and **optionally** return its scopes.

    Behaviour upgrades:
    1. If the token string *looks* like a JWT (contains two ``.`` separators),
       we parse the claims **without** verifying the signature.  The caller is
       responsible for signature checks when needed (the control-plane trusts
       transport-layer secrecy for API tokens).
    2. Otherwise we fall back to the existing ``api_tokens`` table lookup.

    When ``return_scopes`` is ``True`` we return ``(account_id, scopes)``.
    Existing call-sites that expect a bare ``account_id`` continue to work.

    When ``return_details`` is ``True`` we return a mapping including
    ``account_id``, ``scopes`` and ``token_id``.
    """

    # ------------------------------------------------------------------
    # Only opaque D2 tokens are supported going forward
    # ------------------------------------------------------------------

    if not token.startswith("d2_"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format")

    # ------------------------------------------------------------------
    # Scalable lookup: use HMAC-peppered index when available; otherwise fallback
    # to legacy full-scan with bcrypt comparisons.
    # ------------------------------------------------------------------

    token_sha = sha256(token.encode()).hexdigest()
    row = None
    lookup = compute_token_lookup(token)
    if lookup is not None:
        # Try fast-path by keyed lookup
        resp = await query_data(
            supabase,
            API_TOKEN_TABLE,
            filters={"token_lookup": lookup},
            select_fields="token_id,token_sha256,scopes,account_id,expires_at,revoked_at",
        )
        for candidate in getattr(resp, "data", []) or []:
            stored_hash = candidate.get("token_sha256", "")
            if stored_hash and (stored_hash.startswith("$2b") or stored_hash.startswith("$2a")):
                if _verify_hash(token_sha, stored_hash):
                    row = candidate
                    break
    if row is None:
        # Fallback: full scan (backward compatibility, slower)
        resp = await query_data(
            supabase,
            API_TOKEN_TABLE,
            filters={},
            select_fields="token_id,token_sha256,scopes,account_id,expires_at,revoked_at",
        )
        for candidate in getattr(resp, "data", []) or []:
            stored_hash = candidate.get("token_sha256", "")
            if stored_hash and (stored_hash.startswith("$2b") or stored_hash.startswith("$2a")):
                if _verify_hash(token_sha, stored_hash):
                    row = candidate
                    break

    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Revocation / expiry
    if row.get("revoked_at") is not None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token revoked")

    if row.get("expires_at") and datetime.fromisoformat(row["expires_at"]).astimezone(timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")

    scopes = row.get("scopes") or []

    if admin_only and "admin" not in scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin scope required")

    if return_scopes:
        return row["account_id"], (row.get("scopes") or [])

    if return_details:
        return {
            "account_id": row["account_id"],
            "scopes": scopes,
            "token_id": row.get("token_id"),
            "user_id": row.get("created_by_user_id"),
        }

    return row["account_id"]


def generate_rsa_jwk() -> Dict[str, Any]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_jwk = jose_jwk.construct(private_pem, algorithm="RS256").to_dict()
    public_jwk = jose_jwk.construct(public_pem, algorithm="RS256").to_dict()
    return {"private": private_jwk, "public": public_jwk}

# ---------------------------------------------------------------------------
# AES-GCM encryption helpers for storing private JWKs at rest
# ---------------------------------------------------------------------------

_AES_KEY_ENV = "JWK_AES_KEY"  # Must be a 32-byte urlsafe-b64 key


def _get_aes_key() -> bytes | None:
    key_b64 = os.getenv(_AES_KEY_ENV)
    if not key_b64:
        return None
    try:
        # Add padding if needed for base64url decoding
        padding_needed = (4 - len(key_b64) % 4) % 4
        key_b64_padded = key_b64 + '=' * padding_needed
        key_bytes = base64.urlsafe_b64decode(key_b64_padded)
        if len(key_bytes) != 32:
            raise RuntimeError(f"Invalid {_AES_KEY_ENV} – decoded key is {len(key_bytes)} bytes, expected 32 bytes")
        return key_bytes
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"Invalid {_AES_KEY_ENV} – must be base64url-encoded 32-byte key. Error: {e}")


def encrypt_private_jwk(jwk: Dict[str, Any]) -> str:
    key = _get_aes_key()
    if key is None:
        # Dev environment – store as plain JSON string (explicitly marked)
        return json.dumps({"__plain__": True, "jwk": jwk})

    aes = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, json.dumps(jwk).encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt_private_jwk(blob: str | Dict[str, Any]) -> Dict[str, Any]:
    """Return the JWK dict from either plain JSON dict, marked plain-string or
    AES-GCM encrypted base64 string.
    """

    # Fast path – value already a dict (legacy rows or test fixtures)
    if isinstance(blob, dict):
        return blob

    key = _get_aes_key()

    # Might be a plain JSON string – attempt to parse
    try:
        data = json.loads(blob)
        if isinstance(data, dict) and data.get("__plain__"):
            return data["jwk"]
    except json.JSONDecodeError:
        pass  # Encrypted or malformed

    # Encrypted path
    if key is None:
        raise RuntimeError("Encrypted JWK but JWK_AES_KEY not set")

    raw = base64.b64decode(blob.encode())
    nonce, ciphertext = raw[:12], raw[12:]
    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode())


async def get_active_private_jwk(account_id: str, supabase) -> Dict[str, Any]:
    key_row = await query_one(
        supabase,
        JWKS_TABLE,
        match={"account_id": account_id},
        order_by=("created_at", "desc"),
    )
    if not key_row:
        raise HTTPException(status_code=500, detail="Signing key not found")

    return decrypt_private_jwk(key_row["private_jwk"]) 