"""Authentication, authorization & signing helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, Union

import base64
import json
import os
import bcrypt

from fastapi import HTTPException, status
from jose import jwk as jose_jwk
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.utils.dependencies import get_supabase_async
from app.utils.database import query_one, query_data
from app.models import User
from app.main import APP_ENV

API_TOKEN_TABLE = "api_tokens"
JWKS_TABLE = "jwks_keys"
autoerror = False if APP_ENV == "development" else True
security = HTTPBearer(auto_error=autoerror)


# ---------------------------------------------------------------------------
# Supabase Auth JWT verification helpers
# ---------------------------------------------------------------------------

async def verify_supabase_jwt(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    supabase: AsyncClient = Depends(get_supabase_async),  # Inject supabase client
) -> User:
    """
    Verify Supabase JWT token via supabase.auth.get_user()
    and return the corresponding user from the database.
    """
    if APP_ENV == "development":
        # logger.info(f"Using development user ID {DEV_USER_ID} for testing.")
        return await get_user_from_users_table(supabase, DEV_USER_ID)

    token = credentials.credentials
    try:
        # Validate against Supabase Auth - use await for the async client method
        user_response = await supabase.auth.get_user(token)  # Add await
        supabase_user = user_response.user

        if not supabase_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token (Supabase auth failed).",
                headers={"WWW-Authenticate": "Bearer"},  # Added header for clarity
            )

        # Extract necessary info directly from the validated Supabase user object
        user_auth_id = supabase_user.id

        if not user_auth_id:
            # Should not happen if supabase_user exists, but belts and suspenders
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not extract user auth ID from validated token.",
            )

        # Fetch user data from our users table using the auth ID
        # Pass the injected supabase client to the utility function
        user_in_db = await get_user_from_users_table(supabase, user_auth_id)

        if not user_in_db:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User record not found in database.",
            )
        return user_in_db

    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred during token verification.",
        )


# Make get_user_from_users_table async
async def get_user_from_users_table(
    supabase: AsyncClient, user_auth_id: str  # Add supabase client parameter
) -> Union[User, None]:
    
    """Fetches user details from the users table based on Supabase auth ID."""
    try:
        # Pass the injected supabase client to query_data
        response = await query_data(
            supabase,  # Pass client
            table_name="users",
            filters={"user_id": user_auth_id},
            select_fields="*",
        )

        # Check if data exists (response from execute() has a .data attribute)
        if response.data:
            user_data = response.data[0]  # Assuming user_id is unique
        return User(**user_data)
    except Exception as e:
        return None


async def hash_token(raw: str) -> str:
    return bcrypt.hashpw(raw.encode(), bcrypt.gensalt()).decode()


def _verify_hash(raw: str, hashed: str) -> bool:
    return bcrypt.checkpw(raw.encode(), hashed.encode())


async def verify_api_token(
    token: str,
    supabase,
    admin_only: bool = False,
    *,
    return_scopes: bool = False,
) -> str | tuple[str, list[str]]:
    """Validate a bearer token and **optionally** return its scopes.

    Behaviour upgrades:
    1. If the token string *looks* like a JWT (contains two ``.`` separators),
       we parse the claims **without** verifying the signature.  The caller is
       responsible for signature checks when needed (the control-plane trusts
       transport-layer secrecy for API tokens).
    2. Otherwise we fall back to the existing ``api_tokens`` table lookup.

    When ``return_scopes`` is ``True`` we return ``(account_id, scopes)``.
    Existing call-sites that expect a bare ``account_id`` continue to work.
    """

    # ------------------------------------------------------------------
    # Only opaque D2 tokens are supported going forward
    # ------------------------------------------------------------------

    if not token.startswith("d2_"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format")

    # ------------------------------------------------------------------
    # Legacy: opaque token hashed & stored in DB
    # ------------------------------------------------------------------

    token_sha = sha256(token.encode()).hexdigest()

    resp = await query_data(
        supabase,
        API_TOKEN_TABLE,
        filters={},  # full scan for salted hashes
        select_fields="token_sha256, scopes, account_id, expires_at, revoked_at",
    )

    row = None
    for candidate in getattr(resp, "data", []) or []:
        stored_hash = candidate["token_sha256"]
        if stored_hash.startswith("$2b") or stored_hash.startswith("$2a"):
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
        return base64.urlsafe_b64decode(key_b64)
    except Exception:  # noqa: BLE001
        raise RuntimeError(f"Invalid {_AES_KEY_ENV} – must be base64url-encoded 32-byte key")


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