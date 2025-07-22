"""Authentication, authorization & signing helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict

import base64
import json
import os
import bcrypt

from fastapi import HTTPException, status
from jose import jwk as jose_jwk
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.utils.database import query_one

API_TOKEN_TABLE = "api_tokens"
JWKS_TABLE = "jwks_keys"


async def hash_token(raw: str) -> str:
    return bcrypt.hashpw(raw.encode(), bcrypt.gensalt()).decode()


def _verify_hash(raw: str, hashed: str) -> bool:
    return bcrypt.checkpw(raw.encode(), hashed.encode())


async def verify_api_token(token: str, supabase, admin_only: bool = False) -> str:
    """Validate bearer token against `api_tokens` table.

    We support both *legacy* tokens (column stores plain SHA-256 hex) and new
    tokens whose column contains a **bcrypt hash of the SHA-256** (adds salt so
    dumping the table is not enough to brute-force the raw token).
    """

    token_sha = sha256(token.encode()).hexdigest()

    # 1) Fast path – legacy storage (exact match on sha256 column)
    row = await query_one(
        supabase,
        API_TOKEN_TABLE,
        match={"token_sha256": token_sha, "revoked_at": None},
    )

    # 2) If not found, fall back to full scan and bcrypt verify (new storage).
    if not row:
        resp = await supabase.table(API_TOKEN_TABLE).select(
            "token_sha256, scopes, account_id, expires_at, revoked_at"
        ).is_("revoked_at", "null").execute()

        for candidate in getattr(resp, "data", []) or []:
            stored_hash = candidate["token_sha256"]
            if stored_hash.startswith("$2b") or stored_hash.startswith("$2a"):
                # bcrypt format – verify
                if _verify_hash(token_sha, stored_hash):
                    row = candidate
                    break

    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # ---------------------------------------------------------------------
    # Scope & expiry checks (unchanged)
    # ---------------------------------------------------------------------
    if admin_only and "admin" not in (row.get("scopes") or []):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin scope required")

    if row.get("expires_at") and datetime.fromisoformat(row["expires_at"]).astimezone(timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")

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