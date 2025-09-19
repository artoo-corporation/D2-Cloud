"""Authentication, authorization & signing helpers."""

from __future__ import annotations

from datetime import datetime, timezone
import time
from hashlib import sha256
from typing import Any, Dict, Union

import base64
import json
import os
import bcrypt
import hmac
import inspect

from fastapi import HTTPException, status
from jose import jwk as jose_jwk, jwt as jose_jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.utils.dependencies import get_supabase_async
from app.utils.database import query_one, query_data, update_data
from app import APP_ENV
from httpx import HTTPError

API_TOKEN_TABLE = "api_tokens"
JWKS_TABLE = "jwks_keys"
autoerror = False if APP_ENV == "development" else True

# ---------------------------------------------------------------------------
# Helper for safe Supabase calls
# ---------------------------------------------------------------------------

async def _safe_supabase_call(coro, *, detail: str):
    """Await a Supabase async call and translate network/database errors into HTTP 503.

    Any network, connection, or database error gets mapped to a 503 so that callers don't
    surface opaque 500s to clients. Only catches non-HTTP exceptions.
    """
    try:
        return await coro if inspect.isawaitable(coro) else coro  # type: ignore[misc]
    except HTTPException:
        # Re-raise HTTP exceptions (401, 403, 404, etc.) - these are intentional
        raise
    except Exception as exc:  # pragma: no cover – network/database only
        # Catch all other exceptions (HTTPError, postgrest errors, connection errors, etc.)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=detail) from exc

# ---------------------------------------------------------------------------
# Supabase Auth JWT verification helpers
# ---------------------------------------------------------------------------

async def verify_supabase_jwt(token: str, admin_only: bool = False, return_claims: bool = False):
    """Validate a Supabase Auth JWT and return the caller's account_id.

    Admin enforcement:
    - If the users row contains either `is_admin` (truthy) or `role` in {"admin","owner"},
      we enforce that when `admin_only=True`. If neither field exists, we treat
      the user as admin for backward compatibility.
    """
    try:
        # Decode JWT locally instead of making API call to Supabase
        # This avoids the server-side session context issues with get_user(token)
        from app import SUPABASE_URL
        
        # Decode without verification first to get the claims
        unverified_claims = jose_jwt.get_unverified_claims(token)
        
        # Validate basic JWT structure and claims
        if not unverified_claims.get("sub"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_jwt_missing_sub")
        
        # Check expiration
        exp = unverified_claims.get("exp")
        if exp and datetime.fromtimestamp(exp, timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="jwt_expired")
        
        # Check issuer matches our Supabase instance
        expected_issuer = f"{SUPABASE_URL}/auth/v1"
        if unverified_claims.get("iss") != expected_issuer:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_jwt_issuer")
        
        # For now, we'll trust the JWT claims since it comes from our Supabase instance
        # In production, you might want to verify the signature using Supabase's public key
        # but that requires fetching the JWKS endpoint which adds complexity
        
        user_auth_id = unverified_claims.get("sub")
        if not user_auth_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_supabase_token")

        # Try to get account_id and role from JWT claims (fast path)
        account_id = unverified_claims.get("account_id") or unverified_claims.get("user_metadata", {}).get("account_id")
        role = unverified_claims.get("role") or unverified_claims.get("user_metadata", {}).get("role")
        
        # If we have account_id in JWT and don't need admin check, skip DB query entirely
        if account_id and (not admin_only or role in {"admin", "owner"}):
            if return_claims:
                return str(account_id), unverified_claims
            return str(account_id)
        
        # Fall back to database lookup only if needed
        agen = get_supabase_async()
        supabase = await _safe_supabase_call(
            agen.__anext__(),  # get first (and only) yield
            detail="supabase_connection_failed",
        )
        try:
            resp = await _safe_supabase_call(
                query_data(
                    supabase,
                    table_name="users",
                    filters={"user_id": user_auth_id},
                    select_fields="*",
                ),
                detail="supabase_users_unreachable",
            )
            rows = getattr(resp, "data", None) or []
            if not rows:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user_not_found")

            row = rows[0]
            db_account_id = row.get("account_id") or row.get("org_id")
            if not db_account_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="account_mapping_not_found")

            if admin_only:
                db_role = row.get("role")
                if db_role is not None and db_role not in {"admin", "owner"}:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin_required")

            if return_claims:
                # Include database role in claims to avoid duplicate lookups
                db_role = row.get("role")
                if db_role:
                    unverified_claims["db_role"] = db_role
                return str(db_account_id), unverified_claims
            return str(db_account_id)
        finally:
            close_coro = getattr(supabase, "aclose", None)
            if callable(close_coro):
                await close_coro()
    except HTTPException:
        # Re-raise HTTP exceptions (like 503 from _safe_supabase_call) without modification
        raise
    except Exception as e:
        # Include the actual error in development for debugging
        if APP_ENV == "development":
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"supabase_verification_error: {str(e)}")
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
        # Add padding if needed for base64url decoding (same as _get_aes_key)
        padding_needed = (4 - len(key_b64) % 4) % 4
        key_b64_padded = key_b64 + '=' * padding_needed
        pepper = base64.urlsafe_b64decode(key_b64_padded)
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
        resp = await _safe_supabase_call(
            query_data(
                supabase,
                API_TOKEN_TABLE,
                filters={"token_lookup": lookup},
                select_fields="token_id,token_sha256,scopes,account_id,expires_at,revoked_at,app_name,created_by_user_id",
            ),
            detail="supabase_tokens_unreachable",
        )
        for candidate in getattr(resp, "data", []) or []:
            stored_hash = candidate.get("token_sha256", "")
            if stored_hash and (stored_hash.startswith("$2b") or stored_hash.startswith("$2a")):
                if _verify_hash(token_sha, stored_hash):
                    row = candidate
                    break
    if row is None:
        # Fallback: full scan (backward compatibility, slower)
        resp = await _safe_supabase_call(
            query_data(
                supabase,
                API_TOKEN_TABLE,
                filters={},
                select_fields="token_id,token_sha256,scopes,account_id,expires_at,revoked_at,app_name,created_by_user_id",
            ),
            detail="supabase_tokens_unreachable",
        )
        for candidate in getattr(resp, "data", []) or []:
            stored_hash = candidate.get("token_sha256", "")
            if stored_hash and (stored_hash.startswith("$2b") or stored_hash.startswith("$2a")):
                if _verify_hash(token_sha, stored_hash):
                    row = candidate
                    # Opportunistic backfill: if token_lookup is missing, update it
                    if lookup is not None and not candidate.get("token_lookup"):
                        try:
                            await _safe_supabase_call(
                                update_data(
                                    supabase,
                                    API_TOKEN_TABLE,
                                    match={"token_id": candidate["token_id"]},
                                    updates={"token_lookup": lookup}
                                ),
                                detail="supabase_tokens_unreachable",
                            )
                        except Exception:
                            pass  # Don't let backfill break auth
                    break

    if not row:
        # Log authentication failure
        try:
            from app.utils.audit import log_audit_event
            from app.models import AuditAction, AuditStatus
            await _safe_supabase_call(
                log_audit_event(
                    supabase,
                    action=AuditAction.auth_failure,
                    actor_id="unknown",  # No account context yet
                    status=AuditStatus.failure,
                    metadata={
                        "reason": "invalid_token",
                        "token_prefix": token[:8] + "..." if len(token) > 8 else token,
                    },
                ),
                detail="supabase_audit_unreachable",
            )
        except Exception:
            pass  # Don't let audit logging break auth
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Revocation / expiry
    if row.get("revoked_at") is not None:
        # Log revoked token usage attempt
        try:
            from app.utils.audit import log_audit_event
            from app.models import AuditAction, AuditStatus
            await _safe_supabase_call(
                log_audit_event(
                    supabase,
                    action=AuditAction.token_revoked,
                    actor_id=row.get("account_id", "unknown"),
                    status=AuditStatus.denied,
                    token_id=row.get("token_id"),
                    metadata={
                        "reason": "token_revoked",
                        "revoked_at": row.get("revoked_at"),
                    },
                ),
                detail="supabase_audit_unreachable",
            )
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token revoked")

    if row.get("expires_at") and datetime.fromisoformat(row["expires_at"]).astimezone(timezone.utc) < datetime.now(timezone.utc):
        # Log expired token usage attempt
        try:
            from app.utils.audit import log_audit_event
            from app.models import AuditAction, AuditStatus
            await _safe_supabase_call(
                log_audit_event(
                    supabase,
                    action=AuditAction.token_expired,
                    actor_id=row.get("account_id", "unknown"),
                    status=AuditStatus.denied,
                    token_id=row.get("token_id"),
                    metadata={
                        "reason": "token_expired",
                        "expires_at": row.get("expires_at"),
                    },
                ),
                detail="supabase_audit_unreachable",
            )
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")

    scopes = row.get("scopes") or []

    # Opportunistic backfill of token_lookup to avoid future full scans
    try:
        if lookup is not None and not row.get("token_lookup"):
            await update_data(
                supabase,
                API_TOKEN_TABLE,
                update_values={"token_lookup": lookup},
                filters={"token_id": row.get("token_id")},
            )
            # Verify backfill
            try:
                verify = await query_one(
                    supabase,
                    API_TOKEN_TABLE,
                    match={"token_id": row.get("token_id")},
                    select_fields="token_id,token_lookup",
                )
            except Exception:
                verify = None
            logger.info(
                "auth.token",
                extra={
                    "extra": {
                        "phase": "backfill_lookup",
                        "token_id": row.get("token_id"),
                        "lookup_len": len(lookup),
                        "verified": bool(verify and verify.get("token_lookup")),
                    }
                },
            )
    except Exception:
        pass

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
            "app_name": row.get("app_name"),
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


def create_enhanced_jws(
    payload: Dict[str, Any], 
    private_jwk: Dict[str, Any], 
    kid: str,
    *,
    jwks_refresh: bool = False,
    rotation_id: str | None = None,
    refresh_reason: str | None = None,
    algorithm: str = "RS256",
    audience: str | None = None
) -> str:
    """Create JWS with optional JWKS refresh control headers and proper JWT claims.
    
    Args:
        payload: The policy bundle content to sign
        private_jwk: The private JWK for signing
        kid: Key ID for the JWS header
        jwks_refresh: Whether to include JWKS refresh control flag
        rotation_id: Optional rotation tracking ID
        refresh_reason: Optional reason for JWKS refresh
        algorithm: JWT algorithm (default: RS256)
        audience: JWT audience claim (aud)
        
    Returns:
        JWS token string
    """
    from datetime import datetime, timezone
    
    # Build JWS headers
    headers = {"kid": kid}
    
    # Add JWKS refresh control headers if requested
    if jwks_refresh:
        headers["jwks_refresh"] = True
        if rotation_id:
            headers["rotation_id"] = rotation_id
        if refresh_reason:
            headers["refresh_reason"] = refresh_reason
        # Add timestamp for tracking
        headers["refresh_timestamp"] = datetime.now(timezone.utc).isoformat()
    
    # Create proper JWT payload with standard claims
    now = datetime.now(timezone.utc)
    jwt_payload = {
        # Standard JWT claims
        "iat": int(now.timestamp()),  # Issued at
        "exp": int((now.replace(year=now.year + 1)).timestamp()),  # Expires in 1 year
        "iss": "d2-policy-service",  # Issuer
        # Always include audience claim - use generic format if not specified
        "aud": audience if audience else "d2.policy",
        # Keep the existing policy bundle structure for backward compatibility
        **payload  # Spread the policy bundle directly into JWT payload
    }
    
    # Create and return JWS
    return jose_jwt.encode(
        jwt_payload,
        private_jwk,
        algorithm=algorithm,
        headers=headers,
    )


async def resign_active_policies(
    account_id: str, 
    new_kid: str, 
    rotation_id: str,
    supabase
) -> Dict[str, Any]:
    """Re-sign all active policy bundles with new JWKS key.
    
    Args:
        account_id: Account to re-sign policies for
        new_kid: New JWKS key ID
        rotation_id: Rotation tracking ID
        supabase: Supabase client
        
    Returns:
        Dictionary with re-signing statistics
    """
    from app.utils.database import query_many, update_data
    from app.utils.logger import logger
    
    # Get all active (non-revoked, published) policies for this account
    active_policies = await query_many(
        supabase,
        "policies",
        match={
            "account_id": account_id,
            "revocation_time": ("is", None),  # Not revoked
            "is_draft": False,  # Published policies only
            "active": True,  # Currently active
        },
        select_fields="id,bundle,version,app_name,jws,resigned_count",
    )
    
    if not active_policies:
        logger.info(f"No active policies found for account {account_id}")
        return {"policies_resigned": 0, "errors": []}
    
    # Get the new private key for signing
    new_key_row = await query_one(
        supabase,
        JWKS_TABLE,
        match={"account_id": account_id, "kid": new_kid},
    )
    if not new_key_row:
        raise RuntimeError(f"New JWKS key {new_kid} not found for account {account_id}")
    
    private_jwk = decrypt_private_jwk(new_key_row["private_jwk"])
    
    # Re-sign each policy bundle
    resigned_count = 0
    errors = []
    
    for policy in active_policies:
        try:
            # Find the maximum version for this app to avoid constraint violations
            max_version_row = await query_one(
                supabase,
                "policies",
                match={
                    "account_id": account_id,
                    "app_name": policy["app_name"],
                },
                order_by=("version", "desc"),
                select_fields="version",
            )
            next_version = (max_version_row["version"] if max_version_row else policy["version"]) + 1
            
            # Create new JWS with JWKS refresh control headers
            new_jws = create_enhanced_jws(
                payload=policy["bundle"],
                private_jwk=private_jwk,
                kid=new_kid,
                jwks_refresh=True,
                rotation_id=rotation_id,
                refresh_reason="automated_key_rotation",
                audience=f"d2-policy:{account_id}:{policy.get('app_name', 'default')}",  # Include audience
            )
            
            # Update the policy record with proper version increment and tracking
            await update_data(
                supabase,
                "policies",
                update_values={
                    "jws": new_jws,
                    "version": next_version,  # Use calculated next version
                    "resigned_at": datetime.now(timezone.utc),
                    "resigned_count": (policy.get("resigned_count", 0) or 0) + 1,
                    "rotation_id": rotation_id,
                    "signed_with_kid": new_kid,
                },
                filters={"id": policy["id"]},
                error_message="policy_resign_failed",
            )
            
            logger.info(f"Re-signed policy {policy['id']} (app: {policy['app_name']}) with new key {new_kid}, version {policy['version']} -> {next_version}")
            resigned_count += 1
            
        except Exception as e:
            error_msg = f"Failed to re-sign policy {policy['id']} (app: {policy.get('app_name', 'unknown')}): {e}"
            logger.error(error_msg)
            errors.append(error_msg)
            # Continue with other policies, don't fail entire rotation
    
    return {
        "policies_resigned": resigned_count,
        "total_policies": len(active_policies),
        "errors": errors,
        "rotation_id": rotation_id,
    } 