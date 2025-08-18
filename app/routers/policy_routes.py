"""Policy Service routes – CRUD + signer for policy bundles."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from hashlib import sha256
from typing import Dict, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status, Request, Query
from jose import jwt

from app.models import (
    PolicyBundleResponse,
    PolicyDraft,
    PolicyPublishResponse,
    PolicyVersionResponse,
    PolicyRevertRequest,
    MessageResponse,
)
from app.utils.database import insert_data, query_one, query_many, update_data
from app.utils.dependencies import get_supabase_async, require_account_admin
from app.utils.security_utils import get_active_private_jwk, verify_api_token
from app.utils.plans import enforce_bundle_poll
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import base64
from app.utils.require_scope import require_scope
from app.utils.logger import logger

router = APIRouter(prefix="/v1/policy", tags=["policy"])

JWT_ALGORITHM = "RS256"
POLICY_TABLE = "policies"


@router.get("/bundle", response_model=PolicyBundleResponse)
async def get_policy_bundle(
    response: Response,
    account_id: str = Depends(require_scope("policy.read")),
    if_none_match: str | None = Header(None, alias="If-None-Match"),
    supabase=Depends(get_supabase_async),
):
    # First try to get the active published policy
    row = await query_one(
        supabase,
        POLICY_TABLE,
        match={"account_id": account_id, "is_draft": False, "active": True},
    )
    if not row:
        # Fallback to latest draft for preview purposes
        row = await query_one(
            supabase,
            POLICY_TABLE,
            match={"account_id": account_id, "is_draft": True},
            order_by=("version", "desc"),
        )
        if not row:
            raise HTTPException(status_code=404, detail="No policy found for account")

    # 4️⃣  Revocation enforcement
    if row.get("revocation_time") and datetime.fromisoformat(row["revocation_time"]).astimezone(timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=410, detail="Policy revoked")

    # 3️⃣  Basic plan / quota enforcement (bundle size)
    account = await query_one(supabase, "accounts", match={"id": account_id})
    plan = (account or {}).get("plan", "free")
    plan_limits_mb = {"free": 0.5, "starter": 2, "team": 5, "enterprise": 20}
    size_limit = plan_limits_mb.get(plan, 0.5) * 1024 * 1024  # bytes
    if len(row["jws"].encode()) > size_limit:
        raise HTTPException(status_code=413, detail="Bundle exceeds plan size limit")

    # 3b️⃣  Server-side poll-interval enforcement (per-account bucket)
    poll_seconds = int((account or {}).get("poll_seconds", 60))
    try:
        enforce_bundle_poll(account_id, poll_seconds)
    except HTTPException as exc:
        # Bubble up 429 untouched so FastAPI renders proper Retry-After header
        raise exc

    etag = sha256(row["jws"].encode()).hexdigest()

    # If-None-Match only applies to published bundles
    if not row.get("is_draft", False) and if_none_match:
        client_etag = if_none_match.lstrip("W/").strip('"')
        if client_etag == etag:
            response.status_code = status.HTTP_304_NOT_MODIFIED
            return  # No body for 304

    # Emit strong ETag (quoted)
    response.headers["ETag"] = f'"{etag}"'
    # Use per-account poll window if set, otherwise default by plan
    response.headers["X-D2-Poll-Seconds"] = str(poll_seconds)

    return PolicyBundleResponse(jws=row["jws"], version=row["version"], etag=etag)


@router.put("/draft", response_model=MessageResponse)
async def upload_policy_draft(
    draft: PolicyDraft,
    account_id: str = Depends(require_scope("policy.publish")),
    authorization: str = Header(..., description="Bearer API token"),
    supabase=Depends(get_supabase_async),
):
    logger.info(f"Draft upload for account {account_id}")

    # Auto-generate next draft version
    # Check highest version across both drafts and published policies
    latest_draft = await query_one(
        supabase,
        POLICY_TABLE,
        match={"account_id": account_id, "is_draft": True},
        order_by=("version", "desc"),
    )
    
    latest_published = await query_one(
        supabase,
        POLICY_TABLE,
        match={"account_id": account_id, "is_draft": False},
        order_by=("version", "desc"),
    )
    
    # Get the highest version from either drafts or published
    draft_version = latest_draft["version"] if latest_draft else 0
    published_version = latest_published["version"] if latest_published else 0
    next_version = max(draft_version, published_version) + 1
    
    # Delete any existing draft (we only keep one)
    if latest_draft:
        await update_data(
            supabase,
            POLICY_TABLE,
            keys={"id": latest_draft["id"]},
            values={"bundle": draft.bundle, "version": next_version},
        )
        logger.info(f"Updated existing draft to version {next_version} for account {account_id}")
    else:
        # Create new draft
        await insert_data(
            supabase,
            POLICY_TABLE,
            {
                "account_id": account_id,
                "version": next_version,
                "bundle": draft.bundle,
                "is_draft": True,
            },
        )
        logger.info(f"Created new draft version {next_version} for account {account_id}")
    logger.info(f"Draft uploaded for account {account_id}")
    # Audit attribution for draft
    try:
        details = await verify_api_token(authorization.split(" ")[-1], supabase, admin_only=False, return_details=True)  # type: ignore[assignment]
        await insert_data(
            supabase,
            "audit_logs",
            {
                "actor_id": account_id,
                "token_id": details.get("token_id"),
                "action": "policy_draft",
                "version": draft.version,
            },
        )
    except Exception:
        pass
    return MessageResponse(message="Draft uploaded")


@router.post("/publish", response_model=PolicyPublishResponse)
async def publish_policy(
    request: Request,
    x_d2_signature: str = Header(..., alias="X-D2-Signature"),
    x_d2_key_id: str = Header(..., alias="X-D2-Key-Id"),
    if_none_match: str | None = Header(None, alias="If-None-Match"),
    if_match: str | None = Header(None, alias="If-Match"),
    account_id: str = Depends(require_scope("policy.publish")),
    authorization: str = Header(..., description="Bearer API token"),
    supabase=Depends(get_supabase_async),
):
    # ------------------------------------------------------------------
    # Concurrency / ETag guard
    # ------------------------------------------------------------------

    latest_published = await query_one(
        supabase,
        POLICY_TABLE,
        match={"account_id": account_id, "is_draft": False, "active": True},
    )

    logger.info(f"Latest published policy: {latest_published}")

    if latest_published:
        current_etag = sha256(latest_published["jws"].encode()).hexdigest()

        provided_etag = None
        if if_match:
            provided_etag = if_match.lstrip("W/").strip('"')
        elif if_none_match:
            provided_etag = if_none_match.lstrip("W/").strip('"')

        if provided_etag is None or provided_etag != current_etag:
            logger.error(f"ETag mismatch for account {account_id}: provided={provided_etag}, current={current_etag}")
            raise HTTPException(status_code=409, detail="etag_mismatch")

    else:
        # First publish ever – still require header but allow "*"
        if not (if_match or if_none_match):
            logger.error(f"No ETag header provided for first publish, account {account_id}")
            raise HTTPException(status_code=409, detail="etag_mismatch")

    # ------------------------------------------------------------------
    # Fetch draft
    # ------------------------------------------------------------------


    draft_row = await query_one(
        supabase, POLICY_TABLE, match={"account_id": account_id, "is_draft": True}, order_by=("version", "desc")
    )
    if not draft_row:
        logger.error(f"No draft found for account {account_id}")
        raise HTTPException(status_code=400, detail="No draft to publish. Please upload a draft first at /v1/policy/draft")

    # ------------------------------------------------------------------
    # Version rollback guard
    # ------------------------------------------------------------------

    latest_version = latest_published["version"] if latest_published else 0
    if draft_row["version"] < latest_version:
        logger.error(f"Version rollback detected for account {account_id}: draft_version={draft_row['version']}, latest_version={latest_version}")
        raise HTTPException(status_code=409, detail="version_rollback")

    logger.info(f"Latest version: {latest_version}")
    new_version = latest_version + 1
    # ------------------------------------------------------------------
    # Signature verification (Ed25519)
    # ------------------------------------------------------------------
    key_row = await query_one(
        supabase,
        "public_keys",
        match={"account_id": account_id, "key_id": x_d2_key_id},
    )

    if not key_row:
        logger.error(f"Key not found for account {account_id}, key_id={x_d2_key_id}")
        raise HTTPException(status_code=404, detail="key_not_found")
    if key_row.get("revoked_at") is not None:
        logger.error(f"Key revoked for account {account_id}, key_id={x_d2_key_id}")
        raise HTTPException(status_code=403, detail="key_revoked")

    public_key_raw = key_row["public_key"]
    if isinstance(public_key_raw, str):
        # Handle hex format from PostgREST bytea (e.g., "\\x9f4c...")
        if public_key_raw.startswith("\\x"):
            try:
                public_key_bytes = bytes.fromhex(public_key_raw[2:])
            except ValueError as e:
                logger.error(f"Failed to decode hex public key for account {account_id}: {e}")
                raise HTTPException(status_code=400, detail="invalid_public_key_format")
        else:
            # Handle base64 format
            try:
                public_key_bytes = base64.b64decode(public_key_raw)
            except Exception:
                public_key_bytes = public_key_raw.encode()
    else:
        public_key_bytes = public_key_raw

    try:
        signature = base64.b64decode(x_d2_signature)
    except Exception as e:  # noqa: BLE001
        logger.error(f"Failed to decode signature for account {account_id}: {e}")
        raise HTTPException(status_code=400, detail="invalid_signature")

    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, await request.body())
    except Exception as e:  # noqa: BLE001
        logger.error(f"Signature verification failed for account {account_id}: {e}")
        raise HTTPException(status_code=400, detail="invalid_signature")

    # ------------------------------------------------------------------
    private_jwk = await get_active_private_jwk(account_id, supabase)

    jws = jwt.encode(draft_row["bundle"], private_jwk, algorithm=JWT_ALGORITHM)

    # First, deactivate any currently active policy for this account
    if latest_published:
        await update_data(
            supabase,
            POLICY_TABLE,
            keys={"account_id": account_id, "is_draft": False, "active": True},
            values={"active": False},
        )

    # Then publish the new policy as active
    await update_data(
        supabase,
        POLICY_TABLE,
        keys={"id": draft_row["id"]},
        values={
            "jws": jws,
            "is_draft": False,
            "published_at": datetime.now(timezone.utc),
            "version": new_version,
            "active": True,
        },
    )

    # Build response with additional headers
    response = PolicyPublishResponse(jws=jws, version=new_version)

    # Compute ETag (sha256 of JWS)
    etag = sha256(jws.encode()).hexdigest()

    # Determine poll-seconds (account-level override or default by plan)
    account = await query_one(supabase, "accounts", match={"id": account_id})
    poll_seconds = int((account or {}).get("poll_seconds", 60))

    from fastapi.responses import JSONResponse

    headers = {
        "ETag": f'"{etag}"',
        "X-D2-Poll-Seconds": str(poll_seconds),
    }

    # Audit attribution for publish
    try:
        details = await verify_api_token(authorization.split(" ")[-1], supabase, admin_only=False, return_details=True)  # type: ignore[assignment]
        await insert_data(
            supabase,
            "audit_logs",
            {
                "actor_id": account_id,
                "token_id": details.get("token_id"),
                "action": "policy_publish",
                "key_id": x_d2_key_id,
                "version": new_version,
            },
        )
    except Exception:
        pass

    return JSONResponse(content=response.model_dump(), headers=headers)


@router.post("/revoke", response_model=MessageResponse, status_code=status.HTTP_202_ACCEPTED)
async def revoke_policy(
    account_id: str = Depends(require_account_admin),
    supabase=Depends(get_supabase_async),
):
    latest = await query_one(
        supabase, POLICY_TABLE, match={"account_id": account_id}, order_by=("version", "desc")
    )
    if not latest:
        raise HTTPException(status_code=404, detail="No policy found to revoke")

    await update_data(
        supabase,
        POLICY_TABLE,
        keys={"id": latest["id"]},
        values={"revocation_time": datetime.now(timezone.utc)},
    )
    return MessageResponse(message="Policy revoked")


@router.get("/versions", response_model=list[PolicyVersionResponse])
async def list_policy_versions(
    account_id: str = Depends(require_account_admin),
    supabase=Depends(get_supabase_async),
):
    """List all published policy versions for an account, ordered by version desc."""
    rows = await query_many(
        supabase,
        POLICY_TABLE,
        match={"account_id": account_id, "is_draft": False},
        order_by=("version", "desc"),
        select_fields="id,version,active,published_at,revocation_time",
    )
    
    return [PolicyVersionResponse(**row) for row in rows]


@router.post("/revert", response_model=MessageResponse)
async def revert_policy(
    request: PolicyRevertRequest,
    account_id: str = Depends(require_account_admin),
    supabase=Depends(get_supabase_async),
):
    """Revert to a specific policy version by making it active."""
    
    # Verify the target policy exists and belongs to this account
    target_policy = await query_one(
        supabase,
        POLICY_TABLE,
        match={"id": request.policy_id, "account_id": account_id, "is_draft": False},
    )
    if not target_policy:
        raise HTTPException(status_code=404, detail="Policy version not found")
    
    # Check if policy is revoked
    if target_policy.get("revocation_time"):
        raise HTTPException(status_code=409, detail="Cannot revert to a revoked policy")
    
    # Check if it's already active
    if target_policy.get("active"):
        raise HTTPException(status_code=409, detail="Policy version is already active")
    
    # Deactivate current active policy
    current_active = await query_one(
        supabase,
        POLICY_TABLE,
        match={"account_id": account_id, "is_draft": False, "active": True},
    )
    
    if current_active:
        await update_data(
            supabase,
            POLICY_TABLE,
            keys={"id": current_active["id"]},
            values={"active": False},
        )
    
    # Activate the target policy
    await update_data(
        supabase,
        POLICY_TABLE,
        keys={"id": request.policy_id},
        values={"active": True},
    )
    
    return MessageResponse(message=f"Reverted to policy version {target_policy['version']}")
