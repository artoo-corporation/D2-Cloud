"""Policy Service routes – CRUD + signer for policy bundles."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status, Request, Query
from jose import jwt

from app.models import (
    PolicyBundleResponse,
    PolicyDraft,
    PolicyPublishResponse,
    PolicyVersionResponse,
    PolicyRevertRequest,
    PolicyDescriptionUpdate,
    MessageResponse,
    PolicySummary,
)
from app.utils.database import insert_data, query_one, query_many, update_data
from app.utils.dependencies import get_supabase_async, require_account_admin
from app.utils.security_utils import verify_api_token
from app.utils.plans import enforce_bundle_poll, get_plan_limit, effective_plan
import base64
from app.utils.require_scope import require_scope
from app.utils.logger import logger
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from app.utils.policy_expiry import is_policy_expired, extract_and_sync_policy_expiry
from app.utils.policy_validation import validate_d2_policy_bundle, get_policy_summary, extract_app_name
from app.utils.security_utils import decrypt_private_jwk

router = APIRouter(prefix="/v1/policy", tags=["policy"])

JWT_ALGORITHM = "RS256"
POLICY_TABLE = "policies"


@router.get("/bundle", response_model=PolicyBundleResponse)
async def get_policy_bundle(
    response: Response,
    app_name: str = Query("default", description="App name to retrieve policy for"),
    stage: str = Query("auto", description="Which bundle stage to fetch: published, draft, or auto"),
    account_id: str = Depends(require_scope("policy.read")),
    if_none_match: str | None = Header(None, alias="If-None-Match"),
    supabase=Depends(get_supabase_async),
):
    # Stage handling
    stage = stage.lower()

    row = None

    if stage == "published":
        row = await query_one(
            supabase,
            POLICY_TABLE,
            match={"account_id": account_id, "app_name": app_name, "is_draft": False, "active": True},
        )
    elif stage == "draft":
        row = await query_one(
            supabase,
            POLICY_TABLE,
            match={"account_id": account_id, "app_name": app_name, "is_draft": True},
            order_by=("version", "desc"),
        )
    else:  # auto – prefer published then draft
        row = await query_one(
            supabase,
            POLICY_TABLE,
            match={"account_id": account_id, "app_name": app_name, "is_draft": False, "active": True},
        )
        if not row:
            row = await query_one(
                supabase,
                POLICY_TABLE,
                match={"account_id": account_id, "app_name": app_name, "is_draft": True},
                order_by=("version", "desc"),
            )

    if not row:
        raise HTTPException(status_code=404, detail="No policy found for account")

    # 4️⃣  Revocation enforcement
    if row.get("revocation_time") and datetime.fromisoformat(row["revocation_time"]).astimezone(timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=410, detail="Policy revoked")

    # 5️⃣  Policy expiry enforcement and warnings
    policy_expires = row.get("expires")
    
    if policy_expires:
        # Convert string to datetime if needed
        if isinstance(policy_expires, str):
            policy_expires = datetime.fromisoformat(policy_expires).astimezone(timezone.utc)
        
        # Check if policy is expired (just log for monitoring)
        if is_policy_expired(policy_expires):
            logger.warning(f"Policy expired for account {account_id}: {policy_expires}")
            # Expiry is automatically handled during upload/publish

    # 3️⃣  Ensure we actually found a policy row (defence-in-depth – should already be guaranteed)
    if not row or "jws" not in row:
        raise HTTPException(status_code=404, detail="No policy found for account")

    # 4️⃣  Basic plan / quota enforcement (bundle size)
    account = await query_one(supabase, "accounts", match={"id": account_id})
    plan = effective_plan(account)
    # Max bundle size by plan (bytes)
    size_limit = get_plan_limit(plan, "max_bundle_bytes", int(0.5 * 1024 * 1024))

    # For drafts there is no JWS yet – use raw bundle for size check / ETag
    if row.get("jws"):
        payload_bytes = row["jws"].encode()
    else:
        payload_bytes = json.dumps(row["bundle"], separators=(",", ":"), sort_keys=True).encode()

    if len(payload_bytes) > size_limit:
        raise HTTPException(status_code=413, detail="Bundle exceeds plan size limit")

    # 3b️⃣  Server-side poll-interval enforcement (per-account bucket)
    # If the account has an explicit per-tenant poll_seconds override we honour the
    # *smaller* of (override, plan default). This way upgrading plan immediately
    # lowers the minimum poll window without requiring a manual DB update.
    plan_min_poll = get_plan_limit(plan, "min_poll", 60)
    acct_override = (account or {}).get("poll_seconds")
    if acct_override is not None:
        poll_seconds = min(int(acct_override), plan_min_poll)
    else:
        poll_seconds = plan_min_poll
    try:
        enforce_bundle_poll(account_id, poll_seconds)
    except HTTPException as exc:
        # Bubble up 429 untouched so FastAPI renders proper Retry-After header
        raise exc

    etag = sha256(payload_bytes).hexdigest()

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
    
    # Expiry is handled automatically during policy upload/publish

    return PolicyBundleResponse(jws=row["jws"], version=row["version"], etag=etag)


@router.put("/draft", response_model=MessageResponse)
async def upload_policy_draft(
    draft: PolicyDraft,
    account_id: str = Depends(require_scope("policy.publish")),
    authorization: str = Header(..., description="Bearer API token"),
    supabase=Depends(get_supabase_async),
):
    logger.info(f"Draft upload for account {account_id}")

    # Validate D2 policy bundle format
    try:
        is_valid, validation_errors = validate_d2_policy_bundle(draft.bundle, strict=False)
        if not is_valid:
            logger.warning(f"Policy validation warnings for account {account_id}: {validation_errors}")
        
        # Log policy summary for debugging
        policy_summary = get_policy_summary(draft.bundle)
        logger.info(f"Policy summary for account {account_id}: {policy_summary}")
    except Exception as e:
        logger.error(f"Policy validation error for account {account_id}: {e}")
        # Continue anyway - validation is informational for now

    # Auto-generate next draft version
    # Check highest version across both drafts and published policies
    # Extract app name first to determine which app's draft/published versions to check
    temp_app_name = extract_app_name(draft.bundle)
    
    latest_draft = await query_one(
        supabase,
        POLICY_TABLE,
        match={"account_id": account_id, "app_name": temp_app_name, "is_draft": True},
        order_by=("version", "desc"),
    )
    
    latest_published = await query_one(
        supabase,
        POLICY_TABLE,
        match={"account_id": account_id, "app_name": temp_app_name, "is_draft": False},
        order_by=("version", "desc"),
    )
    
    # Get the highest version from either drafts or published
    draft_version = latest_draft["version"] if latest_draft else 0
    published_version = latest_published["version"] if latest_published else 0
    next_version = max(draft_version, published_version) + 1
    
    # Extract app name from bundle metadata
    app_name = extract_app_name(draft.bundle)
    logger.info(f"Extracted app name: {app_name} for account {account_id}")
    
    # Extract and sync expiry information from the policy bundle
    # Auto-extend if expired
    updated_bundle, policy_expiry = extract_and_sync_policy_expiry(draft.bundle)
    logger.info(f"Final policy expiry after sync: {policy_expiry} for account {account_id}")
    
    # Convert datetime to ISO string for database storage
    policy_expiry_str = policy_expiry.isoformat() if policy_expiry else None
    
    # Prepare update values with synchronized bundle
    update_values = {
        "bundle": updated_bundle,
        "version": next_version,
        "app_name": app_name,
        "expires": policy_expiry_str,
    }
    
    # Update existing draft or create new one
    if latest_draft:
        await update_data(
            supabase,
            POLICY_TABLE,
            keys={"id": latest_draft["id"]},
            values=update_values,
        )
        logger.info(f"Updated existing draft to version {next_version} for account {account_id}")
    else:
        # Create new draft
        insert_values = {
            "account_id": account_id,
            "version": next_version,
            "bundle": updated_bundle,
            "app_name": app_name,
            "is_draft": True,
            "expires": policy_expiry_str,
        }
        await insert_data(
            supabase,
            POLICY_TABLE,
            insert_values,
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
                "user_id": details.get("user_id"),
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
    app_name: str = Query(..., description="App name being published"),
    x_d2_signature: str = Header(..., alias="X-D2-Signature"),
    x_d2_key_id: str = Header(..., alias="X-D2-Key-Id"),
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
        match={"account_id": account_id, "app_name": app_name, "is_draft": False, "active": True},
    )

    logger.info(f"Latest published policy: {latest_published}")

    if latest_published:
        current_etag = sha256(latest_published["jws"].encode()).hexdigest()

        provided_etag = if_match.lstrip("W/").strip('"') if if_match else None

        if provided_etag is None or provided_etag != current_etag:
            logger.error(f"ETag mismatch for account {account_id}: provided={provided_etag}, current={current_etag}")
            raise HTTPException(status_code=409, detail="etag_mismatch")

    else:
        # First publish for this app – allow If-Match: * or no header
        provided = (if_match or "*").strip()
        if provided not in ("*", "W/*", "\"*\""):
            logger.error("First publish requires If-Match: '*' (app %s)", app_name)
            raise HTTPException(status_code=409, detail="etag_mismatch")

    # ------------------------------------------------------------------
    # Fetch draft
    # ------------------------------------------------------------------


    draft_row = await query_one(
        supabase,
        POLICY_TABLE,
        match={"account_id": account_id, "app_name": app_name, "is_draft": True},
        order_by=("version", "desc"),
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
    # Sync expiry field inside bundle (auto-extend if needed)
    # ------------------------------------------------------------------

    updated_bundle, policy_expiry = extract_and_sync_policy_expiry(draft_row["bundle"])

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
    # Fetch active RSA key-pair for this tenant
    rsa_row = await query_one(
        supabase,
        "jwks_keys",
        match={"account_id": account_id},
        order_by=("created_at", "desc"),
    )
    if not rsa_row:
        logger.error("Signing key not found for account %s", account_id)
        raise HTTPException(status_code=500, detail="signing_key_not_found")

    rsa_kid = rsa_row["kid"]
    private_jwk = decrypt_private_jwk(rsa_row["private_jwk"])

    # Sign the updated bundle with RSA key and correct kid
    jws = jwt.encode(
        updated_bundle,
        private_jwk,
        algorithm=JWT_ALGORITHM,
        headers={"kid": rsa_kid},
    )
    
    # Convert datetime to ISO string for database storage
    policy_expiry_str = policy_expiry.isoformat() if policy_expiry else None

    # First, deactivate any currently active policy for this account
    if latest_published:
        await update_data(
            supabase,
            POLICY_TABLE,
            keys={"account_id": account_id, "app_name": app_name, "is_draft": False, "active": True},
            values={"active": False},
        )

    # Then publish the new policy as active
    await update_data(
        supabase,
        POLICY_TABLE,
        keys={"id": draft_row["id"]},
        values={
            "bundle": updated_bundle,
            "jws": jws,
            "is_draft": False,
            "published_at": datetime.now(timezone.utc),
            "version": new_version,
            "active": True,
            "expires": policy_expiry_str,
            "app_name": app_name,
        },
    )

    # Build response with additional headers
    response = PolicyPublishResponse(jws=jws, version=new_version)

    # Compute ETag (sha256 of JWS)
    etag = sha256(jws.encode()).hexdigest()

    # Determine poll-seconds (account-level override or default by plan)
    account = await query_one(supabase, "accounts", match={"id": account_id})
    plan_name = effective_plan(account)
    plan_min_poll = get_plan_limit(plan_name, "min_poll", 60)
    acct_override = (account or {}).get("poll_seconds")
    if acct_override is not None:
        poll_seconds = min(int(acct_override), plan_min_poll)
    else:
        poll_seconds = plan_min_poll

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
                "user_id": details.get("user_id"),
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
    app_name: str = Query(..., description="App name to revoke policy for"),
    account_id: str = Depends(require_scope("policy.revoke")),
    supabase=Depends(get_supabase_async),
):
    logger.info(f"Revoking policy for app '{app_name}' in account {account_id}")
    # Find the currently active published policy for this app
    active_policy = await query_one(
        supabase, POLICY_TABLE, 
        match={"account_id": account_id, "app_name": app_name, "is_draft": False, "active": True}
    )
    if not active_policy:
        raise HTTPException(status_code=404, detail=f"No active policy found to revoke for app '{app_name}'")

    await update_data(
        supabase,
        POLICY_TABLE,
        keys={"id": active_policy["id"]},
        values={"revocation_time": datetime.now(timezone.utc)},
    )
    logger.info(f"Revoked active policy (version {active_policy['version']}) for app '{app_name}' in account {account_id}")
    return MessageResponse(message=f"Active policy revoked for app '{app_name}'")


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
        select_fields="id,version,active,published_at,expires,revocation_time",
    )
    
    return [PolicyVersionResponse(**row) for row in rows]


@router.post("/revert", response_model=MessageResponse)
async def revert_policy(
    request: PolicyRevertRequest,
    account_id: str = Depends(require_scope("policy.revert")),
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

# ---------------------------------------------------------------------------
# Front-end helpers: list policies & fetch single bundle + metadata
# ---------------------------------------------------------------------------


@router.get("/list", response_model=list[PolicySummary])
async def list_policies(
    account_id: str = Depends(require_scope("policy.read")),
    supabase=Depends(get_supabase_async),
):
    """Return **all** policies (draft + published) for the caller's account.

    Front-end can client-side filter by `app_name` or `is_draft` if needed.
    """

    rows = await query_many(
        supabase,
        POLICY_TABLE,
        match={"account_id": account_id},
        order_by=("created_at", "desc"),
        select_fields="id,app_name,version,description,active,is_draft,published_at,expires,revocation_time,is_revoked,bundle",
    )
    return [PolicySummary(**r) for r in rows]


@router.get("/{policy_id}", response_model=PolicySummary)
async def get_policy_detail(
    policy_id: str,
    account_id: str = Depends(require_scope("policy.read")),
    supabase=Depends(get_supabase_async),
):
    row = await query_one(
        supabase,
        POLICY_TABLE,
        match={"id": policy_id, "account_id": account_id},
    )
    if not row:
        raise HTTPException(status_code=404, detail="policy_not_found")

    return PolicySummary(**row)


# ---------------------------------------------------------------------------
# Update description
# ---------------------------------------------------------------------------


@router.patch("/{policy_id}/description", response_model=MessageResponse)
async def update_policy_description(
    policy_id: str,
    payload: PolicyDescriptionUpdate,
    account_id: str = Depends(require_scope("policy.publish")),
    supabase=Depends(get_supabase_async),
):
    """Update the free-text description of a draft or published policy.

    Only the owner account can update; requires `policy.publish` or higher
    scope (dev/server/admin roles).
    """

    # Ensure policy belongs to caller
    policy_row = await query_one(
        supabase,
        POLICY_TABLE,
        match={"id": policy_id, "account_id": account_id},
    )
    if not policy_row:
        raise HTTPException(status_code=404, detail="policy_not_found")

    await update_data(
        supabase,
        POLICY_TABLE,
        keys={"id": policy_id},
        values={"description": payload.description},
    )

    return MessageResponse(message="description_updated")
