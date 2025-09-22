"""Policy Service routes – CRUD + signer for policy bundles."""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status, Request, Query
from jose import jwt

from app.models import (
    AuditAction,
    AuditStatus,
    AuthContext,
    MessageResponse,
    PolicyBundleResponse,
    PolicyBundleUpdate,
    PolicyDraft,
    PolicyPublishResponse,
    PolicyRevertRequest,
    PolicySummary,
    PolicyValidationRequest,
    PolicyValidationResponse,
    PolicyVersionResponse,
)
from app.utils.audit import log_audit_event
from app.utils.database import insert_data, query_one, query_many, update_data, query_data
from app.utils.dependencies import get_supabase_async
from app.utils.security_utils import verify_api_token
from app.utils.utils import normalize_app_name
from app.utils.plans import enforce_bundle_poll, get_plan_limit, effective_plan
import base64
from app.utils.auth import require_auth
from app.utils.logger import logger
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from app.utils.policy_expiry import is_policy_expired, extract_and_sync_policy_expiry
from app.utils.policy_validation import validate_d2_policy_bundle, get_policy_summary, extract_app_name, validate_strict_policy_requirements, enforce_server_side_expiry
from app.utils.security_utils import decrypt_private_jwk, create_enhanced_jws

router = APIRouter(prefix="/v1/policy", tags=["policy"])

JWT_ALGORITHM = "RS256"
POLICY_TABLE = "policies"


@router.get("/bundle", response_model=PolicyBundleResponse)
async def get_policy_bundle(
    response: Response,
    app_name: str = Query("default", description="App name to retrieve policy for"),
    stage: str = Query("auto", description="Which bundle stage to fetch: published, draft, or auto"),
    auth: AuthContext = Depends(require_auth("policy.read")),
    if_none_match: str | None = Header(None, alias="If-None-Match"),
    supabase=Depends(get_supabase_async),
):
    # Handle app_name resolution based on token type
    if app_name == "default":
        if auth.is_server() and auth.app_name:
            # Server tokens with app_name can use automatic resolution
            app_name = auth.app_name
        elif auth.is_server():
            # Server tokens without app_name use "default"
            app_name = "default"
        else:
            # Dev/admin tokens cannot use automatic app_name resolution
            # Return 404 as this is likely a server misconfigured with wrong token type
            raise HTTPException(
                status_code=404, 
                detail="No policy found: app_name required for non-server tokens (server tokens have automatic app resolution)"
            )
    
    # Normalize app name (convert spaces to underscores)
    app_name = normalize_app_name(app_name)

    # Stage handling
    stage = stage.lower()

    row = None

    if stage == "published":
        row = await query_one(
            supabase,
            POLICY_TABLE,
            match={"account_id": auth.account_id, "app_name": app_name, "is_draft": False, "active": True},
        )
    elif stage == "draft":
        row = await query_one(
            supabase,
            POLICY_TABLE,
            match={"account_id": auth.account_id, "app_name": app_name, "is_draft": True},
            order_by=("version", "desc"),
        )
    else:  # auto – prefer published then draft
        row = await query_one(
            supabase,
            POLICY_TABLE,
            match={"account_id": auth.account_id, "app_name": app_name, "is_draft": False, "active": True},
        )
        if not row:
            row = await query_one(
                supabase,
                POLICY_TABLE,
                match={"account_id": auth.account_id, "app_name": app_name, "is_draft": True},
                order_by=("version", "desc"),
            )

    if not row:
        # Provide specific error message based on stage requested
        if stage == "published":
            raise HTTPException(status_code=404, detail=f"No published policy found for app '{app_name}'")
        elif stage == "draft":
            raise HTTPException(status_code=404, detail=f"No draft policy found for app '{app_name}'")
        else:  # auto
            raise HTTPException(status_code=404, detail=f"No policy found for app '{app_name}' (checked both published and draft)")

    # 4️⃣  Revocation enforcement
    if row.get("revocation_time") and datetime.fromisoformat(row["revocation_time"]).astimezone(timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=410, detail=f"Policy for app '{app_name}' has been revoked")

    # 5️⃣  Policy expiry enforcement and warnings
    policy_expires = row.get("expires")
    
    if policy_expires:
        # Convert string to datetime if needed
        if isinstance(policy_expires, str):
            policy_expires = datetime.fromisoformat(policy_expires).astimezone(timezone.utc)
        
        # Check if policy is expired and auto-refresh if needed
        if is_policy_expired(policy_expires):
            logger.warning(f"Policy expired for account {auth.account_id}: {policy_expires}")
            
            # Auto-refresh: extend expiry by 1 week from now
            new_expiry = datetime.now(timezone.utc) + timedelta(weeks=1)
            new_expiry_str = new_expiry.isoformat()
            
            logger.info(f"Auto-refreshing expired policy for account {auth.account_id}: {policy_expires} -> {new_expiry_str}")
            
            # Update the policy in database with new expiry
            await update_data(
                supabase,
                POLICY_TABLE,
                keys={"id": row["id"]},
                values={"expires": new_expiry_str}
            )
            
            # Also update the bundle metadata to keep it in sync
            if row.get("bundle") and isinstance(row["bundle"], dict):
                updated_bundle = row["bundle"].copy()
                if "metadata" not in updated_bundle:
                    updated_bundle["metadata"] = {}
                updated_bundle["metadata"]["expires"] = new_expiry_str
                
                # Update bundle in database too
                await update_data(
                    supabase,
                    POLICY_TABLE,
                    keys={"id": row["id"]},
                    values={"bundle": updated_bundle}
                )
                
                # Update our row data for response
                row["bundle"] = updated_bundle
            
            # Update expires field in our row data for response
            row["expires"] = new_expiry_str

    # 3️⃣  Ensure we actually found a policy row (defence-in-depth – should already be guaranteed)
    if not row or "jws" not in row:
        raise HTTPException(status_code=404, detail=f"Policy found for app '{app_name}' but missing JWS signature")

    # 4️⃣  Basic plan / quota enforcement (bundle size)
    account = await query_one(supabase, "accounts", match={"id": auth.account_id})
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
        # Pass token scopes to enable dev-friendly polling
        enforce_bundle_poll(auth.account_id, poll_seconds, auth.scopes)
    except HTTPException as exc:
        # Bubble up 429 untouched so FastAPI renders proper Retry-After header
        raise exc

    etag = sha256(payload_bytes).hexdigest()

    # If-None-Match only applies to published bundles
    if not row.get("is_draft", False) and if_none_match:
        client_etag = if_none_match.lstrip("W/").strip('"')
        if client_etag == etag:
            response.status_code = status.HTTP_304_NOT_MODIFIED
            # Return empty response for 304 - FastAPI will handle the empty body
            return PolicyBundleResponse(
                jws=None,
                version=row["version"],
                etag=etag,
                bundle=None
            )

    # Emit strong ETag (quoted)
    response.headers["ETag"] = f'"{etag}"'
    # Use per-account poll window if set, otherwise default by plan
    response.headers["X-D2-Poll-Seconds"] = str(poll_seconds)

    # Expiry is handled automatically during policy upload/publish

    return PolicyBundleResponse(
        jws=row["jws"], 
        version=row["version"], 
        etag=etag,
        bundle=row["bundle"] if row.get("is_draft") else None
    )


@router.put("/draft", response_model=MessageResponse)
async def upload_policy_draft(
    draft: PolicyDraft,
    auth: AuthContext = Depends(require_auth("policy.publish")),
    supabase=Depends(get_supabase_async),
):
    logger.info(f"Draft upload for account {auth.account_id}")

    # Strict validation for required fields
    try:
        validate_strict_policy_requirements(draft.bundle)
        logger.info(f"Strict policy validation passed for account {auth.account_id}")
    except Exception as e:
        logger.error(f"Policy validation failed for account {auth.account_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"policy_validation_failed: {str(e)}"
        )

    # Enforce server-side expiry (1 week from now, ignoring client input)
    bundle_with_server_expiry = enforce_server_side_expiry(draft.bundle)
    
    # Log policy summary for debugging
    try:
        policy_summary = get_policy_summary(bundle_with_server_expiry)
        logger.info(f"Policy summary for account {auth.account_id}: {policy_summary}")
    except Exception as e:
        logger.warning(f"Error generating policy summary for account {auth.account_id}: {e}")

    # Auto-generate next draft version
    # Check highest version across both drafts and published policies
    # Extract app name first to determine which app's draft/published versions to check
    temp_app_name = normalize_app_name(extract_app_name(draft.bundle))
    
    latest_draft = await query_one(
        supabase,
        POLICY_TABLE,
        match={"account_id": auth.account_id, "app_name": temp_app_name, "is_draft": True},
        order_by=("version", "desc"),
    )
    
    latest_published = await query_one(
        supabase,
        POLICY_TABLE,
        match={"account_id": auth.account_id, "app_name": temp_app_name, "is_draft": False},
        order_by=("version", "desc"),
    )
    
    # Get the highest version from either drafts or published
    draft_version = latest_draft["version"] if latest_draft else 0
    published_version = latest_published["version"] if latest_published else 0
    next_version = max(draft_version, published_version) + 1
    
    # Extract app name from bundle metadata (using server-side bundle)
    app_name = normalize_app_name(extract_app_name(bundle_with_server_expiry))
    logger.info(f"Extracted app name: {app_name} for account {auth.account_id}")
    
    # Use the bundle with server-side expiry (no client-side expiry processing)
    updated_bundle = bundle_with_server_expiry
    policy_expiry_str = updated_bundle["metadata"]["expires"]
    logger.info(f"Server-side policy expiry: {policy_expiry_str} for account {auth.account_id}")
    
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
        logger.info(f"Updated existing draft to version {next_version} for account {auth.account_id}")
    else:
        # Create new draft
        insert_values = {
            "account_id": auth.account_id,
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
        logger.info(f"Created new draft version {next_version} for account {auth.account_id}")
    logger.info(f"Draft uploaded for account {auth.account_id}")
    # Audit log policy draft
    try:
        await log_audit_event(
            supabase,
            action=AuditAction.policy_draft,
            actor_id=auth.account_id,
            status=AuditStatus.success,
            token_id=auth.token_id,
            user_id=auth.user_id,
            version=next_version,
            resource_type="policy",
            resource_id=policy_id,
            metadata={
                "app_name": app_name, 
                "version": next_version,
                "bundle_size": len(str(bundle)),
            }
        )
    except Exception:
        pass
    return MessageResponse(message=f"Draft policy uploaded for '{app_name}' (v{next_version})")


@router.post("/publish", response_model=PolicyPublishResponse)
async def publish_policy(
    request: Request,
    app_name: str = Query(..., description="App name being published"),
    x_d2_signature: str | None = Header(None, alias="X-D2-Signature"),
    x_d2_key_id: str | None = Header(None, alias="X-D2-Key-Id"),
    if_match: str | None = Header(None, alias="If-Match"),
    auth: AuthContext = Depends(require_auth("policy.publish")),
    supabase=Depends(get_supabase_async),
):
    # Normalize app name (convert spaces to underscores)
    app_name = normalize_app_name(app_name)
    
    # ------------------------------------------------------------------
    # Concurrency / ETag guard
    # ------------------------------------------------------------------

    latest_published = await query_one(
        supabase,
        POLICY_TABLE,
        match={"account_id": auth.account_id, "app_name": app_name, "is_draft": False, "active": True},
    )

    logger.info(f"Latest published policy: {latest_published}")

    if latest_published:
        current_etag = sha256(latest_published["jws"].encode()).hexdigest()

        provided_etag = if_match.lstrip("W/").strip('"') if if_match else None

        if provided_etag is None or provided_etag != current_etag:
            logger.error(f"ETag mismatch for account {auth.account_id}: provided={provided_etag}, current={current_etag}")
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
        match={"account_id": auth.account_id, "app_name": app_name, "is_draft": True},
        order_by=("version", "desc"),
    )
    if not draft_row:
        logger.error(f"No draft found for account {auth.account_id}")
        raise HTTPException(status_code=400, detail="No draft to publish. Please upload a draft first at /v1/policy/draft")

    # ------------------------------------------------------------------
    # Version rollback guard
    # ------------------------------------------------------------------

    latest_version = latest_published["version"] if latest_published else 0
    if draft_row["version"] < latest_version:
        logger.error(f"Version rollback detected for account {auth.account_id}: draft_version={draft_row['version']}, latest_version={latest_version}")
        raise HTTPException(status_code=409, detail="version_rollback")

    logger.info(f"Latest version: {latest_version}")
    new_version = latest_version + 1
    # ------------------------------------------------------------------
    # Strict validation and server-side expiry enforcement
    # ------------------------------------------------------------------
    
    # Strict validation for required fields
    try:
        validate_strict_policy_requirements(draft_row["bundle"])
        logger.info(f"Strict policy validation passed for account {auth.account_id}")
    except Exception as e:
        logger.error(f"Policy validation failed during publish for account {auth.account_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"policy_validation_failed: {str(e)}"
        )

    # Enforce server-side expiry (1 week from now, ignoring any existing expiry)
    updated_bundle = enforce_server_side_expiry(draft_row["bundle"])
    policy_expiry_str = updated_bundle["metadata"]["expires"]
    logger.info(f"Server-side policy expiry enforced during publish: {policy_expiry_str} for account {auth.account_id}")

    # ------------------------------------------------------------------
    # App quota enforcement
    # ------------------------------------------------------------------
    
    # Get account and plan information for quota enforcement
    account = await query_one(supabase, "accounts", match={"id": auth.account_id})
    plan_name = effective_plan(account)
    max_apps = get_plan_limit(plan_name, "max_apps")
    
    # Check existing PUBLISHED apps for this account (drafts don't count toward quota)
    resp_apps = await query_data(
        supabase,
        POLICY_TABLE,
        filters={"account_id": auth.account_id, "is_draft": False},
        select_fields="app_name",
    )
    # Use set to get unique published app names
    existing_published_apps = {row["app_name"] for row in (resp_apps.data or []) if row["app_name"]}
    
    logger.info(f"App quota check - Account: {auth.account_id}, Plan: {plan_name}, Max apps: {max_apps}")
    logger.info(f"Current app being published: {app_name}")
    logger.info(f"Existing published apps: {existing_published_apps}")
    logger.info(f"Published app count: {len(existing_published_apps)}")
    
    # If this is a brand-new app (not previously published), enforce quota
    if app_name not in existing_published_apps and len(existing_published_apps) >= max_apps:
        logger.error(f"App quota exceeded for account {auth.account_id}: {len(existing_published_apps)}/{max_apps}")
        logger.error(f"Attempting to publish new app '{app_name}' but quota is full")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="quota_apps_exceeded",
        )
    
    logger.info(f"App quota check passed for account {auth.account_id}: {len(existing_published_apps)}/{max_apps}")

    # ------------------------------------------------------------------
    # Signature verification (Ed25519) - Optional for Supabase users
    # ------------------------------------------------------------------
    
    # Check if this is a Supabase JWT user (frontend) or API token (CLI/SDK)
    is_supabase_user = auth.user_id is not None
    
    if is_supabase_user:
        # Frontend user with Supabase JWT - signature verification is optional
        logger.info(f"Supabase user {auth.user_id} publishing policy - skipping signature verification")
    else:
        # API token user - signature verification is mandatory
        if not x_d2_signature or not x_d2_key_id:
            logger.error(f"API token publish requires signature headers for account {auth.account_id}")
            raise HTTPException(
                status_code=400, 
                detail="signature_required",
                headers={"X-Required-Headers": "X-D2-Signature, X-D2-Key-Id"}
            )
        
        key_row = await query_one(
            supabase,
            "public_keys",
            match={"account_id": auth.account_id, "key_id": x_d2_key_id},
        )

        if not key_row:
            logger.error(f"Key not found for account {auth.account_id}, key_id={x_d2_key_id}")
            raise HTTPException(status_code=404, detail="key_not_found")
        if key_row.get("revoked_at") is not None:
            logger.error(f"Key revoked for account {auth.account_id}, key_id={x_d2_key_id}")
            raise HTTPException(status_code=403, detail="key_revoked")

        public_key_raw = key_row["public_key"]
        if isinstance(public_key_raw, str):
            # Handle hex format from PostgREST bytea (e.g., "\\x9f4c...")
            if public_key_raw.startswith("\\x"):
                try:
                    public_key_bytes = bytes.fromhex(public_key_raw[2:])
                except ValueError as e:
                    logger.error(f"Failed to decode hex public key for account {auth.account_id}: {e}")
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
            logger.error(f"Failed to decode signature for account {auth.account_id}: {e}")
            raise HTTPException(status_code=400, detail="invalid_signature")

        try:
            Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, await request.body())
        except Exception as e:  # noqa: BLE001
            logger.error(f"Signature verification failed for account {auth.account_id}: {e}")
            raise HTTPException(status_code=400, detail="invalid_signature")
        
        logger.info(f"Ed25519 signature verified successfully for account {auth.account_id}")

    # ------------------------------------------------------------------
    # Fetch active RSA key-pair for this tenant
    rsa_row = await query_one(
        supabase,
        "jwks_keys",
        match={"account_id": auth.account_id},
        order_by=("created_at", "desc"),
    )
    if not rsa_row:
        logger.error("Signing key not found for account %s", auth.account_id)
        raise HTTPException(status_code=500, detail="signing_key_not_found")

    rsa_kid = rsa_row["kid"]
    private_jwk = decrypt_private_jwk(rsa_row["private_jwk"])

    # Sign the updated bundle with RSA key and correct kid
    # Use the enhanced JWS creation function (no JWKS refresh for normal publishes)
    jws = create_enhanced_jws(
        payload=updated_bundle,
        private_jwk=private_jwk,
        kid=rsa_kid,
        algorithm=JWT_ALGORITHM,
        audience=f"d2-policy:{auth.account_id}:{app_name}",  # Specific audience for this policy
    )
    
    # policy_expiry_str already set from server-side enforcement above

    # First publish the new policy as active
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

    # Then atomically deactivate all other active policies for this account/app
    # This prevents race conditions by ensuring only one policy is active
    await update_data(
        supabase,
        POLICY_TABLE,
        keys={
            "account_id": auth.account_id, 
            "app_name": app_name, 
            "is_draft": False, 
            "active": True,
            "id": ("neq", draft_row["id"])  # Exclude the policy we just activated
        },
        values={"active": False},
    )

    # Build response with JWS (consistent with GET /bundle endpoint)
    response = PolicyPublishResponse(
        jws=jws,
        version=new_version
    )

    # Compute ETag (sha256 of JWS)
    etag = sha256(jws.encode()).hexdigest()

    # Determine poll-seconds (account-level override or default by plan)
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

    # Audit log policy publish
    try:
        await log_audit_event(
            supabase,
            action=AuditAction.policy_publish,
            actor_id=auth.account_id,
            status=AuditStatus.success,
            token_id=auth.token_id,
            user_id=auth.user_id,
            version=new_version,
            resource_type="policy",
            resource_id=policy_id,
            metadata={
                "app_name": app_name, 
                "version": new_version, 
                "key_id": x_d2_key_id,
                "signature_required": x_d2_signature is not None,
            },
        )
    except Exception:
        pass

    return JSONResponse(content=response.model_dump(), headers=headers)


@router.post("/revoke", response_model=MessageResponse, status_code=status.HTTP_202_ACCEPTED)
async def revoke_policy(
    request: Request,
    app_name: str = Query(..., description="App name to revoke policy for"),
    auth: AuthContext = Depends(require_auth("policy.revoke")),
    supabase=Depends(get_supabase_async),
):
    # Normalize app name (convert spaces to underscores)
    app_name = normalize_app_name(app_name)
    
    logger.info(f"Revoking policy for app '{app_name}' in account {auth.account_id}")
    # Revoke ALL published versions (is_draft = False) for this app
    now_ts = datetime.now(timezone.utc)

    await update_data(
        supabase,
        POLICY_TABLE,
        filters={
            "account_id": auth.account_id,
            "app_name": app_name,
            "is_draft": False,
            "is_revoked": False,
        },
        update_values={
            "revocation_time": now_ts,
            "is_revoked": True,
            "active": False,
        },
        error_message="policy_revoke_failed",
    )

    # Optionally also mark any draft as revoked/inactive (so it can't be published)
    await update_data(
        supabase,
        POLICY_TABLE,
        filters={
            "account_id": auth.account_id,
            "app_name": app_name,
            "is_draft": True,
        },
        update_values={
            "is_revoked": True,
        },
        error_message="policy_revoke_failed_draft",
    )
    
    # Audit log policy revocation (bulk) with user attribution
    await log_audit_event(
        supabase,
        action=AuditAction.policy_revoke,
        actor_id=auth.account_id,
        status=AuditStatus.success,
        token_id=auth.token_id,
        user_id=auth.user_id,
        metadata={"app_name": app_name},
    )

    logger.info(
        "Revoked all published/draft policies for app '%s' in account %s",
        app_name,
        auth.account_id,
    )
    return MessageResponse(message=f"All policies revoked for app '{app_name}'")


@router.get("/versions", response_model=list[PolicyVersionResponse])
async def list_policy_versions(
    app_name: str = Query(None, description="Filter by app name"),
    include_bundle: bool = Query(False, description="Include full bundle content for comparison"),
    auth: AuthContext = Depends(require_auth("policy.read")),
    supabase=Depends(get_supabase_async),
):
    """List all published policy versions for an account, ordered by version desc.
    
    Optionally filter by app_name and include bundle content for editor comparison.
    """
    # Normalize app name if provided (convert spaces to underscores)
    if app_name:
        app_name = normalize_app_name(app_name)
    
    match_filters = {"account_id": auth.account_id, "is_draft": False}
    if app_name:
        match_filters["app_name"] = app_name

    select_fields = "id,version,active,published_at,expires,revocation_time,app_name"
    if include_bundle:
        select_fields += ",bundle"

    rows = await query_many(
        supabase,
        POLICY_TABLE,
        match=match_filters,
        order_by=("version", "desc"),
        select_fields=select_fields,
    )
    
    # Enhance with user attribution from audit logs
    policy_ids = [row["id"] for row in rows]
    user_attribution = {}
    
    if policy_ids:
        # Get publish audit logs for these policies
        audit_rows = await query_many(
            supabase,
            "audit_logs",
            match={"action": "policy.publish"},
            select_fields="version,user_id",
        )
        
        # Get user names
        user_ids = [audit["user_id"] for audit in audit_rows if audit.get("user_id")]
        user_names = {}
        
        if user_ids:
            user_rows = await query_many(
                supabase,
                "users",
                match={"user_id": ("in", user_ids)},
                select_fields="user_id,display_name,full_name",
            )
            for user in user_rows:
                user_names[user["user_id"]] = user.get("display_name") or user.get("full_name") or "Unknown"
        
        # Map versions to user names
        for audit in audit_rows:
            if audit.get("version") and audit.get("user_id"):
                user_attribution[audit["version"]] = user_names.get(audit["user_id"], "Unknown")
    
    # Add published_by to each row
    for row in rows:
        row["published_by"] = user_attribution.get(row["version"])
    
    return [PolicyVersionResponse(**row) for row in rows]


@router.post("/revert", response_model=MessageResponse)
async def revert_policy(
    http_request: Request,
    request: PolicyRevertRequest,
    auth: AuthContext = Depends(require_auth("policy.revert")),
    supabase=Depends(get_supabase_async),
):
    """Revert to a specific policy version by making it active."""
    
    # Verify the target policy exists and belongs to this account
    target_policy = await query_one(
        supabase,
        POLICY_TABLE,
        match={"id": request.policy_id, "account_id": auth.account_id, "is_draft": False},
    )
    if not target_policy:
        raise HTTPException(status_code=404, detail="Policy version not found")
    
    # Check if policy is revoked
    if target_policy.get("revocation_time"):
        raise HTTPException(status_code=409, detail="Cannot revert to a revoked policy")
    
    # Check if it's already active
    if target_policy.get("active"):
        raise HTTPException(status_code=409, detail="Policy version is already active")
    
    # Find and deactivate the currently active policy for this app
    current_active = await query_one(
        supabase,
        POLICY_TABLE,
        match={
            "account_id": auth.account_id, 
            "app_name": target_policy["app_name"], 
            "is_draft": False, 
            "active": True
        },
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
    
    # Audit log policy reversion with user attribution
    await log_audit_event(
        supabase,
        action=AuditAction.policy_revert,
        actor_id=auth.account_id,
        status=AuditStatus.success,
        token_id=auth.token_id,
        user_id=auth.user_id,
        metadata={"policy_id": request.policy_id, "version": target_policy.get("version")},
    )
    
    return MessageResponse(message=f"Reverted to policy version {target_policy['version']}")

# ---------------------------------------------------------------------------
# Front-end helpers: list policies & fetch single bundle + metadata
# ---------------------------------------------------------------------------


@router.get("/list", response_model=list[PolicySummary])
async def list_policies(
    auth: AuthContext = Depends(require_auth("policy.read")),
    supabase=Depends(get_supabase_async),
):
    """Return **all** policies (draft + published) for the caller's account.

    Front-end can client-side filter by `app_name` or `is_draft` if needed.
    """

    rows = await query_many(
        supabase,
        POLICY_TABLE,
        match={"account_id": auth.account_id},
        order_by=("created_at", "desc"),
        select_fields="id,app_name,version,active,is_draft,published_at,expires,revocation_time,is_revoked,bundle",
    )
    return [PolicySummary(**r) for r in rows]


@router.get("/roles-permissions")
async def list_roles_and_permissions(
    auth: AuthContext = Depends(require_auth("policy.read")),
    supabase=Depends(get_supabase_async),
):
    """Extract all unique roles and permissions from policy bundles for UI suggestions.
    
    Returns roles, permissions, and role-to-permission mappings from all policy bundles
    (both draft and published) for this account.
    
    Useful for frontend autocomplete/dropdown suggestions when crafting new policies.
    """
    
    # Fetch all policy bundles for this account (both draft and published)
    rows = await query_many(
        supabase,
        POLICY_TABLE,
        match={"account_id": auth.account_id},
        select_fields="bundle",
    )
    
    # Use sets to automatically handle uniqueness
    all_roles = set()
    all_permissions = set()
    # Use dict to track role -> permissions mappings
    role_permission_mappings = {}
    
    # Process each policy bundle
    for row in rows:
        bundle = row.get("bundle")
        if not bundle or not isinstance(bundle, dict):
            continue
            
        policies = bundle.get("policies", [])
        if not isinstance(policies, list):
            continue
            
        # Extract roles and permissions from each policy rule
        for policy in policies:
            if not isinstance(policy, dict):
                continue
                
            # Extract role
            role = policy.get("role")
            if not role or not isinstance(role, str):
                continue
                
            role = role.strip()
            all_roles.add(role)
            
            # Extract permissions for this role
            permissions = policy.get("permissions", [])
            if isinstance(permissions, list):
                # Initialize role in mappings if not exists
                if role not in role_permission_mappings:
                    role_permission_mappings[role] = set()
                    
                for perm in permissions:
                    if perm and isinstance(perm, str):
                        perm = perm.strip()
                        all_permissions.add(perm)
                        role_permission_mappings[role].add(perm)
    
    # Convert mappings to sorted lists for consistent API response
    role_mappings = {}
    for role, perms in role_permission_mappings.items():
        role_mappings[role] = sorted(list(perms))
    
    # Convert sets to sorted lists for consistent API response
    return {
        "roles": sorted(list(all_roles)),
        "permissions": sorted(list(all_permissions)),
        "role_mappings": role_mappings
    }


@router.get("/{policy_id}", response_model=PolicySummary)
async def get_policy_detail(
    policy_id: str,
    auth: AuthContext = Depends(require_auth("policy.read")),
    supabase=Depends(get_supabase_async),
):
    row = await query_one(
        supabase,
        POLICY_TABLE,
        match={"id": policy_id, "account_id": auth.account_id},
    )
    if not row:
        raise HTTPException(status_code=404, detail="policy_not_found")

    return PolicySummary(**row)


@router.patch("/{policy_id}/bundle", response_model=MessageResponse)
async def update_policy_bundle(
    http_request: Request,
    policy_id: str,
    payload: PolicyBundleUpdate,
    auth: AuthContext = Depends(require_auth("policy.publish")),
    supabase=Depends(get_supabase_async),
):
    """Update policy bundle content and optionally description from the editor.
    
    This endpoint allows frontend editors to save changes to policy content.
    Only works on draft policies or creates a new draft from published policy.
    """
    
    # Ensure policy belongs to caller
    policy_row = await query_one(
        supabase,
        POLICY_TABLE,
        match={"id": policy_id, "account_id": auth.account_id},
    )
    if not policy_row:
        raise HTTPException(status_code=404, detail="policy_not_found")

    # Parse and validate the new bundle
    try:
        import json
        # Ensure it's valid JSON and contains required metadata
        if not isinstance(payload.bundle, dict):
            raise HTTPException(status_code=400, detail="bundle_must_be_object")
        
        metadata = payload.bundle.get("metadata", {})
        if not metadata.get("name"):
            raise HTTPException(status_code=400, detail="bundle_missing_metadata_name")
            
    except Exception:
        raise HTTPException(status_code=400, detail="invalid_bundle_format")

    # Update values
    update_values = {"bundle": payload.bundle}

    await update_data(
        supabase,
        POLICY_TABLE,
        keys={"id": policy_id},
        values=update_values,
    )

    # Audit log policy bundle update with user attribution
    await log_audit_event(
        supabase,
        action=AuditAction.policy_update,
        actor_id=auth.account_id,
        status=AuditStatus.success,
        token_id=auth.token_id,
        user_id=auth.user_id,
        version=policy_row.get("version"),
    )

    return MessageResponse(message="bundle_updated")


@router.post("/validate", response_model=PolicyValidationResponse)
async def validate_policy_bundle(
    validation_request: PolicyValidationRequest,
    auth: AuthContext = Depends(require_auth("policy.read")),
):
    """Validate a policy bundle and provide detailed feedback for the editor.
    
    This endpoint provides real-time validation feedback without saving the policy.
    Useful for editor syntax highlighting and error detection.
    """
    bundle = validation_request.bundle
    errors = []
    warnings = []
    metadata = {}
    
    # Basic structure validation
    if not isinstance(bundle, dict):
        errors.append("Policy bundle must be a JSON object")
        return PolicyValidationResponse(valid=False, errors=errors, warnings=warnings, metadata=metadata)
    
    # Required metadata validation
    meta = bundle.get("metadata", {})
    if not meta:
        errors.append("Missing required 'metadata' section")
    else:
        # Required fields
        if not meta.get("name"):
            errors.append("metadata.name is required")
        else:
            metadata["name"] = meta["name"]
            
        # Optional but recommended fields
        if not meta.get("description"):
            warnings.append("metadata.description is recommended for clarity")
        else:
            metadata["description"] = meta["description"]
            
        if not meta.get("expires"):
            warnings.append("metadata.expires is recommended for policy lifecycle management")
        else:
            metadata["expires"] = meta["expires"]
            # Validate ISO 8601 format
            try:
                from datetime import datetime
                datetime.fromisoformat(meta["expires"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                errors.append("metadata.expires must be valid ISO 8601 timestamp")
    
    # Policies section validation
    policies = bundle.get("policies", [])
    if not policies:
        errors.append("At least one policy rule is required in 'policies' array")
    elif not isinstance(policies, list):
        errors.append("'policies' must be an array")
    else:
        for i, policy in enumerate(policies):
            if not isinstance(policy, dict):
                errors.append(f"Policy rule {i} must be an object")
                continue
                
            # Required fields
            if not policy.get("role"):
                errors.append(f"Policy rule {i}: 'role' is required")
            if not policy.get("permissions"):
                errors.append(f"Policy rule {i}: 'permissions' array is required")
            elif not isinstance(policy.get("permissions"), list):
                errors.append(f"Policy rule {i}: 'permissions' must be an array")
            else:
                perms = policy["permissions"]
                if not perms:
                    warnings.append(f"Policy rule {i}: empty permissions array (no access granted)")
                
                # Check for explicit denies
                has_deny = any(p.startswith("!") for p in perms if isinstance(p, str))
                has_wildcard = "*" in perms
                
                if has_wildcard and not has_deny:
                    warnings.append(f"Policy rule {i}: wildcard '*' without explicit denies may be overly permissive")
    
    # Overall validation result
    valid = len(errors) == 0
    
    return PolicyValidationResponse(
        valid=valid,
        errors=errors,
        warnings=warnings,
        metadata=metadata
    )


@router.get("/apps", response_model=list[str])
async def list_app_names(
    auth: AuthContext = Depends(require_auth("policy.read")),
    supabase=Depends(get_supabase_async),
):
    """Return distinct app names for this account (for token creation dropdown)."""
    
    rows_raw = await query_many(
        supabase,
        POLICY_TABLE,
        match={"account_id": auth.account_id},
        select_fields="DISTINCT app_name",
    )
    
    rows = rows_raw if isinstance(rows_raw, list) else getattr(rows_raw, "data", [])
    app_names = [r["app_name"] for r in rows if r.get("app_name")]
    
    # Always include "default" as an option
    if "default" not in app_names:
        app_names.append("default")
    
    return sorted(app_names)


@router.get("/roles-permissions")
async def list_roles_and_permissions(
    auth: AuthContext = Depends(require_auth("policy.read")),
    supabase=Depends(get_supabase_async),
):
    """Extract all unique roles and permissions from policy bundles for UI suggestions.
    
    Returns two sets: all roles and all permissions that have been used across
    all policy bundles (both draft and published) for this account.
    
    Useful for frontend autocomplete/dropdown suggestions when crafting new policies.
    """
    
    # Fetch all policy bundles for this account (both draft and published)
    rows = await query_many(
        supabase,
        POLICY_TABLE,
        match={"account_id": auth.account_id},
        select_fields="bundle",
    )
    
    # Use sets to automatically handle uniqueness
    all_roles = set()
    all_permissions = set()
    
    # Process each policy bundle
    for row in rows:
        bundle = row.get("bundle")
        if not bundle or not isinstance(bundle, dict):
            continue
            
        policies = bundle.get("policies", [])
        if not isinstance(policies, list):
            continue
            
        # Extract roles and permissions from each policy rule
        for policy in policies:
            if not isinstance(policy, dict):
                continue
                
            # Extract role
            role = policy.get("role")
            if role and isinstance(role, str):
                all_roles.add(role.strip())
                
            # Extract permissions
            permissions = policy.get("permissions", [])
            if isinstance(permissions, list):
                for perm in permissions:
                    if perm and isinstance(perm, str):
                        all_permissions.add(perm.strip())
    
    # Convert sets to sorted lists for consistent API response
    return {
        "roles": sorted(list(all_roles)),
        "permissions": sorted(list(all_permissions)),
        "stats": {
            "total_roles": len(all_roles),
            "total_permissions": len(all_permissions),
            "policies_analyzed": len(rows)
        }
    }



