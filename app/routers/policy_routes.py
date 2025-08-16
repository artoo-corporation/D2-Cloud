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
    MessageResponse,
)
from app.utils.database import insert_data, query_one, update_data
from app.utils.dependencies import get_supabase_async, require_account_admin
from app.utils.security_utils import get_active_private_jwk, verify_api_token
from app.utils.plans import enforce_bundle_poll
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import base64
from app.utils.require_scope import require_scope

# Helper to detect "deny" statements in bundle


def _count_denies(obj: dict | list) -> int:  # noqa: WPS231
    if isinstance(obj, list):
        return sum(_count_denies(item) for item in obj)
    if isinstance(obj, dict):
        deny_here = 1 if obj.get("effect") == "deny" else 0
        return deny_here + sum(_count_denies(v) for v in obj.values())
    return 0

router = APIRouter(prefix="/v1/policy", tags=["policy"])

JWT_ALGORITHM = "RS256"
POLICY_TABLE = "policies"


@router.get("/bundle", response_model=PolicyBundleResponse)
async def get_policy_bundle(
    response: Response,
    account_id: str = Depends(require_scope("read")),
    if_none_match: str | None = Header(None, alias="If-None-Match"),
    supabase=Depends(get_supabase_async),
):
    row = await query_one(
        supabase,
        POLICY_TABLE,
        match={"account_id": account_id},
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

    # If-None-Match header present and matches → 304 Not Modified
    if if_none_match:
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
    account_id: str = Depends(require_account_admin),
    authorization: str = Header(..., description="Bearer API token"),
    supabase=Depends(get_supabase_async),
):
    await insert_data(
        supabase,
        POLICY_TABLE,
        {
            "account_id": account_id,
            "version": draft.version,
            "bundle": draft.bundle,
            "is_draft": True,
        },
    )
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
    force: bool = Query(False),
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
        match={"account_id": account_id, "is_draft": False},
        order_by=("version", "desc"),
    )

    if latest_published:
        current_etag = sha256(latest_published["jws"].encode()).hexdigest()

        provided_etag = None
        if if_match:
            provided_etag = if_match.lstrip("W/").strip('"')
        elif if_none_match:
            provided_etag = if_none_match.lstrip("W/").strip('"')

        if provided_etag is None or provided_etag != current_etag:
            raise HTTPException(status_code=409, detail="etag_mismatch")

    else:
        # First publish ever – still require header but allow "*"
        if not (if_match or if_none_match):
            raise HTTPException(status_code=409, detail="etag_mismatch")

    # ------------------------------------------------------------------
    # Fetch draft
    # ------------------------------------------------------------------

    draft_row = await query_one(
        supabase, POLICY_TABLE, match={"account_id": account_id, "is_draft": True}, order_by=("version", "desc")
    )
    if not draft_row:
        raise HTTPException(status_code=400, detail="No draft to publish. Please upload a draft first at /v1/policy/draft")

    # ------------------------------------------------------------------
    # Version rollback guard
    # ------------------------------------------------------------------

    latest_version = latest_published["version"] if latest_published else 0
    if draft_row["version"] < latest_version:
        raise HTTPException(status_code=409, detail="version_rollback")

    new_version = latest_version + 1

    # ------------------------------------------------------------------
    # Deny-rule guard
    # ------------------------------------------------------------------

    deny_count = _count_denies(draft_row["bundle"])
    if deny_count == 0 and not force:
        raise HTTPException(status_code=400, detail="no_deny_rules")

    # ------------------------------------------------------------------
    # Signature verification (Ed25519)
    # ------------------------------------------------------------------
    key_row = await query_one(
        supabase,
        "public_keys",
        match={"account_id": account_id, "key_id": x_d2_key_id},
    )

    if not key_row:
        raise HTTPException(status_code=404, detail="key_not_found")
    if key_row.get("revoked_at") is not None:
        raise HTTPException(status_code=403, detail="key_revoked")

    public_key_raw = key_row["public_key"]
    if isinstance(public_key_raw, str):
        try:
            public_key_bytes = base64.b64decode(public_key_raw)
        except Exception:
            public_key_bytes = public_key_raw.encode()
    else:
        public_key_bytes = public_key_raw

    try:
        signature = base64.b64decode(x_d2_signature)
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="invalid_signature")

    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, await request.body())
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="invalid_signature")

    # ------------------------------------------------------------------
    private_jwk = await get_active_private_jwk(account_id, supabase)

    jws = jwt.encode(draft_row["bundle"], private_jwk, algorithm=JWT_ALGORITHM)

    await update_data(
        supabase,
        POLICY_TABLE,
        keys={"id": draft_row["id"]},
        values={
            "jws": jws,
            "is_draft": False,
            "published_at": datetime.now(timezone.utc),
            "version": new_version,
        },
    )

    if force:
        await insert_data(
            supabase,
            "audit_logs",
            {
                "actor_id": account_id,
                "action": "force_publish",
                "token_id": None,
                "ip": None,
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
