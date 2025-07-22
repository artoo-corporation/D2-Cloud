"""Policy Service routes – CRUD + signer for policy bundles."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from hashlib import sha256
from typing import Dict, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from jose import jwt

from app.schemas import (
    PolicyBundleResponse,
    PolicyDraft,
    PolicyPublishResponse,
    MessageResponse,
)
from app.utils.database import insert_data, query_one, update_data
from app.utils.dependencies import get_supabase_async
from app.utils.security_utils import verify_api_token, get_active_private_jwk
from app.utils.plan_limits import enforce_bundle_poll

router = APIRouter(prefix="/v1/policy", tags=["policy"])

JWT_ALGORITHM = "RS256"
POLICY_TABLE = "policies"


@router.get("/bundle", response_model=PolicyBundleResponse)
async def get_policy_bundle(
    response: Response,
    authorization: str = Header(..., description="Bearer API token"),
    supabase=Depends(get_supabase_async),
):
    token = authorization.split(" ")[-1]
    account_id = await verify_api_token(token, supabase)

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
    response.headers["ETag"] = etag
    # Use per-account poll window if set, otherwise default by plan
    response.headers["X-D2-Poll-Seconds"] = str(poll_seconds)

    return PolicyBundleResponse(jws=row["jws"], version=row["version"], etag=etag)


@router.put("/draft", response_model=MessageResponse)
async def upload_policy_draft(
    draft: PolicyDraft,
    authorization: str = Header(...),
    supabase=Depends(get_supabase_async),
):
    token = authorization.split(" ")[-1]
    account_id = await verify_api_token(token, supabase, admin_only=True)

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
    return MessageResponse(message="Draft uploaded")


@router.post("/publish", response_model=PolicyPublishResponse)
async def publish_policy(
    authorization: str = Header(...),
    supabase=Depends(get_supabase_async),
):
    token = authorization.split(" ")[-1]
    account_id = await verify_api_token(token, supabase, admin_only=True)

    draft_row = await query_one(
        supabase, POLICY_TABLE, match={"account_id": account_id, "is_draft": True}, order_by=("version", "desc")
    )
    if not draft_row:
        raise HTTPException(status_code=400, detail="No draft to publish")

    private_jwk = await get_active_private_jwk(account_id, supabase)

    jws = jwt.encode(draft_row["bundle"], private_jwk, algorithm=JWT_ALGORITHM)

    await update_data(
        supabase,
        POLICY_TABLE,
        keys={"id": draft_row["id"]},
        values={"jws": jws, "is_draft": False, "published_at": datetime.now(timezone.utc)},
    )

    return PolicyPublishResponse(jws=jws, version=draft_row["version"])


@router.post("/revoke", response_model=MessageResponse, status_code=status.HTTP_202_ACCEPTED)
async def revoke_policy(
    authorization: str = Header(...),
    supabase=Depends(get_supabase_async),
):
    token = authorization.split(" ")[-1]
    account_id = await verify_api_token(token, supabase, admin_only=True)

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
