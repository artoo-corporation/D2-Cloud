"""JWKS endpoint – serves public keys for SDK verification."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

from fastapi import APIRouter, Depends, Header, Query, status, Response, Request, HTTPException, BackgroundTasks
# Rate limiter exported by main.py
from app.main import limiter

from app.models import MessageResponse, JWKSConfigurationResponse, JWKSRotationResponse, JWKSHistoryResponse, JWKSKeyHistoryItem, AuthContext
from app.utils.security_utils import generate_rsa_jwk, encrypt_private_jwk, resign_active_policies
from app.utils.database import insert_data, query_many, query_one
from app.utils.dependencies import get_supabase_async
from app.utils.auth import require_auth

# Public discovery endpoints (no auth)
public_router = APIRouter(prefix="/.well-known", tags=["jwks-public"])

# Admin-only management endpoints
admin_router = APIRouter(prefix="/v1/jwks", tags=["jwks-admin"])


@public_router.get("/jwks.json", response_model=Dict[str, Any])
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
        rows = await query_many(
            supabase, 
            "jwks_keys", 
            match=filters,
            select_fields="kid,public_jwk,created_at"
        )
    except Exception:  # noqa: BLE001
        rows = []  # Supabase unavailable – return empty set

    # Build enhanced key list with additional metadata for debugging
    enhanced_keys = []
    key_ids = []
    
    for row in rows:
        if row.get("public_jwk"):
            key = row["public_jwk"].copy()
            
            # Add useful metadata that's not in the standard JWK
            key["kid"] = str(row["kid"])  # Ensure kid is always a string
            
            # Add creation timestamp for debugging (not part of JWK standard)
            if row.get("created_at"):
                key["iat"] = int(datetime.fromisoformat(str(row["created_at"])).timestamp()) if isinstance(row["created_at"], str) else int(row["created_at"].timestamp())
            
            enhanced_keys.append(key)
            key_ids.append(str(row["kid"]))
    
    # Reduce cache time during key rotations to prevent stale key issues
    # Still cache for performance, but allow faster updates
    response.headers["Cache-Control"] = "public, max-age=60, must-revalidate"
    
    # Add debugging headers for the SDK team
    response.headers["X-JWKS-Key-Count"] = str(len(enhanced_keys))
    response.headers["X-JWKS-Generated-At"] = datetime.now(timezone.utc).isoformat()
    if key_ids:
        response.headers["X-JWKS-Key-IDs"] = ",".join(key_ids)
    
    return {"keys": enhanced_keys}


# ---------------------------------------------------------------------------
# Admin-only: get current JWKS configuration
# ---------------------------------------------------------------------------


@admin_router.get("/configuration", response_model=JWKSConfigurationResponse)
async def get_jwks_configuration(
    request: Request,
    auth: AuthContext = Depends(require_auth(admin_only=True)),
    supabase=Depends(get_supabase_async),
):
    """Get current JWKS configuration for the authenticated account."""
    
    # Get the most recent (active) key for this account
    key_row = await query_one(
        supabase,
        "jwks_keys", 
        match={"account_id": auth.account_id},
        order_by=("created_at", "desc"),
    )
    
    if not key_row:
        raise HTTPException(status_code=404, detail="No JWKS key found for account")
    
    # Construct the JWKS URL based on the current request
    base_url = f"{request.url.scheme}://{request.headers.get('host', request.url.netloc)}"
    jwks_url = f"{base_url}/.well-known/jwks.json?account_id={account_id}"
    
    return JWKSConfigurationResponse(
        current_key_id=str(key_row["kid"]),  # Convert UUID to string
        algorithm=key_row["public_jwk"].get("alg", "RS256"),
        jwks_url=jwks_url,
        public_key=key_row["public_jwk"],
        rotation_enabled=False,  # You can add this to your DB schema later
        rotation_interval_days=90,  # Default value, can be made configurable
    )


# ---------------------------------------------------------------------------
# Admin-only: get JWKS rotation history
# ---------------------------------------------------------------------------


@admin_router.get("/history", response_model=JWKSHistoryResponse)
async def get_jwks_history(
    auth: AuthContext = Depends(require_auth(admin_only=True)),
    supabase=Depends(get_supabase_async),
):
    """Get complete JWKS rotation history for the authenticated account."""
    
    # Get all keys for this account, ordered by creation date (newest first)
    rows = await query_many(
        supabase,
        "jwks_keys",
        match={"account_id": auth.account_id},
        order_by=("created_at", "desc"),
        select_fields="kid,public_jwk,created_at,expires_at",
    )
    
    if not rows:
        # No keys exist - return empty history
        return JWKSHistoryResponse(
            keys=[],
            total_rotations=0,
            overlap_days=0,  # No longer used - automated rotation handles cleanup
        )
    
    # Convert to history items
    history_items = []
    for i, row in enumerate(rows):
        history_items.append(
            JWKSKeyHistoryItem(
                key_id=str(row["kid"]),
                algorithm=row["public_jwk"].get("alg", "RS256"),
                created_at=row["created_at"] if isinstance(row["created_at"], datetime) else datetime.fromisoformat(row["created_at"]),
                expires_at=row.get("expires_at"),
                is_active=(i == 0),  # First item (newest) is active
                public_key=row["public_jwk"],
            )
        )
    
    return JWKSHistoryResponse(
        keys=history_items,
        total_rotations=len(rows),
        overlap_days=0,  # No longer used - automated rotation handles cleanup
    )


# ---------------------------------------------------------------------------
# Admin-only: rotate RSA key-pair for the tenant
# ---------------------------------------------------------------------------


async def automated_rotation_workflow(
    account_id: str, 
    new_kid: str, 
    rotation_id: str,
    supabase
):
    """Background task: Orchestrates the complete automated rotation process."""
    from app.utils.logger import logger
    
    try:
        logger.info(f"Starting automated rotation workflow for account {account_id}, rotation {rotation_id}")
        
        # Phase 1: Re-sign all active policies with new key
        resign_result = await resign_active_policies(
            account_id=auth.account_id,
            new_kid=new_kid,
            rotation_id=rotation_id,
            supabase=supabase
        )
        
        logger.info(f"Rotation {rotation_id} policy re-signing complete: {resign_result}")
        
        # Phase 2: Immediate cleanup of old keys (no overlap needed)
        await cleanup_old_jwks_keys(account_id, new_kid, rotation_id, supabase)
        
        # Phase 3: Log completion
        await log_rotation_completion(account_id, rotation_id, resign_result, supabase)
        
    except Exception as e:
        logger.error(f"Automated rotation workflow failed for {account_id}: {e}")
        await log_rotation_failure(account_id, rotation_id, str(e), supabase)


async def log_rotation_completion(account_id: str, rotation_id: str, result: Dict[str, Any], supabase):
    """Log successful rotation completion."""
    from app.utils.logger import logger
    
    logger.info(f"JWKS rotation {rotation_id} completed successfully for account {account_id}")
    logger.info(f"Rotation stats: {result}")
    
    # Could store rotation history in database here
    # For now, just comprehensive logging


async def cleanup_old_jwks_keys(account_id: str, new_kid: str, rotation_id: str, supabase):
    """Cleanup old JWKS keys after a safe delay to ensure SDK cache refresh."""
    import asyncio
    from app.utils.logger import logger
    from app.utils.database import query_many
    
    # Wait 2 minutes to allow SDK JWKS cache to refresh (cache is 60s + buffer)
    await asyncio.sleep(120)
    
    try:
        # Find all old keys (not the new one we just created)
        old_keys = await query_many(
            supabase,
            "jwks_keys",
            match={"account_id": auth.account_id},
            select_fields="id,kid,created_at",
        )
        
        keys_to_delete = [key for key in old_keys if key["kid"] != new_kid]
        
        if not keys_to_delete:
            logger.info(f"No old JWKS keys to cleanup for account {account_id}")
            return
        
        # Delete old keys after safe delay
        for key in keys_to_delete:
            await supabase.table("jwks_keys").delete().eq("id", key["id"]).execute()
            logger.info(f"Deleted old JWKS key {key['kid']} for account {account_id} after safe delay")
        
        logger.info(f"Cleaned up {len(keys_to_delete)} old JWKS keys for rotation {rotation_id} after 2-minute delay")
        
    except Exception as e:
        logger.error(f"Failed to cleanup old JWKS keys for {account_id}: {e}")
        # Don't fail the rotation if cleanup fails


async def log_rotation_failure(account_id: str, rotation_id: str, error: str, supabase):
    """Log rotation failure for monitoring."""
    from app.utils.logger import logger
    
    logger.error(f"JWKS rotation {rotation_id} failed for account {account_id}: {error}")
    
    # Could store failure record in database here
    # For now, just error logging


@admin_router.post("/rotate", response_model=JWKSRotationResponse, status_code=status.HTTP_201_CREATED)
async def rotate_jwk(
    background_tasks: BackgroundTasks,
    auth: AuthContext = Depends(require_auth(admin_only=True)),
    supabase=Depends(get_supabase_async),
):
    """Fully automated JWKS rotation with zero disruption."""
    jwk_pair = generate_rsa_jwk()
    new_kid = str(uuid.uuid4())
    rotation_time = datetime.now(timezone.utc)
    rotation_id = f"rot_{auth.account_id}_{rotation_time.strftime('%Y%m%d_%H%M%S')}"

    # Store new key (old key remains for overlap)
    await insert_data(
        supabase,
        "jwks_keys",
        {
            "account_id": auth.account_id,
            "kid": new_kid,
            "public_jwk": jwk_pair["public"],
            "private_jwk": encrypt_private_jwk(jwk_pair["private"]),
        },
    )

    # Trigger automated background workflow
    background_tasks.add_task(
        automated_rotation_workflow,
        account_id=auth.account_id,
        new_kid=new_kid,
        rotation_id=rotation_id,
        supabase=supabase
    )
    
    # Short overlap to ensure SDK cache refresh before cleanup
    old_keys_expire_at = rotation_time + timedelta(minutes=2)  # 2 minute safety buffer for cache refresh

    return JWKSRotationResponse(
        message=f"Automated JWKS rotation initiated (ID: {rotation_id})",
        new_key_id=new_kid,
        algorithm=jwk_pair["public"].get("alg", "RS256"),
        rotation_completed_at=rotation_time,
        old_keys_expire_at=old_keys_expire_at,
    )


# Re-export for main.py
__all__ = ["public_router", "admin_router"] 