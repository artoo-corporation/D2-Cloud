"""Comprehensive audit logging utilities for tracking all system operations."""

from datetime import datetime, timezone
from typing import Optional

from app.models import AuditAction, AuditStatus
from app.utils.database import insert_data


async def log_audit_event(
    supabase,
    action: AuditAction,
    actor_id: str,
    status: AuditStatus = AuditStatus.success,
    token_id: Optional[str] = None,
    user_id: Optional[str] = None,
    key_id: Optional[str] = None,
    version: Optional[int] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> None:
    """
    Log an audit event using the comprehensive audit_logs schema.
    
    Args:
        supabase: Supabase client
        action: Standardized action type (AuditAction enum)
        actor_id: Account ID performing the action
        status: Operation status (success/failure/denied/allowed)
        token_id: API token used (if applicable)
        user_id: User who performed the action (if applicable)
        key_id: Cryptographic key ID (for key operations)
        version: Resource version (for versioned resources)
        resource_type: Type of resource acted upon (policy, token, key, invitation, user)
        resource_id: ID of the specific resource acted upon
        metadata: Additional structured data about the operation
    """
    audit_entry = {
        "actor_id": actor_id,
        "action": action.value,
        "status": status.value,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    
    # Add optional fields only if provided
    if token_id:
        audit_entry["token_id"] = token_id
    if user_id:
        audit_entry["user_id"] = user_id
    if key_id:
        audit_entry["key_id"] = key_id
    if version is not None:
        audit_entry["version"] = version
    if resource_type:
        audit_entry["resource_type"] = resource_type
    if resource_id:
        audit_entry["resource_id"] = resource_id
    if metadata:
        audit_entry["metadata"] = metadata
    
    try:
        await insert_data(supabase, "audit_logs", audit_entry)
    except Exception as e:
        # Never let audit logging break the main operation
        # In production, you might want to log this to a separate error tracking system
        from app.utils.logger import logger
        logger.warning(f"Failed to log audit event: {e}")
        pass


async def extract_token_details_for_audit(authorization: str, supabase) -> dict:
    """
    Extract token details for audit logging from Authorization header.
    
    Returns dict with token_id, user_id, and account_id for audit context.
    """
    try:
        from app.utils.auth import verify_api_token
        
        if not authorization or not authorization.startswith("Bearer "):
            return {}
            
        token = authorization.split(" ")[-1]
        details = await verify_api_token(
            token, supabase, admin_only=False, return_details=True
        )
        
        if isinstance(details, dict):
            return {
                "token_id": details.get("token_id"),
                "user_id": details.get("user_id"),
                "account_id": details.get("account_id"),
            }
    except Exception:
        # If token verification fails, return empty dict
        # The main operation should handle auth failures separately
        pass
    
    return {}
