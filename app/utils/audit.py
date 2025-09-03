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
) -> None:
    """
    Log an audit event using existing audit_logs schema.
    
    Args:
        supabase: Supabase client
        action: Standardized action type (AuditAction enum)
        actor_id: Account ID performing the action
        status: Operation status (success/failure/denied/allowed) - stored in action field
        token_id: API token used (if applicable)
        user_id: User who created the token (if applicable)
        key_id: Cryptographic key ID (for key operations)
        version: Resource version (for versioned resources)
    """
    # Format action with status for existing schema
    action_with_status = f"{action.value}:{status.value}" if status != AuditStatus.success else action.value
    
    audit_entry = {
        "actor_id": actor_id,
        "action": action_with_status,
        "created_at": datetime.now(timezone.utc),
    }
    
    # Add optional fields only if provided (matching existing schema)
    if token_id:
        audit_entry["token_id"] = token_id
    if user_id:
        audit_entry["user_id"] = user_id
    if key_id:
        audit_entry["key_id"] = key_id
    if version is not None:
        audit_entry["version"] = version
    
    try:
        await insert_data(supabase, "audit_logs", audit_entry)
    except Exception:
        # Never let audit logging break the main operation
        # In production, you might want to log this to a separate error tracking system
        pass


async def extract_token_details_for_audit(authorization: str, supabase) -> dict:
    """
    Extract token details for audit logging from Authorization header.
    
    Returns dict with token_id, user_id, and account_id for audit context.
    """
    try:
        from app.utils.security_utils import verify_api_token
        
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
