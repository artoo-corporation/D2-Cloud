"""Policy expiry parsing and management utilities."""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

def extract_policy_expiry(bundle: Dict[str, Any]) -> Optional[datetime]:
    """
    Extract expiry information from a D2 policy bundle.
    
    According to D2 policy schema:
    - metadata.expires is REQUIRED in local mode, recommended in cloud
    - Should be ISO-8601 format string
    
    Primary location: bundle.metadata.expires
    Fallback locations for backward compatibility:
    - bundle.metadata.expiry  
    - bundle.expires
    
    Returns the expiry datetime, or None if no valid expiry found.
    """
    try:
        # Primary: Check required metadata.expires field (D2 standard)
        metadata = bundle.get("metadata", {})
        if isinstance(metadata, dict) and "expires" in metadata:
            expiry_value = metadata["expires"]
            parsed_expiry = _parse_expiry_value(expiry_value)
            if parsed_expiry:
                logger.info(f"Found policy expiry in metadata.expires: {parsed_expiry}")
                return parsed_expiry
            else:
                logger.warning(f"Could not parse metadata.expires value: {expiry_value}")
        
        # Fallback: Check alternative field names for backward compatibility
        if isinstance(metadata, dict):
            for field in ["expiry", "expiration"]:
                if field in metadata:
                    expiry_value = metadata[field]
                    parsed_expiry = _parse_expiry_value(expiry_value)
                    if parsed_expiry:
                        logger.info(f"Found policy expiry in metadata.{field}: {parsed_expiry}")
                        return parsed_expiry
        
        # Final fallback: Top-level expires field (legacy support)
        if "expires" in bundle:
            expiry_value = bundle["expires"]
            parsed_expiry = _parse_expiry_value(expiry_value)
            if parsed_expiry:
                logger.info(f"Found policy expiry in bundle.expires: {parsed_expiry}")
                return parsed_expiry
        
        # No expiry found
        logger.debug("No expiry information found in policy bundle")
        return None
            
    except Exception as e:
        logger.warning(f"Error parsing policy expiry: {e}")
        return None


def _parse_expiry_value(value: Any) -> Optional[datetime]:
    """Parse various expiry value formats to datetime."""
    if not value:
        return None
    
    try:
        # If already a datetime
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
        
        # If string, try to parse ISO format
        if isinstance(value, str):
            # Handle ISO format with various endings
            if value.endswith('Z'):
                return datetime.fromisoformat(value[:-1]).replace(tzinfo=timezone.utc)
            else:
                # Try direct parsing
                dt = datetime.fromisoformat(value)
                return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        
        # If timestamp (int/float)
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        
        return None
        
    except (ValueError, TypeError) as e:
        logger.debug(f"Could not parse expiry value '{value}': {e}")
        return None


def calculate_policy_expiry_warning(expiry: Optional[datetime], warning_days: int = 7) -> Optional[datetime]:
    """
    Calculate when to start warning about policy expiry.
    
    Args:
        expiry: The policy expiry datetime
        warning_days: How many days before expiry to start warning
        
    Returns:
        Datetime when warnings should start, or None if no expiry
    """
    if not expiry:
        return None
    
    warning_time = expiry - timedelta(days=warning_days)
    return warning_time


def is_policy_expired(expiry: Optional[datetime], current_time: Optional[datetime] = None) -> bool:
    """Check if a policy is currently expired."""
    if not expiry:
        return False  # No expiry means never expired
    
    if current_time is None:
        current_time = datetime.now(timezone.utc)
    
    return current_time >= expiry


def is_policy_expiring_soon(expiry: Optional[datetime], warning_days: int = 7, current_time: Optional[datetime] = None) -> bool:
    """Check if a policy is expiring within the warning period."""
    if not expiry:
        return False
    
    if current_time is None:
        current_time = datetime.now(timezone.utc)
    
    warning_time = calculate_policy_expiry_warning(expiry, warning_days)
    return warning_time and current_time >= warning_time


def get_policy_expiry_status(expiry: Optional[datetime], warning_days: int = 7) -> Dict[str, Any]:
    """
    Get comprehensive expiry status for a policy.
    
    Returns:
        Dict with expiry status information
    """
    current_time = datetime.now(timezone.utc)
    
    return {
        "expires_at": expiry.isoformat() if expiry else None,
        "is_expired": is_policy_expired(expiry, current_time),
        "is_expiring_soon": is_policy_expiring_soon(expiry, warning_days, current_time),
        "days_until_expiry": (expiry - current_time).days if expiry else None,
        "warning_threshold_days": warning_days,
    }


def sync_bundle_expiry(bundle: Dict[str, Any], new_expiry: Optional[datetime]) -> Dict[str, Any]:
    """
    Sync the bundle's metadata.expires field with the provided expiry datetime.
    
    This ensures the bundle content always reflects the current expiry state.
    
    Args:
        bundle: The policy bundle to update
        new_expiry: The expiry datetime to set (or None to remove expiry)
    
    Returns:
        Updated bundle with synchronized expiry
    """
    try:
        # Create a deep copy to avoid modifying the original
        import copy
        updated_bundle = copy.deepcopy(bundle)
        
        # Ensure metadata exists
        if "metadata" not in updated_bundle:
            updated_bundle["metadata"] = {}
        
        # Update the expiry field
        if new_expiry:
            updated_bundle["metadata"]["expires"] = new_expiry.isoformat()
            logger.info(f"Updated bundle metadata.expires to: {new_expiry.isoformat()}")
        else:
            # Remove expiry if None
            updated_bundle["metadata"].pop("expires", None)
            logger.info("Removed bundle metadata.expires (no expiry set)")
        
        return updated_bundle
        
    except Exception as e:
        logger.error(f"Error syncing bundle expiry: {e}")
        return bundle  # Return original if sync fails


def extract_and_sync_policy_expiry(bundle: Dict[str, Any], auto_extend_if_expired: bool = True) -> tuple[Dict[str, Any], Optional[datetime]]:
    """
    Extract expiry from bundle and automatically extend if expired.
    
    Args:
        bundle: The policy bundle
        auto_extend_if_expired: If True, automatically extends expiry if policy is expired
    
    Returns:
        Tuple of (updated_bundle, expiry_datetime)
    """
    try:
        # Extract current expiry
        current_expiry = extract_policy_expiry(bundle)
        
        # Check if policy is expired and auto-extend if needed
        if auto_extend_if_expired and current_expiry and is_policy_expired(current_expiry):
            # Extend expiry by 1 week if expired
            new_expiry = datetime.now(timezone.utc) + timedelta(weeks=1)
            logger.info(f"Policy expired ({current_expiry}), auto-extending to {new_expiry}")
            
            # Update bundle with new expiry
            updated_bundle = sync_bundle_expiry(bundle, new_expiry)
            return updated_bundle, new_expiry
        
        # Normal case: just return current expiry
        return bundle, current_expiry
        
    except Exception as e:
        logger.error(f"Error in extract_and_sync_policy_expiry: {e}")
        return bundle, None
