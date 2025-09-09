"""D2 Policy bundle validation utilities."""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Tuple, Optional

logger = logging.getLogger(__name__)

class PolicyValidationError(Exception):
    """Raised when a policy bundle fails validation."""
    pass

def validate_d2_policy_bundle(bundle: Dict[str, Any], strict: bool = True) -> Tuple[bool, List[str]]:
    """
    Validate a D2 policy bundle against the official schema.
    
    Args:
        bundle: The policy bundle to validate
        strict: If True, enforces all REQUIRED fields. If False, only warns.
    
    Returns:
        Tuple of (is_valid, list_of_errors)
    
    Raises:
        PolicyValidationError: If strict=True and validation fails
    """
    errors = []
    
    try:
        # Check top-level structure
        if not isinstance(bundle, dict):
            errors.append("Policy bundle must be a JSON object")
            if strict:
                raise PolicyValidationError("Policy bundle must be a JSON object")
            return False, errors
        
        # Validate metadata section (REQUIRED)
        metadata = bundle.get("metadata")
        if not metadata:
            errors.append("Missing required 'metadata' section")
        elif not isinstance(metadata, dict):
            errors.append("'metadata' must be an object")
        else:
            # Validate metadata.name (REQUIRED)
            if not metadata.get("name"):
                errors.append("Missing required 'metadata.name' field")
            elif not isinstance(metadata["name"], str):
                errors.append("'metadata.name' must be a string")
            
            # Validate metadata.expires (REQUIRED in local, recommended in cloud)
            if not metadata.get("expires"):
                if strict:
                    errors.append("Missing 'metadata.expires' field (required in local mode, recommended in cloud)")
                else:
                    logger.warning("Missing 'metadata.expires' field - recommended for all policies")
            elif not isinstance(metadata["expires"], str):
                errors.append("'metadata.expires' must be an ISO-8601 string")
            
            # Validate metadata.description (OPTIONAL)
            if "description" in metadata and not isinstance(metadata["description"], str):
                errors.append("'metadata.description' must be a string")
        
        # Validate policies section (REQUIRED)
        policies = bundle.get("policies")
        if not policies:
            errors.append("Missing required 'policies' section")
        elif not isinstance(policies, list):
            errors.append("'policies' must be an array")
        elif len(policies) == 0:
            errors.append("'policies' array must contain at least one role")
        else:
            # Validate each policy/role
            for i, policy in enumerate(policies):
                if not isinstance(policy, dict):
                    errors.append(f"policies[{i}] must be an object")
                    continue
                
                # Validate role (REQUIRED)
                if not policy.get("role"):
                    errors.append(f"policies[{i}] missing required 'role' field")
                elif not isinstance(policy["role"], str):
                    errors.append(f"policies[{i}].role must be a string")
                
                # Validate permissions (REQUIRED)
                permissions = policy.get("permissions")
                if not permissions:
                    errors.append(f"policies[{i}] missing required 'permissions' field")
                elif not isinstance(permissions, list):
                    errors.append(f"policies[{i}].permissions must be an array")
                elif len(permissions) == 0:
                    errors.append(f"policies[{i}].permissions must contain at least one entry")
                else:
                    # Validate each permission
                    for j, permission in enumerate(permissions):
                        if not isinstance(permission, str):
                            errors.append(f"policies[{i}].permissions[{j}] must be a string")
                
                # Validate description (OPTIONAL)
                if "description" in policy and not isinstance(policy["description"], str):
                    errors.append(f"policies[{i}].description must be a string")
        
        # Check for unknown top-level fields (informational)
        expected_fields = {"metadata", "policies"}
        extra_fields = set(bundle.keys()) - expected_fields
        if extra_fields:
            logger.info(f"Policy bundle contains extra fields (ignored): {extra_fields}")
        
        # Determine if validation passed
        is_valid = len(errors) == 0
        
        if strict and not is_valid:
            error_msg = f"Policy validation failed: {'; '.join(errors)}"
            raise PolicyValidationError(error_msg)
        
        return is_valid, errors
        
    except PolicyValidationError:
        raise
    except Exception as e:
        error_msg = f"Unexpected error during policy validation: {e}"
        logger.error(error_msg)
        if strict:
            raise PolicyValidationError(error_msg)
        return False, [error_msg]


def get_policy_summary(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract summary information from a D2 policy bundle.
    
    Returns:
        Dict with policy summary information
    """
    try:
        metadata = bundle.get("metadata", {})
        policies = bundle.get("policies", [])
        
        # Count permissions by type
        total_permissions = 0
        allow_permissions = 0
        deny_permissions = 0
        wildcard_permissions = 0
        
        roles = []
        
        for policy in policies:
            if isinstance(policy, dict):
                role_name = policy.get("role", "unknown")
                permissions = policy.get("permissions", [])
                
                roles.append({
                    "role": role_name,
                    "permission_count": len(permissions),
                    "description": policy.get("description")
                })
                
                for perm in permissions:
                    if isinstance(perm, str):
                        total_permissions += 1
                        if perm == "*":
                            wildcard_permissions += 1
                        elif perm.startswith("!"):
                            deny_permissions += 1
                        else:
                            allow_permissions += 1
        
        return {
            "name": metadata.get("name"),
            "description": metadata.get("description"),
            "expires": metadata.get("expires"),
            "role_count": len(roles),
            "roles": roles,
            "permission_stats": {
                "total": total_permissions,
                "allow": allow_permissions,
                "deny": deny_permissions,
                "wildcard": wildcard_permissions
            }
        }
        
    except Exception as e:
        logger.warning(f"Error generating policy summary: {e}")
        return {"error": str(e)}


def normalize_d2_policy_bundle(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a D2 policy bundle to ensure consistent format.
    
    - Ensures all required fields have default values
    - Sorts policies by role name
    - Removes any null/empty values
    
    Returns:
        Normalized policy bundle
    """
    try:
        normalized = {}
        
        # Normalize metadata
        metadata = bundle.get("metadata", {})
        normalized["metadata"] = {
            "name": metadata.get("name", "Unnamed Policy"),
            "expires": metadata.get("expires"),
        }
        
        # Add optional metadata fields if present
        if "description" in metadata:
            normalized["metadata"]["description"] = metadata["description"]
        
        # Preserve any extra metadata fields for future compatibility
        extra_metadata = {k: v for k, v in metadata.items() 
                         if k not in ["name", "expires", "description"]}
        normalized["metadata"].update(extra_metadata)
        
        # Normalize policies
        policies = bundle.get("policies", [])
        normalized_policies = []
        
        for policy in policies:
            if isinstance(policy, dict):
                normalized_policy = {
                    "role": policy.get("role", "unknown"),
                    "permissions": policy.get("permissions", [])
                }
                
                # Add optional description if present
                if "description" in policy:
                    normalized_policy["description"] = policy["description"]
                
                normalized_policies.append(normalized_policy)
        
        # Sort policies by role name for consistency
        normalized_policies.sort(key=lambda p: p["role"])
        normalized["policies"] = normalized_policies
        
        return normalized
        
    except Exception as e:
        logger.error(f"Error normalizing policy bundle: {e}")
        return bundle  # Return original if normalization fails


def enforce_server_side_expiry(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """
    Force server-side expiry generation, ignoring any client-provided expiry.
    Always sets expiry to 1 week from now.
    
    Args:
        bundle: The policy bundle to modify
        
    Returns:
        Modified bundle with server-generated expiry
    """
    try:
        # Generate expiry as 1 week from now
        one_week_from_now = datetime.now(timezone.utc) + timedelta(weeks=1)
        expiry_iso = one_week_from_now.isoformat()
        
        # Make a copy of the bundle to avoid modifying the original
        modified_bundle = bundle.copy()
        
        # Ensure metadata exists
        if "metadata" not in modified_bundle:
            modified_bundle["metadata"] = {}
        elif not isinstance(modified_bundle["metadata"], dict):
            modified_bundle["metadata"] = {}
        
        # Force server-side expiry
        modified_bundle["metadata"]["expires"] = expiry_iso
        
        logger.info(f"Server-side expiry enforced: {expiry_iso}")
        return modified_bundle
        
    except Exception as e:
        logger.error(f"Error enforcing server-side expiry: {e}")
        # Return original bundle if something goes wrong
        return bundle


def validate_strict_policy_requirements(bundle: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Strict validation for policy bundle requirements:
    - metadata.name (app name) required
    - at least one policy required
    - each policy must have at least one role
    - each policy must have at least one permission
    
    Args:
        bundle: The policy bundle to validate
        
    Returns:
        Tuple of (is_valid, list_of_errors)
        
    Raises:
        PolicyValidationError: If validation fails
    """
    errors = []
    
    try:
        # Check top-level structure
        if not isinstance(bundle, dict):
            errors.append("Policy bundle must be a JSON object")
            raise PolicyValidationError("Policy bundle must be a JSON object")
        
        # Validate metadata section (REQUIRED)
        metadata = bundle.get("metadata")
        if not metadata:
            errors.append("Missing required 'metadata' section")
        elif not isinstance(metadata, dict):
            errors.append("'metadata' must be an object")
        else:
            # Validate metadata.name (REQUIRED - this is the app name)
            app_name = metadata.get("name")
            if not app_name:
                errors.append("Missing required 'metadata.name' field (app name)")
            elif not isinstance(app_name, str):
                errors.append("'metadata.name' must be a string")
            elif not app_name.strip():
                errors.append("'metadata.name' cannot be empty or whitespace only")
        
        # Validate policies section (REQUIRED)
        policies = bundle.get("policies")
        if not policies:
            errors.append("Missing required 'policies' section")
        elif not isinstance(policies, list):
            errors.append("'policies' must be an array")
        elif len(policies) == 0:
            errors.append("'policies' array must contain at least one policy")
        else:
            # Validate each policy
            for i, policy in enumerate(policies):
                if not isinstance(policy, dict):
                    errors.append(f"policies[{i}] must be an object")
                    continue
                
                # Validate role (REQUIRED)
                role = policy.get("role")
                if not role:
                    errors.append(f"policies[{i}] missing required 'role' field")
                elif not isinstance(role, str):
                    errors.append(f"policies[{i}].role must be a string")
                elif not role.strip():
                    errors.append(f"policies[{i}].role cannot be empty or whitespace only")
                
                # Validate permissions (REQUIRED - at least one)
                permissions = policy.get("permissions")
                if not permissions:
                    errors.append(f"policies[{i}] missing required 'permissions' field")
                elif not isinstance(permissions, list):
                    errors.append(f"policies[{i}].permissions must be an array")
                elif len(permissions) == 0:
                    errors.append(f"policies[{i}].permissions must contain at least one permission")
                else:
                    # Validate each permission is a non-empty string
                    for j, permission in enumerate(permissions):
                        if not isinstance(permission, str):
                            errors.append(f"policies[{i}].permissions[{j}] must be a string")
                        elif not permission.strip():
                            errors.append(f"policies[{i}].permissions[{j}] cannot be empty or whitespace only")
        
        # Check if validation passed
        is_valid = len(errors) == 0
        
        if not is_valid:
            error_msg = f"Policy validation failed: {'; '.join(errors)}"
            raise PolicyValidationError(error_msg)
        
        return is_valid, errors
        
    except PolicyValidationError:
        raise
    except Exception as e:
        error_msg = f"Unexpected error during strict policy validation: {e}"
        logger.error(error_msg)
        raise PolicyValidationError(error_msg)


def extract_app_name(bundle: Dict[str, Any]) -> str:
    """
    Extract the app name from a policy bundle's metadata.
    
    Args:
        bundle: The policy bundle
        
    Returns:
        The app name from metadata.name, or 'default' if not found
    """
    try:
        metadata = bundle.get("metadata", {})
        app_name = metadata.get("name", "").strip()
        
        if not app_name:
            logger.warning("No metadata.name found in policy bundle, using 'default'")
            return "default"
            
        # Sanitize app name for database storage
        import re
        app_name = re.sub(r'[^\w\-.]', '_', app_name)
        app_name = app_name[:100]  # Limit length
        
        return app_name
        
    except Exception as e:
        logger.error(f"Error extracting app name from bundle: {e}")
        return "default"
