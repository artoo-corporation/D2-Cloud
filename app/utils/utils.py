"""Misc cross-cutting helpers."""

from __future__ import annotations

import os
from uuid import uuid4


def generate_uuid() -> str:
    return str(uuid4())


def get_env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(int(default))).lower() in {"1", "true", "yes"}


def normalize_app_name(app_name: str) -> str:
    """Normalize app names by converting spaces to underscores for consistency.
    
    This ensures that app names like "my app" and "my_app" are treated as the same app.
    We standardize on underscores since they're more URL-friendly and database-safe.
    
    Args:
        app_name: The raw app name from user input
        
    Returns:
        Normalized app name with spaces converted to underscores
        
    Examples:
        >>> normalize_app_name("my cool app")
        "my_cool_app"
        >>> normalize_app_name("already_normalized")
        "already_normalized"
    """
    if not app_name:
        return app_name
    
    # Convert spaces to underscores and strip whitespace
    return app_name.strip().replace(" ", "_") 