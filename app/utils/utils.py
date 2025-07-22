"""Misc cross-cutting helpers."""

from __future__ import annotations

import os
from uuid import uuid4


def generate_uuid() -> str:
    return str(uuid4())


def get_env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(int(default))).lower() in {"1", "true", "yes"} 