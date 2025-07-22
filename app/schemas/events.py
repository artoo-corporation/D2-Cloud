from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic.dataclasses import dataclass


@dataclass
class EventIngest:  # noqa: D101  (simple data container)
    """Single usage event payload for the ingest endpoint."""

    event_type: str
    payload: dict[str, Any]
    occurred_at: datetime 