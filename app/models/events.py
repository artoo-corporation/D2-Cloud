from __future__ import annotations

from datetime import datetime
from typing import Any, List

from pydantic import BaseModel


class SingleEvent(BaseModel):
    """Individual event within a batch."""
    event_type: str
    payload: dict[str, Any]
    occurred_at: datetime


class EventIngest(BaseModel):
    """Batched events payload matching SDK telemetry structure."""
    events: List[SingleEvent] 