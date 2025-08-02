from datetime import datetime, timezone
import pytest
from tests.conftest import api_client, patch_verify, make_token
from app.utils.plans import _last_events_ts
import time

# ---------------------------------------------------------------------------
# Pydantic v2 compatibility shim – the production code calls `.model_dump_json()`
# which only exists on Pydantic v1 models.  Add a thin wrapper so the tests can
# run against either major version without touching application code.
# ---------------------------------------------------------------------------

from app.models.events import EventIngest  # noqa: E402

if not hasattr(EventIngest, "model_dump_json"):
    import json  # noqa: WPS433
    import dataclasses

    def _model_dump_json(self):  # noqa: D401
        """Poly-fill for pydantic dataclass (no model_dump/dict)."""

        # Try modern BaseModel helpers first
        if hasattr(self, "model_dump"):
            return json.dumps(self.model_dump(mode="json"), default=_dt)  # type: ignore[attr-defined]

        if hasattr(self, "dict"):
            return json.dumps(self.dict(), default=_dt)  # type: ignore[attr-defined]

        # Fallback: standard library dataclass
        return json.dumps(dataclasses.asdict(self), default=_dt)

    from datetime import datetime  # noqa: WPS433

    def _dt(obj):  # noqa: D401
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError

    EventIngest.model_dump_json = _model_dump_json  # type: ignore[assignment]

ACCOUNT = "acct_test"
PATH = "/v1/events/ingest"

def _event():
    return {"event_type": "x", "payload": {}, "occurred_at": datetime.now(timezone.utc).isoformat()}


def test_ingest_rate_limited(api_client, patch_verify, monkeypatch):
    token = make_token(ACCOUNT, ["read"])

    # First call populates timestamp dict via plan enforcement
    api_client.post(PATH, json=_event(), headers={"Authorization": f"Bearer {token}"})

    # Monkeypatch time to simulate immediate retry (< default min interval 60s)
    original = time.time()
    monkeypatch.setattr(time, "time", lambda: original)  # same timestamp
    resp = api_client.post(PATH, json=_event(), headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 429
    assert resp.headers.get("Retry-After") is not None 