import json
import os
from datetime import datetime, timezone

from fastapi import FastAPI
from starlette.testclient import TestClient

os.environ.setdefault("FRONTEND_ORIGIN", "https://dashboard.test.com")
os.environ.setdefault("SUPABASE_URL", "https://test.supabase.co")
os.environ.setdefault("SUPABASE_KEY", "test_key")

from app.main import create_app  # noqa: E402  pylint: disable=wrong-import-position

app: FastAPI = create_app()
client = TestClient(app)

INGEST_PATH = "/v1/events/ingest"


def test_ingest_rejects_large_payload():
    """Body >32 KiB should be rejected with 413."""
    # Build a payload ~33 KiB in size
    big_string = "a" * 33 * 1024  # 33 KiB
    payload = {
        "event_type": "test",
        "payload": {"data": big_string},
        "occurred_at": datetime.now(timezone.utc).isoformat(),
    }

    resp = client.post(
        INGEST_PATH,
        data=json.dumps(payload),
        headers={"Content-Type": "application/json", "Authorization": "Bearer test"},
    )
    assert resp.status_code == 413 