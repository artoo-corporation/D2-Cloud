import time
from app.utils.plans import enforce_event_limits, enforce_bundle_poll, MAX_BATCH_BYTES
from fastapi import HTTPException, status

ACCOUNT = "acct_test"


def test_event_size_cap():
    big = MAX_BATCH_BYTES + 1
    try:
        enforce_event_limits(ACCOUNT, "trial", big)
    except HTTPException as exc:
        assert exc.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    else:
        assert False, "expected HTTPException"


def test_event_interval_throttle(monkeypatch):
    # first call OK, second within interval 429
    enforce_event_limits(ACCOUNT, "essentials", 10)
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)  # immediate retry
    try:
        enforce_event_limits(ACCOUNT, "essentials", 10)
    except HTTPException as exc:
        assert exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert "Retry-After" in exc.headers
    else:
        assert False


def test_bundle_poll_throttle(monkeypatch):
    enforce_bundle_poll(ACCOUNT, 60)
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    try:
        enforce_bundle_poll(ACCOUNT, 60)
    except HTTPException as exc:
        assert exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    else:
        assert False 