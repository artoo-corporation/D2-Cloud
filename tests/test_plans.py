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


def test_bundle_poll_dev_token_no_throttle(monkeypatch):
    """Dev tokens should bypass polling restrictions for local development."""
    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["dev"])
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    
    # Should NOT raise exception even with immediate retry
    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["dev"])
    # Multiple rapid calls should work
    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["dev"])
    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["dev"])


def test_bundle_poll_admin_token_no_throttle(monkeypatch):
    """Admin tokens should bypass polling restrictions."""
    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["admin"])
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    
    # Should NOT raise exception even with immediate retry
    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["admin"])


def test_bundle_poll_server_token_throttle(monkeypatch):
    """Server tokens should respect polling restrictions."""
    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["server"])
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    
    try:
        enforce_bundle_poll(ACCOUNT, 60, token_scopes=["server"])
    except HTTPException as exc:
        assert exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    else:
        assert False, "expected HTTPException for server token"


def test_bundle_poll_mixed_scopes_dev_wins(monkeypatch):
    """If token has both dev and server scopes, dev behavior should win."""
    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["dev", "server"])
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    
    # Should NOT raise exception because dev scope is present
    enforce_bundle_poll(ACCOUNT, 60, token_scopes=["dev", "server"]) 