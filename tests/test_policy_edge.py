import base64
import pytest
from tests.conftest import api_client, patch_verify, make_token

ACCOUNT = "acct_test"


def test_publish_key_not_found(monkeypatch, api_client, patch_verify):
    admin = make_token(ACCOUNT, ["admin"])

    # stub DB to return draft row but no key row
    from app.utils import database as db

    async def _query_one_stub(_sp, table_name, match=None, order_by=None, **kw):  # noqa: ANN001
        if table_name == "policies" and match.get("is_draft"):
            return {"id": 1, "account_id": ACCOUNT, "version": 1, "bundle": {}, "is_draft": True}
        return None

    monkeypatch.setattr(db, "query_one", _query_one_stub, raising=True)

    sig = base64.b64encode(b"bad").decode()
    resp = api_client.post(
        "/v1/policy/publish",
        json={},
        headers={
            "Authorization": f"Bearer {admin}",
            "X-D2-Signature": sig,
            "X-D2-Key-Id": "missing",
            "If-Match": "*",
        },
    )
    assert resp.status_code in {400, 404}  # 400 if signature/key validation fails early 