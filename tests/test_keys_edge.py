import base64
from tests.conftest import api_client, make_token, patch_verify

ACCOUNT = "acct_test"


def test_key_upload_invalid_base64(api_client, patch_verify):
    admin = make_token(ACCOUNT, ["admin"])
    bad = "!!!notb64"
    resp = api_client.post(
        "/v1/keys",
        json={"public_key": bad},
        headers={"Authorization": f"Bearer {admin}"},
    )
    assert resp.status_code == 400 