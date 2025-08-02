import os, base64, json
from app.utils.security_utils import encrypt_private_jwk, decrypt_private_jwk

JWK = {"kty": "RSA", "n": "abc", "e": "AQAB"}


def test_encrypt_decrypt_roundtrip():
    os.environ["JWK_AES_KEY"] = base64.urlsafe_b64encode(os.urandom(32)).decode()
    blob = encrypt_private_jwk(JWK)
    out = decrypt_private_jwk(blob)
    assert out == JWK


def test_plaintext_path():
    # unset key ⇒ encrypt returns marked plain JSON
    os.environ.pop("JWK_AES_KEY", None)
    blob = encrypt_private_jwk(JWK)
    data = json.loads(blob)
    assert data["__plain__"] is True
    assert decrypt_private_jwk(blob) == JWK 