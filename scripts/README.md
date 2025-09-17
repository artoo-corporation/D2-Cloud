## Scripts Guide

This folder contains operational scripts for key management and performance hardening. This guide explains what each script does, when to use it, how to run it, and what to expect.

### Table of contents
- AES key (JWK_AES_KEY) rotation: `rotate_jwk_aes_key.py`
- RSA JWKS rotation (signing keys): `rotate_all_jwks.py`
- Legacy utility: `generate_jwk_aes_key.py`

---

## AES key rotation (JWK_AES_KEY)

Script: `scripts/rotate_jwk_aes_key.py`

Purpose:
- Rotates the AES key used to encrypt `jwks_keys.private_jwk`
- Keeps all RSA keypairs (JWKS) the same; does not change `kid` or re-sign policies
- Also impacts API token lookup “pepper” (see Expectations)

When to use:
- Your JWK_AES_KEY is exposed or needs scheduled rotation
- You want to start using JWK_AES_KEY for the first time (set it and re-encrypt any plaintext private_jwk rows)

How it works (safely):
- Decrypt each `jwks_keys.private_jwk` using the current AES key
- Re-encrypt the plaintext with a NEW AES key
- Verify each updated row can be decrypted with the NEW key
- Print the NEW key so you can set it in your service env

Run:
```
# Use the currently running application key as OLD; no manual export needed
# (If you set OLD_JWK_AES_KEY explicitly, the script will prefer that or JWK_AES_KEY)
python scripts/rotate_jwk_aes_key.py

# Optional: supply your own NEW key (otherwise generated securely)
# export NEW_JWK_AES_KEY="<base64url 32-byte>"
# python scripts/rotate_jwk_aes_key.py
```

Output:
- Summary of rows processed (updated/errors)  
- Confirmation that token_lookup values were cleared
- NEW_JWK_AES_KEY printed to stdout

Next steps:
1) Local `.env` file is automatically updated with the new key
2) Set `JWK_AES_KEY` in your **production/server** environment to the printed NEW key  
3) Restart the API
4) Expect one slow request per existing API token the first time it's used (we automatically backfill `token_lookup` so subsequent requests are fast)

**Important**: This script now automatically clears all `token_lookup` values when rotating the AES key, preventing authentication latency issues that would occur if stale lookup values were left in the database.

Expectations & side-effects:
- RSA keys and `kid` values remain the same; clients keep working
- Existing `jwks_keys.private_jwk` become unreadable with the OLD key, readable with the NEW key
- API token verification: the `token_lookup` pepper changes with the new AES key; the next use of each legacy token will do one slow full-scan, then be backfilled and become fast
- Recommended index (if not present):
  ```sql
  create index concurrently if not exists api_tokens_token_lookup_idx on api_tokens (token_lookup);
  ```

Rollback:
- Re-run the script with the NEW key as OLD and a fresh NEW; or restore from backup

---

## RSA JWKS rotation (signing keys)

Script: `scripts/rotate_all_jwks.py`

Purpose:
- Generates new RSA keypairs and rotates active signing keys (`kid`)
- Re-signs active policies with the new `kid`

When to use:
- Suspected private-key exposure or compromise
- Scheduled security rotation of RSA keypairs
- You want a fresh `kid` and re-signed policies

Preconditions:
- `JWK_AES_KEY` is set so new `private_jwk` rows can be encrypted
- Maintenance window recommended (brief policy re-sign churn)

Effects:
- Clients that fetch JWKS via `/.well-known/jwks.json` will pick up the new public keys automatically
- Old keys should remain available for overlap until safely retired

Run:
```
python scripts/rotate_all_jwks.py
```

---

## Legacy utility: generate_jwk_aes_key.py

Script: `scripts/generate_jwk_aes_key.py`

Purpose:
- Prints a random base64url-encoded 32-byte AES key suitable for `JWK_AES_KEY`

Status:
- Optional. `rotate_jwk_aes_key.py` already generates a new key if `NEW_JWK_AES_KEY` is not provided

Run:
```
python scripts/generate_jwk_aes_key.py
```

---

## Operational notes

- Keep `JWK_AES_KEY` secure; losing it prevents decrypting stored private JWKs
- After setting/rotating `JWK_AES_KEY`, existing API tokens will be slow once (full-scan) then fast (we backfill `token_lookup` automatically)
- Monitor logs for:
  - `auth.token phase=fast_lookup hit=true` → fast path OK
  - `auth.token phase=full_scan` → legacy token (will be backfilled)
  - `auth.jwt phase=fast_path` vs `db_fallback` → whether Supabase JWT required a DB lookup


