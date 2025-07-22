# Changelog

## Unreleased

* **Hardened CORS**: private control-plane API now enforces an env-driven allow-list.  Public JWKS endpoint moved to `/public` sub-app with wildcard CORS for safe unauthenticated access. 