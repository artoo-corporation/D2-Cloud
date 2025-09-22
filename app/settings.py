from __future__ import annotations

"""Application-level configuration helpers (env → constants).

Only generic utilities that may be imported *anywhere* in the code-base
should live in this module.  Avoid importing heavy libraries to keep the
import cost near-zero even in cold-start environments (e.g. serverless).
"""

# Standard library
import os

__all__ = ["ALLOWED_ORIGINS"]


def _collect_origins() -> list[str]:
    """Collect allowed CORS origins from the environment.

    Falls back to the local Vite dev-server (localhost:5173) to avoid
    breaking front-end hot-reload in local development when no explicit
    env vars are set.
    """
    origins: list[str] = []
    for name in ("FRONTEND_ORIGIN", "DOCS_ORIGIN", "EXTRA_ORIGIN"):
        if (val := os.getenv(name)):
            origins.append(val)

    # Local-dev fallback (vite / react-dev-server default)
    if not origins:
        origins.extend(
            ["https://artoo.love", 
            "https://d2-dashboard.artoo.love",
            # "http://localhost:3000"
            ]
        )
    return origins


ALLOWED_ORIGINS: list[str] = _collect_origins() 