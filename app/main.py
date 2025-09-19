"""Entry-point for Vercel → FastAPI ASGI app.

This module constructs the FastAPI instance, wires global middleware,
registers all route groups, and exposes the `app` variable that Vercel
expects (detects `app` attribute).
"""

from __future__ import annotations

import os
import logging
import traceback
from dotenv import load_dotenv
from contextvars import ContextVar
from time import perf_counter
from typing import Callable, Awaitable, Dict, Any

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app import APP_ENV

# Router imports moved *inside* create_app() to avoid circular dependency
# with jwks_routes importing `limiter` from this module before it's defined.
from app.utils.logger import configure_logging, logger
from app.settings import ALLOWED_ORIGINS  # <-- new central settings module

# ---------------------------------------------------------------------------
# Runtime environment
# ---------------------------------------------------------------------------


# Rate limiter (IP-based by default)
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach request-level context vars for structured logging."""

    _request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:  # type: ignore[override]
        start = perf_counter()
        request_id = request.headers.get("X-Request-Id", os.urandom(4).hex())
        token = self._request_id_ctx.set(request_id)
        try:
            response = await call_next(request)
        finally:
            duration_ms = (perf_counter() - start) * 1000
            logger.info(
                "request.complete",
                extra={
                    "path": request.url.path,
                    "method": request.method,
                    "status_code": response.status_code if "response" in locals() else 500,
                    "duration_ms": round(duration_ms, 2),
                    "request_id": request_id,
                },
            )
            self._request_id_ctx.reset(token)
        return response


def create_app() -> FastAPI:  # noqa: C901
    configure_logging()

    app = FastAPI(
        title="D2 Cloud Control-Plane API",
        version="0.1.0",
        docs_url="/docs" if APP_ENV != "production" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if APP_ENV != "production" else None,
    )

    # Global middleware
    app.add_middleware(RequestContextMiddleware)
    # Rate limiting middleware (SlowAPI expects limiter via app.state)
    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)

    # Register default handler for 429 responses from SlowAPI
    from slowapi.errors import RateLimitExceeded  # noqa: WPS433  (runtime import)
    from slowapi import _rate_limit_exceeded_handler

    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    
    # Global exception handler - logs full tracebacks for any unhandled 500s
    @app.exception_handler(Exception)
    async def log_unhandled_exceptions(request: Request, exc: Exception):
        """Log full traceback for any unhandled exception that would become a 500."""
        error_logger = logging.getLogger("uvicorn.error")
        error_logger.error(
            "UNHANDLED %s at %s %s\n%s",
            type(exc).__name__,
            request.method,
            request.url.path,
            "".join(traceback.format_tb(exc.__traceback__))
        )
        # Re-raise so FastAPI still returns the appropriate status code
        raise exc

    # -------------------------------------------------------------------
    # Private-API CORS (env-driven allow-list)
    # -------------------------------------------------------------------

    print(f"ALLOWED_ORIGINS: {ALLOWED_ORIGINS}")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Org-ID"],
        max_age=600,
    )

    # Health check
    @app.get("/")
    async def root() -> Dict[str, str]:  # pylint: disable=unused-variable
        return {"status": "ok"}

    # -------------------------------------------------------------------
    # Mount public (unauthenticated) sub-app → wildcard CORS
    # -------------------------------------------------------------------
    public_app = FastAPI(
        title="D2 Cloud Public API",
        docs_url="/docs" if APP_ENV != "production" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if APP_ENV != "production" else None,
    )
    public_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "OPTIONS"],
        allow_headers=["*"],
        max_age=600,
    )
    # Re-use existing JWKS router (/.well-known/jwks.json)
    from app.routers.jwks_routes import public_router as jwks_public_router, admin_router as jwks_admin_router
    # Make JWKS reachable both at /public/.well-known/jwks.json and
    # directly at /.well-known/jwks.json for clients that assume the
    # standard location.
    public_app.include_router(jwks_public_router)
    app.include_router(jwks_public_router)

    # Mount at /public (eg. /public/.well-known/jwks.json)
    app.mount("/public", public_app)

    # Expose OpenAPI YAML at /public/openapi.yaml
    from app.openapi import install_openapi_route  # noqa: WPS433 (runtime import)

    install_openapi_route(public_app)

    # Register private routers – explicit order matters for overrides
    from app.routers import policy_routes, events_routes, keys_routes, accounts_routes, tokens_routes, audit_routes, invitations_routes, metrics_routes
    app.include_router(policy_routes.router)
    app.include_router(keys_routes.router)
    app.include_router(jwks_admin_router)
    app.include_router(events_routes.router)
    app.include_router(audit_routes.router)
    # Resource-oriented routers
    app.include_router(accounts_routes.router)
    app.include_router(tokens_routes.router)
    app.include_router(invitations_routes.router)
    app.include_router(metrics_routes.router)
    
    # Public invitation routes (no auth required)
    app.include_router(invitations_routes.invitation_public_router)

    return app

# The object Vercel imports
app = create_app()

