from __future__ import annotations

"""OpenAPI exposure helper – mounts /public/openapi.yaml on the main app."""

from datetime import datetime, timezone

import yaml
from fastapi import FastAPI, Response, Request

__all__ = ["install_openapi_route"]


def install_openapi_route(app: FastAPI) -> None:  # noqa: D401
    """Attach a YAML OpenAPI exporter at /public/openapi.yaml.

    The route is *not* included in the Swagger UI itself (``include_in_schema=False``)
    and is public‐cacheable for 5 minutes so docs hosting & SDK generators can
    fetch it without hitting cold-start limits.
    """

    # Assume the caller mounts this app where desired. For the main control-plane we
    # call install_openapi_route(public_app) so the final path becomes
    # /public/openapi.yaml.

    @app.get("/openapi.yaml", include_in_schema=False)
    async def _openapi_yaml(_: Request) -> Response:  # noqa: D401, WPS430
        spec = app.openapi()
        yaml_str = yaml.safe_dump(spec, sort_keys=False)
        date_comment = f"# generated: {datetime.utcnow().date().isoformat()}\n"
        body = date_comment + yaml_str
        return Response(
            content=body,
            media_type="application/x-yaml",
            headers={"Cache-Control": "public, max-age=300"},
        ) 