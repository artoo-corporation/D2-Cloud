# Lightweight shim for Vercel Cron (legacy path)

from app.cron.key_rotation_sweeper import _run  # noqa: WPS450

# Vercel invokes the default exportable object – we expose it as an async handler
# that simply reuses the existing coroutine.

def handler(_req, _res):  # type: ignore[unused-argument]
    import asyncio
    asyncio.run(_run())
    return {"status": "ok"} 