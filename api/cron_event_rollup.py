from app.cron.event_rollup import _run  # noqa: WPS450

def handler(_req, _res):
    import asyncio
    asyncio.run(_run())
    return {"status": "ok"} 
