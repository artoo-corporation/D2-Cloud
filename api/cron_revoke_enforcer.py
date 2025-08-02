from app.cron.revoke_enforcer import _run  # noqa: WPS450

def handler(_req, _res):
    import asyncio
    asyncio.run(_run())
    return {"status": "ok"} 