from typing import Any, List

class _DummyResponse:
    data: List[Any] = []

class SupabaseStub:  # noqa: D101
    def table(self, *_a, **_k):
        return self
    select = insert = update = order = limit = in_ = gt = lt = gte = lte = like = ilike = neq = is_ = eq = table
    async def execute(self, *_, **__):
        return _DummyResponse()
    async def aclose(self):
        return None 