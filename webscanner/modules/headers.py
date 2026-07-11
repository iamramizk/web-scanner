"""HTTP response headers (reuses the shared prefetch response)."""

from __future__ import annotations

from typing import Any

from ..core.module import ScanModule
from ..core.context import ScanContext


class HeadersModule(ScanModule):
    name = "headers"
    label = "Headers"

    async def run(self, ctx: ScanContext) -> dict[str, Any]:
        return dict(ctx.headers)
