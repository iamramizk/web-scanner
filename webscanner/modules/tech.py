"""Technology detection via techfinder.

Note: techfinder returns a flat list of technology names (no versions or
categories) — unlike the old Wappalyzer shape.
"""

from __future__ import annotations

import asyncio

from TechFinder.detector import Detector

from ..core.module import ScanModule
from ..core.context import ScanContext


class TechModule(ScanModule):
    name = "tech"
    label = "Tech"

    async def run(self, ctx: ScanContext) -> list[str]:
        def detect() -> list[str]:
            return Detector().final_function(ctx.url) or []

        return await asyncio.to_thread(detect)
