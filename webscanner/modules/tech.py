"""Technology detection via Wappalyzer.

Uses ``analyze(..., scan_type="fast")`` — a pure-HTTP path (no headless browser) —
which returns per-technology version, confidence, categories and groups. Rendered as
a multi-column :class:`Grid`.
"""

from __future__ import annotations

import asyncio

from wappalyzer import analyze

from ..core.module import ScanModule
from ..core.context import ScanContext
from ..core.models import Grid

COLUMNS = ["Name", "Category", "Confidence", "Groups", "Version"]


class TechModule(ScanModule):
    name = "tech"
    label = "Tech"

    async def run(self, ctx: ScanContext) -> Grid:
        def detect() -> Grid:
            results = analyze(url=ctx.url, scan_type="fast", timeout=30)
            techs = results.get(ctx.url) or next(iter(results.values()), {})
            rows = [
                [
                    name,
                    ", ".join(info.get("categories") or []) or "-",
                    f"{info.get('confidence', 0)}%",
                    ", ".join(info.get("groups") or []) or "-",
                    info.get("version") or "-",
                ]
                for name, info in techs.items()
            ]
            # highest-confidence first, then alphabetical
            rows.sort(key=lambda r: (-int(r[2].rstrip("%") or 0), r[0].lower()))
            return Grid(COLUMNS, rows)

        return await asyncio.to_thread(detect)
