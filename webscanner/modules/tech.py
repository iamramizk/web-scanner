"""Technology detection via Wappalyzer.

Uses ``analyze(..., scan_type="fast")`` — a pure-HTTP path (no headless browser) —
which returns per-technology version, confidence, categories and groups. Rendered as
one :class:`Grid` per *group* (Wappalyzer's high-level bucket, e.g. "Web servers",
"Analytics"), stacked as titled :class:`Sections`. A technology in several groups
appears in each of their tables.
"""

from __future__ import annotations

import asyncio

from wappalyzer import analyze

from ..core.module import ScanModule
from ..core.context import ScanContext
from ..core.models import Grid, Section, Sections

COLUMNS = ["Name", "Category", "Confidence", "Version"]
#: fixed column widths so every per-group table on the tab lines up identically
WIDTHS = [26, 22, 12, 12]
#: bucket for technologies Wappalyzer reports without any group
UNGROUPED = "Other"


class TechModule(ScanModule):
    name = "tech"
    label = "Tech"

    async def run(self, ctx: ScanContext) -> Sections:
        def detect() -> Sections:
            results = analyze(url=ctx.url, scan_type="fast", timeout=30)
            techs = results.get(ctx.url) or next(iter(results.values()), {})
            # group name -> rows; a tech lands in every group it declares
            groups: dict[str, list[list[str]]] = {}
            for name, info in techs.items():
                row = [
                    name,
                    ", ".join(info.get("categories") or []) or "-",
                    f"{info.get('confidence', 0)}%",
                    info.get("version") or "-",
                ]
                for group in info.get("groups") or [UNGROUPED]:
                    groups.setdefault(group, []).append(row)
            sections = Sections()
            for group in sorted(groups, key=str.lower):  # tables A→Z by group
                rows = sorted(groups[group], key=lambda r: r[0].lower())  # names A→Z
                sections.append(Section(group, Grid(COLUMNS, rows, widths=WIDTHS)))
            return sections

        return await asyncio.to_thread(detect)
