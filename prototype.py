"""Prototype harness for the v2 async core + braille world map.

Runs the full async scan (no Textual UI yet), printing live progress events as
modules complete concurrently, then a per-module summary and the world map with
the server location plotted. Proves the core end-to-end.

Usage:
    source .venv2/bin/activate
    python prototype.py example.com
"""

from __future__ import annotations

import asyncio
import sys
import time

from rich.console import Console
from rich.panel import Panel

from webscanner.core import AsyncScanner, ModuleStatus, ScanContext, ScanEvent
from webscanner.modules import all_modules
from webscanner.ui.worldmap import render

console = Console()

_ICON = {
    ModuleStatus.RUNNING: "[yellow]…[/]",
    ModuleStatus.DONE: "[green]✓[/]",
    ModuleStatus.EMPTY: "[dim]∅[/]",
    ModuleStatus.FAILED: "[red]✗[/]",
}


def make_reporter(start: float):
    def on_event(ev: ScanEvent) -> None:
        if ev.status is ModuleStatus.RUNNING:
            return
        t = time.perf_counter() - start
        icon = _ICON.get(ev.status, "?")
        extra = ""
        if ev.result and ev.result.duration_ms is not None:
            extra = f"[dim]{ev.result.duration_ms:6.0f}ms[/]"
        console.print(f"  [dim]{t:5.2f}s[/] {icon} {ev.name:<11} {extra}")

    return on_event


async def main(target: str) -> None:
    ctx = ScanContext.from_target(target)
    console.print(f"\n[bold cyan]Scanning[/] {ctx.domain}  [dim]({ctx.url})[/]\n")

    start = time.perf_counter()
    scanner = AsyncScanner(ctx, all_modules(), on_event=make_reporter(start))
    results = await scanner.run()
    total = time.perf_counter() - start

    console.print(f"\n[bold]Done in {total:.2f}s[/] (concurrent)\n")

    # Fixed status panel content (from prefetch).
    geo = ctx.geo or {}
    status_lines = [
        f"[bold]Online:[/] {'[green]yes[/]' if ctx.online else '[red]no[/]'}"
        + (f"  ({ctx.status_code}, {ctx.response_time_ms:.0f}ms)" if ctx.online else ""),
        f"[bold]IP:[/] {ctx.ip or '-'}",
        f"[bold]Location:[/] {geo.get('city', '-')}, {geo.get('country', '-')}",
        f"[bold]ISP:[/] {geo.get('isp', '-')}",
    ]
    console.print(Panel("\n".join(status_lines), title="status", width=60))

    # Fixed map panel.
    if geo.get("lat") is not None:
        console.print(
            Panel(
                render(geo["lat"], geo["lon"], width=56, height=13),
                title=f"server location — {geo.get('city', '?')}",
                width=60,
            )
        )

    # Per-module data preview.
    for name, res in results.items():
        head = f"[bold]{name}[/] {_ICON.get(res.status, '')}"
        if res.status is ModuleStatus.FAILED:
            console.print(f"{head}  [red]{res.error}[/]")
            continue
        preview = repr(res.data)
        if len(preview) > 400:
            preview = preview[:400] + " …"
        console.print(f"{head}  [dim]{preview}[/]")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    asyncio.run(main(target))
