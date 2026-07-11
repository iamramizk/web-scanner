"""AsyncScanner — concurrent orchestrator.

Flow:
  1. prefetch()  — resolve IP, HTTP GET, TLS handshake and geo lookup, all
     concurrently, populating the shared ScanContext.
  2. run()       — run every module concurrently, each failure-isolated, emitting
     ScanEvents so the UI can animate progress and colour tabs live.

Blocking libraries (pydig, requests, wappalyzer, system whois) are offloaded to
threads via ``asyncio.to_thread`` so the event loop never stalls.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Iterable

from ..net import http
from .context import ScanContext
from .models import ModuleResult, ModuleStatus, ScanEvent
from .module import ScanModule

EventCallback = Callable[[ScanEvent], None]

PREFETCH = "__prefetch__"


def _is_empty(data: object) -> bool:
    if data is None:
        return True
    if isinstance(data, (dict, list, str, tuple, set)):
        return len(data) == 0
    return False


class AsyncScanner:
    def __init__(
        self,
        ctx: ScanContext,
        modules: Iterable[ScanModule],
        on_event: EventCallback | None = None,
    ) -> None:
        self.ctx = ctx
        self.modules = list(modules)
        self.on_event = on_event
        self.results: dict[str, ModuleResult] = {}

    def _emit(self, name: str, status: ModuleStatus, result: ModuleResult | None = None) -> None:
        if self.on_event is not None:
            self.on_event(ScanEvent(name=name, status=status, result=result))

    async def prefetch(self) -> None:
        """Populate the shared context (IP first, then fetch/geo/tls concurrently)."""
        self.ctx.ip = await asyncio.to_thread(http.resolve_ip, self.ctx.domain)

        async def _fetch() -> None:
            try:
                r = await asyncio.to_thread(http.fetch, self.ctx.url)
                self.ctx.status_code = r["status_code"]
                self.ctx.headers = r["headers"]
                self.ctx.html = r["html"]
                self.ctx.response_time_ms = r["elapsed_ms"]
                self.ctx.final_url = r["final_url"]
            except Exception as exc:  # noqa: BLE001 - surfaced, not raised
                self.ctx.fetch_error = repr(exc)

        async def _geo() -> None:
            if self.ctx.ip:
                try:
                    self.ctx.geo = await asyncio.to_thread(http.get_geo, self.ctx.ip)
                except Exception:  # noqa: BLE001
                    pass

        async def _tls() -> None:
            try:
                self.ctx.tls_cert = await asyncio.to_thread(http.get_tls_cert, self.ctx.domain)
            except Exception:  # noqa: BLE001
                pass

        await asyncio.gather(_fetch(), _geo(), _tls())

    async def _run_module(self, module: ScanModule) -> ModuleResult:
        self._emit(module.name, ModuleStatus.RUNNING)
        start = time.perf_counter()
        try:
            data = await module.run(self.ctx)
            duration = (time.perf_counter() - start) * 1000
            status = ModuleStatus.EMPTY if _is_empty(data) else ModuleStatus.DONE
            result = ModuleResult(module.name, status, data=data, duration_ms=duration)
        except Exception as exc:  # noqa: BLE001 - isolate module failures
            duration = (time.perf_counter() - start) * 1000
            result = ModuleResult(module.name, ModuleStatus.FAILED, error=repr(exc), duration_ms=duration)
        self.results[module.name] = result
        self._emit(module.name, result.status, result)
        return result

    async def run(self) -> dict[str, ModuleResult]:
        self._emit(PREFETCH, ModuleStatus.RUNNING)
        await self.prefetch()
        self._emit(PREFETCH, ModuleStatus.DONE)
        await asyncio.gather(*(self._run_module(m) for m in self.modules))
        return self.results
