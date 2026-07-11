"""Native subdomain discovery — no external service (replaces crt.sh).

Two native sources:
  1. Subject Alternative Names on the live TLS certificate (grabbed once in
     prefetch via ``ssl``/``socket``) — real hostnames the cert is valid for.
  2. Resolving a curated list of common subdomains via ``socket`` and keeping the
     ones that exist.

Less exhaustive than a Certificate Transparency search, but instant and
dependency-free. Swap in a CT/API source later if broader coverage is needed.
"""

from __future__ import annotations

import asyncio
import socket

from ..core.module import ScanModule
from ..core.context import ScanContext

COMMON_SUBDOMAINS = (
    "www", "mail", "webmail", "smtp", "imap", "pop", "ftp", "cpanel", "webdisk",
    "ns1", "ns2", "mx", "api", "dev", "staging", "blog", "shop", "admin",
    "portal", "vpn", "cdn", "m",
)


class SubdomainsModule(ScanModule):
    name = "subdomains"
    label = "Subdomains"

    async def run(self, ctx: ScanContext) -> list[str]:
        found: set[str] = set()

        # 1. certificate SANs (from the prefetch TLS handshake)
        if ctx.tls_cert:
            for entry_type, value in ctx.tls_cert.get("subjectAltName", ()):
                if entry_type != "DNS":
                    continue
                host = value.lstrip("*.").lower()
                if host == ctx.domain or host.endswith("." + ctx.domain):
                    found.add(host)

        # 2. resolve common subdomains concurrently
        async def probe(sub: str) -> str | None:
            host = f"{sub}.{ctx.domain}"
            try:
                await asyncio.to_thread(socket.gethostbyname, host)
                return host
            except OSError:
                return None

        resolved = await asyncio.gather(*(probe(s) for s in COMMON_SUBDOMAINS))
        found.update(host for host in resolved if host)
        found.discard(ctx.domain)
        return sorted(found)
