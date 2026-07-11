"""Security module — three tables: Open Ports, HTTP Security, Blocklists.

- Open Ports: TCP-connect scan of a short list of common ports.
- HTTP Security: presence of key response security headers (from prefetch).
- Blocklists: whether the domain is blocked by popular filtering DNS resolvers
  (AdGuard, CleanBrowsing, Cloudflare, Google, OpenDNS, Quad9), queried directly
  by IP via ``dig``.
"""

from __future__ import annotations

import asyncio

from ..colors import GREEN, RED
from ..core.module import ScanModule
from ..core.context import ScanContext
from ..core.models import Section, Sections

# port -> service label (short common set)
COMMON_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
    443: "HTTPS", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}

# response header -> short label shown in the table
SEC_HEADERS: dict[str, str] = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-embedder-policy": "Cross-Origin-Embedder-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
}

# filtering DNS resolver -> IP (we ask each whether it blocks the domain)
FILTERS: dict[str, str] = {
    "AdGuard": "94.140.14.14",
    "AdGuard Family": "94.140.14.15",
    "CleanBrowsing Adult": "185.228.168.10",
    "CleanBrowsing Family": "185.228.168.168",
    "CleanBrowsing Security": "185.228.168.9",
    "CloudFlare": "1.1.1.1",
    "CloudFlare Family": "1.1.1.3",
    "Google DNS": "8.8.8.8",
    "OpenDNS": "208.67.222.222",
    "OpenDNS Family": "208.67.222.123",
    "Quad9": "9.9.9.9",
}
# answer IPs that mean "blocked/sinkhole" rather than a real result
_BLOCK_PREFIXES = ("0.0.0.0", "146.112.61.", "146.112.255.", "208.69.38.", "208.69.39.", "::")

_YES, _NO = f"[{GREEN}]Yes[/]", f"[{RED}]No[/]"


async def _port_open(ip: str, port: int) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1.5)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return True
    except Exception:  # noqa: BLE001
        return False


async def _scan_ports(ip: str) -> dict[str, str]:
    opens = await asyncio.gather(*(_port_open(ip, p) for p in COMMON_PORTS))
    return {
        f"{port} ({svc})": f"[{GREEN}]open[/]" if is_open else "[dim]closed[/]"
        for (port, svc), is_open in zip(COMMON_PORTS.items(), opens)
    }


def _http_security(headers: dict[str, str]) -> dict[str, str]:
    present = {k.lower() for k in headers}
    return {label: (_YES if h in present else _NO) for h, label in SEC_HEADERS.items()}


async def _query_filter(domain: str, ip: str) -> str:
    """Ask a filtering resolver for the domain; classify Blocked/Not Blocked."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "+time=2", "+tries=1", f"@{ip}", domain, "A",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        answers = [ln.strip() for ln in out.decode(errors="replace").splitlines() if ln.strip()]
        if not answers:  # NXDOMAIN / refused / empty
            return f"[{RED}]Blocked[/]"
        if any(a.startswith(_BLOCK_PREFIXES) for a in answers):
            return f"[{RED}]Blocked[/]"
        return f"[{GREEN}]Not Blocked[/]"
    except Exception:  # noqa: BLE001
        return "[dim]error[/]"


async def _blocklists(domain: str) -> dict[str, str]:
    names = list(FILTERS)
    outcomes = await asyncio.gather(*(_query_filter(domain, FILTERS[n]) for n in names))
    return dict(zip(names, outcomes))


class SecurityModule(ScanModule):
    name = "security"
    label = "Security"

    async def run(self, ctx: ScanContext) -> Sections:
        ports_coro = _scan_ports(ctx.ip) if ctx.ip else _empty()
        ports, blocks = await asyncio.gather(ports_coro, _blocklists(ctx.domain))
        r = (3, 2)  # 60/40 columns across all three tables
        return Sections([
            Section("Open Ports", ports or {"note": "no IP to scan"}, ("Port", "Status"), ratio=r),
            Section("HTTP Security", _http_security(ctx.headers), ("Header", "Present"), ratio=r),
            Section("Blocklists", blocks, ("Blocklist", "Status"), ratio=r),
        ])


async def _empty() -> dict[str, str]:
    return {}
