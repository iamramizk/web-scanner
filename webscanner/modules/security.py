"""Security module — four tables: WAF Detection, Open Ports, HTTP Security, Blocklists.

- WAF Detection: identify the target's WAF / security CDN two ways. (1) *Passive* —
  fingerprint the baseline response headers + Set-Cookie (from prefetch, no request).
  (2) *Active* — one dedicated GET carrying obvious attack payloads (XSS / traversal /
  SQLi in the query string) to provoke a block, then read the block status + body
  signatures. The active probe is what *confirms blocking* and names header-less WAFs;
  it's a single benign request run concurrently with the port/blocklist scans. A *clean*
  result still never proves "no WAF" (we can't spoof the TLS/HTTP2 fingerprint), so the
  Activity Log stays silent unless a vendor is named or the probe is actively blocked.
- Open Ports: TCP-connect scan of a short list of common ports.
- HTTP Security: presence of key response security headers (from prefetch).
- Blocklists: whether the domain is blocked by popular filtering DNS resolvers
  (AdGuard, CleanBrowsing, Cloudflare, Google, OpenDNS, Quad9), queried directly
  by IP via ``dig``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import requests

from ..colors import GREEN, RED, MUTED
from ..core.module import ScanModule
from ..core.context import ScanContext
from ..core.models import Section, Sections
from ..net.agents import Profile
from ..net.http import TIMEOUT

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

# Passive WAF / security-CDN signatures. A vendor matches if ANY of its markers is
# present in the baseline response:
#   "headers" — a response header name is present (value irrelevant),
#   "server"  — a substring of the Server header value,
#   "cookies" — a substring of the (comma-joined) Set-Cookie blob (usually a cookie name),
#   "values"  — a (header-name, value-substring) pair.
# All matching is case-insensitive. Curated for false-positive resistance — presence of a
# vendor marker is a strong signal; absence proves nothing (see the module docstring).
WAF_SIGNATURES: dict[str, dict[str, tuple]] = {
    "Cloudflare": {
        "headers": ("cf-ray", "cf-cache-status"),
        "server": ("cloudflare",),
        "cookies": ("__cf_bm", "__cfduid", "cf_clearance"),
    },
    "Sucuri": {
        "headers": ("x-sucuri-id", "x-sucuri-cache"),
        "server": ("sucuri",),
    },
    "Imperva Incapsula": {
        "headers": ("x-iinfo",),
        "values": (("x-cdn", "incapsula"),),
        "cookies": ("incap_ses", "visid_incap", "nlbi_"),
    },
    "Akamai": {
        "headers": ("x-akamai-transformed", "akamai-grn"),
        "server": ("akamaighost",),
    },
    "Amazon CloudFront": {
        "headers": ("x-amz-cf-id",),
        "server": ("cloudfront",),
    },
    "Fastly": {
        "headers": ("x-fastly-request-id",),
        "server": ("fastly",),
    },
    "F5 BIG-IP": {
        "headers": ("x-waf-event-info",),
        "cookies": ("bigipserver",),
    },
    "Barracuda": {
        "cookies": ("barra_counter_session", "bni__barracuda", "bni_persistence"),
    },
    "Wordfence": {
        "cookies": ("wfvt_", "wordfence_verifiedhuman"),
    },
    "DDoS-Guard": {
        "server": ("ddos-guard",),
        "cookies": ("__ddg",),
    },
    "StackPath": {
        "server": ("stackpath",),
    },
    "Fortinet FortiWeb": {
        "cookies": ("fortiwafsid",),
    },
    "Reblaze": {
        "server": ("reblaze",),
        "cookies": ("rbzid", "rbzsessionid"),
    },
    "Azure Front Door": {
        "headers": ("x-azure-ref", "x-azure-fdid"),
    },
}


def _waf_match(sig: dict[str, tuple], names: set[str], lowered: dict[str, str],
               server: str, cookies: str) -> bool:
    if any(h in names for h in sig.get("headers", ())):
        return True
    if any(s in server for s in sig.get("server", ())):
        return True
    if any(c.lower() in cookies for c in sig.get("cookies", ())):
        return True
    return any(sub.lower() in lowered.get(hdr, "").lower() for hdr, sub in sig.get("values", ()))


def identify_waf(headers: dict[str, str]) -> list[str]:
    """Vendor names whose passive signature matches ``headers`` (order = signature order).

    Pure — no I/O. ``headers`` is the prefetch response headers (keys any casing;
    Set-Cookie collapsed into one comma-joined value by requests). Empty list = nothing
    matched, which is *not* proof there's no WAF."""
    lowered = {k.lower(): v for k, v in headers.items()}
    names = set(lowered)
    server = lowered.get("server", "").lower()
    cookies = lowered.get("set-cookie", "").lower()
    return [
        vendor for vendor, sig in WAF_SIGNATURES.items()
        if _waf_match(sig, names, lowered, server, cookies)
    ]


# --- active probe ----------------------------------------------------------

# Obvious attack payloads (XSS / directory traversal / SQLi) in the query string — enough
# to trip any standard WAF ruleset, harmless to a real server (requests URL-encodes them).
_PROBE_PARAMS = {
    "q": "<script>alert(1)</script>",
    "file": "../../../../../etc/passwd",
    "id": "1' OR '1'='1",
}
# Status codes a WAF returns to reject an attack (403 Forbidden, 406 Not Acceptable,
# 429 Too Many Requests, 501, and Imperva's signature 999).
_BLOCK_STATUSES = frozenset({403, 406, 429, 501, 999})

# Vendor -> block-page body markers (lower-case substrings). Some (ModSecurity, Wordfence)
# are only ever visible on the block page, so the active probe is the only way to see them.
# Kept tight — a marker must be distinctive to a block page, not a word that shows up on
# ordinary content.
WAF_BODY_SIGNATURES: dict[str, tuple[str, ...]] = {
    "Cloudflare": ("cloudflare ray id", "attention required! | cloudflare", "cf-error-details"),
    "Sucuri": ("sucuri website firewall",),
    "Imperva Incapsula": ("incapsula incident", "_incapsula_resource"),
    "Wordfence": ("generated by wordfence", "your access to this site has been limited"),
    "ModSecurity": ("mod_security", "modsecurity"),
    "Fortinet FortiWeb": ("fortiweb",),
}


@dataclass(slots=True)
class ProbeResult:
    #: True = the probe was blocked, False = it went through, None = couldn't probe.
    blocked: bool | None
    status: int | None
    vendors: list[str]  # vendors named by the block-page body


def _assess_probe(status: int, baseline_status: int | None, body: str) -> tuple[bool, list[str]]:
    """Pure verdict from a probe response — blocked? + any vendor the body names.

    ``blocked`` requires a WAF-style reject status that *differs from the baseline*: a site
    whose homepage already 403s isn't "blocking" our probe specifically."""
    body = body.lower()
    vendors = [v for v, pats in WAF_BODY_SIGNATURES.items() if any(p in body for p in pats)]
    blocked = status in _BLOCK_STATUSES and status != baseline_status
    return blocked, vendors


def _probe_waf(base: str, profile: Profile, baseline_status: int | None) -> ProbeResult:
    """Send the provocation GET and classify it. Blocking — run via ``asyncio.to_thread``."""
    url = f"{base}/"
    try:
        resp = requests.get(
            url, params=_PROBE_PARAMS, headers=profile.headers(url),
            timeout=TIMEOUT, allow_redirects=True,
        )
    except Exception:  # noqa: BLE001 — a failed probe is inconclusive, not an error
        return ProbeResult(None, None, [])
    blocked, vendors = _assess_probe(resp.status_code, baseline_status, resp.text[:8000])
    return ProbeResult(blocked, resp.status_code, vendors)


def _probe_cell(probe: ProbeResult) -> str:
    if probe.status is None:
        return f"[{MUTED}]Inconclusive[/]"
    if probe.blocked:
        return f"[{GREEN}]Blocked · HTTP {probe.status}[/]"
    return f"[{MUTED}]Not blocked · HTTP {probe.status}[/]"


def _waf_section(vendors: list[str], probe: ProbeResult) -> dict[str, str]:
    rows = {vendor: f"[{GREEN}]Detected[/]" for vendor in vendors}
    # Nothing named and the probe wasn't blocked → say so plainly (else the probe row tells
    # the story on its own — a blocked probe with no vendor still means a WAF is present).
    if not vendors and not probe.blocked:
        rows["Firewall"] = f"[{MUTED}]None detected[/]"
    rows["Active Probe"] = _probe_cell(probe)
    return rows


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
        f"{port} ({svc})": f"[{GREEN}]open[/]" if is_open else f"[{MUTED}]closed[/]"
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
        probe_coro = asyncio.to_thread(_probe_waf, ctx.base, ctx.profile, ctx.status_code)
        ports, blocks, probe = await asyncio.gather(
            ports_coro, _blocklists(ctx.domain), probe_coro
        )
        # Passive header fingerprint + any vendor the probe's block page named (dedup, order).
        vendors = identify_waf(ctx.headers)
        vendors += [v for v in probe.vendors if v not in vendors]
        r = (3, 2)  # 60/40 columns across all four tables
        waf = _waf_section(vendors, probe)
        return Sections([
            Section("WAF Detection", waf, ("Firewall", "Status"), ratio=r),
            Section("Open Ports", ports or {"note": "no IP to scan"}, ("Port", "Status"), ratio=r),
            Section("HTTP Security", _http_security(ctx.headers), ("Header", "Present"), ratio=r),
            Section("Blocklists", blocks, ("Blocklist", "Status"), ratio=r),
        ])


async def _empty() -> dict[str, str]:
    return {}
