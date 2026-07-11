"""Blocking HTTP / DNS / TLS primitives.

Kept synchronous on purpose: the async core calls these via ``asyncio.to_thread``.
Centralising them here gives every module one user-agent, one timeout policy and
one place to add retries/proxying later.
"""

from __future__ import annotations

import socket
import ssl
import time
from typing import Any

import requests

USER_AGENT = "web-scanner/2.0 (+https://github.com/iamramizk/web-scanner)"
TIMEOUT = 12
DEFAULT_HEADERS = {"User-Agent": USER_AGENT}


def fetch(url: str) -> dict[str, Any]:
    """GET a URL, following redirects; return status/headers/body/timing/final-url."""
    start = time.perf_counter()
    resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=TIMEOUT, allow_redirects=True)
    elapsed = (time.perf_counter() - start) * 1000
    return {
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "html": resp.text,
        "elapsed_ms": elapsed,
        "final_url": resp.url,
    }


def resolve_ip(domain: str) -> str | None:
    """Resolve a host to its first IPv4 address."""
    try:
        return socket.gethostbyname(domain)
    except OSError:
        return None


def get_geo(ip: str) -> dict[str, Any]:
    """Geolocate an IP via ip-api.com (free, no key)."""
    resp = requests.get(f"http://ip-api.com/json/{ip}", headers=DEFAULT_HEADERS, timeout=TIMEOUT)
    return resp.json()


def get_tls_cert(host: str, port: int = 443) -> dict[str, Any] | None:
    """Complete a TLS handshake and return the peer certificate dict (or None)."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert()


def doh_query(name: str, rtype: str = "A") -> dict[str, Any]:
    """DNS-over-HTTPS query via Cloudflare (used for blocklist checks)."""
    resp = requests.get(
        "https://cloudflare-dns.com/dns-query",
        params={"name": name, "type": rtype},
        headers={"accept": "application/dns-json", "User-Agent": USER_AGENT},
        timeout=TIMEOUT,
    )
    return resp.json()
