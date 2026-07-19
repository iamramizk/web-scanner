"""Blocking HTTP / DNS / TLS primitives.

Kept synchronous on purpose: the async core calls these via ``asyncio.to_thread``.
Centralising them here gives every module one timeout policy and one place to add
retries/proxying later.

Two identities live here, and the split is deliberate:

* **Target-facing** requests (homepage, robots.txt, sitemaps) wear the scan's
  :class:`~webscanner.net.agents.Profile` — a browser identity, passed in by the
  caller from ``ctx.profile``. See ``agents.py`` for why.
* **Third-party APIs** (ip-api, Cloudflare DoH) use :data:`API_HEADERS`, which
  identifies the tool honestly. They don't block and don't care, and there's no
  reason to wear a costume for a free service we depend on.

``API_HEADERS`` is named for that job rather than "default" on purpose: there is no
sensible default here, and a name like ``DEFAULT_HEADERS`` is exactly what someone
reaches for by accident on a target request.
"""

from __future__ import annotations

import socket
import ssl
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from .agents import Profile
from .psl import registrable_domain

USER_AGENT = "web-scanner/2.0 (+https://github.com/iamramizk/web-scanner)"
TIMEOUT = 12
#: For third-party APIs only — never for the target. See the module docstring.
API_HEADERS = {"User-Agent": USER_AGENT}


def fetch(url: str, profile: Profile) -> dict[str, Any]:
    """GET a URL, following redirects; return status/headers/body/timing/final-url.

    ``redirect`` is set (e.g. "301 Moved Permanently") only when a redirect crossed
    to a *different* registrable domain (mane.agency → iamramiz.com), not for a
    same-site hop like http→https or bare→www. Registrable domain is resolved via
    the Public Suffix List, so ccTLDs like co.uk / com.au are compared correctly.

    If an ``https://`` GET fails to connect (bad/mismatched TLS cert, TLS not
    served, connection refused/timeout), retry once over ``http://`` so the site
    still scans instead of coming back offline. An HTTP *status* error (4xx/5xx)
    is a normal response, not a connection failure, and does not trigger a retry.
    """
    try:
        return _get(url, profile)
    except requests.exceptions.RequestException:
        if url.lower().startswith("https://"):
            return _get("http://" + url[len("https://"):], profile)
        raise


def _get(url: str, profile: Profile) -> dict[str, Any]:
    start = time.perf_counter()
    # headers(url), not a cached dict: the http:// retry above must drop the client
    # hints, which are https-only.
    resp = requests.get(url, headers=profile.headers(url), timeout=TIMEOUT, allow_redirects=True)
    elapsed = (time.perf_counter() - start) * 1000

    orig = registrable_domain(urlparse(url).hostname)
    redirect: str | None = None
    for hop in resp.history:
        target = urljoin(hop.url, hop.headers.get("Location", ""))
        if registrable_domain(urlparse(target).hostname) != orig:
            redirect = f"{hop.status_code} {hop.reason}"
            break

    return {
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "html": resp.text,
        "elapsed_ms": elapsed,
        "final_url": resp.url,
        "redirect": redirect,
    }


def resolve_ip(domain: str) -> str | None:
    """Resolve a host to its first IPv4 address."""
    try:
        return socket.gethostbyname(domain)
    except OSError:
        return None


def get_geo(ip: str) -> dict[str, Any]:
    """Geolocate an IP via ip-api.com (free, no key)."""
    resp = requests.get(f"http://ip-api.com/json/{ip}", headers=API_HEADERS, timeout=TIMEOUT)
    return resp.json()


def reverse_ip_lookup(ip: str) -> list[str] | None:
    """Hostnames sharing ``ip``, via hackertarget.com (free, unauthenticated).

    Returns the list of hostnames on the IP, or ``None`` on any failure — network
    error, non-200, or a sentinel body (``error …`` / ``No DNS A records found`` /
    ``API count exceeded …`` when the 50-request/day/IP quota is spent). Callers show
    nothing rather than guess. Uses ``API_HEADERS`` (honest UA): a third-party API,
    not a target request.
    """
    try:
        resp = requests.get(
            "https://api.hackertarget.com/reverseiplookup/",
            params={"q": ip},
            headers=API_HEADERS,
            timeout=TIMEOUT,
        )
    except requests.exceptions.RequestException:
        return None
    if resp.status_code != 200:
        return None
    lines = [ln.strip() for ln in resp.text.splitlines() if ln.strip()]
    # Every hostname line is space-free; every sentinel/error message contains spaces.
    if not lines or any(" " in ln for ln in lines):
        return None
    return lines


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
