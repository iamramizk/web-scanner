"""Shared per-scan context passed to every module.

The orchestrator's prefetch phase populates the shared network fields (one DNS
resolve, one HTTP GET, one TLS handshake, one geo lookup) so individual modules
reuse them instead of refetching.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from .. import helpers
from ..net.agents import Profile, random_profile


@dataclass
class ScanContext:
    # inputs
    domain: str  # bare host, e.g. "example.com"
    url: str  # full url, e.g. "https://example.com"

    #: The browser identity every target-facing request wears. Chosen once per scan
    #: and shared, so the site sees one consistent visitor rather than a different
    #: browser per request — see net/agents.py. Not used for ip-api/DoH.
    profile: Profile = field(default_factory=random_profile)

    # shared prefetch results (filled by AsyncScanner.prefetch)
    ip: str | None = None
    html: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    status_code: int | None = None
    response_time_ms: float | None = None
    final_url: str | None = None
    redirect_status: str | None = None  # e.g. "301 Moved Permanently" for cross-domain redirects
    tls_cert: dict[str, Any] | None = None
    geo: dict[str, Any] | None = None
    fetch_error: str | None = None

    @classmethod
    def from_target(cls, target: str) -> "ScanContext":
        domain, url = helpers.normalise(target)
        return cls(domain=domain, url=url)

    @property
    def base(self) -> str:
        """Origin to build target URLs from: ``<scheme>://<domain>``.

        The scheme is the one prefetch actually *reached*, not the one we asked for.
        ``helpers.normalise()`` always hands us ``https://`` regardless of what the
        user typed, so :attr:`url` is not a scheme signal; ``http.fetch()`` retries
        over ``http://`` when https won't connect, and :attr:`final_url` records
        where it landed. An http-only site that builds its URLs from :attr:`url`
        silently gets nothing back (no robots.txt, no sitemap, no tech) while the
        rest of the scan succeeds.

        The host comes from :attr:`domain`, *not* from ``final_url``: a bare→www
        redirect would otherwise pin us to ``www.example.com``, and requests we
        build follow redirects there anyway.

        **Only valid after prefetch.** Before it (``final_url`` is None) this falls
        back to https — which is also the right answer when the fetch failed
        outright, since nothing else will connect either. ``prefetch()`` itself must
        never read this: it is what determines the scheme.
        """
        scheme = urlparse(self.final_url).scheme if self.final_url else ""
        return f"{scheme or 'https'}://{self.domain}"

    @property
    def online(self) -> bool:
        return self.status_code is not None and self.fetch_error is None
