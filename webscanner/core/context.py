"""Shared per-scan context passed to every module.

The orchestrator's prefetch phase populates the shared network fields (one DNS
resolve, one HTTP GET, one TLS handshake, one geo lookup) so individual modules
reuse them instead of refetching.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

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
    def online(self) -> bool:
        return self.status_code is not None and self.fetch_error is None
