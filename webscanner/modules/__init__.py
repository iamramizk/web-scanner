"""Scan module registry.

``all_modules()`` order defines the tab order in the UI:
DNS · Whois · Subdomains · SSL · Security · Headers · Tech · SEO · Sitemap · Links
(Email auth — DMARC/DKIM — is folded into DNS. Security = ports + HTTP headers + blocklists.
SEO = schema + content + keywords. Sitemap = the site's published sitemap(s) as a tree.
Links = internal + external page links.)
"""

from __future__ import annotations

from ..core.module import ScanModule
from .dns import DnsModule
from .headers import HeadersModule
from .links import LinksModule
from .security import SecurityModule
from .seo import SeoModule
from .sitemap import SitemapModule
from .ssl import SslModule
from .subdomains import SubdomainsModule
from .tech import TechModule
from .whois import WhoisModule


def all_modules() -> list[ScanModule]:
    """Fresh instances in tab order."""
    return [
        DnsModule(),
        WhoisModule(),
        SubdomainsModule(),
        SslModule(),
        SecurityModule(),
        HeadersModule(),
        TechModule(),
        SeoModule(),
        SitemapModule(),
        LinksModule(),
    ]


__all__ = ["all_modules"]
