"""Page links module — internal vs external links found on the page.

Two tables (link text → href URL): Internal (same registrable domain, incl.
relative links and subdomains) and External (everything else). Uses the HTML
fetched once during prefetch.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..core.module import ScanModule
from ..core.context import ScanContext
from ..core.models import Section, Sections

_SKIP_PREFIXES = ("#", "javascript:", "mailto:", "tel:", "data:")


class LinksModule(ScanModule):
    name = "links"
    label = "Links"

    async def run(self, ctx: ScanContext) -> Sections:
        if not ctx.html:
            internal: list[tuple[str, str]] = []
            external: list[tuple[str, str]] = []
        else:
            internal, external = await asyncio.to_thread(self._parse, ctx)

        return Sections([
            Section("Internal", internal or [("—", "no internal links found")], ("Link text", "URL")),
            Section("External", external or [("—", "no external links found")], ("Link text", "URL")),
        ])

    @staticmethod
    def _parse(ctx: ScanContext) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
        soup = BeautifulSoup(ctx.html, "html.parser")
        base = ctx.final_url or ctx.url
        internal: list[tuple[str, str]] = []
        external: list[tuple[str, str]] = []
        seen_i: set[str] = set()
        seen_e: set[str] = set()

        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href or href.startswith(_SKIP_PREFIXES):
                continue
            url = urljoin(base, href)
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                continue

            text = " ".join(tag.get_text(strip=True).split()) or "-"
            host = parsed.netloc.lower()
            if host.startswith("www."):
                host = host[4:]

            if host == ctx.domain or host.endswith("." + ctx.domain):
                if url not in seen_i:
                    seen_i.add(url)
                    internal.append((text, url))
            elif url not in seen_e:
                seen_e.add(url)
                external.append((text, url))

        return internal, external
