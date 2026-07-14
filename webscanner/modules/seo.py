"""SEO module — Content, Keywords, Robots, and Schema tables.

- Content: title / description (each with a character-count + recommended-length
  hint, green when in range, red when out), h1–h3 headings + socials.
- Keywords: the top-10 most frequent 1-, 2- and 3-word phrases on the page.
- Robots: robots.txt presence, any sitemaps, and the raw file.
- Schema: whether the page has schema.org structured data (JSON-LD) + the parsed
  JSON (shown last, in full).

Parses the HTML fetched once during prefetch; robots.txt is a small extra fetch.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections import Counter
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from rich.markup import escape

from ..colors import GREEN, RED, MUTED
from ..core.module import ScanModule
from ..core.context import ScanContext
from ..core.models import Section, Sections
from ..net.http import DEFAULT_HEADERS, TIMEOUT

TITLE_RANGE = (30, 60)
DESC_RANGE = (70, 160)

SOCIAL_DOMAINS = (
    "facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com",
    "youtube.com", "youtu.be", "pinterest.com", "tiktok.com", "reddit.com",
    "medium.com", "discord.com", "discord.gg", "twitch.tv", "vimeo.com",
)

_STOPWORDS = frozenset(
    "the a an and or but if of to in on for with as by at from is are was were be "
    "been being this that these those it its you your we our us they their he she "
    "his her not no so do does did has have had can will would should could may "
    "might just than then there here what which who when where how all any some "
    "more most other into out up down over under about also new get one two".split()
)


def _len_line(text: str, lo: int, hi: int) -> str:
    n = len(text)
    colour = GREEN if lo <= n <= hi else RED
    return f"[{MUTED}]{escape(text)}[/]\n[{colour}]{n} chars · rec. {lo}-{hi}[/]"


class SeoModule(ScanModule):
    name = "seo"
    label = "SEO"

    async def run(self, ctx: ScanContext) -> Sections:
        robots_coro = asyncio.to_thread(self._fetch_robots, ctx.domain)
        if not ctx.html:
            robots = await robots_coro
            note = {"note": "no page content"}
            schema, content, keywords = {"Has Schema": f"[{RED}]No[/]"}, note, note
        else:
            parsed, robots = await asyncio.gather(
                asyncio.to_thread(self._parse, ctx), robots_coro
            )
            schema, content, keywords = parsed

        return Sections([
            Section("Content", content, ("Field", "Value"), spaced=True),
            Section("Keywords", keywords, ("N-gram", "Top 10 (by frequency)"), spaced=True),
            Section("Robots", robots, ("Field", "Value"), spaced=True),
            Section("Schema", schema, ("Field", "Value"), spaced=True),
        ])

    @staticmethod
    def _parse(ctx: ScanContext) -> tuple[dict, dict, dict]:
        soup = BeautifulSoup(ctx.html, "html.parser")

        # --- Schema (JSON-LD structured data) ---
        blocks = []
        for tag in soup.find_all("script", attrs={"type": "application/ld+json"}):
            try:
                blocks.append(json.loads(tag.string or tag.get_text()))
            except Exception:  # noqa: BLE001
                pass
        schema: dict[str, str] = {"Has Schema": f"[{GREEN}]Yes[/]" if blocks else f"[{RED}]No[/]"}
        if blocks:
            schema["Schema"] = json.dumps(
                blocks[0] if len(blocks) == 1 else blocks, indent=2, ensure_ascii=False
            )

        # --- Content ---
        title_el = soup.find("title")
        title = title_el.get_text(strip=True) if title_el else None
        desc_el = soup.find("meta", attrs={"name": "description"})
        desc = (desc_el.get("content") or "").strip() if desc_el else None
        content: dict[str, object] = {
            "Title": _len_line(title, *TITLE_RANGE) if title else "-",
            "Description": _len_line(desc, *DESC_RANGE) if desc else "-",
        }
        for lvl in range(1, 4):
            content[f"H{lvl}"] = [h.get_text(strip=True) for h in soup.find_all(f"h{lvl}")]
        content["Socials"] = sorted({
            tag["href"].rstrip("/")
            for tag in soup.find_all("a", href=True)
            if any(urlparse(tag["href"]).netloc.lower().endswith(d) for d in SOCIAL_DOMAINS)
        })

        # --- Keywords (n-grams) ---
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text(" ", strip=True).lower()
        tokens = [t for t in re.findall(r"[a-z][a-z'-]{2,}", text) if t not in _STOPWORDS]

        def top(n: int) -> str:
            grams = (" ".join(tokens[i:i + n]) for i in range(len(tokens) - n + 1))
            return ", ".join(g for g, _ in Counter(grams).most_common(10)) or "-"

        keywords = {"1-word": top(1), "2-word": top(2), "3-word": top(3)}
        return schema, content, keywords

    @staticmethod
    def _fetch_robots(domain: str) -> dict[str, object]:
        try:
            resp = requests.get(
                f"https://{domain}/robots.txt",
                headers=DEFAULT_HEADERS, timeout=TIMEOUT, allow_redirects=True,
            )
            text = resp.text.strip()
            ctype = resp.headers.get("content-type", "").lower()
            looks_html = "html" in ctype or "<html" in text[:200].lower() or text[:20].lower().startswith("<!doctype")
            if resp.status_code == 200 and text and not looks_html:
                result: dict[str, object] = {"Found": f"[{GREEN}]Yes[/]"}
                sitemaps = [
                    ln.split(":", 1)[1].strip()
                    for ln in text.splitlines()
                    if ln.strip().lower().startswith("sitemap:")
                ]
                if sitemaps:
                    result["Sitemaps"] = sitemaps
                result["robots.txt"] = text
                return result
        except Exception:  # noqa: BLE001
            pass
        return {"Found": f"[{RED}]No[/]"}
