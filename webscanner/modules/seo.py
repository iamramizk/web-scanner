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
from ..net.agents import Profile
from ..net.http import TIMEOUT

TITLE_RANGE = (30, 60)
DESC_RANGE = (70, 160)

SOCIAL_DOMAINS = (
    "facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com",
    "youtube.com", "youtu.be", "pinterest.com", "tiktok.com", "reddit.com",
    "medium.com", "discord.com", "discord.gg", "twitch.tv", "vimeo.com",
)

_STOPWORDS = frozenset(
    (
        # core articles / conjunctions / prepositions / pronouns
        "the a an and or but if of to in on for with as by at from is are was were be "
        "been being this that these those it its you your we our us they their he she "
        "his her not no so do does did has have had can will would should could may "
        "might just than then there here what which who when where how all any some "
        "more most other into out up down over under about also new get one two "
        # additional pronouns / possessives
        "him them myself yourself himself herself itself ourselves themselves "
        "whom whose mine yours ours hers theirs "
        # modals / auxiliaries
        "shall must cannot ought need used "
        # conjunctions / subordinators
        "nor yet because while since until unless although though whether whereas "
        "whenever wherever whoever whatever "
        # prepositions
        "off per via upon above below beneath between among amongst throughout during "
        "before after against without within along across behind beyond near toward "
        "towards onto "
        # determiners / quantifiers
        "each every either neither both few many much such own same only very too quite "
        "rather enough none another several "
        # common adverbs / fillers
        "back even still again ever never always often once now thus hence therefore "
        "however moreover otherwise indeed perhaps maybe actually really simply almost "
        "already else yes why well like "
        # contractions (the tokenizer keeps apostrophes, so these survive verbatim)
        "don't doesn't didn't isn't aren't wasn't weren't won't wouldn't can't couldn't "
        "shouldn't hasn't haven't hadn't i'm i've i'll i'd you're you've you'll you'd "
        "we're we've we'll we'd they're they've they'll it's he's she's that's there's "
        "here's what's who's let's"
    ).split()
)


# JSON syntax-highlight colours (dark-friendly, aligned with the app palette).
_J_KEY = "#5FAFFF"   # object keys — blue
_J_STR = GREEN       # string values
_J_NUM = "#D7AF87"   # numbers — amber
_J_KW = RED          # true / false / null
_J_PUNCT = MUTED     # braces, brackets, commas, colons

_JSON_TOKEN = re.compile(
    r'(?P<space>\s+)'
    r'|(?P<str>"(?:[^"\\]|\\.)*")'
    r'|(?P<num>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)'
    r'|(?P<kw>true|false|null)'
    r'|(?P<punct>[{}\[\],:])'
)


def _highlight_json(obj: object) -> str:
    """Pretty-print `obj` as indented JSON with Rich colour markup. Brackets in
    the payload are escaped so Rich doesn't parse them; `_value_cell` renders the
    markup and CSV export strips it back to plain JSON."""
    raw = json.dumps(obj, indent=2, ensure_ascii=False)
    tokens = list(_JSON_TOKEN.finditer(raw))
    out: list[str] = []
    pos = 0
    for i, m in enumerate(tokens):
        if m.start() > pos:  # any char the tokenizer skipped, kept verbatim
            out.append(escape(raw[pos:m.start()]))
        pos = m.end()
        kind, text = m.lastgroup, m.group()
        if kind == "space":
            out.append(text)
        elif kind == "str":
            # a string is a key iff the next non-space token is a colon
            nxt = next((t for t in tokens[i + 1:] if t.lastgroup != "space"), None)
            colour = _J_KEY if nxt and nxt.group() == ":" else _J_STR
            out.append(f"[{colour}]{escape(text)}[/]")
        elif kind == "num":
            out.append(f"[{_J_NUM}]{text}[/]")
        elif kind == "kw":
            out.append(f"[{_J_KW}]{text}[/]")
        else:  # punct
            out.append(f"[{_J_PUNCT}]{escape(text)}[/]")
    out.append(escape(raw[pos:]))
    return "".join(out)


def _len_line(text: str, lo: int, hi: int) -> str:
    n = len(text)
    colour = GREEN if lo <= n <= hi else RED
    return f"[{MUTED}]{escape(text)}[/]\n[{colour}]{n} chars · rec. {lo}-{hi}[/]"


def _text(el) -> str:
    """Element text as the browser's `textContent` sees it, whitespace collapsed.

    `get_text(strip=True)` strips each child text node then joins with no
    separator, so words split across spans/newlines fuse ("One <span>Two</span>
    <span>Three</span>" -> "OneTwoThree"). Taking the raw text and re-joining on
    whitespace keeps the gaps that actually exist between nodes without inventing
    any where the DOM has none (e.g. `<br>`).
    """
    return " ".join(el.get_text().split())


class SeoModule(ScanModule):
    name = "seo"
    label = "SEO"

    async def run(self, ctx: ScanContext) -> Sections:
        robots_coro = asyncio.to_thread(self._fetch_robots, ctx.base, ctx.profile)
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
            schema["Schema"] = _highlight_json(
                blocks[0] if len(blocks) == 1 else blocks
            )

        # --- Content ---
        title_el = soup.find("title")
        title = _text(title_el) if title_el else None
        desc_el = soup.find("meta", attrs={"name": "description"})
        desc = (desc_el.get("content") or "").strip() if desc_el else None
        content: dict[str, object] = {
            "Title": _len_line(title, *TITLE_RANGE) if title else "-",
            "Description": _len_line(desc, *DESC_RANGE) if desc else "-",
        }
        for lvl in range(1, 4):
            content[f"H{lvl}"] = [_text(h) for h in soup.find_all(f"h{lvl}")]
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
    def _fetch_robots(base: str, profile: Profile) -> dict[str, object]:
        url = f"{base}/robots.txt"
        try:
            resp = requests.get(
                url,
                headers=profile.headers(url), timeout=TIMEOUT, allow_redirects=True,
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
