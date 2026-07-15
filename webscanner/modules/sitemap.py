"""Sitemap module — the site's URLs as a folder tree built from their paths.

This does **not** crawl the site: it discovers the sitemap(s) the site already
publishes (``Sitemap:`` lines in robots.txt, falling back to ``/sitemap.xml`` and
``/sitemap_index.xml``), fetches them (recursing into any nested ``<sitemapindex>``
files, gunzipping ``.xml.gz``), and collects every page ``<loc>``.

Those flat URLs are then rebuilt into a hierarchy keyed by their **path segments**,
so the tree reads like the site's folder structure — first level is the first slug
(``/blog``, ``/news``, ``/wp-content`` …), leaves are the final pages — rather than
mirroring the sitemap *files*. If the sitemaps span more than one host (e.g.
subdomains), the differing host becomes the top level so URLs aren't merged.

Robustness: a ``visited`` set + caps on total sitemap files, collected URLs and
sitemap-index nesting depth guard against loops and pathologically huge sitemaps.
"""

from __future__ import annotations

import asyncio
import gzip
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import requests

from ..core.module import ScanModule
from ..core.context import ScanContext
from ..core.models import TreeNode
from ..net.http import DEFAULT_HEADERS, TIMEOUT

#: total sitemap files fetched across the whole tree (loop / fan-out guard)
MAX_SITEMAPS = 60
#: total page URLs collected before we stop (bounds the tree size)
MAX_URLS = 10000
#: how deep a chain of nested <sitemapindex> files we follow
MAX_DEPTH = 6


class SitemapModule(ScanModule):
    name = "sitemap"
    label = "Sitemap"

    async def run(self, ctx: ScanContext) -> TreeNode | None:
        return await asyncio.to_thread(self._build, ctx)

    # ---- build (blocking; runs in a thread) -------------------------------

    def _build(self, ctx: ScanContext) -> TreeNode | None:
        urls = self._collect(ctx.domain)
        if not urls:
            return None  # -> EMPTY
        truncated = len(urls) >= MAX_URLS
        return _url_tree(urls, truncated)

    def _collect(self, domain: str) -> list[str]:
        """Fetch every sitemap (recursing indexes) and return the page URLs found."""
        visited: set[str] = set()
        urls: list[str] = []
        budget = [MAX_SITEMAPS]  # mutable counter shared across the recursion
        for sitemap in self._discover(domain):
            self._crawl(sitemap, visited, urls, budget, depth=0)
            if len(urls) >= MAX_URLS:
                break
        seen: set[str] = set()  # dedupe, preserve order
        return [u for u in urls if not (u in seen or seen.add(u))]

    def _crawl(self, url: str, visited: set[str], urls: list[str], budget: list[int], depth: int) -> None:
        if url in visited or budget[0] <= 0 or depth > MAX_DEPTH or len(urls) >= MAX_URLS:
            return
        visited.add(url)
        budget[0] -= 1

        raw = self._get(url)
        if raw is None:
            return
        kind, locs = _parse_sitemap(raw)
        if kind == "index":
            for loc in locs:
                self._crawl(loc, visited, urls, budget, depth + 1)
                if len(urls) >= MAX_URLS:
                    return
        elif kind == "urlset":
            for loc in locs:
                urls.append(loc)
                if len(urls) >= MAX_URLS:
                    return

    # ---- discovery + fetch ------------------------------------------------

    def _discover(self, domain: str) -> list[str]:
        """Sitemap URLs from robots.txt, else the two conventional defaults."""
        urls = self._robots_sitemaps(domain)
        if not urls:
            base = f"https://{domain}"
            urls = [f"{base}/sitemap.xml", f"{base}/sitemap_index.xml"]
        seen: set[str] = set()
        return [u for u in urls if not (u in seen or seen.add(u))]

    @staticmethod
    def _robots_sitemaps(domain: str) -> list[str]:
        try:
            resp = requests.get(
                f"https://{domain}/robots.txt",
                headers=DEFAULT_HEADERS, timeout=TIMEOUT, allow_redirects=True,
            )
            if resp.status_code != 200:
                return []
            return [
                ln.split(":", 1)[1].strip()
                for ln in resp.text.splitlines()
                if ln.strip().lower().startswith("sitemap:")
            ]
        except Exception:  # noqa: BLE001
            return []

    @staticmethod
    def _get(url: str) -> bytes | None:
        """Fetch a sitemap; gunzip ``.xml.gz`` / gzip payloads by magic bytes."""
        try:
            resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=TIMEOUT, allow_redirects=True)
            if resp.status_code != 200:
                return None
            raw = resp.content
            if raw[:2] == b"\x1f\x8b":  # gzip magic — a served .gz file (not transport enc.)
                raw = gzip.decompress(raw)
            return raw
        except Exception:  # noqa: BLE001
            return None


# ---- parsing + tree building ----------------------------------------------


def _parse_sitemap(raw: bytes) -> tuple[str | None, list[str]]:
    """Return ``("index"|"urlset", [loc, …])`` or ``(None, [])`` if unparseable."""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return None, []
    locs = [
        el.text.strip()
        for el in root.iter()
        if _localname(el.tag) == "loc" and el.text and el.text.strip()
    ]
    kind = "index" if _localname(root.tag) == "sitemapindex" else "urlset"
    return kind, locs


def _localname(tag: str) -> str:
    """Strip the ``{namespace}`` prefix ElementTree keeps on namespaced tags."""
    return tag.rsplit("}", 1)[-1].lower()


def _segments(url: str, include_host: bool) -> list[str]:
    """Path segments for `url` as tree labels: ``/blog``, ``/post`` … An empty path
    (the homepage) yields ``[]`` — it *is* the ``/`` root, not a child of it. When
    `include_host`, a leading host label (no slash) groups multi-host sitemaps. Any
    query is kept on the final leaf."""
    p = urlparse(url)
    parts = [s for s in p.path.split("/") if s]
    segs: list[str] = []
    if include_host and p.netloc:
        segs.append(p.netloc)
    segs += ["/" + s for s in parts]
    if p.query and segs:
        segs[-1] = segs[-1] + "?" + p.query
    return segs


def _url_tree(urls: list[str], truncated: bool) -> TreeNode:
    """Build a path-keyed tree under a visible ``/`` root. Within every level,
    branches (toggleable folders) sort first, then leaf pages — both alphabetical."""
    include_host = len({urlparse(u).netloc for u in urls if urlparse(u).netloc}) > 1
    root = TreeNode(label="/")  # the site root / homepage; shown + expanded by the UI
    index: dict[tuple[str, ...], TreeNode] = {(): root}
    for url in sorted(urls):
        parent = root
        node = root
        key: tuple[str, ...] = ()
        for seg in _segments(url, include_host):
            key += (seg,)
            node = index.get(key)
            if node is None:
                node = TreeNode(label=seg)
                index[key] = node
                parent.children.append(node)
            parent = node
        node.url = url  # deepest node for this URL (a leaf, unless it later gains children)
    if truncated:
        root.children.append(TreeNode(label=f"… (truncated at {MAX_URLS} URLs)"))
    root.total = len(urls)
    _sort_tree(root)
    return root


def _sort_tree(node: TreeNode) -> None:
    """Recursively order children: branches (have children) before leaves, each
    group alphabetical by label."""
    for child in node.children:
        _sort_tree(child)
    node.children.sort(key=lambda c: (not c.children, c.label.lower()))
