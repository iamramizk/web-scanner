"""An http-only site must still get robots.txt, its sitemap and tech detection.

Regression guard for the hardcoded ``https://`` that used to sit in seo, sitemap
(x2) and tech. ``helpers.normalise()`` always yields ``https://<domain>`` whatever
the user typed, so those modules could never reach a site that only serves http —
they returned "no robots.txt" / EMPTY / no technologies while the rest of the scan
succeeded, because ``http.fetch()`` quietly retries over http://. Silently wrong
rather than an error, which is the worst failure mode for a recon tool.

Runs against a local http-only server, so it needs no network and is deterministic.
"""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from webscanner.core.context import ScanContext
from webscanner.core.scanner import AsyncScanner
from webscanner.modules.seo import SeoModule
from webscanner.modules.sitemap import SitemapModule
from webscanner.ui.tables import _plain

ROBOTS_TXT = b"User-agent: *\nDisallow: /private\nSitemap: %s/sitemap.xml\n"
SITEMAP_XML = (
    b'<?xml version="1.0"?>'
    b'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    b"<url><loc>%s/a</loc></url>"
    b"<url><loc>%s/blog/b</loc></url>"
    b"</urlset>"
)
PAGE_HTML = (
    b"<html><head><title>Test Site</title>"
    b'<meta name="description" content="a test page">'
    b'<meta name="generator" content="WordPress 6.4">'
    b"</head><body><h1>Heading</h1><p>some words on the page</p></body></html>"
)


@pytest.fixture(scope="module")
def http_only_site():
    """A server that speaks http and nothing else — no TLS listener at all."""
    origin_box: list[bytes] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            origin = origin_box[0]
            routes = {
                "/robots.txt": (ROBOTS_TXT % origin, "text/plain"),
                "/sitemap.xml": (SITEMAP_XML % (origin, origin), "application/xml"),
            }
            body, ctype = routes.get(self.path, (PAGE_HTML, "text/html"))
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:  # keep pytest output clean
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)  # port 0 -> OS picks a free one
    host, port = srv.server_address[0], srv.server_address[1]
    origin_box.append(f"http://{host}:{port}".encode())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"{host}:{port}"
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture(scope="module")
def scanned(http_only_site):
    """Scan the http-only server the way the app does: prefetch, then modules."""
    ctx = ScanContext(domain=http_only_site, url=f"https://{http_only_site}")
    scanner = AsyncScanner(ctx, [SeoModule(), SitemapModule()])
    asyncio.run(scanner.run())
    return ctx, scanner


def test_prefetch_falls_back_to_http(scanned):
    """The premise: fetch() reaches the site over http and records it in final_url."""
    ctx, _ = scanned
    assert ctx.fetch_error is None
    assert ctx.final_url.startswith("http://")


def test_base_carries_the_reached_scheme(scanned):
    ctx, _ = scanned
    assert ctx.base == f"http://{ctx.domain}"


def test_seo_finds_robots_txt(scanned):
    _, scanner = scanned
    robots = next(s.data for s in scanner.results["seo"].data if s.title == "Robots")
    assert _plain(robots["Found"]) == "Yes"
    assert "Disallow: /private" in robots["robots.txt"]


def test_sitemap_collects_urls(scanned):
    _, scanner = scanned
    tree = scanner.results["sitemap"].data
    assert tree is not None, "sitemap came back EMPTY on an http-only site"
    assert tree.total == 2


def test_base_defaults_to_https_before_prefetch():
    """No final_url (pre-prefetch, or the fetch failed outright) -> today's behaviour."""
    ctx = ScanContext(domain="example.com", url="https://example.com")
    assert ctx.base == "https://example.com"


def test_base_is_identical_to_url_for_https_sites():
    """The no-op guarantee: an https site must be byte-identical to the old code.

    Includes the bare->www redirect case, which is why the host comes from `domain`
    rather than from final_url.
    """
    ctx = ScanContext(domain="example.com", url="https://example.com")
    ctx.final_url = "https://www.example.com/"
    assert ctx.base == ctx.url
