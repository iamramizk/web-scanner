"""Sitemap page/asset classification is pure URL parsing — never a request.

``_is_asset`` reads the extension off the last path segment only; a missing or
unknown extension, or a trailing slash, is a page. ``_url_tree`` then reports the
split on the root (``pages`` + ``assets`` == ``total``), and ``_sitemap_subtitle``
renders it. These cover the extension edges (query strings, dotted path segments,
uppercase, no extension) and the counts that feed the tab subtitle.
"""

from __future__ import annotations

import pytest

from webscanner.modules.sitemap import _is_asset, _url_tree
from webscanner.ui.app import _sitemap_subtitle

PAGES = [
    "https://ex.com/",                       # homepage, no extension
    "https://ex.com/about",                  # bare route
    "https://ex.com/blog/post-1",            # nested route
    "https://ex.com/index.html",             # explicit page extension
    "https://ex.com/product.php",            # dynamic page
    "https://ex.com/search?q=shoes.pdf",     # extension only in the query → page
    "https://ex.com/v1.2/release-notes",     # dot in a non-final segment → page
    "https://ex.com/weird.xyz",              # unknown extension → page (bias to page)
]
ASSETS = [
    "https://ex.com/logo.png",
    "https://ex.com/deck.PDF",               # uppercase extension
    "https://ex.com/app.min.js",             # double extension → last wins
    "https://ex.com/fonts/body.woff2",
    "https://ex.com/media/promo.mp4?v=3",    # query ignored
    "https://ex.com/downloads/report.xlsx",
]


@pytest.mark.parametrize("url", PAGES)
def test_pages_not_assets(url: str) -> None:
    assert _is_asset(url) is False


@pytest.mark.parametrize("url", ASSETS)
def test_assets(url: str) -> None:
    assert _is_asset(url) is True


def test_tree_counts_split_pages_and_assets() -> None:
    root = _url_tree(PAGES + ASSETS, truncated=False)
    assert root.total == len(PAGES) + len(ASSETS)
    assert root.pages == len(PAGES)
    assert root.assets == len(ASSETS)
    assert root.pages + root.assets == root.total


def test_subtitle_shows_both_when_assets_present() -> None:
    root = _url_tree(PAGES + ASSETS, truncated=False)
    assert _sitemap_subtitle(root) == f"{len(PAGES)} pages • {len(ASSETS)} assets"


def test_subtitle_omits_assets_when_none() -> None:
    root = _url_tree(PAGES, truncated=False)
    assert _sitemap_subtitle(root) == f"{len(PAGES)} pages"


def test_subtitle_singular() -> None:
    root = _url_tree(["https://ex.com/about", "https://ex.com/logo.png"], truncated=False)
    assert _sitemap_subtitle(root) == "1 page • 1 asset"
