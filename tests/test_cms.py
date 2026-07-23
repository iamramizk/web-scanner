"""CMS detection is a pure function over the Tech result + page HTML.

Wappalyzer's ``CMS`` category is the primary signal; ``Page builders`` is a fallback for
standalone site builders that carry no ``CMS`` tag (Webflow, Wix). The ordering is
load-bearing: ``Page builders`` also holds WordPress *plugins* that are not the CMS
(Elementor, Divi), so a real ``CMS`` hit must always win — even when the page builder
appears first, in an earlier section. The ``<meta name="generator">`` path is covered by
its own split/precedence cases.
"""

from __future__ import annotations

from webscanner.core.models import Grid, Section, Sections
from webscanner.ui.app import _cms_from_tech, _detect_cms, _split_generator


def _tech(*rows: tuple[str, str, str]) -> Sections:
    """A one-section Tech result from (name, categories, version) triples."""
    grid = Grid(
        ["Name", "Category", "Confidence", "Version"],
        [[name, cats, "100%", ver] for name, cats, ver in rows],
    )
    return Sections([Section("Group", grid)])


def test_cms_category_detected():
    assert _cms_from_tech(_tech(("WordPress", "CMS", "6.4"))) == ("WordPress", "6.4")


def test_unknown_version_is_none():
    assert _cms_from_tech(_tech(("WordPress", "CMS", "-"))) == ("WordPress", None)


def test_page_builder_fallback():
    # Webflow (the mary-annethomas.com.au case): tagged Page builders, no CMS tag.
    assert _cms_from_tech(_tech(("Webflow", "Page builders", "-"))) == ("Webflow", None)


def test_cms_beats_page_builder_across_sections():
    # Elementor (Page builders) appears first, in an earlier section, than WordPress.
    secs = Sections(
        [
            Section("Web development", Grid(
                ["Name", "Category", "Confidence", "Version"],
                [["Elementor", "Page builders", "100%", "3.1"]],
            )),
            Section("CMS", Grid(
                ["Name", "Category", "Confidence", "Version"],
                [["WordPress", "CMS", "100%", "6.4"]],
            )),
        ]
    )
    assert _cms_from_tech(secs) == ("WordPress", "6.4")


def test_no_cms_no_page_builder():
    assert _cms_from_tech(_tech(("Cloudflare", "CDN", "-"))) is None


def test_detect_cms_page_builder_no_generator():
    # End-to-end: page builder in tech, no <meta generator> — the real-site scenario.
    assert _detect_cms(_tech(("Webflow", "Page builders", "-")), None) == ("Webflow", None)
