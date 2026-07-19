"""WAF detection has two pure cores: ``identify_waf`` over the baseline response headers
(passive) and ``_assess_probe`` over the active-probe response (blocked? + body vendors).

Passive: a vendor matches on any of its markers (a header name, a Server-value substring,
a Set-Cookie substring, or a header value/substring pair), case-insensitively — these
cover each marker kind, multi-vendor stacks, the clean case, and the casing guard
(requests keeps the server's casing, so ``CF-RAY`` must match ``cf-ray``).

Active: ``_assess_probe`` flags a block only on a WAF-style status that *differs from the
baseline* (a site that already 403s isn't blocking our probe), and reads vendor names out
of the block-page body.
"""

from __future__ import annotations

import pytest

from webscanner.modules.security import _assess_probe, identify_waf


@pytest.mark.parametrize(
    "headers, expected",
    [
        # Cloudflare — three independent markers.
        ({"CF-RAY": "abc123-LHR"}, ["Cloudflare"]),
        ({"Server": "cloudflare"}, ["Cloudflare"]),
        ({"Set-Cookie": "__cf_bm=xyz; path=/; HttpOnly"}, ["Cloudflare"]),
        # Sucuri.
        ({"X-Sucuri-ID": "12006"}, ["Sucuri"]),
        # Imperva Incapsula — header, cookie, and x-cdn value.
        ({"X-Iinfo": "9-12345-0 NNNN"}, ["Imperva Incapsula"]),
        ({"Set-Cookie": "incap_ses_123=abc; visid_incap_456=def"}, ["Imperva Incapsula"]),
        ({"X-CDN": "Incapsula"}, ["Imperva Incapsula"]),
        # Akamai server token.
        ({"Server": "AkamaiGHost"}, ["Akamai"]),
        # Amazon CloudFront.
        ({"X-Amz-Cf-Id": "abc=="}, ["Amazon CloudFront"]),
        # Casing: header names are matched lowercased.
        ({"cf-ray": "abc"}, ["Cloudflare"]),
        # Nothing to match.
        ({}, []),
        ({"Server": "nginx", "Content-Type": "text/html"}, []),
    ],
)
def test_identify_waf(headers, expected):
    assert identify_waf(headers) == expected


def test_multiple_vendors_stack():
    # A Cloudflare-fronted site behind an origin CDN can trip two signatures; both surface,
    # in signature (declaration) order.
    headers = {"CF-RAY": "abc", "Server": "cloudflare", "X-Sucuri-ID": "1"}
    assert identify_waf(headers) == ["Cloudflare", "Sucuri"]


def test_server_substring_is_case_insensitive():
    assert identify_waf({"Server": "CloudFront"}) == ["Amazon CloudFront"]
    assert identify_waf({"server": "Fastly"}) == ["Fastly"]


# ---- _assess_probe --------------------------------------------------------


@pytest.mark.parametrize(
    "status, baseline, body, expected_blocked",
    [
        (403, 200, "", True),           # attack rejected, baseline was fine
        (406, 200, "", True),           # Not Acceptable (mod_security)
        (999, 200, "", True),           # Imperva's signature code
        (200, 200, "", False),          # probe went through
        (403, 403, "", False),          # site 403s everything — not blocking us specifically
        (301, 200, "", False),          # a redirect isn't a block
    ],
)
def test_assess_probe_blocked(status, baseline, body, expected_blocked):
    blocked, _ = _assess_probe(status, baseline, body)
    assert blocked is expected_blocked


def test_assess_probe_reads_body_vendors():
    body = "<title>Attention Required! | Cloudflare</title> ... Cloudflare Ray ID: 8a1b"
    blocked, vendors = _assess_probe(403, 200, body)
    assert blocked is True
    assert vendors == ["Cloudflare"]


def test_assess_probe_names_header_less_waf():
    # ModSecurity is only ever visible on the block page — no passive header.
    blocked, vendors = _assess_probe(406, 200, "<h1>Not Acceptable!</h1> mod_security ...")
    assert blocked is True
    assert vendors == ["ModSecurity"]


def test_assess_probe_clean_body_no_vendors():
    blocked, vendors = _assess_probe(200, 200, "<html>normal page</html>")
    assert blocked is False
    assert vendors == []
