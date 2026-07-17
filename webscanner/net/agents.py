"""Browser identities for target-facing requests.

One :class:`Profile` is one coherent desktop-Chrome identity: a User-Agent plus the
headers that Chrome genuinely sends beside it. They live together because a UA on its
own is *worse* than no disguise — ``requests`` defaults to ``Accept: */*`` and no
``Sec-Fetch-*``/``Sec-CH-UA``, and a "Chrome" that sends those is trivially spotted by
the mid-tier WAFs that then serve a block page instead of the site. Getting real
content back is the point; looking natural is how.

Scope: **target-facing requests only** (homepage, robots.txt, sitemaps). ip-api and
Cloudflare DoH keep the honest ``http.USER_AGENT`` — they don't block, don't care, and
a browser UA beside ``accept: application/dns-json`` would be incoherent anyway.

Why the pool is all recent desktop Chrome, and not a browser zoo: the scan picks one
profile and reuses it, so rotation only ever varies things *between* scans. Sites do
serve different markup to Safari vs Firefox, so a mixed pool would make two scans of
one domain disagree — a reliability cost paid for a stealth benefit that isn't real,
since the IP and TLS fingerprint are identical across scans regardless. Chrome N vs
N-2 on Windows vs macOS is variation *below the threshold where sites branch*, so
rotation costs nothing here. Chrome-on-Windows is also the most common UA on earth:
the most boring thing you can claim. Pin ``CHROME_VERSIONS``/``PLATFORMS`` to one
entry each if you ever want scans fully deterministic.

Known ceiling: this controls headers, not the TLS (JA3/JA4) or HTTP/2 fingerprint.
``requests`` speaks HTTP/1.1 with an OpenSSL handshake no Chrome would produce, so
against enterprise bot management (Cloudflare, Akamai) the disguise does not hold —
those read the handshake, not the string. This buys the naive-UA-filter case, which is
nearly all of them. Header *order* is likewise not ours to set (requests merges its own
session defaults in first). Don't chase either through this file; the lever there is a
TLS-impersonating client such as curl_cffi, which is a compiled dependency and a much
bigger trade.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

#: Chrome stable majors, newest first — current + two back, which is roughly how the
#: real Chrome population spreads across a release window.
#:
#: **Checked against the Chrome release API on 2026-07-17 (stable was 151).** These
#: rot: a UA claiming a Chrome that shipped 18 months ago is a louder signal than an
#: honest scanner UA, which defeats the whole file. Re-check when you next touch this:
#: https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions
CHROME_VERSIONS: tuple[str, ...] = ("151", "150", "149")

#: (UA platform token, sec-ch-ua-platform value). Both are frozen strings in modern
#: Chrome: its reduced UA reports every macOS as "10_15_7" and every Windows as
#: "Windows NT 10.0" no matter the real OS, so these are correct as literals rather
#: than lazily hardcoded.
PLATFORMS: tuple[tuple[str, str], ...] = (
    ("Windows NT 10.0; Win64; x64", "Windows"),
    ("Macintosh; Intel Mac OS X 10_15_7", "macOS"),
)

#: What Chrome sends for a top-level navigation. A homepage/robots.txt/sitemap.xml GET
#: is exactly what you'd get by typing the URL in the bar, so one navigation header set
#: covers all three honestly.
_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
    "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
)

#: Real Chrome 151 sends "gzip, deflate, br, zstd". We deliberately advertise less.
#:
#: This is the one place we knowingly diverge from the browser, and it is not an
#: oversight: brotli needs the `brotli` package and zstd needs `zstandard` (or a
#: Python 3.14 stdlib that `requires-python = ">=3.11"` does not promise). Advertise an
#: encoding we can't decode and the body comes back as bytes-shaped garbage — which
#: silently poisons ctx.html and, with it, seo, links and tech. A hypothetical
#: fingerprinter noticing the missing `br` beats a guaranteed corrupted scan.
#:
#: If you ever want the profile fully coherent, add `brotli` as a dependency and put
#: `br` back — don't add `br` without it.
_ACCEPT_ENCODING = "gzip, deflate"


@dataclass(frozen=True)
class Profile:
    """One browser identity, chosen once per scan and reused for every request to the
    target — a real browser keeps one identity per session. Rotating per *request*
    would be the louder tell: one IP fetching `/` as Chrome and 60 sitemaps as Safari
    within a few seconds is not a thing a browser does."""

    chrome: str
    """Chrome major version, e.g. "151"."""

    ua_platform: str
    """The platform token inside the UA string."""

    platform: str
    """The `sec-ch-ua-platform` value, e.g. "Windows"."""

    @property
    def user_agent(self) -> str:
        # Chrome freezes the minor version at 0.0.0 in its reduced UA — the real build
        # number (151.0.7922.34) never appears, so writing one would be the error.
        return (
            f"Mozilla/5.0 ({self.ua_platform}) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{self.chrome}.0.0.0 Safari/537.36"
        )

    @property
    def label(self) -> str:
        """Short human form for the activity log — "Chrome 151 · Windows"."""
        return f"Chrome {self.chrome} · {self.platform}"

    def headers(self, url: str) -> dict[str, str]:
        """The full header set for a GET of ``url``.

        Client hints are dropped for plaintext ``http://``: they're a secure-context
        feature, so real Chrome doesn't send them there and doing so would contradict
        the very UA they're meant to corroborate. This matters because ``http.fetch``
        retries over http:// when TLS fails.
        """
        headers = {
            "User-Agent": self.user_agent,
            "Accept": _ACCEPT,
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": _ACCEPT_ENCODING,
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Connection": "keep-alive",
        }
        if url.lower().startswith("https://"):
            headers |= {
                # The "Not?A_Brand" entry is GREASE: deliberately arbitrary padding
                # Chrome varies to stop anyone parsing this list rigidly. Any plausible
                # value is as correct as another — it is designed to be ignored.
                "sec-ch-ua": (
                    f'"Chromium";v="{self.chrome}", '
                    f'"Google Chrome";v="{self.chrome}", '
                    f'"Not?A_Brand";v="24"'
                ),
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": f'"{self.platform}"',
            }
        return headers


def random_profile() -> Profile:
    """Pick one identity for a scan. See the module docstring for why the pool is
    narrow — the randomness is confined to axes sites don't branch on."""
    ua_platform, platform = random.choice(PLATFORMS)
    return Profile(
        chrome=random.choice(CHROME_VERSIONS),
        ua_platform=ua_platform,
        platform=platform,
    )
