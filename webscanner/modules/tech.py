"""Technology detection via Wappalyzer.

Uses ``analyze(..., scan_type="fast")`` — a pure-HTTP path (no headless browser) —
which returns per-technology version, confidence, categories and groups. Rendered as
one :class:`Grid` per *group* (Wappalyzer's high-level bucket, e.g. "Web servers",
"Analytics"), stacked as titled :class:`Sections`. A technology in several groups
appears in each of their tables.

Wappalyzer fetches the page *itself* — this is the one target-facing request the scan
doesn't make through ``net.http`` — and ``analyze()`` takes no header argument, so its
UA is patched in below.
"""

from __future__ import annotations

import asyncio

import requests
from wappalyzer import analyze

from ..core.module import ScanModule
from ..core.context import ScanContext
from ..core.models import Grid, Section, Sections
from ..net.agents import Profile

COLUMNS = ["Name", "Category", "Confidence", "Version"]
#: fixed column widths so every per-group table on the tab lines up identically
WIDTHS = [26, 22, 12, 12]
#: bucket for technologies Wappalyzer reports without any group
UNGROUPED = "Other"


class _UARewrite:
    """Stands in for the ``requests`` module inside ``wappalyzer.core.requester``.

    Wappalyzer hardcodes its own User-Agent (a Chrome on **X11; Linux**) in a local
    dict inside ``get_response``, and exposes no way to override it. Left alone, the
    target sees two visitors from one IP in the same second — our profile, plus a
    Linux desktop Chrome — which is precisely the inconsistency the profile exists to
    avoid, and Linux desktop is the rarer claim of the two.

    Why swap the module's ``requests`` attribute rather than patch ``get_response``:
    ``core/analyzer.py`` does ``from ...requester import get_response``, binding the
    function into its own namespace at import time, so patching ``requester.get_response``
    would silently do nothing. The function *body*, though, looks up its module-global
    ``requests`` on every call — so replacing that attribute catches the call wherever
    the function was imported from.

    Only the User-Agent key is rewritten; the rest of Wappalyzer's header block is
    passed through untouched. That is deliberate — its ``Accept-Encoding: deflate`` is
    load-bearing (see ``net/agents.py`` on advertising encodings you can't decode), and
    passing its dict through rather than restating it means their header block can
    change without us diverging from it.

    Scoped to Wappalyzer's own module attribute, so our ``requests`` calls are
    unaffected. Re-applying per scan never nests wrappers: ``_real`` is the genuine
    module, captured here, not whatever currently sits on ``requester.requests``.
    """

    def __init__(self, user_agent: str) -> None:
        self._user_agent = user_agent
        self._real = requests

    def get(self, url: str, **kwargs: object):
        headers = {**(kwargs.pop("headers", None) or {}), "User-Agent": self._user_agent}
        return self._real.get(url, headers=headers, **kwargs)

    def __getattr__(self, name: str) -> object:
        # requester also reaches for requests.exceptions.RequestException.
        return getattr(requests, name)


def _wear_profile(profile: Profile) -> None:
    """Point Wappalyzer's request at the scan's identity.

    Guarded end-to-end: ``wappalyzer.core.requester`` is a private path that a version
    bump could move or restructure. If it isn't where we expect, the tech module simply
    scans with Wappalyzer's own UA — today's behaviour — rather than failing the tab.
    """
    try:
        from wappalyzer.core import requester

        requester.requests = _UARewrite(profile.user_agent)
    except Exception:  # noqa: BLE001 - a moved internal must not cost us the tab
        pass


class TechModule(ScanModule):
    name = "tech"
    label = "Tech"

    async def run(self, ctx: ScanContext) -> Sections:
        _wear_profile(ctx.profile)

        def detect() -> Sections:
            results = analyze(url=ctx.url, scan_type="fast", timeout=30)
            techs = results.get(ctx.url) or next(iter(results.values()), {})
            # group name -> rows; a tech lands in every group it declares
            groups: dict[str, list[list[str]]] = {}
            for name, info in techs.items():
                row = [
                    name,
                    ", ".join(info.get("categories") or []) or "-",
                    f"{info.get('confidence', 0)}%",
                    info.get("version") or "-",
                ]
                for group in info.get("groups") or [UNGROUPED]:
                    groups.setdefault(group, []).append(row)
            sections = Sections()
            for group in sorted(groups, key=str.lower):  # tables A→Z by group
                rows = sorted(groups[group], key=lambda r: r[0].lower())  # names A→Z
                sections.append(Section(group, Grid(COLUMNS, rows, widths=WIDTHS)))
            return sections

        return await asyncio.to_thread(detect)
