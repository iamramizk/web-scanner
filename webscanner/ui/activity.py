"""Activity-log lines — one short, informative sentence per scan event.

Pure ``ScanEvent -> str``: no Textual imports, so the whole line catalogue can be
exercised without an app, an event loop or the network. That matters because a
healthy live scan never reaches the branches most likely to be wrong (FAILED, EMPTY,
and the ``{"note": ...}`` "nothing to report" shape).

Grammar is fixed at ``<Label>: Complete. <facts>`` so the coloured verb always lands
in the same column. Only the verb and the odd warning word carry markup; the caller
(``ActivityLog.add``) supplies the timestamp and the body colour.

Lines are composed **at full length** — nothing here truncates to a character budget.
``ActivityLog`` renders each line ``no_wrap`` with ``overflow="ellipsis"``, so a line
is cut at the panel edge and a wider terminal simply shows more of it. Keep the facts
front-loaded (the tail is what gets dropped), but don't pre-crop a value to make it
fit some assumed width.

The facts are the point — "DNS: Complete." tells you nothing the tab colour didn't.
Each summarizer digs the headline number out of its module's own return shape, which
is different for every module and booby-trapped in several (see the notes below).
"""

from __future__ import annotations

import re
from typing import Any, Callable

from urllib.parse import urlparse

from rich.markup import escape

from ..colors import BLUE, GREEN, RED
from ..net.psl import registrable_domain
from ..core.context import ScanContext
from ..core.models import ModuleResult, ModuleStatus, ScanEvent
from ..core.scanner import PREFETCH, SHARED_IP
from ..net.agents import Profile
from ..modules import all_modules
from ..modules.dns import RECORD_TYPES, assess_spoofing
from ..modules.links import EMPTY_EXTERNAL, EMPTY_INTERNAL
from ..modules.sitemap import MAX_URLS
from .tables import _plain

#: module name -> tab label ("dns" -> "DNS"), so a line's prefix matches its tab.
_LABELS: dict[str, str] = {m.name: m.label for m in all_modules()}

_DONE = f"[{GREEN}]Complete[/]"
_ERROR = f"[{RED}]Error[/]"

#: repr(exc) -> ("TimeoutError", "'timed out'")
_ERROR_REPR = re.compile(r"^(\w+)\((.*)\)$", re.S)


# ---- helpers --------------------------------------------------------------


def _esc(value: Any) -> str:
    """Collapse whitespace and escape rich markup.

    Every externally-sourced value in a log line goes through here. Escaping is not
    cosmetic: an unescaped ``[/]`` (from a registrar name, a Server header, a
    repr(exc)) raises MarkupError inside ``RichLog.write``, which propagates out of
    ``on_scan_progress`` and takes the handler down mid-scan.

    Deliberately does **not** truncate: values are written in full and the widget
    ellipsises at the panel edge, so a wide terminal shows the whole thing. A hard
    cap here would crop "Web Address Registration Pty Ltd" on a 200-column display.
    """
    return escape(" ".join(str(value).split()))


def _plural(n: int, singular: str, plural: str | None = None) -> str:
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


def _sentence(text: str) -> str:
    """Upper-case the first letter and full-stop it, leaving the rest alone —
    ``str.capitalize`` would flatten the modules' own wording (WHOIS -> Whois)."""
    text = " ".join(str(text).split()).rstrip(".")
    return f"{text[:1].upper()}{text[1:]}." if text else ""


def _note(data: Any) -> str | None:
    """The module's own wording when it returned a lone ``{"note": ...}``.

    whois, security's port table and seo all use this shape to say "nothing to
    report". Echoing it verbatim keeps the wording with the module that owns it.
    """
    if isinstance(data, dict) and set(data) == {"note"}:
        return str(data["note"])
    return None


def _sections(result: ModuleResult) -> dict[str, Any]:
    """A Sections result as {title: data}."""
    return {section.title: section.data for section in result.data or []}


def _short_error(error: str | None) -> str:
    """``repr(exc)`` boiled down to ``Type: message``.

    Unwrapping the repr is formatting, not trimming — the message is kept whole and
    the panel ellipsises whatever doesn't fit.
    """
    text = (error or "unknown error").strip()
    if match := _ERROR_REPR.match(text):
        name, args = match.group(1), match.group(2).strip().strip("'\"")
        text = f"{name}: {args}" if args else name
    return _esc(text)


def _date_only(value: Any) -> str:
    """The date half of a whois timestamp — they arrive both as bare dates and as
    ISO datetimes, so slicing [:10] is not safe."""
    text = str(value or "").replace("T", " ").strip()
    return text.split()[0] if text else ""


# ---- per-module summaries -------------------------------------------------


def _dns(result: ModuleResult) -> str:
    # Keys are only present when non-empty, and DMARC/DKIM are folded in alongside
    # the record types — count only the latter, then name the email auth found.
    data = result.data or {}
    if not data:
        return f"{_DONE}. No records found."
    types = [key for key in data if key in RECORD_TYPES]
    records = sum(len(data[key]) for key in types)
    line = f"{_DONE}. {_plural(records, 'record')} across {_plural(len(types), 'type')}"
    auth = [key for key in ("DMARC", "DKIM") if key in data]
    return f"{line} · {', '.join(auth)}." if auth else f"{line}."


def _registrar_root(url: str | None) -> str:
    """Registrar's registrable domain from its WHOIS ``registrar_url``.

    ``http://www.hostinger.com`` → ``hostinger.com``. Tolerates a scheme-less
    value (``www.hostinger.com``) — ``urlparse`` puts that in ``path``, not
    ``netloc``, so fall back to the whole string as the host. Returns "" when
    nothing usable (no URL, or no registrable domain resolves)."""
    if not url:
        return ""
    parsed = urlparse(url.strip())
    host = parsed.netloc or parsed.path
    return registrable_domain(host.split("/")[0].split("@")[-1])


def _whois(result: ModuleResult) -> str:
    data = result.data or {}
    if not data:
        return f"{_DONE}. No WHOIS data returned."
    if (note := _note(data)) is not None:
        return f"{_DONE}. {_sentence(note)}"
    bits = []
    # Prefer the registrar's root domain (registrable eTLD+1 of its URL) over its
    # legal name — "hostinger.com" reads truer than "HOSTINGER operations, UAB".
    # Fall back to the name when there's no URL (sparse ccTLD output).
    registrar = _registrar_root(data.get("registrar_url")) or data.get("registrar")
    if registrar:
        # Unlabelled: the Whois prefix and the "expires" half make it obvious enough,
        # and the 10 chars "Registrar " costs are better spent on the name itself.
        bits.append(_esc(registrar))
    if expiry := _date_only(data.get("expiry_date")):
        bits.append(f"expires {_esc(expiry)}")
    # Sparse ccTLD output can carry neither field; say what did come back.
    return f"{_DONE}. {' · '.join(bits) or _plural(len(data), 'field')}."


def _subdomains(result: ModuleResult) -> str:
    found = result.data or []
    if not found:
        return f"{_DONE}. None found."
    return f"{_DONE}. Found {_plural(len(found), 'subdomain')}."


def _ssl(result: ModuleResult) -> str:
    data = result.data or {}
    if not data:
        return "No certificate found (TLS handshake failed)."
    issuer = _esc(data.get("issuer_org") or data.get("issuer_cn") or "unknown issuer")
    # san_count, not len(san) — the san list is capped at 20.
    sans = _plural(data.get("san_count") or 0, "SAN")
    if data.get("expired"):
        return f"Certificate [{RED}]expired[/] — {issuer} · {sans}."
    bits = [issuer]
    # days_until_expiry is absent when the notAfter date failed to parse.
    if (days := data.get("days_until_expiry")) is not None:
        bits.append(f"{_plural(days, 'day')} left")
    bits.append(sans)
    return f"{_DONE}. {' · '.join(bits)}."


def _security(result: ModuleResult) -> str:
    # All three tables are fixed-length (every port/header/blocklist gets a row), so
    # the counts have to come from the values, not len().
    sections = _sections(result)
    ports = sections.get("Open Ports", {})
    headers = sections.get("HTTP Security", {})
    blocklists = sections.get("Blocklists", {})

    if (note := _note(ports)) is not None:
        port_bit = _sentence(note).rstrip(".")  # the module's wording, leading the list
    else:
        port_bit = _plural(sum(1 for v in ports.values() if _plain(v) == "open"), "open port")
    present = sum(1 for v in headers.values() if _plain(v) == "Yes")
    # Exact match: "Not Blocked" contains "Blocked".
    blocked = sum(1 for v in blocklists.values() if _plain(v) == "Blocked")
    return f"{_DONE}. {port_bit}, {present}/{len(headers)} headers, {blocked} blocked."


def _headers(result: ModuleResult) -> str:
    data = result.data or {}
    if not data:
        return f"{_DONE}. No headers (fetch failed)."
    # dict(ctx.headers) drops requests' CaseInsensitiveDict, so keys keep whatever
    # casing the server sent.
    server = next((v for k, v in data.items() if k.lower() == "server"), None)
    line = f"{_DONE}. {_plural(len(data), 'header')}"
    # Whole value, incl. "Apache/2.4.41 (Ubuntu) mod_wsgi/4.6.8" — it's the last
    # thing on the line, so a narrow panel ellipsises only its tail.
    return f"{line} · Server {_esc(server)}." if server else f"{line}."


def _tech(result: ModuleResult) -> str:
    # A tech declaring three groups appears in three Grids — dedupe on name.
    sections = result.data or []
    names = {name for section in sections for name in section.data.names}
    if not names:
        return f"{_DONE}. No technologies detected."
    return (
        f"{_DONE}. {_plural(len(names), 'technology', 'technologies')} "
        f"across {_plural(len(sections), 'group')}."
    )


def _seo(result: ModuleResult) -> str:
    sections = _sections(result)
    content = sections.get("Content", {})
    if (note := _note(content)) is not None:
        return f"{_DONE}. {_sentence(note)}"
    bits = []
    if content.get("Title", "-") != "-":
        bits.append("title")
    if content.get("Description", "-") != "-":
        bits.append("desc")
    bits.append(_plural(len(content.get("H1") or []), "H1", "H1s"))
    if _plain(sections.get("Schema", {}).get("Has Schema", "")) == "Yes":
        bits.append("schema")
    if _plain(sections.get("Robots", {}).get("Found", "")) == "Yes":
        bits.append("robots")
    return f"{_DONE}. {_sentence(', '.join(bits))}"


def _sitemap(result: ModuleResult) -> str:
    root = result.data
    if root is None:
        return f"{_DONE}. No sitemap found."
    total = root.total or 0
    suffix = " (truncated)" if total >= MAX_URLS else ""
    assets = root.assets or 0
    pages = root.pages if root.pages is not None else total
    tally = _plural(pages, "page")
    if assets:
        tally += f", {_plural(assets, 'asset')}"
    return f"{_DONE}. {tally} found{suffix}."


def _links(result: ModuleResult) -> str:
    # An empty section holds one placeholder row, so len() reads 1 for "none".
    sections = _sections(result)
    internal = sections.get("Internal", [])
    external = sections.get("External", [])
    n_internal = 0 if internal == [EMPTY_INTERNAL] else len(internal)
    n_external = 0 if external == [EMPTY_EXTERNAL] else len(external)
    if not n_internal and not n_external:
        return f"{_DONE}. No links found."
    return f"{_DONE}. {n_internal} internal, {n_external} external links."


_SUMMARIZERS: dict[str, Callable[[ModuleResult], str]] = {
    "dns": _dns,
    "whois": _whois,
    "subdomains": _subdomains,
    "ssl": _ssl,
    "security": _security,
    "headers": _headers,
    "tech": _tech,
    "seo": _seo,
    "sitemap": _sitemap,
    "links": _links,
}


# ---- public API -----------------------------------------------------------


def started(target: str, count: int) -> str:
    """The opening line."""
    return f"Scan: Started {_esc(target)} · {_plural(count, 'module')}."


def agent(profile: Profile) -> str:
    """The browser identity this scan wore.

    Worth a line because the profile is chosen at random per scan: when a scan returns
    something surprising (a block page, a tech list that shifted since last run), the
    first question is what the site thought we were, and the answer differs run to run.
    The label — "Chrome 151 · Windows" — is enough to reproduce it; the full UA string
    is ~110 chars and would be ellipsised to no benefit.
    """
    return f"Agent: {_esc(profile.label)}."


def email_spoofing(result: ModuleResult) -> str:
    """The DNS module's derived email-spoofing verdict, as its own log line.

    Not a module: like the CMS line, ``app.py`` emits this straight after the DNS event
    so it lands directly under DNS's line. Recomputed from the DNS result's records via
    the same ``assess_spoofing`` the tab row uses (one source of truth) — the coloured
    verb (green Protected / red otherwise) then lands in the same column as every other
    line's verb. See the DNS module notes for why DMARC, not SPF, decides this.
    """
    data = result.data or {}
    verdict, reason = assess_spoofing(
        data.get("TXT", []), data.get("DMARC", []), "DKIM" in data
    )
    colour = GREEN if verdict.startswith("Protected") else RED
    return f"Email Spoofing: [{colour}]{verdict}[/]. {_esc(reason)}."


def cms(detected: tuple[str, str | None] | None) -> str:
    """The Server panel's CMS row, as a log line — wording kept identical to it.

    Not a module: the UI derives this from the Tech result plus the page's
    ``<meta name="generator">``, so ``app.py`` calls this straight after the Tech
    event and the line lands directly under Tech's.
    """
    if detected is None:
        return "CMS: Not detected."
    name, version = detected
    return f"CMS: {_esc(f'{name} {version}' if version else name)}."


def waf(result: ModuleResult) -> str | None:
    """The Security module's WAF verdict (passive + active probe), as its own log line.

    Like ``email_spoofing``/``cms``, ``app.py`` emits this straight after the Security
    event so it lands under Security's line. It reads the "WAF Detection" section back out
    of the result (one source of truth with the tab) via the same ``_sections``/``_plain``
    the ``_security`` summary uses — the "Active Probe" row plain-texts to ``Blocked · …``
    when the provocation was rejected. Returns ``None`` when nothing was named *and* the
    probe wasn't blocked: a clean result isn't proof of no-WAF, so we stay silent rather
    than announce an absence — the line only ever reports a positive.
    """
    section = _sections(result).get("WAF Detection", {})
    vendors = [name for name, cell in section.items()
               if name != "Active Probe" and _plain(cell) == "Detected"]
    blocked = _plain(section.get("Active Probe", "")).startswith("Blocked")
    if not vendors and not blocked:
        return None
    who = ", ".join(vendors) if vendors else "Unidentified"
    line = f"WAF: [{GREEN}]{_esc(who)}[/]"
    return f"{line} · actively blocking." if blocked else f"{line}."


def update_available(latest: str) -> str:
    """A newer release exists on PyPI. Emitted once, after the scan's own closing
    line, only when a newer version was actually found — see net/version_check.py."""
    return f"Update: [{BLUE}]v{_esc(latest)} available[/] — run `pipx upgrade web-scanner`."


def overall(completed: int, failed: int, total: int, seconds: float) -> str:
    """The closing line. ``seconds`` is wall-clock for the whole scan — modules run
    concurrently, so summing their durations would overstate it several-fold."""
    ok = completed - failed
    took = f"in {round(seconds)}s"
    if failed:
        return (
            f"Overall Scan Status: {ok}/{total} modules [{GREEN}]completed[/] {took}, "
            f"[{RED}]{_plural(failed, 'error')}[/]."
        )
    return f"Overall Scan Status: {total}/{total} modules [{GREEN}]completed[/] {took}."


def _prefetch(ctx: ScanContext | None) -> str:
    if ctx is None:
        return f"Prefetch: {_ERROR}. No scan context."
    if ctx.fetch_error:
        return f"Prefetch: [{RED}]error[/] — {_esc(ctx.fetch_error)}."
    bits = [_esc(ctx.ip)] if ctx.ip else []
    if ctx.status_code is not None:
        bits.append(f"HTTP {ctx.status_code}")
    if ctx.response_time_ms is not None:
        bits.append(f"{round(ctx.response_time_ms)}ms")
    return f"Prefetch: {' · '.join(bits) or 'no response'}."


def summarize(event: ScanEvent, ctx: ScanContext | None) -> str | None:
    """One log line for a ScanEvent, or ``None`` if it shouldn't be logged.

    Module RUNNING events are dropped on purpose: all ten fire in a single
    ``asyncio.gather`` burst, so logging them would push ten lines through a
    four-line panel in one tick and none of them would be read.
    """
    if event.name == PREFETCH:
        # Prefetch events never carry a result — the numbers live on the context.
        return _prefetch(ctx) if event.status is ModuleStatus.DONE else None
    if event.name == SHARED_IP:
        # Panel-only signal (see app.py); it isn't a module and gets no log line.
        return None
    if event.status is ModuleStatus.RUNNING:
        return None

    label = _LABELS.get(event.name, event.name)
    result = event.result
    if result is None or event.status is ModuleStatus.FAILED:
        error = result.error if result is not None else None
        return f"{label}: {_ERROR}. {_short_error(error)}"
    try:
        body = _SUMMARIZERS[event.name](result)
    except Exception:  # noqa: BLE001
        # Modules are failure-isolated; the handler that logs them isn't. A summary
        # that trips over an unexpected shape must not take the scan down with it.
        body = f"{_DONE}."
    return f"{label}: {body}"
