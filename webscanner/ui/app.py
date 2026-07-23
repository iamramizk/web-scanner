"""WebScanner v2 Textual application.

Layout mirrors the dnsglobe reference: a bordered top bar (domain input + tab
row), an inline animated progress line, then a 2-column grid — main data table
(left, full height), fixed world map (top-right) and fixed status panel
(bottom-right) — over a keybind footer.

The scan runs as an async worker; the orchestrator's ScanEvents arrive as
``ScanProgress`` messages that colour tabs, advance progress and fill panels
live as each module completes.
"""

from __future__ import annotations

import asyncio
import re
import time

from bs4 import BeautifulSoup
from rich.padding import Padding
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.widgets import Input, LoadingIndicator, Static

from .. import __version__
from ..colors import ORANGE
from ..core import AsyncScanner, ModuleStatus, ScanContext, ScanEvent
from ..core.scanner import PREFETCH, SHARED_IP
from ..modules import all_modules
from ..net.version_check import update_status
from . import activity
from .export import export_csvs
from .tables import UNSET, render_result, render_status
from .widgets import ActivityLog, MapPanel, SitemapTree, StatusPanel, TabBar, Tab

#: width (cells) of the footer progress bar and its dim (incomplete) colour
_BAR_WIDTH = 22
_BAR_DIM = "grey30"

#: The status-bar version dot is shown only when a newer PyPI release is available
#: (`_version_status == "outdated"`; see net/version_check.py) — an orange `•`. The
#: initial/unknown and up-to-date states show no dot, keeping the footer quiet until
#: there's something to say.

#: below this terminal width the layout collapses to a single column (the fixed map
#: + Server panels become tabs, activity becomes a tab) — see _apply_narrow.
_NARROW_MAX = 90

#: pseudo-tabs shown only in the narrow layout, before the real module tabs: the
#: Activity log and the Server panel, which are fixed side/bottom panels on wide
#: terminals. (name, label) — names must not collide with any module name.
_PSEUDO_TABS: tuple[tuple[str, str], ...] = (("activity", "Activity"), ("server", "Server"))
_PSEUDO_NAMES = frozenset(name for name, _ in _PSEUDO_TABS)
_PSEUDO_LABELS = {name: label for name, label in _PSEUDO_TABS}


#: Wappalyzer categories that name the CMS, in priority order. ``CMS`` is the reliable
#: signal (the broader "Content" *group* also covers non-CMS tools). ``Page builders``
#: is a fallback for standalone site builders that carry no ``CMS`` tag (Webflow, Wix,
#: Squarespace, Duda, Framer). It is checked *only after* ``CMS`` comes up empty, because
#: the same category also holds WordPress *plugins* that are not the CMS (Elementor, Divi,
#: WPBakery) — on those sites Wappalyzer tags WordPress ``CMS`` and the first pass wins.
_CMS_CATEGORIES = ("CMS", "Page builders")


def _cms_from_tech(data: object) -> tuple[str, str | None] | None:
    """The CMS (name, version) from the Tech result, or ``None`` if none detected.

    The Tech result is a ``Sections`` of per-group ``Grid``s whose rows are
    ``[name, categories, confidence, version]`` (see ``modules/tech.py``). A CMS is any
    tech Wappalyzer tags with a category in ``_CMS_CATEGORIES`` — tried in order, so a
    real ``CMS`` hit always beats a ``Page builders`` one across the whole result.
    ``categories`` is a ", "-joined string; version is ``"-"`` when unknown → ``None``.
    """
    for target in _CMS_CATEGORIES:
        for section in data or []:
            for name, categories, _confidence, version in section.data:
                if target in [c.strip() for c in str(categories).split(",")]:
                    return name, (version if version and version != "-" else None)
    return None


#: matches a ``<meta name="generator">`` name attribute — real pages ship
#: ``name="Generator"`` as often as lowercase, so the value is matched case-insensitively
_GENERATOR_ATTR = re.compile(r"^\s*generator\s*$", re.I)


def _split_generator(content: str) -> tuple[str, str | None]:
    """Split a ``<meta name="generator">`` content value into (name, version|None).

    The version is the first token that contains a digit, plus everything after it
    ("Sitefinity 14.4.8152.0 DX" → ``("Sitefinity", "14.4.8152.0 DX")``); a value with
    no such token is all name ("Webflow" → ``("Webflow", None)``). A leading digit-ish
    token is part of the name, not a version ("1C-Bitrix", "TYPO3 CMS"). Trailing
    parentheticals are dropped ("Drupal 10 (https://www.drupal.org)" → "Drupal", "10").
    """
    content = re.sub(r"\s*\([^)]*\)", "", content).strip()
    tokens = content.split()
    for i, token in enumerate(tokens):
        if i and any(char.isdigit() for char in token):
            return " ".join(tokens[:i]), " ".join(tokens[i:])
    return content, None


def _generators(html: str | None) -> list[tuple[str, str | None]]:
    """Every ``<meta name="generator">`` in the page, as (name, version|None) pairs."""
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    found = []
    for tag in soup.find_all("meta", attrs={"name": _GENERATOR_ATTR}):
        content = (tag.get("content") or "").strip()
        if content:
            found.append(_split_generator(content))
    return found


def _same_cms(left: str, right: str) -> bool:
    """Do two CMS names refer to the same product? Compared on letters/digits only,
    either containing the other, so "Wix" matches "Wix.com Website Builder"."""
    left, right = (re.sub(r"[^a-z0-9]", "", name.lower()) for name in (left, right))
    return bool(left and right) and (left in right or right in left)


def _detect_cms(tech_data: object, html: str | None) -> tuple[str, str | None] | None:
    """The CMS (name, version) for the Server panel, or ``None`` if nothing detected.

    ``_cms_from_tech`` is the primary signal (Wappalyzer's ``CMS`` category, then a
    ``Page builders`` fallback — see there). The ``<meta name="generator">`` tag covers
    the two cases it misses: a CMS Wappalyzer has no fingerprint for at all (e.g.
    Sitefinity) → the generator is used outright; and a CMS it detects but can't version
    → the generator supplies the version, but only when it names the *same* product, so
    an "Elementor 3.x" generator can't hijack a "WordPress" hit.
    """
    tech = _cms_from_tech(tech_data)
    generators = _generators(html)
    if tech is None:
        # Nothing in the tech stack — fall back to the generator, preferring a
        # versioned one when the page carries several.
        versioned = next((gen for gen in generators if gen[1]), None)
        return versioned or (generators[0] if generators else None)
    name, version = tech
    if version is None:
        for gen_name, gen_version in generators:
            if gen_version and _same_cms(name, gen_name):
                return name, gen_version
    return tech


def _sitemap_subtitle(root: object) -> str:
    """The Sitemap tab's ``#main`` subtitle: ``"12 pages • 3 assets"`` (pages vs.
    assets split purely by URL extension — see ``sitemap._is_asset``). Assets are
    only shown when present; falls back to the raw total if the split is missing."""
    pages = getattr(root, "pages", None)
    assets = getattr(root, "assets", None) or 0
    if pages is None:  # older/other tree without the split — show the plain count
        return f"{getattr(root, 'total', 0) or 0} Total"
    parts = [f"{pages} {'page' if pages == 1 else 'pages'}"]
    if assets:
        parts.append(f"{assets} {'asset' if assets == 1 else 'assets'}")
    return " • ".join(parts)


class ScanProgress(Message):
    """A ScanEvent surfaced onto the Textual message pump."""

    def __init__(self, event: ScanEvent) -> None:
        self.event = event
        super().__init__()


class ScanFinished(Message):
    pass


class VersionChecked(Message):
    """Result of the background PyPI update check (see net/version_check.py).

    ``status`` is one of ``"unknown"`` / ``"latest"`` / ``"outdated"`` — it drives
    the colour of the status-bar version dot. ``latest`` is the newer version string
    when ``status == "outdated"`` (else None) — used for the Activity Log line.
    """

    def __init__(self, status: str, latest: str | None) -> None:
        self.status = status
        self.latest = latest
        super().__init__()


class WebScannerApp(App):
    CSS_PATH = "app.tcss"
    TITLE = "WebScanner"
    # We manage focus by hand (input focused only when editing the domain) so
    # single-key nav reaches the app; disable Textual's auto-refocus.
    AUTO_FOCUS = None
    # Custom keybar replaces the Footer, so drop the built-in command palette.
    ENABLE_COMMAND_PALETTE = False

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=False),
        Binding("q", "quit", "Quit", show=False),
        Binding("left", "prev_tab", "Prev tab", show=False),
        Binding("right", "next_tab", "Next tab", show=False),
        # Tab/Shift+Tab navigate tabs and are priority so Textual's focus
        # traversal never runs (keeps the keybar stable while editing).
        Binding("tab", "next_tab", show=False, priority=True),
        Binding("shift+tab", "prev_tab", show=False, priority=True),
        Binding("r", "rescan", "Rescan", show=False),
        Binding("s", "save", "Save", show=False),
        Binding("escape", "toggle_edit", "Edit domain", show=False),
        Binding("plus,equals_sign", "zoom_in", "Zoom map in", show=False),
        Binding("minus,underscore", "zoom_out", "Zoom map out", show=False),
        Binding("pageup", "scroll_main_up", "Scroll up", show=False),
        Binding("pagedown", "scroll_main_down", "Scroll down", show=False),
        # Number keys jump to the Nth visible tab: 1 = first tab (DNS when wide,
        # Activity when narrow) … 9 = ninth, 0 = tenth. Not priority, so a digit typed
        # into the focused domain input is entered as text rather than switching tabs.
        *[Binding(str(d), f"select_tab({d})", show=False) for d in range(10)],
    ]

    def __init__(self, target: str | None = None) -> None:
        # ansi_color=True keeps ANSI keywords (e.g. `ansi_default`) as real
        # terminal escapes instead of converting them to concrete RGB. It does
        # NOT downgrade our truecolor hex — only ANSI-named values are affected.
        # This is what lets `Screen { background: ansi_default; }` emit the
        # terminal's default background so a translucent terminal shows through.
        super().__init__(ansi_color=True)
        self._target = target
        self.ctx: ScanContext | None = None
        self.modules = all_modules()
        self.results: dict = {}
        # Detected CMS for the Server panel (and its CSV export): UNSET until Tech
        # completes, then None ("Not detected") or (name, version|None). Mirrors the
        # value handed to StatusPanel so the export matches what's on screen.
        self._cms: object = UNSET
        self.selected = self.modules[0].name
        # Narrow (phone-width) layout: right column + activity strip become tabs.
        # Applied for real in on_mount/on_resize once the terminal size is known.
        self._narrow = False
        self.completed = 0
        self.failed = 0
        self._scanning = False
        # monotonic (not wall clock — immune to the system clock moving) start of the
        # current scan, for the log's closing "completed in Ns".
        self._scan_start = 0.0
        # last result rendered into the sitemap Tree, so switching tabs doesn't
        # rebuild (and re-collapse) it every visit.
        self._tree_result = None
        # background PyPI update check (see _check_version) — drives the colour of the
        # status-bar version dot. "unknown" (blue) until the check answers.
        self._version_status = "unknown"
        # …and, when a newer release exists, an Activity Log line announced once after
        # whichever finishes last: the scan or the check itself (the dot is not enough
        # on its own — the log line spells out the upgrade command).
        self._update_available: str | None = None
        self._version_checked = False
        self._update_announced = False

    # ---- layout -----------------------------------------------------------

    def compose(self) -> ComposeResult:
        with Vertical(id="topbar"):
            yield Input(value=self._target or "", placeholder="domain… (press enter to scan)", id="domain")
            yield TabBar(self.modules, pseudo=_PSEUDO_TABS, id="tabs")
        with Grid(id="grid"):
            with Vertical(id="left"):
                with VerticalScroll(id="main"):
                    yield LoadingIndicator(id="main-loading")
                    yield Static("", id="main-content")
                    yield SitemapTree(id="main-tree")
                yield ActivityLog(id="activity")
            yield MapPanel(id="map")
            with VerticalScroll(id="status"):
                yield StatusPanel(id="status-content")
        with Horizontal(id="footer"):
            yield Static("", id="keybar")
            yield Static("", id="progress")

    def on_mount(self) -> None:
        self.query_one("#topbar").border_title = "🌐 WebScanner"
        self.query_one("#map").border_title = "server location"
        self.query_one("#status", VerticalScroll).border_title = "Server"
        self.query_one("#activity", ActivityLog).border_title = "Activity Log"
        self.query_one("#tabs", TabBar).set_selected(self.selected)
        # Establish the layout (wide vs narrow) before the first paint / scan.
        self._apply_narrow(self.size.width < _NARROW_MAX)
        # Show the version + (blue) update dot straight away; the dot recolours once
        # the background check answers, and the progress bar reclaims the slot mid-scan.
        self._refresh_version()
        # own group: the scan worker below is exclusive=True, which cancels every
        # other worker in its group — a shared/default group would kill this one.
        self.run_worker(
            self._check_version(), name="version-check", group="version-check"
        )
        if self._target:
            self.start_scan(self._target)
        else:
            self.action_toggle_edit()

    def on_resize(self, event) -> None:
        """Switch between the wide and narrow layouts as the terminal is resized."""
        narrow = event.size.width < _NARROW_MAX
        if narrow != self._narrow:
            self._apply_narrow(narrow)

    def _apply_narrow(self, narrow: bool) -> None:
        """Toggle the single-column phone layout.

        Adds/removes the ``-narrow`` class on the Screen (which drives the CSS: the
        map + Server panels hide, the grid collapses to one column) and re-derives the
        Python-side state that CSS can't: the visible tab set (Activity/Server become
        real tabs), the selected tab (a pseudo tab can't stay selected once it vanishes
        on the way back to wide), and which of #main / #activity is shown.
        """
        self._narrow = narrow
        if self.screen is not None:
            self.screen.set_class(narrow, "-narrow")
        if narrow:
            # Entering narrow: select the first tab (Activity), mirroring how DNS is
            # the default first tab on wide terminals.
            self.selected = _PSEUDO_TABS[0][0]
        elif self.selected in _PSEUDO_NAMES:
            # The pseudo tabs don't exist on wide terminals — fall back to the first
            # real module tab so the selection stays valid.
            self.selected = self.modules[0].name
        self.query_one("#tabs", TabBar).set_selected(self.selected)
        self._refresh_main()
        editing = self.focused is not None and self.focused.id == "domain"
        self._set_keybar(editing=editing)

    async def _check_version(self) -> None:
        status, latest = await asyncio.to_thread(update_status, __version__)
        self.post_message(VersionChecked(status, latest))

    def on_version_checked(self, message: VersionChecked) -> None:
        self._version_status = message.status
        self._update_available = message.latest
        self._version_checked = True
        self._refresh_version()
        self._maybe_announce_update()

    def _maybe_announce_update(self) -> None:
        """Append the "update available" Activity Log line once, after the scan's own
        closing line — so it lands as the last message. Gated on the scan being done
        (otherwise it would jump ahead of the module lines) and on a newer release
        actually existing; the check may finish before or after the scan, so both
        on_version_checked and on_scan_finished call this."""
        if (
            self._update_announced
            or self._scanning
            or not self._version_checked
            or self._update_available is None
        ):
            return
        self._update_announced = True
        self.query_one("#activity", ActivityLog).add(
            activity.update_available(self._update_available)
        )

    def _refresh_version(self) -> None:
        """Draw the version + update dot at the right of the footer, unless a scan is
        in progress (then the progress bar owns that slot — restored on finish)."""
        if self._scanning:
            return
        # Only show the dot when an update is available (hide the initial blue /
        # up-to-date green states) — a quiet footer until there's something to say.
        dot = f" [{ORANGE}]•[/]" if self._version_status == "outdated" else ""
        self.query_one("#progress", Static).update(f"v{__version__}{dot}")

    # ---- scanning ---------------------------------------------------------

    def start_scan(self, target: str) -> None:
        self.ctx = ScanContext.from_target(target)
        self.modules = all_modules()
        self.results = {}
        self._cms = UNSET
        self.completed = 0
        self.failed = 0
        self._scanning = True
        self._scan_start = time.monotonic()
        self._tree_result = None

        tabs = self.query_one("#tabs", TabBar)
        for module in self.modules:
            tabs.set_status(module.name, ModuleStatus.PENDING)

        self._set_main_loading(True)
        self.query_one("#map", MapPanel).show_loading()
        self.query_one("#status-content", StatusPanel).show_loading(self.ctx)
        log = self.query_one("#activity", ActivityLog)
        log.clear()
        log.add(activity.started(self.ctx.domain, len(self.modules)))
        log.add(activity.agent(self.ctx.profile))
        self._update_progress()

        # Blur the input so single-key nav (←/→, q, r) reaches the app rather
        # than being typed into the field; Escape refocuses it to edit.
        self.set_focus(None)
        self._set_keybar(editing=False)

        scanner = AsyncScanner(self.ctx, self.modules, on_event=self._on_event)
        self._run_scan(scanner)

    def _on_event(self, event: ScanEvent) -> None:
        # Runs inside the event loop (orchestrator coroutine); hand off via the
        # message pump so all UI mutation happens in message handlers.
        self.post_message(ScanProgress(event))

    def _run_scan(self, scanner: AsyncScanner) -> None:
        async def worker() -> None:
            await scanner.run()
            self.post_message(ScanFinished())

        self.run_worker(worker(), exclusive=True, name="scan")

    def on_scan_progress(self, message: ScanProgress) -> None:
        event = message.event
        # Above the early returns below — the log wants prefetch events too.
        if (line := activity.summarize(event, self.ctx)) is not None:
            self.query_one("#activity", ActivityLog).add(line)
        if event.name == PREFETCH:
            if event.status is ModuleStatus.DONE and self.ctx is not None:
                self.query_one("#map", MapPanel).set_geo(self.ctx.geo)
                self.query_one("#status-content", StatusPanel).set_ctx(self.ctx)
                self._refresh_server_tab()
            return
        if event.name == SHARED_IP:
            # Not a module — a late panel-only refresh once the shared-IP lookup lands.
            # Re-pass the tracked CMS so a completed Tech row isn't dropped back to UNSET.
            if self.ctx is not None:
                self.query_one("#status-content", StatusPanel).set_ctx(self.ctx, cms=self._cms)
                self._refresh_server_tab()
            return

        self.query_one("#tabs", TabBar).set_status(event.name, event.status)

        if event.status is ModuleStatus.RUNNING:
            return

        # terminal status
        self.completed += 1
        if event.status is ModuleStatus.FAILED:
            self.failed += 1
        if event.result is not None:
            self.results[event.name] = event.result
        if event.name == self.selected:
            self._refresh_main()
        if event.name == "dns" and event.result is not None:
            # Derived email-spoofing verdict — its own line, right under DNS's summary.
            self.query_one("#activity", ActivityLog).add(
                activity.email_spoofing(event.result)
            )
        if event.name == "security" and event.result is not None:
            # Passive WAF verdict — its own line under Security's, only when detected.
            if (line := activity.waf(event.result)) is not None:
                self.query_one("#activity", ActivityLog).add(line)
        if event.name == "tech" and self.ctx is not None:
            # No result guard: a failed Tech scan can still surface a CMS via the
            # page's <meta name="generator">.
            data = event.result.data if event.result is not None else None
            detected = _detect_cms(data, self.ctx.html)
            self._cms = detected
            self.query_one("#status-content", StatusPanel).set_ctx(self.ctx, cms=detected)
            self._refresh_server_tab()
            self.query_one("#activity", ActivityLog).add(activity.cms(detected))
        self._update_progress()

    def on_scan_finished(self, message: ScanFinished) -> None:
        self._scanning = False
        total = len(self.modules)
        self.query_one("#activity", ActivityLog).add(
            activity.overall(
                self.completed, self.failed, total, time.monotonic() - self._scan_start
            )
        )
        self._refresh_version()
        self._maybe_announce_update()

    # ---- progress line ----------------------------------------------------

    def _update_progress(self) -> None:
        """Draw a determinate progress bar (blue = done, grey = remaining) with the
        percentage in white, right-aligned on the footer row."""
        if not self._scanning:
            return
        total = len(self.modules)
        frac = self.completed / total if total else 0
        filled = round(frac * _BAR_WIDTH)
        blue = self.current_theme.primary
        bar = f"[{blue}]{'━' * filled}[/][{_BAR_DIM}]{'━' * (_BAR_WIDTH - filled)}[/]"
        self.query_one("#progress", Static).update(
            f"{bar} [white]{round(frac * 100)}%[/]"
        )

    # ---- tab selection ----------------------------------------------------

    def _module_names(self) -> list[str]:
        return [m.name for m in self.modules]

    def _nav_names(self) -> list[str]:
        """Tab names in cycle order — the pseudo tabs (Activity/Server) lead the list
        in the narrow layout, and are absent (fixed panels) when wide."""
        names = self._module_names()
        if self._narrow:
            return [name for name, _ in _PSEUDO_TABS] + names
        return names

    def _select(self, name: str) -> None:
        self.selected = name
        self.query_one("#tabs", TabBar).set_selected(name)
        self._refresh_main()
        # Reset the shared main-panel scroll so a tab left scrolled-down doesn't carry
        # its offset onto the next tab (they all share the one #main VerticalScroll).
        self.query_one("#main", VerticalScroll).scroll_home(animate=False)
        # keybar depends on the selected tab (Sitemap shows tree-nav hints); keep
        # the editing state if the domain input still has focus.
        editing = self.focused is not None and self.focused.id == "domain"
        self._set_keybar(editing=editing)

    def _update_main_title(self) -> None:
        label = _PSEUDO_LABELS.get(self.selected) or next(
            m.label for m in self.modules if m.name == self.selected
        )
        main = self.query_one("#main")
        main.border_title = label
        main.border_subtitle = ""  # only the Sitemap tab sets one (URL total)

    def _set_main(self, markup: str) -> None:
        # Leading blank line + space so placeholders sit clear of the border,
        # matching where real section content begins.
        self.query_one("#main-content", Static).update(f"\n {markup}")

    def _set_main_loading(self, loading: bool) -> None:
        """Toggle the in-panel LoadingIndicator vs. the content Static (keeps the
        panel's own border + title, unlike Widget.loading which covers them)."""
        self.query_one("#main-loading", LoadingIndicator).display = loading
        self.query_one("#main-content", Static).display = not loading

    def _main_avail(self) -> int | None:
        """Character width available to the main-panel table (inside border + padding),
        or None before the panel is laid out — the table renderer then skips the ⅓ cap."""
        width = self.query_one("#main", VerticalScroll).content_size.width
        return width or None

    def _refresh_main(self) -> None:
        self._update_main_title()
        main = self.query_one("#main", VerticalScroll)
        activity = self.query_one("#activity", ActivityLog)

        # Activity pseudo-tab (narrow only): show the live log widget full-height in
        # place of the main panel. In the wide layout it's the fixed bottom strip.
        if self._narrow and self.selected == "activity":
            main.display = False
            activity.display = True
            # Drop tree visibility so _sync_focus doesn't park focus on a widget
            # whose parent (#main) is now hidden.
            self.query_one("#main-tree", SitemapTree).display = False
            self._sync_focus()
            return
        main.display = True
        activity.display = not self._narrow

        tree = self.query_one("#main-tree", SitemapTree)
        content = self.query_one("#main-content", Static)
        loading_widget = self.query_one("#main-loading", LoadingIndicator)

        # Server pseudo-tab (narrow only): render the same status table the fixed
        # Server panel shows, into the main content area.
        if self.selected == "server":
            main.border_subtitle = ""
            tree.display = False
            has_ctx = self.ctx is not None
            loading_widget.display = not has_ctx
            content.display = has_ctx
            if has_ctx:
                # 1ch top + left pad so the status table sits clear of the border,
                # consistent with where the other tabs' content begins.
                content.update(Padding(render_status(self.ctx, self._cms), (1, 0, 0, 1)))
            self._sync_focus()
            return

        result = self.results.get(self.selected)
        loading = result is None
        # Spinner inside the panel until this tab's module completes; swap to the
        # Tree (Sitemap tab) or the Static content once there's a result to render.
        loading_widget.display = loading

        want_tree = (
            self.selected == "sitemap"
            and result is not None
            and result.status is ModuleStatus.DONE
        )
        tree.display = want_tree
        content.display = not loading and not want_tree

        if loading:
            self._sync_focus()
            return
        if want_tree:
            if self._tree_result is not result:
                tree.populate(result.data)
                self._tree_result = result
            if result.data.total is not None:
                self.query_one("#main").border_subtitle = _sitemap_subtitle(result.data)
        elif result.status is ModuleStatus.FAILED:
            self._set_main(f"[red]failed:[/] {result.error}")
        elif result.status is ModuleStatus.EMPTY:
            msg = "no sitemap found" if self.selected == "sitemap" else "no data found"
            self._set_main(f"[dim]{msg}[/]")
        else:
            avail = self._main_avail()
            content.update(
                render_result(self.selected, result.data, narrow=self._narrow, avail=avail)
            )
            # When switching from a tab that had #main hidden (Activity), the panel's
            # content_size isn't known this tick, so the ⅓ column cap was skipped.
            # Re-render once layout settles so the cap applies.
            if avail is None:
                self.call_after_refresh(self._reflow)
        self._sync_focus()

    def _reflow(self) -> None:
        """Re-render the current tab once the main panel has a known width (used after
        it was un-hidden, when the first render ran before layout gave it a size)."""
        if self._main_avail() is not None:
            self._refresh_main()

    def _refresh_server_tab(self) -> None:
        """Re-render the Server pseudo-tab as its status data lands (narrow only)."""
        if self._narrow and self.selected == "server":
            self._refresh_main()

    def _sync_focus(self) -> None:
        """Focus the Sitemap Tree while that tab is up (so ↑/↓/space reach it); drop
        focus otherwise. Never steals focus from the domain input while editing."""
        if self.focused is not None and self.focused.id == "domain":
            return
        tree = self.query_one("#main-tree", SitemapTree)
        if tree.display:
            if self.focused is not tree:
                self.set_focus(tree)
        elif self.focused is tree:
            self.set_focus(None)

    def on_tab_clicked(self, message: Tab.Clicked) -> None:
        self._select(message.tab_name)

    # ---- actions ----------------------------------------------------------

    def action_prev_tab(self) -> None:
        if self.focused and self.focused.id == "domain":
            return
        names = self._nav_names()
        idx = (names.index(self.selected) - 1) % len(names)
        self._select(names[idx])

    def action_next_tab(self) -> None:
        if self.focused and self.focused.id == "domain":
            return
        names = self._nav_names()
        idx = (names.index(self.selected) + 1) % len(names)
        self._select(names[idx])

    def action_select_tab(self, digit: int) -> None:
        """Jump to the Nth visible tab. ``digit`` is the key pressed: 1..9 select the
        1st..9th tab, 0 selects the 10th. Ignored while editing the domain input (the
        digit is typed there instead) or when there's no such tab."""
        if self.focused and self.focused.id == "domain":
            return
        position = 10 if digit == 0 else digit
        names = self._nav_names()
        if position <= len(names):
            self._select(names[position - 1])

    def action_rescan(self) -> None:
        if self.ctx is not None:
            self.start_scan(self.ctx.domain)

    def action_save(self) -> None:
        """Save every completed tab to CSV under output/<domain>_<timestamp>/."""
        if self.ctx is None or not self.results:
            self.query_one("#progress", Static).update("[dim]nothing to save yet[/]")
            return
        folder = export_csvs(self.ctx, self.modules, self.results, cms=self._cms)
        if folder:
            base = folder.parent  # where it saved, minus the domain_<ts> folder name
            names = [p for p in base.parts if p != base.anchor]  # drop the '/' root
            tail = names[-2:]
            shown = "/".join(tail) if tail else str(base)
            if len(names) > len(tail):
                shown = "…/" + shown
            msg = f"[dim]saved → {shown}[/]"
        else:
            msg = "[dim]nothing to save yet[/]"
        self.query_one("#progress", Static).update(msg)

    def action_toggle_edit(self) -> None:
        """Esc toggles domain editing (and the keybar) without moving other focus."""
        editing = self.focused is not None and self.focused.id == "domain"
        if editing:
            self.set_focus(None)
            self._set_keybar(editing=False)
        else:
            self.query_one("#domain", Input).focus()
            self._set_keybar(editing=True)

    def action_zoom_in(self) -> None:
        self.query_one("#map", MapPanel).zoom_by(1)

    def action_zoom_out(self) -> None:
        self.query_one("#map", MapPanel).zoom_by(-1)

    def _page_target(self):
        """The widget page-up/down should scroll. Usually the main panel, but the
        Activity pseudo-tab (narrow only) shows the #activity RichLog full-height in
        #main's place, so page keys must scroll that instead — #main is hidden there."""
        if self._narrow and self.selected == "activity":
            return self.query_one("#activity", ActivityLog)
        return self.query_one("#main", VerticalScroll)

    def action_scroll_main_up(self) -> None:
        self._page_target().scroll_page_up()

    def action_scroll_main_down(self) -> None:
        self._page_target().scroll_page_down()

    def on_input_submitted(self, message: Input.Submitted) -> None:
        target = message.value.strip()
        if target:
            self.set_focus(None)
            self.start_scan(target)

    # ---- keybar -----------------------------------------------------------

    def _set_keybar(self, editing: bool) -> None:
        c = self.current_theme.primary  # primary blue for key hints
        if editing:
            pairs = [("enter", "Scan"), ("esc", "Cancel")]
        elif self.selected == "sitemap":
            # tree-navigation hints, shown only while the Sitemap tab is up. The
            # narrow layout drops Rescan/Edit to fit the phone-width footer.
            if self._narrow:
                pairs = [("↑/↓", "Move"), ("enter", "Toggle"), ("space", "All"), ("←/→", "Tab")]
            else:
                pairs = [
                    ("←/→", "Tab"), ("↑/↓", "Move"), ("enter", "Toggle"),
                    ("space", "All"), ("r", "Rescan"), ("esc", "Edit"),
                ]
        elif self._narrow:
            # Compact set — the full labels overflow a phone-width footer.
            pairs = [("←/→", "Tab"), ("r", "Scan"), ("s", "Save"), ("q", "Quit")]
        else:
            # PgUp/Dn scrolls #main — only shown wide; the narrow footer has no room.
            pairs = [
                ("q", "Quit"), ("←/→", "Tab"), ("Pg↑/↓", "Scroll"),
                ("r", "Rescan"), ("s", "Save"), ("esc", "Edit domain"),
            ]
        text = "   ".join(f"[b {c}]{k}[/] {label}" for k, label in pairs)
        self.query_one("#keybar", Static).update(text)
