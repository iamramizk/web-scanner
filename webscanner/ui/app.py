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

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Vertical, VerticalScroll
from textual.message import Message
from textual.widgets import Input, Static

from ..core import AsyncScanner, ModuleStatus, ScanContext, ScanEvent
from ..core.scanner import PREFETCH
from ..modules import all_modules
from .tables import render_result
from .widgets import MapPanel, StatusPanel, TabBar, Tab

_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class ScanProgress(Message):
    """A ScanEvent surfaced onto the Textual message pump."""

    def __init__(self, event: ScanEvent) -> None:
        self.event = event
        super().__init__()


class ScanFinished(Message):
    pass


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
        Binding("escape", "toggle_edit", "Edit domain", show=False),
        Binding("plus,equals_sign", "zoom_in", "Zoom map in", show=False),
        Binding("minus,underscore", "zoom_out", "Zoom map out", show=False),
    ]

    def __init__(self, target: str | None = None) -> None:
        super().__init__()
        self._target = target
        self.ctx: ScanContext | None = None
        self.modules = all_modules()
        self.results: dict = {}
        self.selected = self.modules[0].name
        self.completed = 0
        self.failed = 0
        self._frame = 0
        self._scanning = False

    # ---- layout -----------------------------------------------------------

    def compose(self) -> ComposeResult:
        with Vertical(id="topbar"):
            yield Input(value=self._target or "", placeholder="domain… (press enter to scan)", id="domain")
            yield TabBar(self.modules, id="tabs")
        with Grid(id="grid"):
            with VerticalScroll(id="main"):
                yield Static("", id="main-content")
            yield MapPanel(id="map")
            yield StatusPanel(id="status")
        yield Static("", id="progress")
        yield Static("", id="keybar")

    def on_mount(self) -> None:
        self.query_one("#topbar").border_title = "🌐 WebScanner"
        self.query_one("#map").border_title = "server location"
        self.query_one("#status").border_title = "Server"
        self._spinner_timer = self.set_interval(0.08, self._tick, pause=True)
        self.query_one("#tabs", TabBar).set_selected(self.selected)
        self._update_main_title()
        self._set_keybar(editing=False)
        if self._target:
            self.start_scan(self._target)
        else:
            self.action_toggle_edit()

    # ---- scanning ---------------------------------------------------------

    def start_scan(self, target: str) -> None:
        self.ctx = ScanContext.from_target(target)
        self.modules = all_modules()
        self.results = {}
        self.completed = 0
        self.failed = 0
        self._scanning = True

        tabs = self.query_one("#tabs", TabBar)
        for module in self.modules:
            tabs.set_status(module.name, ModuleStatus.PENDING)

        self.query_one("#main-content", Static).update("[dim]scanning…[/]")
        self.query_one("#map", MapPanel).show_loading()
        self.query_one("#status", StatusPanel).show_loading(self.ctx)
        self._spinner_timer.resume()

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
        if event.name == PREFETCH:
            if event.status is ModuleStatus.DONE and self.ctx is not None:
                self.query_one("#map", MapPanel).set_geo(self.ctx.geo)
                self.query_one("#status", StatusPanel).set_ctx(self.ctx)
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
        if event.name == "tech" and self.ctx is not None and event.result is not None:
            self.query_one("#status", StatusPanel).set_ctx(self.ctx, event.result.data)
        self._update_progress()

    def on_scan_finished(self, message: ScanFinished) -> None:
        self._scanning = False
        self._spinner_timer.pause()
        total = len(self.modules)
        self.query_one("#progress", Static).update(
            f"done · {total}/{total} · {self._errs()}"
        )

    # ---- progress line ----------------------------------------------------

    def _errs(self) -> str:
        if self.failed == 0:
            return "no errors"
        return "1 error" if self.failed == 1 else f"{self.failed} errors"

    def _tick(self) -> None:
        self._frame = (self._frame + 1) % len(_SPINNER)
        self._update_progress()

    def _update_progress(self) -> None:
        if not self._scanning:
            return
        frame = _SPINNER[self._frame]
        self.query_one("#progress", Static).update(
            f"{frame} scanning… {self.completed}/{len(self.modules)} · {self._errs()}"
        )

    # ---- tab selection ----------------------------------------------------

    def _module_names(self) -> list[str]:
        return [m.name for m in self.modules]

    def _select(self, name: str) -> None:
        self.selected = name
        self.query_one("#tabs", TabBar).set_selected(name)
        self._refresh_main()

    def _update_main_title(self) -> None:
        label = next(m.label for m in self.modules if m.name == self.selected)
        self.query_one("#main").border_title = label

    def _refresh_main(self) -> None:
        self._update_main_title()
        content = self.query_one("#main-content", Static)
        result = self.results.get(self.selected)
        if result is None:
            content.update("[dim]scanning…[/]")
        elif result.status is ModuleStatus.FAILED:
            content.update(f"[red]failed:[/] {result.error}")
        elif result.status is ModuleStatus.EMPTY:
            content.update("[dim]no data found[/]")
        else:
            content.update(render_result(self.selected, result.data))

    def on_tab_clicked(self, message: Tab.Clicked) -> None:
        self._select(message.tab_name)

    # ---- actions ----------------------------------------------------------

    def action_prev_tab(self) -> None:
        if self.focused and self.focused.id == "domain":
            return
        names = self._module_names()
        idx = (names.index(self.selected) - 1) % len(names)
        self._select(names[idx])

    def action_next_tab(self) -> None:
        if self.focused and self.focused.id == "domain":
            return
        names = self._module_names()
        idx = (names.index(self.selected) + 1) % len(names)
        self._select(names[idx])

    def action_rescan(self) -> None:
        if self.ctx is not None:
            self.start_scan(self.ctx.domain)

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
        else:
            pairs = [("q", "Quit"), ("←/→", "Tab"), ("r", "Rescan"), ("esc", "Edit domain")]
        text = "   ".join(f"[b {c}]{k}[/] {label}" for k, label in pairs)
        self.query_one("#keybar", Static).update(text)
