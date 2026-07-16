"""Custom Textual widgets: tab bar, world-map panel, status panel, activity log."""

from __future__ import annotations

from collections import deque
from datetime import datetime

from rich.markup import escape
from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal
from textual.message import Message
from textual.widgets import RichLog, Static, Tree

from ..colors import BODY, MUTED
from ..core.context import ScanContext
from ..core.models import ModuleStatus, TreeNode
from .tables import UNSET, render_status
from .worldmap import country_name, render as render_map

_STATUS_CLASSES = ("-pending", "-running", "-done", "-empty", "-failed")


class Tab(Static):
    """A single tab in the tab bar; colour reflects its module's status."""

    class Clicked(Message):
        def __init__(self, tab_name: str) -> None:
            self.tab_name = tab_name
            super().__init__()

    def __init__(self, name: str, label: str) -> None:
        super().__init__(label, id=f"tab-{name}")
        self.tab_name = name
        self.add_class("-pending")

    def set_status(self, status: ModuleStatus) -> None:
        self.remove_class(*_STATUS_CLASSES)
        self.add_class(f"-{status.value}")

    def set_selected(self, selected: bool) -> None:
        self.set_class(selected, "-selected")

    def on_click(self) -> None:
        self.post_message(self.Clicked(self.tab_name))


class TabBar(Horizontal):
    def __init__(self, modules, **kwargs) -> None:
        super().__init__(**kwargs)
        self._modules = list(modules)

    def compose(self):
        for module in self._modules:
            yield Tab(module.name, module.label)

    def set_status(self, name: str, status: ModuleStatus) -> None:
        self.query_one(f"#tab-{name}", Tab).set_status(status)

    def set_selected(self, name: str) -> None:
        for tab in self.query(Tab):
            tab.set_selected(tab.tab_name == name)


class MapPanel(Static):
    """Fixed country-level location map; re-renders on resize to fill the panel."""

    _geo: dict | None = None
    _zoom: float = 1.0

    def set_geo(self, geo: dict | None) -> None:
        self._geo = geo
        self._draw()

    def zoom_by(self, direction: int) -> None:
        factor = 1.3 if direction > 0 else 1 / 1.3
        self._zoom = max(0.25, min(6.0, self._zoom * factor))
        self._draw()

    def show_loading(self) -> None:
        self.update("[dim]locating…[/]")

    def on_resize(self) -> None:
        if self._geo is not None:
            self._draw()

    def _draw(self) -> None:
        geo = self._geo or {}
        lat, lon = geo.get("lat"), geo.get("lon")
        if lat is None:
            self.update("[dim]no location[/]")
            return
        width = max(20, self.content_size.width)
        height = max(6, self.content_size.height)
        country = geo.get("country") or country_name(lat, lon) or "?"
        self.border_title = f"Location — {country}"
        self.border_subtitle = "+/- zoom"
        self.update(render_map(lat, lon, cols=width, rows=height, zoom=self._zoom))


class StatusPanel(Static):
    """Fixed status summary panel."""

    def show_loading(self, ctx: ScanContext) -> None:
        self.update(f"[dim]scanning {ctx.domain}…[/]")

    def set_ctx(self, ctx: ScanContext, cms: object = UNSET) -> None:
        self.update(render_status(ctx, cms))


class ActivityLog(RichLog):
    """Fixed scan log under the main panel; the newest line is always in view.

    Lines are composed by ``activity.py`` — this only stamps the time, paints the
    body, and decides how a too-long line is cut, so the wording stays testable
    without an app.

    Each line is written as a ``no_wrap`` / ``overflow="ellipsis"`` Text at the
    panel's exact width, so it's truncated with "…" at the panel edge and a wider
    terminal reveals more of it. Nothing is pre-cropped to an assumed width.

    ``can_focus=False`` is load-bearing, not tidiness: RichLog inherits
    ScrollableContainer's ungated up/down bindings, so a focused log would swallow
    ↑/↓ from the Sitemap tree once it overflows. It also stops a click on the panel
    from taking focus off the app, which is what keeps single-key nav (q/r/s/←/→)
    working.
    """

    can_focus = False

    #: scrollback kept for re-rendering on resize; matches RichLog's max_lines
    _MAX_LINES = 200

    def __init__(self, **kwargs) -> None:
        # min_width=0: the 78 default renders every write at >=78 cells, overflowing
        # a narrower panel. wrap=True: with wrap=False, RichLog forces
        # overflow="ignore" on Text and the tail vanishes with no ellipsis.
        super().__init__(markup=True, wrap=True, min_width=0, max_lines=self._MAX_LINES, **kwargs)
        # RichLog renders to strips at write time and never re-renders, so keep the
        # markup to replay when the width changes.
        self._entries: deque[str] = deque(maxlen=self._MAX_LINES)
        self._rendered_width: int | None = None

    def add(self, body: str) -> None:
        """Write one line, stamped with a muted [HH:MM:SS]."""
        stamp = escape(f"[{datetime.now():%H:%M:%S}]")
        markup = f"[{MUTED}]{stamp}[/] [{BODY}]{body}[/]"
        self._entries.append(markup)
        self._write(markup)

    def _write(self, markup: str) -> None:
        text = Text.from_markup(markup)
        text.no_wrap = True
        text.overflow = "ellipsis"
        # Explicit width, because RichLog's own sizing measures against
        # `app.console`, which is a plain 80 columns regardless of how wide the app
        # actually is — every line would ellipsise at 80 on a wider terminal. Passing
        # width bypasses measure/shrink/min_width entirely. Width 0 means we aren't
        # laid out yet: let RichLog defer the write, and on_resize replays it.
        width = self.scrollable_content_region.width
        if width:
            self.write(text, width=width)
        else:
            self.write(text)

    def clear(self) -> "ActivityLog":
        self._entries.clear()
        super().clear()
        return self

    def on_resize(self, event) -> None:
        # Flushes any deferred writes, once, when a size is first known.
        super().on_resize(event)
        width = self.scrollable_content_region.width
        if not width or width == self._rendered_width:
            return
        self._rendered_width = width
        if not self._entries:
            return
        # RichLog renders to strips at write time and never re-renders, so replay at
        # the new width: a wider terminal reveals more of each line, a narrower one
        # re-ellipsises. Also fixes the first sizing, where deferred lines were
        # rendered by RichLog without our explicit width.
        entries = list(self._entries)
        super().clear()
        for markup in entries:
            self._write(markup)


class SitemapTree(Tree):
    """Sitemap tab: the site's URL-path hierarchy as a collapsed tree.

    Navigation: ``up``/``down`` move the cursor (Textual defaults). ``enter`` toggles
    the node under the cursor; ``space`` toggles the *whole* tree — expand all if
    anything is collapsed, else collapse all (both override Textual's defaults, which
    map space to a single node and shift+space to same-level siblings). The visible
    ``/`` root is expanded by default; its children (the first URL slugs) start
    collapsed. A node is a branch iff it has children; otherwise it's a leaf.

    Leaf pages carry a ``@click`` action so a mouse click opens the URL in the browser
    (styled to look identical to plain text — see the ``link-*`` rules in app.tcss).
    URLs are held in ``_leaf_urls`` and referenced by index, so no URL text has to be
    escaped into the click-action markup.
    """

    BINDINGS = [
        Binding("enter", "toggle_node", "Toggle", show=False),
        Binding("space", "toggle_all", "Expand/collapse all", show=False),
    ]

    #: Textual gives the expand/collapse chevron no component class of its own — it
    #: renders with the widget's base style, so plain CSS can't reach it without
    #: recolouring every label too. Adding one here (Textual unions COMPONENT_CLASSES
    #: across the MRO) lets `#main-tree > .tree--toggle` in app.tcss style it alone.
    COMPONENT_CLASSES = {"tree--toggle"}

    def __init__(self, **kwargs) -> None:
        super().__init__("/", **kwargs)
        self.show_root = True
        self.guide_depth = 3
        self._leaf_urls: list[str] = []

    def populate(self, root: TreeNode) -> None:
        """Rebuild from a data ``TreeNode``: the ``/`` root shows expanded, its
        children collapsed."""
        self.clear()
        self._leaf_urls = []
        self.root.set_label(root.label)  # "/"
        self.root.expand()
        for child in root.children:
            self._add(self.root, child)

    def _add(self, parent, data: TreeNode) -> None:
        if data.children:
            branch = parent.add(data.label, expand=False)
            for child in data.children:
                self._add(branch, child)
        elif data.url:
            index = len(self._leaf_urls)
            self._leaf_urls.append(data.url)
            parent.add_leaf(f"[@click=open_leaf({index})]{escape(data.label)}[/]")
        else:
            parent.add_leaf(data.label)  # e.g. the "… (truncated)" note — not a link

    def render_label(self, node, base_style, style) -> Text:
        """Paint the chevron with ``tree--toggle``, leaving the label untouched.

        Textual builds the line as ``ICON + label``, styling the icon with the
        widget's own base style; re-styling that span is the only way to colour the
        chevron independently. The icon is a fixed-width prefix (``"▼ "``/``"▶ "``)
        present only on expandable nodes, so the span is the first ``len(ICON_NODE)``
        cells. A partial style layers over the base, so only the colour changes.

        The ``_component_styles`` guard is required, not defensive: this also runs
        pre-mount via ``get_label_width`` (a reactive in ``__init__`` rebuilds the
        tree lines), and component styles don't exist until the stylesheet is applied
        on mount — asking for one before that raises ``KeyError``. That early call
        only measures, and a colour never changes cell width, so skipping is safe.
        """
        label = super().render_label(node, base_style, style)
        if node.allow_expand and "tree--toggle" in self._component_styles:
            label.stylize(
                self.get_component_rich_style("tree--toggle", partial=True),
                0,
                len(self.ICON_NODE),
            )
        return label

    def action_open_leaf(self, index: int) -> None:
        if 0 <= index < len(self._leaf_urls):
            self.app.open_url(self._leaf_urls[index])

    def action_toggle_all(self) -> None:
        branches = self._branches()
        if not branches:
            return
        if any(b.is_collapsed for b in branches):
            self.root.expand_all()
        else:
            for child in self.root.children:
                child.collapse_all()

    def _branches(self) -> list:
        """Every expandable node below the (hidden) root."""
        out: list = []

        def walk(node) -> None:
            for child in node.children:
                if child.allow_expand:
                    out.append(child)
                walk(child)

        walk(self.root)
        return out
