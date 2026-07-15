"""Custom Textual widgets: tab bar, world-map panel, status panel."""

from __future__ import annotations

from rich.markup import escape
from textual.binding import Binding
from textual.containers import Horizontal
from textual.message import Message
from textual.widgets import Static, Tree

from ..core.context import ScanContext
from ..core.models import ModuleStatus, TreeNode
from .tables import render_status
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

    def set_ctx(self, ctx: ScanContext, tech: list[str] | None = None) -> None:
        self.update(render_status(ctx, tech))


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
