"""Custom Textual widgets: tab bar, world-map panel, status panel."""

from __future__ import annotations

from textual.containers import Horizontal
from textual.message import Message
from textual.widgets import Static

from ..core.context import ScanContext
from ..core.models import ModuleStatus
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
