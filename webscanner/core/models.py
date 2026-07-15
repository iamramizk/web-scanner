"""Result and event data models shared across the core and UI."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ModuleStatus(str, Enum):
    """Lifecycle state of a single scan module (also drives tab colouring)."""

    PENDING = "pending"  # not started
    RUNNING = "running"  # in flight
    DONE = "done"  # finished with data
    EMPTY = "empty"  # finished, no data found
    FAILED = "failed"  # raised


@dataclass(slots=True)
class ModuleResult:
    """Outcome of one module run."""

    name: str
    status: ModuleStatus
    data: Any = None
    error: str | None = None
    duration_ms: float | None = None

    @property
    def ok(self) -> bool:
        return self.status in (ModuleStatus.DONE, ModuleStatus.EMPTY)


@dataclass(slots=True)
class ScanEvent:
    """Progress signal emitted by the orchestrator; the UI subscribes to these."""

    name: str  # module name, or "__prefetch__" for the shared fetch phase
    status: ModuleStatus
    result: ModuleResult | None = None


@dataclass(slots=True)
class Section:
    """One titled sub-table within a multi-table module result."""

    title: str
    data: Any
    headers: tuple[str, str] | None = None
    #: fixed column proportions (col1, col2), e.g. (3, 2) for 60/40; None = content-fit
    ratio: tuple[int, int] | None = None
    #: blank line between rows
    spaced: bool = False


class Sections(list):
    """A module result rendered as several stacked, titled sub-tables.

    A ``list`` of :class:`Section`. Used by modules (e.g. Security) that show more
    than one table under a single tab.
    """


@dataclass(slots=True)
class TreeNode:
    """One node in a hierarchical result (e.g. the Sitemap tab's URL tree).

    The module returns a synthetic root ``TreeNode`` whose descendants mirror the
    site's URL-path hierarchy (``/blog`` → ``/blog/post-1`` …). A node is a branch
    (expandable folder) iff it has ``children``; otherwise it's a leaf (a page). The
    UI turns the root into a Textual ``Tree`` widget. ``total`` (set on the root only)
    is the count of page URLs behind the tree, shown in the panel subtitle. ``url`` is
    the full page URL a node stands for (set on leaves), so the UI can make it clickable.
    """

    label: str
    children: list["TreeNode"] = field(default_factory=list)
    total: int | None = None
    url: str | None = None


class Grid(list):
    """A multi-column table result: rows (list of value-lists) + column headers.

    A ``list`` of rows, so an empty ``Grid`` reports EMPTY via ``_is_empty``. The
    first column is treated as each row's primary name.
    """

    def __init__(self, columns: list[str], rows: Any) -> None:
        super().__init__(rows)
        self.columns = list(columns)

    @property
    def names(self) -> list[str]:
        """First-column values (e.g. tech names for the Server-panel summary)."""
        return [row[0] for row in self]
