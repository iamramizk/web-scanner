"""Result and event data models shared across the core and UI."""

from __future__ import annotations

from dataclasses import dataclass
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
