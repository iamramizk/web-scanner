"""The scan-module contract.

Every module is a small, independently replaceable unit. It reads what it needs
from the shared ``ScanContext``, does its work, and returns structured data.
Modules must never manage their own status/timing/error handling — the
orchestrator wraps each ``run`` call and isolates failures so one broken module
cannot abort the whole scan.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .context import ScanContext


class ScanModule(ABC):
    #: one-word identifier; also the tab id (e.g. "dns")
    name: str = ""
    #: human label shown in the tab bar (e.g. "DNS")
    label: str = ""

    @abstractmethod
    async def run(self, ctx: ScanContext) -> Any:
        """Do the scan and return JSON-serialisable data (or raise)."""
        raise NotImplementedError
