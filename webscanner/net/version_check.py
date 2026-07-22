"""PyPI version check: is a newer web-scanner release available?

Cached locally (24h TTL) so a user running the scanner many times a day doesn't hit
PyPI on every launch. Every failure mode (network, parse, filesystem) is swallowed —
a broken update check must never surface as a broken scan.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import requests

from .http import API_HEADERS, TIMEOUT

PACKAGE = "web-scanner"
_TTL_SECONDS = 24 * 60 * 60


def _cache_file() -> Path:
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    elif os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "web-scanner" / "version_check.json"


def _parse(version: str) -> tuple[int, ...]:
    """Dotted-numeric version -> comparable tuple. Good enough for this project's
    own X.Y.Z scheme — no need for the `packaging` dependency just for this."""
    parts = []
    for chunk in version.split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _fetch_latest() -> str:
    resp = requests.get(
        f"https://pypi.org/pypi/{PACKAGE}/json", headers=API_HEADERS, timeout=TIMEOUT
    )
    resp.raise_for_status()
    return resp.json()["info"]["version"]


def _cached_latest() -> str | None:
    data = json.loads(_cache_file().read_text())
    if time.time() - data.get("checked_at", 0) > _TTL_SECONDS:
        return None
    return data.get("latest")


def _write_cache(latest: str) -> None:
    path = _cache_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"latest": latest, "checked_at": time.time()}))


def update_status(current: str) -> tuple[str, str | None]:
    """The update state as ``(status, latest)``:

    - ``("outdated", latest)`` — a newer PyPI release exists;
    - ``("latest", None)`` — confirmed up to date;
    - ``("unknown", None)`` — couldn't check (network, parse, or filesystem failure).

    The ``unknown`` case is kept distinct from ``latest`` on purpose: the status-bar
    dot shows green only for a *confirmed* up-to-date check, and stays neutral (blue)
    when the check couldn't complete — a broken update check must never look like a
    scan problem, nor falsely claim "up to date".
    """
    try:
        latest = _cached_latest()
    except (OSError, ValueError):
        latest = None
    try:
        if latest is None:
            latest = _fetch_latest()
            _write_cache(latest)
    except Exception:  # noqa: BLE001
        return "unknown", None
    if _parse(latest) > _parse(current):
        return "outdated", latest
    return "latest", None


def check_for_update(current: str) -> str | None:
    """The latest PyPI version if newer than ``current``, else ``None``.

    Silent on any failure — network, parse, or filesystem — since a broken update
    check must never be visible as a scan problem.
    """
    status, latest = update_status(current)
    return latest if status == "outdated" else None
