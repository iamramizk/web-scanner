"""Export scan results to CSV — one file per tab, under ``output/<domain>_<ts>/``.

Each tab is written with columns that mirror its on-screen table: key/value tabs
get their ``TAB_HEADERS`` pair, multi-table tabs (Sections) get ``Section, Field,
Value``, and the Tech ``Grid`` keeps its native columns. Rich colour markup in
values is stripped so the CSV holds plain text.
"""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from ..core.models import Grid, ModuleStatus, Sections, TreeNode
from .tables import TAB_HEADERS, _SMART_LABEL_TABS, _label, _plain

def _output_base() -> Path:
    """Parent directory for the ``<domain>_<ts>/`` scan folder.

    Keyed on the current working directory, not on where the package is installed —
    an editable install still runs from wherever the user `cd`'d to. If cwd is the
    project's own source checkout (a ``pyproject.toml`` next to the ``webscanner/``
    package) results go in the repo's gitignored ``output/`` folder, keeping the
    checkout tidy. Anywhere else, the ``<domain>_<ts>/`` folder is written straight
    into the current directory.
    """
    cwd = Path.cwd()
    if (cwd / "pyproject.toml").is_file() and (cwd / "webscanner" / "__init__.py").is_file():
        return cwd / "output"
    return cwd


def _is_pairs(data: Any) -> bool:
    return (
        isinstance(data, (list, tuple))
        and bool(data)
        and all(isinstance(x, (list, tuple)) and len(x) == 2 for x in data)
    )


def _rows_from(data: Any, mode: str = "raw") -> Iterator[tuple[str, str]]:
    """Yield (field, value) plain-text pairs for a dict / pair-list / scalar-list.

    ``mode`` cases dict keys the same way the on-screen table does (see
    ``tables._label``): ``"smart"`` for whois/ssl/headers, ``"upper"`` for dns,
    ``"raw"`` for Sections sub-tables.
    """
    if isinstance(data, dict):
        for k, v in data.items():
            yield _label(k, mode), _plain(v)
    elif _is_pairs(data):
        for a, b in data:
            yield _plain(a), _plain(b)
    elif isinstance(data, (list, tuple)):
        for i, item in enumerate(data, 1):
            yield str(i), _plain(item)
    else:
        yield "", _plain(data)


def _walk_tree(root: TreeNode, prefix: str = "", depth: int = 0) -> Iterator[tuple[int, str, str]]:
    """Depth-first ``(depth, kind, path)`` for the tree, skipping the synthetic root.

    ``path`` is the accumulated path (node labels already carry their ``/`` or host
    separator); ``kind`` is ``folder`` (has children) or ``page`` (a leaf)."""
    for child in root.children:
        path = prefix + child.label
        yield depth, ("folder" if child.children else "page"), path
        yield from _walk_tree(child, path, depth + 1)


def _write_tab(path: Path, name: str, data: Any) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if isinstance(data, TreeNode):
            writer.writerow(["Depth", "Type", "Path"])
            for depth, kind, path in _walk_tree(data):
                writer.writerow([depth, kind, path])
        elif isinstance(data, Grid):
            writer.writerow(data.columns)
            for row in data:
                writer.writerow([_plain(cell) for cell in row])
        elif isinstance(data, Sections):
            # Sections of Grids (e.g. Tech's per-group tables) flatten with the
            # section title as a leading "Group" column; key/value sections stay
            # Section/Field/Value.
            if data and isinstance(data[0].data, Grid):
                writer.writerow(["Group", *data[0].data.columns])
                for sec in data:
                    for row in sec.data:
                        writer.writerow([sec.title, *[_plain(c) for c in row]])
            else:
                writer.writerow(["Section", "Field", "Value"])
                for sec in data:
                    for field, value in _rows_from(sec.data):
                        writer.writerow([sec.title, field, value])
        else:
            mode = "smart" if name in _SMART_LABEL_TABS else "upper"
            writer.writerow(list(TAB_HEADERS.get(name, ("Field", "Value"))))
            for field, value in _rows_from(data, mode):
                writer.writerow([field, value])


def export_csvs(domain: str, modules: list, results: dict) -> Path | None:
    """Write one CSV per tab that produced data; return the output folder (or None
    if nothing was written)."""
    tabs = [
        m for m in modules
        if (r := results.get(m.name)) is not None
        and r.status is ModuleStatus.DONE
        and r.data is not None
    ]
    if not tabs:
        return None
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    folder = _output_base() / f"{domain}_{ts}"
    folder.mkdir(parents=True, exist_ok=True)
    for module in tabs:
        _write_tab(folder / f"{module.name}.csv", module.name, results[module.name].data)
    return folder
