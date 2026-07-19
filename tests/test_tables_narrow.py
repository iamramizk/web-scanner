"""The narrow (phone-width) layout collapses wide (>2 column) Grids to their first +
last column so a multi-column tab (Tech: Name/Category/Confidence/Version) still reads
on a ~54-col terminal. ``render_grid(narrow=True)`` is the pure core of that — it keeps
Name + Version, drops the middle columns, and discards the fixed ``widths`` so the two
survivors expand to fit. Two-column Grids are already fine and pass through untouched.
"""

from __future__ import annotations

from rich.console import Console

from webscanner.core.models import Grid
from webscanner.ui.tables import _cap_key_width, render_grid, render_table


def _render(table, width: int = 54) -> str:
    """The table as plain text at a given width (what the terminal would show)."""
    console = Console(width=width, file=open("/dev/null", "w"))
    with console.capture() as cap:
        console.print(table)
    return cap.get()


def _tech_grid() -> Grid:
    return Grid(
        ["Name", "Category", "Confidence", "Version"],
        [["Nginx", "Web servers", "100%", "1.25.3"], ["jQuery", "JavaScript", "95%", "3.7.1"]],
        widths=[26, 22, 12, 12],
    )


def test_narrow_keeps_first_and_last_column() -> None:
    out = _render(render_grid(_tech_grid(), narrow=True))
    assert "Name" in out and "Version" in out
    # the middle columns are dropped
    assert "Category" not in out and "Confidence" not in out
    # first + last values survive, in the right pairing
    assert "Nginx" in out and "1.25.3" in out
    assert "jQuery" in out and "3.7.1" in out


def test_wide_keeps_every_column() -> None:
    out = _render(render_grid(_tech_grid(), narrow=False), width=120)
    for col in ("Name", "Category", "Confidence", "Version"):
        assert col in out


def test_narrow_leaves_two_column_grid_untouched() -> None:
    grid = Grid(["Name", "Value"], [["a", "1"], ["b", "2"]])
    out = _render(render_grid(grid, narrow=True))
    assert "Name" in out and "Value" in out
    assert "a" in out and "1" in out and "b" in out and "2" in out


def test_cap_key_width_is_one_third() -> None:
    # ~⅓ of the available width, floored at 6; a smaller content-fit width wins.
    assert _cap_key_width(25, 60) == 20
    assert _cap_key_width(10, 60) == 10  # already under the cap → unchanged
    assert _cap_key_width(25, None) == 25  # width unknown → no cap
    assert _cap_key_width(25, 9) == 6  # floor


def test_render_table_caps_long_first_column() -> None:
    # A long key can't dominate: it's capped near ⅓ and wraps instead of running wide.
    data = {"Strict-Transport-Security": "max-age=31536000", "X": "y"}
    table = render_table(data, ("Header", "Value"), mode="smart", avail=60)
    assert table.columns[0].width == 20  # 60 // 3
    assert table.columns[0].overflow == "fold" and not table.columns[0].no_wrap
