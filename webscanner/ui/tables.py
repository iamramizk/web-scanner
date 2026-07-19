"""Rich renderables for the main data table and the fixed status panel."""

from __future__ import annotations

from typing import Any

from rich.console import Group, RenderableType
from rich import box
from rich.table import Table
from rich.text import Text

from ..colors import RED, MUTED
from ..core.context import ScanContext
from ..core.models import Grid, Sections

# Neutral, non-cyan key styling + a muted header + a very dim divider rule.
KEY_STYLE = "bold"
HEADER_STYLE = "bold grey62"
DIVIDER_STYLE = "grey23"
#: section-title chip — matches the selected-tab look (bg + 1-char side padding)
SECTION_STYLE = "bold white on #393939"

# Per-tab column headers (col1, col2). Meaningful names beat a generic pair since
# each tab's data is different. (Tabs with multi-table results, e.g. Security,
# carry headers per Section instead.)
TAB_HEADERS: dict[str, tuple[str, str]] = {
    "dns": ("Record", "Value"),
    "whois": ("Field", "Value"),
    "subdomains": ("#", "Subdomain"),
    "ssl": ("Field", "Value"),
    "headers": ("Header", "Value"),
    "content": ("Field", "Value"),
}


#: cap on the (content-fit) first-column width
MAX_KEY_WIDTH = 34

# Tabs whose key column is smart-cased (Title Case, acronyms kept upper) instead of
# ALL CAPS. dns stays "upper" — its keys are record types (AAAA/CNAME/DNSKEY/DMARC).
_SMART_LABEL_TABS = {"whois", "ssl", "headers"}

# Tokens that render upper-case rather than Title-cased. Lowercase keys. Only needs
# the acronyms that actually appear as key tokens in the smart-cased tabs — NOT an
# exhaustive dictionary. Unknown tokens fall back to Title Case (correct for the long
# tail, incl. header names from servers we've never seen). Extend freely.
_ACRONYMS: frozenset[str] = frozenset({
    # whois
    "id", "url", "iana", "whois", "dnssec",
    # ssl
    "cn", "san", "ssl", "tls",
    # headers / general web acronyms
    "xss", "csp", "hsts", "cors", "www", "ua", "md5", "ip", "dns",
    "http", "https", "uri", "api", "spf", "dkim", "dmarc",
})


def _smart_token(tok: str) -> str:
    return tok.upper() if tok.lower() in _ACRONYMS else tok.capitalize()


def _cap_key_width(width: int | None, avail: int | None) -> int | None:
    """Cap a first-column width at ~⅓ of the available table width so a long key
    (a header name, a whois field) can't dominate the row; the column then wraps
    within that cap. ``avail`` unknown (pre-layout) → the width is left uncapped.
    ``width`` None means "no content-fit width yet" → take the cap outright."""
    if avail and avail > 0:
        cap = max(6, avail // 3)
        return min(width, cap) if width else cap
    return width


def render_result(name: str, data: Any, narrow: bool = False, avail: int | None = None) -> RenderableType:
    """Render a module's result: multi-column Grid, stacked sub-tables (Sections),
    or one key/value table.

    ``narrow`` collapses wide (>2 column) Grids to their first + last column so a
    multi-column tab (Tech: Name/…/Version) still reads on a phone-width terminal.
    ``avail`` is the table's available character width; when known, the first column
    is capped at ~⅓ of it and wraps rather than running the row wide.
    """
    if isinstance(data, Grid):
        return render_grid(data, narrow=narrow, avail=avail)
    if isinstance(data, Sections):
        # SEO pins all sub-tables to one fixed first-column width so its four
        # tables (Content/Keywords/Robots/Schema) line up exactly.
        return render_sections(data, key_width=12 if name == "seo" else None, narrow=narrow, avail=avail)
    mode = "smart" if name in _SMART_LABEL_TABS else "upper"
    return render_table(data, TAB_HEADERS.get(name), mode=mode, avail=avail)


def render_grid(grid: Grid, narrow: bool = False, avail: int | None = None) -> Table:
    """Render a multi-column table (e.g. Tech: Name/Category/Confidence/…).

    First column is the primary name (bold); the rest are dim, matching the
    key/value tables. Long list columns fold rather than truncate. When the Grid
    carries ``widths``, every column is pinned to that fixed width (and the table
    stops expanding) so sibling Grids on one tab line up identically.

    ``narrow`` (phone-width terminals) keeps only the first + last column — for
    Tech that's Name + Version, the two that matter — and pins both to a fixed 50/50
    ``ratio`` (not content-fit) so every sibling sub-table on the tab lines up
    identically instead of each fitting its own name lengths.
    """
    collapsed = narrow and len(grid.columns) > 2
    if collapsed:
        keep = [0, len(grid.columns) - 1]
        columns = [grid.columns[i] for i in keep]
        rows = [[row[i] for i in keep] for row in grid]
        grid = Grid(columns, rows)  # widths dropped → columns sized by the ratio below
    widths = grid.widths
    table = Table(
        show_header=True,
        header_style=HEADER_STYLE,
        border_style=DIVIDER_STYLE,
        box=box.SIMPLE,
        expand=widths is None,
        pad_edge=False,
        show_lines=False,
        padding=(0, 1),
    )
    for i, col in enumerate(grid.columns):
        w = widths[i] if widths else None
        if collapsed:
            # Fixed 50/50 across every sub-table, so the Name/Version columns align
            # regardless of each group's name lengths.
            style = KEY_STYLE if i == 0 else MUTED
            table.add_column(col, style=style, ratio=1, no_wrap=False, overflow="fold")
        elif i == 0 and w is None:
            # No fixed widths (e.g. the narrow 2-column Tech): content-fit the Name
            # column but cap it at ~⅓ and let it wrap, like the key/value tables.
            name_fit = min(
                MAX_KEY_WIDTH,
                max((len(str(row[0])) for row in grid), default=len(col)),
            )
            table.add_column(col, style=KEY_STYLE, width=_cap_key_width(name_fit, avail), no_wrap=False, overflow="fold")
        elif i == 0:
            table.add_column(col, style=KEY_STYLE, width=w, no_wrap=True, overflow="ellipsis")
        else:
            table.add_column(col, style=MUTED, width=w, no_wrap=False, overflow="fold")
    rows = [[str(cell) for cell in row] for row in grid]
    for i, row in enumerate(rows):
        table.add_row(*row)
        if i != len(rows) - 1:
            table.add_row(*[""] * len(grid.columns))  # blank spacer line
    return table


def render_sections(sections: Sections, key_width: int | None = None, narrow: bool = False, avail: int | None = None) -> Group:
    """Render several titled sub-tables stacked; content-fit sections share one
    first-column width, ratio sections use their fixed proportions. A caller may
    pass ``key_width`` to pin that shared first-column width explicitly. ``narrow``
    is forwarded to any Grid sub-tables (Tech) so they collapse to two columns.
    ``avail`` caps the shared first-column width at ~⅓ of the table width."""
    if key_width is None:
        widths = [_col1_width(s.data, s.headers, mode="raw") for s in sections if not s.ratio]
        key_width = max([w for w in widths if w], default=None)
    # Cap the shared key column at ~⅓ so a long field can't widen every sub-table.
    key_width = _cap_key_width(key_width, avail)
    parts: list[RenderableType] = [Text("")]  # space above the first section title
    for i, sec in enumerate(sections):
        if i:
            parts.append(Text(""))
        # chip: 1-char padding inside the bg; the leading space also aligns the
        # title text with the table's cell padding
        parts.append(Text(f" {sec.title.upper()} ", style=SECTION_STYLE))
        if isinstance(sec.data, Grid):
            # e.g. Tech's per-group tables — multi-column, not key/value
            parts.append(render_grid(sec.data, narrow=narrow, avail=avail))
        else:
            parts.append(
                render_table(sec.data, sec.headers, mode="raw", spaced=sec.spaced, key_width=key_width, ratio=sec.ratio)
            )
    return Group(*parts)


def _stringify(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return "\n".join(str(v) for v in value) if value else "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if value is None:
        return "-"
    return str(value)


def _plain(value: Any) -> str:
    """Stringify and strip rich markup (e.g. ``[green]Yes[/]`` -> ``Yes``).

    Shared with export (CSV cells) and activity (log counts) — both need the plain
    text behind a module's colour markup.
    """
    s = _stringify(value)
    return Text.from_markup(s).plain if "[/]" in s else s


def _label(key: Any, mode: str = "upper") -> str:
    """Format a dict key as a column label. ``mode``: ``"upper"`` (ALL CAPS),
    ``"smart"`` (Title Case, acronyms kept upper), or ``"raw"`` (separators
    normalised, original case)."""
    s = str(key).replace("_", " ").replace("-", " ")
    if mode == "upper":
        return s.upper()
    if mode == "smart":
        return " ".join(_smart_token(t) for t in s.split())
    return s


def _is_pairs(data: Any) -> bool:
    """True for a list of (col1, col2) tuples (e.g. the Links tables)."""
    return (
        isinstance(data, (list, tuple))
        and bool(data)
        and all(isinstance(x, (list, tuple)) and len(x) == 2 for x in data)
    )


def _value_cell(value: str) -> Text:
    """Value cell: keep intentional colour markup (Security), else muted grey."""
    if "[/]" in value:
        return Text.from_markup(value)
    return Text(value, style=MUTED)


def _col1_width(data: Any, headers: tuple[str, str] | None, mode: str) -> int | None:
    """Content-fit width for the first column (incl. its header), or None for a
    fixed index column."""
    c1 = (headers or ("Field", "Value"))[0]
    if isinstance(data, dict):
        labels = [len(_label(k, mode)) for k in data]
    elif _is_pairs(data):
        labels = [len(str(a)) for a, _ in data]
    else:
        return None  # list-of-scalars uses the fixed index width
    return min(MAX_KEY_WIDTH, max(labels + [len(c1)], default=len(c1)))


def render_table(
    data: Any,
    headers: tuple[str, str] | None = None,
    mode: str = "upper",
    spaced: bool = True,
    key_width: int | None = None,
    ratio: tuple[int, int] | None = None,
    avail: int | None = None,
) -> Table:
    """Generic key/value (dict), pair-list, or indexed (list) table.

    ``headers`` labels the two columns. ``mode`` cases dict keys — ``"upper"``,
    ``"smart"`` (Title Case, acronyms upper), or ``"raw"``. ``spaced`` inserts a
    blank line between rows. ``key_width`` fixes the first-column width (content-fit
    by default). ``ratio`` (col1, col2) forces proportional columns instead of
    content-fit (e.g. (3, 2) for 60/40). ``avail`` caps the content-fit first column
    at ~⅓ of the table width (it then wraps instead of running the row wide).
    """
    table = Table(
        show_header=headers is not None,
        header_style=HEADER_STYLE,
        border_style=DIVIDER_STYLE,  # very dim header rule
        box=box.SIMPLE,
        expand=True,
        pad_edge=False,
        show_lines=False,
        padding=(0, 1),  # tight; row spacing added via spacer rows below
    )
    if key_width is None:
        key_width = _col1_width(data, headers, mode)
    key_width = _cap_key_width(key_width, avail)

    if isinstance(data, dict) or _is_pairs(data):
        if isinstance(data, dict):
            c1, c2 = headers or ("Field", "Value")
            rows = [(_label(k, mode), _value_cell(_stringify(v))) for k, v in data.items()]
        else:
            c1, c2 = headers or ("Name", "Value")
            rows = [(str(a), _value_cell(str(b))) for a, b in data]
        if ratio:
            table.add_column(c1, style=KEY_STYLE, ratio=ratio[0], no_wrap=False, overflow="fold")
            table.add_column(c2, ratio=ratio[1], no_wrap=False, overflow="fold")
        else:
            # ``ratio`` on the value column makes it the sole flexible column, so
            # Table(expand=True) routes all surplus width there and the fixed-width
            # key column stays put — otherwise Rich spreads the surplus across both
            # columns proportionally and the key column widens when values are short
            # (e.g. an empty Robots/Schema section in the SEO tab). The key column
            # folds (not ellipsis) so a field wider than its ~⅓ cap wraps in place.
            table.add_column(c1, style=KEY_STYLE, width=key_width, no_wrap=False, overflow="fold")
            table.add_column(c2, ratio=1, no_wrap=False, overflow="fold")
        _add_spaced(table, rows, spaced)
    elif isinstance(data, (list, tuple)):
        c1, c2 = headers or ("#", "Value")
        table.add_column(c1, style="dim", width=5)  # left-aligned index
        table.add_column(c2, ratio=1, no_wrap=False, overflow="fold")
        rows = [(str(i), _value_cell(str(row))) for i, row in enumerate(data, 1)]
        _add_spaced(table, rows, spaced)
    else:
        table.add_column(headers[1] if headers else "Value")
        table.add_row(_value_cell(str(data)))
    return table


def _add_spaced(table: Table, rows: list[tuple[str, Any]], spaced: bool = True) -> None:
    """Add rows, optionally with a blank spacer line between them."""
    for i, (a, b) in enumerate(rows):
        table.add_row(a, b)
        if spaced and i != len(rows) - 1:
            table.add_row("", "")


def _flag(country_code: str | None) -> str:
    if not country_code or len(country_code) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code.upper())


#: sentinel: the Tech scan hasn't completed yet, so omit the CMS row entirely
#: (distinct from a completed scan that found no CMS → "Not detected").
UNSET = object()


def render_status(ctx: ScanContext, cms: object = UNSET) -> Table:
    """Fixed status panel: online state, IP, location, ISP/AS, CMS.

    ``cms`` is ``UNSET`` before the Tech scan finishes (row omitted), ``None`` when
    it finished with no CMS ("Not detected"), or ``(name, version|None)`` otherwise.
    """
    geo = ctx.geo or {}
    table = Table(
        show_header=False,
        box=None,
        expand=True,
        pad_edge=False,
        padding=(0, 1, 1, 0),  # blank line under each row, matches main table
    )
    table.add_column("k", style=KEY_STYLE, width=10)
    table.add_column("v", overflow="fold")

    def dim(value: Any) -> Text:
        return Text(str(value), style=MUTED)

    if ctx.online:
        state = Text.from_markup(
            f"[green]● online[/]  [{MUTED}]{ctx.status_code} · {ctx.response_time_ms:.0f}ms[/]"
        )
    elif ctx.fetch_error is not None:
        state = Text.from_markup(f"[{RED}]● offline[/]")
    else:
        state = Text.from_markup("[dim]…[/]")
    table.add_row("Status", state)
    if ctx.final_url:
        table.add_row("Final URL", dim(ctx.final_url))
    if ctx.redirect_status:
        table.add_row("Redirected", dim(ctx.redirect_status))
    ip_cell = Text(ctx.ip or "-", style=MUTED)
    if ctx.ip_shared and ctx.shared_ip_count:
        # Its own line under the IP, e.g. "23.185.0.4\n(Shared · 113 sites)".
        ip_cell.append(f"\n(Shared · {ctx.shared_ip_count} sites)", style=MUTED)
    table.add_row("IP", ip_cell)

    # Location: flag emoji stays in colour (not dimmed), the text is muted.
    if geo:
        loc = Text()
        flag = _flag(geo.get("countryCode"))
        if flag:
            loc.append(flag + " ")
        loc.append(f"{geo.get('city', '-')}, {geo.get('country', '-')}", style=MUTED)
    else:
        loc = dim("-")
    table.add_row("Location", loc)

    # ip-api's `org` is often the actual host (e.g. "Pantheon") vs the network
    # ISP/AS (e.g. "Fastly"); show it when present and distinct.
    org = geo.get("org")
    if org and org != geo.get("isp"):
        table.add_row("Host", dim(org))
    table.add_row("ISP", dim(geo.get("isp") or "-"))
    table.add_row("AS", dim(geo.get("as") or "-"))
    if cms is not UNSET:
        if cms is None:
            table.add_row("CMS", dim("Not detected"))
        else:
            name, version = cms
            table.add_row("CMS", dim(f"{name} {version}" if version else name))
    return table
