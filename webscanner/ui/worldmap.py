"""Country-level location map, rendered from embedded country borders.

Re-engineered from the old coarse box model: it loads low-resolution Natural
Earth country polygons (``data/countries.json``, built once from the 110m
dataset), auto-frames the view to the server's country plus surrounding
countries, and rasterises the real border lines into a braille grid with the
location marked. Projection is equirectangular with a cos(latitude) correction
so shapes aren't stretched. No zoom — the frame is chosen automatically.
"""

from __future__ import annotations

import json
import math
from functools import lru_cache
from pathlib import Path

from rich.text import Text

_DATA = Path(__file__).parent / "data" / "countries.json"
_CHAR_ASPECT = 2.0  # terminal cell height:width

# braille dot bit for a (row, col) within a 2-wide x 4-tall cell
_BITS = {
    (0, 0): 0x01, (1, 0): 0x02, (2, 0): 0x04, (3, 0): 0x40,
    (0, 1): 0x08, (1, 1): 0x10, (2, 1): 0x20, (3, 1): 0x80,
}

Ring = list[tuple[float, float]]
BBox = tuple[float, float, float, float]  # minlon, minlat, maxlon, maxlat


@lru_cache(maxsize=1)
def _countries() -> list[tuple[str, list[tuple[Ring, BBox]]]]:
    """Load countries as (name, [(ring, bbox), ...]); cached for the process."""
    raw = json.loads(_DATA.read_text())
    out = []
    for country in raw:
        rings = []
        for ring in country["r"]:
            pts = [(p[0], p[1]) for p in ring]
            if len(pts) < 3:
                continue
            lons = [p[0] for p in pts]
            lats = [p[1] for p in pts]
            rings.append((pts, (min(lons), min(lats), max(lons), max(lats))))
        out.append((country["n"], rings))
    return out


def _point_in_ring(lon: float, lat: float, ring: Ring) -> bool:
    inside = False
    n = len(ring)
    j = n - 1
    for i in range(n):
        xi, yi = ring[i]
        xj, yj = ring[j]
        if (yi > lat) != (yj > lat):
            x_cross = (xj - xi) * (lat - yi) / (yj - yi) + xi
            if lon < x_cross:
                inside = not inside
        j = i
    return inside


def _containing_ring(lat: float, lon: float) -> tuple[str, BBox] | None:
    """Return (country_name, bbox) of the specific landmass ring under (lat, lon)."""
    for name, rings in _countries():
        for ring, (mnx, mny, mxx, mxy) in rings:
            if mnx <= lon <= mxx and mny <= lat <= mxy and _point_in_ring(lon, lat, ring):
                return name, (mnx, mny, mxx, mxy)
    return None


def render(
    lat: float | None = None,
    lon: float | None = None,
    cols: int = 56,
    rows: int = 14,
    zoom: float = 1.0,
    marker: str = "●",
    marker_style: str = "bold green",
    border_style: str = "grey58",
    home_style: str = "grey85",
) -> Text:
    """Render an outline map framed on the server's country + neighbours.

    ``zoom`` > 1 tightens the frame (closer), < 1 widens it (more surroundings).
    """
    cols, rows = max(8, cols), max(4, rows)
    if lat is None or lon is None:
        return Text("no location", style="dim")

    hit = _containing_ring(lat, lon)
    home_name = hit[0] if hit else None
    if hit:
        mnx, mny, mxx, mxy = hit[1]
    else:  # ocean / unmatched — frame a default box around the marker
        mnx, mny, mxx, mxy = lon - 6, lat - 6, lon + 6, lat + 6

    cx, cy = (mnx + mxx) / 2, (mny + mxy) / 2
    # frame span: country size + margin, with a floor so tiny countries aren't over-zoomed
    lon_span = max(mxx - mnx, 6.0) * 1.6
    lat_span = max(mxy - mny, 4.0) * 1.6

    # aspect fit (cos-corrected) — expand the deficient axis so nothing distorts
    k = max(0.15, math.cos(math.radians(cy)))
    target = cols / (2 * rows)  # desired projected width:height for square pixels
    if (lon_span * k) / lat_span < target:
        lon_span = target * lat_span / k
    else:
        lat_span = (lon_span * k) / target

    lon_span /= zoom  # user zoom (both axes equally → aspect preserved)
    lat_span /= zoom

    # Keep the marker inside the frame (within the central 80%) at any zoom, by
    # nudging the frame centre toward it — so zooming in never loses the point.
    cx = min(max(cx, lon - lon_span * 0.4), lon + lon_span * 0.4)
    cy = min(max(cy, lat - lat_span * 0.4), lat + lat_span * 0.4)

    lon0, lat_top = cx - lon_span / 2, cy + lat_span / 2
    pw, ph = cols * 2, rows * 4
    view = (lon0, cy - lat_span / 2, lon0 + lon_span, lat_top)  # for bbox culling

    def to_px(lon_: float, lat_: float) -> tuple[float, float]:
        return (lon_ - lon0) / lon_span * pw, (lat_top - lat_) / lat_span * ph

    grid = [bytearray(pw) for _ in range(ph)]  # 0 empty, 1 border, 2 home border

    def plot(x: int, y: int, v: int) -> None:
        if 0 <= x < pw and 0 <= y < ph and grid[y][x] < v:
            grid[y][x] = v

    def draw_line(x0: float, y0: float, x1: float, y1: float, v: int) -> None:
        # integer Bresenham over the (possibly out-of-range) endpoints
        xi0, yi0, xi1, yi1 = int(x0), int(y0), int(x1), int(y1)
        dx, dy = abs(xi1 - xi0), -abs(yi1 - yi0)
        sx = 1 if xi0 < xi1 else -1
        sy = 1 if yi0 < yi1 else -1
        err = dx + dy
        while True:
            plot(xi0, yi0, v)
            if xi0 == xi1 and yi0 == yi1:
                break
            e2 = 2 * err
            if e2 >= dy:
                err += dy
                xi0 += sx
            if e2 <= dx:
                err += dx
                yi0 += sy

    vmnx, vmny, vmxx, vmxy = view
    for name, rings in _countries():
        v = 2 if name == home_name else 1
        for ring, (rmnx, rmny, rmxx, rmxy) in rings:
            if rmxx < vmnx or rmnx > vmxx or rmxy < vmny or rmny > vmxy:
                continue  # ring entirely outside view
            prev = ring[-1]
            for cur in ring:
                x0, y0 = to_px(*prev)
                x1, y1 = to_px(*cur)
                draw_line(x0, y0, x1, y1, v)
                prev = cur

    mpx, mpy = to_px(lon, lat)
    mcx, mcy = int(mpx) // 2, int(mpy) // 4

    text = Text()
    for cyc in range(rows):
        for cxc in range(cols):
            if cxc == mcx and cyc == mcy:
                text.append(marker, style=marker_style)
                continue
            bits = home = 0
            for (r, c), bit in _BITS.items():
                cell = grid[cyc * 4 + r][cxc * 2 + c]
                if cell:
                    bits |= bit
                    if cell == 2:
                        home = 1
            if bits:
                text.append(chr(0x2800 + bits), style=home_style if home else border_style)
            else:
                text.append(" ")
        if cyc != rows - 1:
            text.append("\n")
    return text


def country_name(lat: float | None, lon: float | None) -> str | None:
    """Name of the country at (lat, lon), for the panel title (or None)."""
    if lat is None or lon is None:
        return None
    hit = _containing_ring(lat, lon)
    return hit[0] if hit else None
