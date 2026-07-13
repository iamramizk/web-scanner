"""Public Suffix List → registrable domain (eTLD+1) resolution.

Uses a vendored snapshot of Mozilla's Public Suffix List
(``data/public_suffix_list.dat``) — a static file, no network at runtime. The
list is the only way to know a suffix's length: ``.com`` is one label, ``.co.uk``
two, ``.pvt.k12.ma.us`` four, so there is no rule, only the list.

Matching follows the PSL algorithm: pick the longest suffix rule matching the
host's trailing labels (``*`` matches any single label, ``!`` marks an exception
that shortens the match by one), then the registrable domain is that suffix plus
one more label to its left.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

_DATA = Path(__file__).with_name("data") / "public_suffix_list.dat"


def _puny(label: str) -> str:
    """Normalise a single DNS label to lowercase ASCII (punycode).

    The PSL stores IDN entries in Unicode (公司.cn) while real hostnames arrive as
    punycode (xn--55qx5d.cn); normalising both to ASCII lets them match. ASCII and
    wildcard/exception markers pass through unchanged."""
    if label.isascii():
        return label.lower()
    try:
        return label.encode("idna").decode("ascii")
    except Exception:  # noqa: BLE001 - un-encodable label: leave as-is
        return label.lower()


def _normalise(name: str) -> str:
    """Punycode-normalise every label of a dotted name (keeps ``*``/``!`` markers)."""
    return ".".join(_puny(lbl) for lbl in name.split("."))


@lru_cache(maxsize=1)
def _rules() -> tuple[frozenset[str], frozenset[str]]:
    """Parse the PSL once into (normal+wildcard rules, exception rules)."""
    rules: set[str] = set()
    exceptions: set[str] = set()
    for raw in _DATA.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("!"):
            exceptions.add(_normalise(line[1:]))
        else:
            rules.add(_normalise(line))
    return frozenset(rules), frozenset(exceptions)


def public_suffix(host: str) -> str | None:
    """Return the effective TLD (public suffix) for ``host``, or None.

    e.g. ``www.example.co.uk`` → ``co.uk``, ``a.github.io`` → ``github.io``.
    """
    host = _normalise(host.strip("."))
    if not host:
        return None
    rules, exceptions = _rules()
    labels = host.split(".")

    # An exception rule wins: the suffix is the exception minus its leftmost label.
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in exceptions:
            return ".".join(labels[i + 1:]) or None

    # Otherwise the longest matching normal/wildcard rule wins.
    best: str | None = None
    for i in range(len(labels)):
        suffix = labels[i:]
        exact = ".".join(suffix)
        wildcard = ".".join(["*", *suffix[1:]]) if suffix else ""
        if exact in rules or (wildcard and wildcard in rules):
            best = exact
            break  # first match is the longest (we scan left→right, longest first)
    if best is not None:
        return best
    # Unlisted TLD: the PSL default rule is "*", so the suffix is the last label.
    return labels[-1]


def registrable_domain(host: str | None) -> str:
    """Return the registrable domain (eTLD+1) for ``host``.

    ``www.example.co.uk`` → ``example.co.uk``; ``a.github.io`` → ``a.github.io``.
    Returns the lowercased host itself when it is a public suffix with nothing to
    its left, or "" for an empty/None host.
    """
    if not host:
        return ""
    host = _normalise(host.strip("."))
    suffix = public_suffix(host)
    if suffix is None or suffix == host:
        return host
    extra = host[: -(len(suffix) + 1)]  # strip ".<suffix>"
    if not extra:
        return host  # host *is* the public suffix
    return f"{extra.rsplit('.', 1)[-1]}.{suffix}"
