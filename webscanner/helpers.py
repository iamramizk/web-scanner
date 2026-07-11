"""URL validation and normalisation helpers (ported/modernised from v1)."""

from __future__ import annotations

import re
from urllib.parse import urlparse

_URL_RE = re.compile(
    r"^(?:http|ftp)s?://"  # scheme
    r"|^"  # or no scheme
    r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"  # domain labels
    r"(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"  # tld
    r"localhost|"
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|"  # ipv4
    r"\[?[A-F0-9]*:[A-F0-9:]+\]?)"  # ipv6
    r"(?::\d+)?"  # port
    r"(?:/?|[/?]\S+)?$",  # path
    re.IGNORECASE,
)


def is_valid_url(url: str) -> bool:
    """True if the string looks like a URL/host we can scan."""
    return re.match(_URL_RE, url) is not None


def to_domain(url: str) -> str:
    """Reduce any URL/host to its bare registrable host (drops scheme, path, www.)."""
    if not urlparse(url).scheme:
        url = "https://" + url
    domain = urlparse(url).netloc or urlparse(url).path
    domain = domain.split("/")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.lower()


def normalise(target: str) -> tuple[str, str]:
    """Return (bare_domain, full_https_url) for a user-supplied target."""
    domain = to_domain(target.strip())
    return domain, f"https://{domain}"
