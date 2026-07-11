"""WHOIS module — async subprocess, no temp files, rich normalised key set.

Shells out to the system ``whois`` (the same output you'd see in a terminal) and
parses it robustly:

- If the output contains a referral marker (``# whois.<server>``), only the last
  section is parsed — this drops the IANA/registry TLD block (which for ccTLDs
  like .au otherwise pollutes the domain fields with the *TLD's* dates/nameservers).
- Fields are matched **most-specific prefix first** across all lines, so e.g.
  ``Domain Name:`` wins over a stray ``domain:``.
- Covers gTLD *and* ccTLD label variants incl. per-contact names (Registrant /
  Admin / Tech Contact Name).
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

from ..core.module import ScanModule
from ..core.context import ScanContext

# canonical field -> candidate label prefixes (lowercased), most-specific first
_FIELDS: dict[str, tuple[str, ...]] = {
    "domain": ("domain name:", "domain:"),
    "registry_domain_id": ("registry domain id:",),
    "registrar": ("registrar name:", "registrar:", "sponsoring registrar:"),
    "registrar_url": ("registrar url:", "registrar web:", "referral url:"),
    "registrar_whois": ("registrar whois server:", "whois server:"),
    "registrar_iana_id": ("registrar iana id:",),
    "registrar_abuse_email": ("registrar abuse contact email:",),
    "registrar_abuse_phone": ("registrar abuse contact phone:",),
    "reseller": ("reseller name:", "reseller:"),
    "creation_date": ("creation date:", "created on:", "registered on:", "domain registration date:", "created:", "registered:"),
    "updated_date": ("updated date:", "last modified:", "last updated:", "modified:", "changed:"),
    "expiry_date": ("registry expiry date:", "registrar registration expiration date:", "expiry date:", "expiration date:", "expires:", "expire:", "paid-till:"),
    "registrant_name": ("registrant contact name:", "registrant name:"),
    "registrant_org": ("registrant organization:", "registrant organisation:", "registrant:", "organization:", "org:"),
    "registrant_id": ("registrant contact id:", "registrant id:"),
    "registrant_email": ("registrant contact email:", "registrant email:"),
    "registrant_phone": ("registrant contact phone:", "registrant phone:"),
    "registrant_country": ("registrant country:", "country:"),
    "admin_name": ("admin contact name:", "admin name:", "administrative contact:"),
    "admin_email": ("admin contact email:", "admin email:"),
    "tech_name": ("tech contact name:", "tech name:", "technical contact:"),
    "tech_email": ("tech contact email:", "tech email:"),
    "eligibility": ("eligibility type:",),
    "status_reason": ("status reason:",),
    "dnssec": ("dnssec:",),
}


def _first(lines: list[tuple[str, str]], prefixes: tuple[str, ...]) -> str | None:
    for pfx in prefixes:  # prefix-priority: most specific wins regardless of order
        for low, raw in lines:
            if low.startswith(pfx):
                value = raw[len(pfx):].strip()
                if value:
                    return value
    return None


def _multi(lines: list[tuple[str, str]], *prefixes: str) -> list[str]:
    out: list[str] = []
    for low, raw in lines:
        if low.startswith(prefixes):
            out.append(raw.split(":", 1)[1].strip())
    return out


class WhoisModule(ScanModule):
    name = "whois"
    label = "Whois"

    async def run(self, ctx: ScanContext) -> dict[str, Any]:
        proc = await asyncio.create_subprocess_exec(
            "whois",
            ctx.domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        text = stdout.decode("utf-8", errors="replace")

        raw = text.splitlines()
        # keep only the authoritative section (after the last referral marker)
        markers = [i for i, ln in enumerate(raw) if ln.lstrip().lower().startswith("# whois.")]
        if markers:
            raw = raw[markers[-1] + 1:]

        lines = [
            (ln.strip().lower(), ln.strip())
            for ln in raw
            if ":" in ln and not ln.lstrip().startswith(("%", "#", ">>>"))
        ]

        result: dict[str, Any] = {}
        for field, prefixes in _FIELDS.items():
            value = _first(lines, prefixes)
            if value:
                result[field] = value

        ns = _multi(lines, "name server:", "nserver:", "nameserver:")
        if ns:
            result["name_servers"] = sorted({n.split()[0].lower() for n in ns if n})

        status = _multi(lines, "domain status:", "status:")
        if status:
            result["status"] = sorted({s for s in status if s})

        if not result and re.search(r"no match|not found|no entries found", text, re.IGNORECASE):
            result["note"] = "no WHOIS match / not found"
        return result
