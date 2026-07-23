"""DNS records module (also folds in email auth: DMARC + DKIM discovery).

SPF and MX already surface as normal TXT/MX records, so we don't duplicate them.
DMARC lives at ``_dmarc.<domain>`` and DKIM keys at ``<selector>._domainkey.<domain>``,
so those aren't in the default record set — we look them up and append rows only
when found (no "present: yes/no" noise).
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import pydig

from ..colors import GREEN, RED
from ..core.module import ScanModule
from ..core.context import ScanContext

RECORD_TYPES = ("A", "AAAA", "NS", "CNAME", "SOA", "MX", "TXT", "CAA", "DS", "DNSKEY")

# Known DKIM selectors across the major providers/ESPs. DKIM can't be enumerated
# from DNS alone, so we probe this list of well-known selectors. The value is the
# provider a hit points to (shown next to the selector); an empty string means the
# selector is generic and doesn't identify a provider on its own.
DKIM_SELECTORS: dict[str, str] = {
    # generic — the selector name alone doesn't identify a provider
    "default": "", "dkim": "", "mail": "", "selector": "", "s": "",
    "s1": "", "s2": "", "key1": "", "dk": "",
    # Microsoft 365 / Outlook
    "selector1": "Microsoft 365", "selector2": "Microsoft 365",
    # Google Workspace
    "google": "Google Workspace",
    # Amazon SES
    "amazonses": "Amazon SES",
    # Zoho
    "zoho": "Zoho", "zmail": "Zoho",
    # ProtonMail
    "protonmail": "Proton Mail", "protonmail2": "Proton Mail", "protonmail3": "Proton Mail",
    # Fastmail
    "fm1": "Fastmail", "fm2": "Fastmail", "fm3": "Fastmail",
    # Mailchimp / Mandrill
    "k1": "Mailchimp", "k2": "Mailchimp", "k3": "Mailchimp", "mandrill": "Mandrill",
    # SendGrid
    "smtpapi": "SendGrid",
    # Postmark
    "pm": "Postmark",
    # Mailgun / generic smtp
    "smtp": "", "mg": "Mailgun", "mailo": "",
    # Campaign Monitor
    "cm": "Campaign Monitor",
    # Apple iCloud
    "sig1": "Apple iCloud",
    # HubSpot
    "hs1": "HubSpot", "hs2": "HubSpot",
    # misc common
    "mxvault": "MXVault", "everlytickey1": "Everlytic", "everlytickey2": "Everlytic",
    "titan1": "Titan", "titan2": "Titan", "turbo-smtp": "TurboSMTP",
    "mailjet": "Mailjet", "sendinblue": "Brevo (Sendinblue)", "klaviyo": "Klaviyo",
}


def _is_dkim(records: list[str]) -> bool:
    return any(("dkim1" in r.lower() or "p=" in r.lower()) for r in records)


# ---- email-spoofing assessment -------------------------------------------
#
# A *configuration* verdict from what DNS already tells us — the same thing MXToolbox /
# dmarcian report, not a live send test. The load-bearing insight: **DMARC enforcement,
# not SPF, is what stops visible (From-header) spoofing.** SPF only authenticates the
# envelope/return-path, so a domain with a perfect `-all` SPF but no DMARC (or `p=none`)
# is still spoofable in a way the recipient sees. So the verdict keys off DMARC policy,
# with SPF only breaking the tie when DMARC is absent.

_ALL_MECHANISM = re.compile(r"([~+?-])all\b", re.I)
_DMARC_TAG = re.compile(r"\b(p|sp|pct)\s*=\s*([^;]+)", re.I)


def _spf_qualifier(txt_records: list[str]) -> str | None:
    """The qualifier of the SPF record's ``all`` mechanism (``-all``/``~all``/``?all``/
    ``+all``), or ``None`` if there's no ``v=spf1`` record or it carries no ``all``."""
    for record in txt_records:
        if record.strip().lower().startswith("v=spf1"):
            if match := _ALL_MECHANISM.search(record):
                return f"{match.group(1)}all"
            return None  # SPF present but no `all` — treat as no explicit policy
    return None


def _dmarc_policy(dmarc_records: list[str]) -> tuple[str | None, int]:
    """``(policy, pct)`` from the first DMARC record — policy is ``p=`` lower-cased
    (``reject``/``quarantine``/``none``) or ``None``; ``pct`` defaults to 100."""
    for record in dmarc_records:
        tags = {m.group(1).lower(): m.group(2).strip() for m in _DMARC_TAG.finditer(record)}
        policy = tags.get("p", "").lower() or None
        try:
            pct = int(tags.get("pct", "100"))
        except ValueError:
            pct = 100
        return policy, pct
    return None, 100


def assess_spoofing(
    txt_records: list[str], dmarc_records: list[str], has_dkim: bool
) -> tuple[str, str]:
    """``(verdict, reason)`` — verdict is ``Protected`` / ``Weak`` / ``Vulnerable``.

    Pure (no ctx, no I/O) so it's unit-testable like the activity-line catalogue.
    """
    spf = _spf_qualifier(txt_records)
    policy, pct = _dmarc_policy(dmarc_records)

    if policy in ("reject", "quarantine"):
        if pct < 100:
            return "Weak", f"DMARC p={policy} but only pct={pct}"
        label = "Protected" if policy == "reject" else "Protected (quarantine)"
        return label, f"DMARC p={policy}"
    if policy == "none":
        return "Weak", "DMARC p=none — monitoring only, mail still delivered"
    # No enforcing DMARC — SPF alone can't stop From-header spoofing.
    if spf == "-all":
        return "Weak", "SPF -all but no DMARC policy"
    if spf:
        return "Vulnerable", f"no DMARC and SPF {spf} (not enforcing)"
    return "Vulnerable", "no DMARC policy and no SPF record"


def _verdict_cell(verdict: str, reason: str) -> str:
    """Colour the verdict verb (green Protected, else red — Weak and Vulnerable are both
    spoofable) with the reason kept alongside. A value with ``[/]`` renders via markup in
    ``_value_cell``."""
    colour = GREEN if verdict.startswith("Protected") else RED
    return f"[{colour}]{verdict}[/] — {reason}"


class DnsModule(ScanModule):
    name = "dns"
    label = "DNS"

    async def run(self, ctx: ScanContext) -> dict[str, Any]:
        domain = ctx.domain

        def records() -> dict[str, list[str]]:
            out: dict[str, list[str]] = {}
            for rtype in RECORD_TYPES:
                res = pydig.query(domain, rtype)
                if res:
                    out[rtype] = res
            return out

        async def www_cname() -> list[str]:
            # The apex almost never has a CNAME (forbidden alongside its SOA/NS), so
            # the standard CNAME lookup above is usually empty. Hosting providers put
            # the CNAME on `www.` instead — surface it when the apex has none.
            return await asyncio.to_thread(pydig.query, f"www.{domain}", "CNAME")

        async def dmarc() -> list[str]:
            txt = await asyncio.to_thread(pydig.query, f"_dmarc.{domain}", "TXT")
            return [t for t in txt if "dmarc1" in t.lower()]

        async def dkim_selector(sel: str) -> str | None:
            txt = await asyncio.to_thread(pydig.query, f"{sel}._domainkey.{domain}", "TXT")
            return sel if txt and _is_dkim(txt) else None

        out, www, dmarc_records, dkim_hits = await asyncio.gather(
            asyncio.to_thread(records),
            www_cname(),
            dmarc(),
            asyncio.gather(*(dkim_selector(s) for s in DKIM_SELECTORS)),
        )

        # Show the www CNAME when the apex has none (the common hosting-provider case).
        if www and "CNAME" not in out:
            out["CNAME (www)"] = www

        if dmarc_records:
            out["DMARC"] = dmarc_records
        found = [s for s in dkim_hits if s]
        if found:
            out["DKIM"] = [
                f"{s}  ({DKIM_SELECTORS[s]})" if DKIM_SELECTORS[s] else s
                for s in found
            ]

        # Derived email-spoofing verdict from the records above (no extra network work).
        # SPF sits inside the TXT records; surface its `all` qualifier, then the verdict.
        if (spf := _spf_qualifier(out.get("TXT", []))) is not None:
            out["SPF"] = [spf]
        verdict, reason = assess_spoofing(out.get("TXT", []), dmarc_records, bool(found))
        out["Email Spoofing"] = [_verdict_cell(verdict, reason)]
        return out
