"""DNS records module (also folds in email auth: DMARC + DKIM discovery).

SPF and MX already surface as normal TXT/MX records, so we don't duplicate them.
DMARC lives at ``_dmarc.<domain>`` and DKIM keys at ``<selector>._domainkey.<domain>``,
so those aren't in the default record set — we look them up and append rows only
when found (no "present: yes/no" noise).
"""

from __future__ import annotations

import asyncio
from typing import Any

import pydig

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

        async def dmarc() -> list[str]:
            txt = await asyncio.to_thread(pydig.query, f"_dmarc.{domain}", "TXT")
            return [t for t in txt if "dmarc1" in t.lower()]

        async def dkim_selector(sel: str) -> str | None:
            txt = await asyncio.to_thread(pydig.query, f"{sel}._domainkey.{domain}", "TXT")
            return sel if txt and _is_dkim(txt) else None

        out, dmarc_records, dkim_hits = await asyncio.gather(
            asyncio.to_thread(records),
            dmarc(),
            asyncio.gather(*(dkim_selector(s) for s in DKIM_SELECTORS)),
        )

        if dmarc_records:
            out["DMARC"] = dmarc_records
        found = [s for s in dkim_hits if s]
        if found:
            out["DKIM"] = [
                f"{s}  ({DKIM_SELECTORS[s]})" if DKIM_SELECTORS[s] else s
                for s in found
            ]
        return out
