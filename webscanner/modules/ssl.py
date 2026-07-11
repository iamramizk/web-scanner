"""SSL/TLS certificate module (uses the cert grabbed in prefetch)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..core.module import ScanModule
from ..core.context import ScanContext

_CERT_DATE = "%b %d %H:%M:%S %Y %Z"


def _flatten(pairs: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for rdn in pairs or ():
        for key, value in rdn:
            out[key] = value
    return out


class SslModule(ScanModule):
    name = "ssl"
    label = "SSL"

    async def run(self, ctx: ScanContext) -> dict[str, Any]:
        cert = ctx.tls_cert
        if not cert:
            return {}

        subject = _flatten(cert.get("subject"))
        issuer = _flatten(cert.get("issuer"))
        sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]

        result: dict[str, Any] = {
            "subject_cn": subject.get("commonName"),
            "issuer_org": issuer.get("organizationName"),
            "issuer_cn": issuer.get("commonName"),
            "valid_from": cert.get("notBefore"),
            "valid_until": cert.get("notAfter"),
            "san_count": len(sans),
            "san": sans[:20],
        }

        not_after = cert.get("notAfter")
        if not_after:
            try:
                expires = datetime.strptime(not_after, _CERT_DATE).replace(tzinfo=timezone.utc)
                days = (expires - datetime.now(timezone.utc)).days
                result["days_until_expiry"] = days
                result["expired"] = days < 0
                # A successful handshake in prefetch means the chain validated
                # against the system trust store.
                result["trusted"] = not result["expired"]
            except ValueError:
                pass
        return result
