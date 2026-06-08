"""CERTPATROL engine.

Inputs come from a Certificate Transparency monitor export (e.g. certspotter /
crt.sh JSON, or your own CT poller dumped to a file). Each record describes one
issued leaf certificate: the DNS names it covers, the issuer, validity window,
and a serial / SHA-256 fingerprint.

The engine answers two operational questions:

  1. ROGUE ISSUANCE: was a certificate issued for a domain I monitor, by an
     issuer / for a key I never authorized? (the certspotter use case)
  2. LIFECYCLE: which of my legitimately-issued certs are expiring soon (or
     already expired) so I can renew before an outage?

Pure standard library; no network. All time handling is UTC.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Iterable


# --------------------------------------------------------------------------- #
# Time helpers
# --------------------------------------------------------------------------- #
_NOW_OVERRIDE: datetime | None = None  # tests pin "now" for determinism


def _now() -> datetime:
    return _NOW_OVERRIDE or datetime.now(timezone.utc)


def _parse_dt(value: str) -> datetime:
    """Accept ISO-8601 with 'Z' or offset, or a bare date."""
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        dt = datetime.strptime(s, "%Y-%m-%d")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def days_until(value: str) -> int:
    """Whole days from now until `value` (negative if past). Rounded down."""
    delta = _parse_dt(value) - _now()
    return delta.days


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Certificate:
    dns_names: list[str]
    issuer: str
    not_before: str
    not_after: str
    serial: str = ""
    fingerprint_sha256: str = ""
    pubkey_sha256: str = ""
    source: str = ""

    @classmethod
    def from_obj(cls, obj: dict[str, Any]) -> "Certificate":
        raw_names = (
            obj.get("dns_names")
            or obj.get("names")
            or obj.get("subject_alt_names")
            or []
        )
        if isinstance(raw_names, str):
            raw_names = [n.strip() for n in re.split(r"[,\s]+", raw_names) if n.strip()]
        norm = [n.strip().lower().rstrip(".") for n in raw_names]

        return cls(
            dns_names=norm,
            issuer=str(obj.get("issuer") or obj.get("issuer_name") or "unknown"),
            not_before=str(obj.get("not_before") or obj.get("notBefore") or ""),
            not_after=str(obj.get("not_after") or obj.get("notAfter") or ""),
            serial=str(obj.get("serial") or obj.get("serial_number") or ""),
            fingerprint_sha256=str(
                obj.get("fingerprint_sha256")
                or obj.get("sha256")
                or obj.get("tbs_sha256")
                or ""
            ).lower(),
            pubkey_sha256=str(
                obj.get("pubkey_sha256") or obj.get("spki_sha256") or ""
            ).lower(),
            source=str(obj.get("source") or obj.get("log") or ""),
        )


@dataclass
class Watchlist:
    """Domains you own and the issuance you DO authorize."""
    domains: list[str] = field(default_factory=list)
    allowed_issuers: list[str] = field(default_factory=list)
    allowed_fingerprints: list[str] = field(default_factory=list)
    allowed_pubkeys: list[str] = field(default_factory=list)
    expiry_warn_days: int = 21

    @classmethod
    def from_obj(cls, obj: dict[str, Any]) -> "Watchlist":
        return cls(
            domains=[d.strip().lower().rstrip(".") for d in obj.get("domains", [])],
            allowed_issuers=[s.lower() for s in obj.get("allowed_issuers", [])],
            allowed_fingerprints=[s.lower() for s in obj.get("allowed_fingerprints", [])],
            allowed_pubkeys=[s.lower() for s in obj.get("allowed_pubkeys", [])],
            expiry_warn_days=int(obj.get("expiry_warn_days", 21)),
        )


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    kind: str            # rogue_issuance | unauthorized_issuer | expiring | expired
    severity: str        # critical | high | medium | low | info
    domain: str          # which monitored domain matched
    message: str
    certificate: dict[str, Any]


# --------------------------------------------------------------------------- #
# Matching logic
# --------------------------------------------------------------------------- #
def name_covered(cert_name: str, monitored: str) -> bool:
    """Does a cert SAN entry cover a monitored domain?

    Matches exact, subdomain (monitored apex catches a cert for any of its
    subdomains), and wildcard certs (a single label below the wildcard base).
    Both sides are lowercased & dot-stripped.
    """
    cert_name = cert_name.lower().rstrip(".")
    monitored = monitored.lower().rstrip(".")
    if cert_name == monitored:
        return True
    if cert_name.startswith("*."):
        base = cert_name[2:]
        return monitored == base or (
            monitored.endswith("." + base)
            and monitored[: -(len(base) + 1)].count(".") == 0
        )
    if monitored.startswith("*."):
        base = monitored[2:]
        return cert_name == base or cert_name.endswith("." + base)
    # monitored apex catches any cert covering a subdomain of it
    return cert_name.endswith("." + monitored)


def _matched_domains(cert: Certificate, watch: Watchlist) -> list[str]:
    hits = []
    for mon in watch.domains:
        for cn in cert.dns_names:
            if name_covered(cn, mon):
                hits.append(mon)
                break
    return hits


def _issuer_authorized(cert: Certificate, watch: Watchlist) -> bool:
    if not watch.allowed_issuers:
        return True  # no allowlist => issuer is not the signal
    iss = cert.issuer.lower()
    return any(allowed in iss for allowed in watch.allowed_issuers)


def _fingerprint_authorized(cert: Certificate, watch: Watchlist) -> bool:
    fp = cert.fingerprint_sha256
    pk = cert.pubkey_sha256
    if fp and fp in watch.allowed_fingerprints:
        return True
    if pk and pk in watch.allowed_pubkeys:
        return True
    return False


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def parse_certs(data: str | bytes | Iterable[dict]) -> list[Certificate]:
    """Parse a CT monitor export: JSON array, JSON object {certificates:[...]},
    or newline-delimited JSON (one cert per line)."""
    if isinstance(data, (list, tuple)):
        return [Certificate.from_obj(o) for o in data]
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    text = data.strip()
    if not text:
        return []
    objs: list[dict] = []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            parsed = parsed.get("certificates") or parsed.get("certs") or [parsed]
        objs = list(parsed)
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if line:
                objs.append(json.loads(line))
    return [Certificate.from_obj(o) for o in objs]


def load_watchlist(data: str | bytes | dict) -> Watchlist:
    if isinstance(data, dict):
        return Watchlist.from_obj(data)
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return Watchlist.from_obj(json.loads(data))


def analyze(certs: list[Certificate], watch: Watchlist) -> list[Finding]:
    """Produce findings for certs that touch a monitored domain."""
    findings: list[Finding] = []
    for cert in certs:
        domains = _matched_domains(cert, watch)
        if not domains:
            continue
        primary = domains[0]
        cert_d = asdict(cert)

        explicit_ok = _fingerprint_authorized(cert, watch)
        issuer_ok = _issuer_authorized(cert, watch)

        if not explicit_ok and not issuer_ok:
            findings.append(Finding(
                kind="rogue_issuance",
                severity="critical",
                domain=primary,
                message=(
                    f"Certificate for {', '.join(domains)} issued by "
                    f"'{cert.issuer}' is NOT on the allowed-issuer list and its "
                    f"fingerprint/key is unrecognized — possible mis-issuance."
                ),
                certificate=cert_d,
            ))
        elif not explicit_ok and watch.allowed_fingerprints and not issuer_ok:
            findings.append(Finding(
                kind="unauthorized_issuer",
                severity="high",
                domain=primary,
                message=f"Unrecognized cert for {primary} from '{cert.issuer}'.",
                certificate=cert_d,
            ))

        # lifecycle checks
        if cert.not_after:
            left = days_until(cert.not_after)
            if left < 0:
                findings.append(Finding(
                    kind="expired",
                    severity="high",
                    domain=primary,
                    message=f"Certificate for {primary} EXPIRED {abs(left)}d ago "
                            f"({cert.not_after}).",
                    certificate=cert_d,
                ))
            elif left <= watch.expiry_warn_days and (explicit_ok or issuer_ok):
                findings.append(Finding(
                    kind="expiring",
                    severity="medium" if left > 7 else "high",
                    domain=primary,
                    message=f"Certificate for {primary} expires in {left}d "
                            f"({cert.not_after}) — renew soon.",
                    certificate=cert_d,
                ))

    findings.sort(key=lambda f: (SEV_ORDER.get(f.severity, 9), f.kind, f.domain))
    return findings
