"""Smoke tests for CERTPATROL. No network. Deterministic 'now'."""
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import certpatrol  # noqa: E402
from certpatrol import core  # noqa: E402
from certpatrol.cli import main  # noqa: E402


def _pin_now(monkeypatch):
    monkeypatch.setattr(core, "_NOW_OVERRIDE",
                        datetime(2026, 6, 8, tzinfo=timezone.utc))


def test_exports():
    assert certpatrol.TOOL_NAME == "certpatrol"
    assert certpatrol.TOOL_VERSION


def test_name_covered():
    assert core.name_covered("www.greenway.com", "www.greenway.com")
    assert core.name_covered("*.greenway.com", "mail.greenway.com")
    assert not core.name_covered("*.greenway.com", "a.b.greenway.com")
    assert core.name_covered("mail.greenway.com", "greenway.com")  # apex catches sub
    assert not core.name_covered("greenway.com", "other.com")


def test_rogue_issuance_detected(monkeypatch):
    _pin_now(monkeypatch)
    certs = core.parse_certs(json.dumps([
        {"dns_names": ["*.greenway.com"], "issuer": "WoSign Free",
         "not_after": "2027-01-01Z", "fingerprint_sha256": "bad"},
    ]))
    watch = core.load_watchlist({"domains": ["greenway.com"],
                                 "allowed_issuers": ["Let's Encrypt"]})
    findings = core.analyze(certs, watch)
    kinds = {f.kind for f in findings}
    assert "rogue_issuance" in kinds
    assert findings[0].severity == "critical"


def test_authorized_cert_no_rogue(monkeypatch):
    _pin_now(monkeypatch)
    certs = core.parse_certs(json.dumps([
        {"dns_names": ["greenway.com"], "issuer": "Let's Encrypt R3",
         "not_after": "2027-01-01Z"},
    ]))
    watch = core.load_watchlist({"domains": ["greenway.com"],
                                 "allowed_issuers": ["Let's Encrypt"]})
    findings = core.analyze(certs, watch)
    assert not any(f.kind == "rogue_issuance" for f in findings)


def test_expiry_detection(monkeypatch):
    _pin_now(monkeypatch)
    certs = core.parse_certs(json.dumps([
        {"dns_names": ["greenway.com"], "issuer": "Let's Encrypt R3",
         "not_after": "2026-06-15Z"},
        {"dns_names": ["greenway.com"], "issuer": "Let's Encrypt R3",
         "not_after": "2026-05-01Z"},
    ]))
    watch = core.load_watchlist({"domains": ["greenway.com"],
                                 "allowed_issuers": ["Let's Encrypt"]})
    findings = core.analyze(certs, watch)
    kinds = {f.kind for f in findings}
    assert "expiring" in kinds
    assert "expired" in kinds


def test_unrelated_cert_ignored(monkeypatch):
    _pin_now(monkeypatch)
    certs = core.parse_certs(json.dumps([
        {"dns_names": ["evil.example.org"], "issuer": "WoSign",
         "not_after": "2027-01-01Z"},
    ]))
    watch = core.load_watchlist({"domains": ["greenway.com"]})
    assert core.analyze(certs, watch) == []


def test_ndjson_parsing():
    text = ('{"dns_names": ["a.com"], "issuer": "X", "not_after": "2027-01-01Z"}\n'
            '{"dns_names": ["b.com"], "issuer": "Y", "not_after": "2027-01-01Z"}')
    certs = core.parse_certs(text)
    assert len(certs) == 2


def test_cli_json_and_exit_code(tmp_path, monkeypatch, capsys):
    _pin_now(monkeypatch)
    certs_f = tmp_path / "c.json"
    watch_f = tmp_path / "w.json"
    certs_f.write_text(json.dumps([
        {"dns_names": ["*.greenway.com"], "issuer": "WoSign",
         "not_after": "2027-01-01Z"},
    ]))
    watch_f.write_text(json.dumps({"domains": ["greenway.com"],
                                   "allowed_issuers": ["Let's Encrypt"]}))
    rc = main(["watch", "--certs", str(certs_f),
               "--watchlist", str(watch_f), "--format", "json"])
    assert rc == 2  # findings present
    out = json.loads(capsys.readouterr().out)
    assert out["tool"] == "certpatrol"
    assert out["finding_count"] >= 1


def test_cli_clean_exit_zero(tmp_path, monkeypatch, capsys):
    _pin_now(monkeypatch)
    certs_f = tmp_path / "c.json"
    watch_f = tmp_path / "w.json"
    certs_f.write_text(json.dumps([
        {"dns_names": ["greenway.com"], "issuer": "Let's Encrypt R3",
         "not_after": "2027-01-01Z"},
    ]))
    watch_f.write_text(json.dumps({"domains": ["greenway.com"],
                                   "allowed_issuers": ["Let's Encrypt"]}))
    rc = main(["watch", "--certs", str(certs_f), "--watchlist", str(watch_f)])
    assert rc == 0


def test_cli_missing_file_exit_one(tmp_path):
    rc = main(["watch", "--certs", str(tmp_path / "nope.json"),
               "--watchlist", str(tmp_path / "nope2.json")])
    assert rc == 1
