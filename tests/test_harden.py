"""Hardening tests: edge cases, bad input, error paths. No network."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from certpatrol import core  # noqa: E402
from certpatrol.cli import main  # noqa: E402


def _pin_now(monkeypatch):
    monkeypatch.setattr(core, "_NOW_OVERRIDE",
                        datetime(2026, 6, 8, tzinfo=timezone.utc))


# ---------------------------------------------------------------------------
# core._parse_dt — bad input
# ---------------------------------------------------------------------------

def test_parse_dt_empty_string():
    """Empty string must raise ValueError, not crash with AttributeError."""
    with pytest.raises(ValueError, match="empty"):
        core._parse_dt("")


def test_parse_dt_whitespace_only():
    with pytest.raises(ValueError, match="empty"):
        core._parse_dt("   ")


def test_parse_dt_garbage():
    with pytest.raises(ValueError, match="unrecognised date format"):
        core._parse_dt("not-a-date")


# ---------------------------------------------------------------------------
# core.parse_certs — malformed NDJSON
# ---------------------------------------------------------------------------

def test_parse_certs_empty_input():
    """Empty string must return an empty list."""
    assert core.parse_certs("") == []
    assert core.parse_certs(b"") == []


def test_parse_certs_empty_array():
    """JSON empty array must return an empty list."""
    assert core.parse_certs("[]") == []


def test_parse_certs_malformed_ndjson():
    """A bad NDJSON line must raise ValueError with a line number, not crash."""
    bad = ('{"dns_names": ["a.com"], "issuer": "X", "not_after": "2027-01-01Z"}\n'
           'NOT JSON AT ALL\n')
    with pytest.raises(ValueError, match="line 2"):
        core.parse_certs(bad)


# ---------------------------------------------------------------------------
# core.load_watchlist — bad expiry_warn_days
# ---------------------------------------------------------------------------

def test_watchlist_negative_expiry_warn_days():
    with pytest.raises(ValueError, match="expiry_warn_days"):
        core.load_watchlist({"domains": ["example.com"], "expiry_warn_days": -1})


def test_watchlist_non_integer_expiry_warn_days():
    with pytest.raises(ValueError, match="expiry_warn_days"):
        core.load_watchlist({"domains": ["example.com"], "expiry_warn_days": "soon"})


def test_watchlist_domains_null():
    """domains: null is treated leniently as an empty domain list (no crash)."""
    wl = core.load_watchlist({"domains": None})
    assert wl.domains == []


def test_watchlist_zero_expiry_warn_days():
    """Zero is a valid (if unusual) setting."""
    wl = core.load_watchlist({"domains": [], "expiry_warn_days": 0})
    assert wl.expiry_warn_days == 0


# ---------------------------------------------------------------------------
# core.analyze — malformed not_after date
# ---------------------------------------------------------------------------

def test_analyze_malformed_not_after(monkeypatch):
    """A cert with a garbage not_after date must produce a finding, not crash."""
    _pin_now(monkeypatch)
    certs = core.parse_certs(json.dumps([
        {"dns_names": ["greenway.com"], "issuer": "Let's Encrypt R3",
         "not_after": "GARBAGE-DATE"},
    ]))
    watch = core.load_watchlist({"domains": ["greenway.com"],
                                 "allowed_issuers": ["Let's Encrypt"]})
    findings = core.analyze(certs, watch)
    assert len(findings) == 1
    assert findings[0].kind == "expiring"
    assert "unreadable" in findings[0].message


def test_analyze_empty_cert_list(monkeypatch):
    """Empty cert list must return empty findings."""
    _pin_now(monkeypatch)
    watch = core.load_watchlist({"domains": ["greenway.com"]})
    assert core.analyze([], watch) == []


def test_analyze_empty_domain_list(monkeypatch):
    """Watchlist with no domains — no cert can match, zero findings."""
    _pin_now(monkeypatch)
    certs = core.parse_certs(json.dumps([
        {"dns_names": ["greenway.com"], "issuer": "Let's Encrypt R3",
         "not_after": "2027-01-01Z"},
    ]))
    watch = core.load_watchlist({"domains": []})
    assert core.analyze(certs, watch) == []


# ---------------------------------------------------------------------------
# cli — bad input exit codes
# ---------------------------------------------------------------------------

def test_cli_malformed_json_exit_one(tmp_path):
    """Malformed JSON certs file must print to stderr and return exit code 1."""
    certs_f = tmp_path / "bad.json"
    watch_f = tmp_path / "w.json"
    certs_f.write_text("this is not json")
    watch_f.write_text(json.dumps({"domains": ["greenway.com"]}))
    rc = main(["watch", "--certs", str(certs_f), "--watchlist", str(watch_f)])
    assert rc == 1


def test_cli_malformed_watchlist_exit_one(tmp_path):
    """Malformed watchlist must return exit code 1."""
    certs_f = tmp_path / "c.json"
    watch_f = tmp_path / "bad.json"
    certs_f.write_text("[]")
    watch_f.write_text("{invalid}")
    rc = main(["watch", "--certs", str(certs_f), "--watchlist", str(watch_f)])
    assert rc == 1


def test_cli_empty_certs_exit_zero(tmp_path):
    """An empty certs feed (no certs) with a watchlist must cleanly exit 0."""
    certs_f = tmp_path / "c.json"
    watch_f = tmp_path / "w.json"
    certs_f.write_text("[]")
    watch_f.write_text(json.dumps({"domains": ["greenway.com"]}))
    rc = main(["watch", "--certs", str(certs_f), "--watchlist", str(watch_f)])
    assert rc == 0


def test_cli_invalid_expiry_warn_days_exit_one(tmp_path, capsys):
    """A watchlist with invalid expiry_warn_days must return exit code 1."""
    certs_f = tmp_path / "c.json"
    watch_f = tmp_path / "w.json"
    certs_f.write_text("[]")
    watch_f.write_text(json.dumps({"domains": ["greenway.com"],
                                   "expiry_warn_days": -5}))
    rc = main(["watch", "--certs", str(certs_f), "--watchlist", str(watch_f)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "expiry_warn_days" in err
