"""CERTPATROL command-line interface.

  certpatrol watch --certs ct_export.json --watchlist watch.json [--format table|json]

Exit codes:
  0  no findings
  1  bad usage / unreadable input
  2  findings present (rogue issuance, expiry, etc.) — useful for CI/cron alerting
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

from . import TOOL_NAME, TOOL_VERSION
from .core import analyze, load_watchlist, parse_certs


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _render_table(findings) -> str:
    if not findings:
        return "No findings. All monitored certificates are authorized and current."
    rows = [("SEVERITY", "KIND", "DOMAIN", "MESSAGE")]
    for f in findings:
        msg = f.message if len(f.message) <= 70 else f.message[:67] + "..."
        rows.append((f.severity.upper(), f.kind, f.domain, msg))
    widths = [max(len(r[i]) for r in rows) for i in range(4)]
    out = []
    for i, r in enumerate(rows):
        out.append("  ".join(c.ljust(widths[j]) for j, c in enumerate(r)))
        if i == 0:
            out.append("  ".join("-" * widths[j] for j in range(4)))
    crit = sum(1 for f in findings if f.severity in ("critical", "high"))
    out.append("")
    out.append(f"{len(findings)} finding(s), {crit} high/critical.")
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="TLS cert lifecycle & rogue-issuance watch via Certificate Transparency.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    w = sub.add_parser("watch", help="Analyze a CT export against a watchlist.")
    w.add_argument("--certs", required=True, help="CT monitor export (JSON / NDJSON).")
    w.add_argument("--watchlist", required=True, help="Watchlist JSON file.")
    w.add_argument("--format", choices=["table", "json"], default="table")
    return p


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "watch":
        try:
            certs = parse_certs(_read(args.certs))
            watch = load_watchlist(_read(args.watchlist))
        except FileNotFoundError as e:
            print(f"error: file not found: {e.filename}", file=sys.stderr)
            return 1
        except (json.JSONDecodeError, ValueError) as e:
            print(f"error: could not parse input: {e}", file=sys.stderr)
            return 1

        findings = analyze(certs, watch)

        if args.format == "json":
            payload = {
                "tool": TOOL_NAME,
                "version": TOOL_VERSION,
                "monitored_domains": watch.domains,
                "certs_examined": len(certs),
                "finding_count": len(findings),
                "findings": [dataclasses.asdict(f) for f in findings],
            }
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(_render_table(findings))

        return 2 if findings else 0

    parser.print_help(sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
