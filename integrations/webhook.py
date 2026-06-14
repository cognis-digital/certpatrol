#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations
import argparse
import json
import sys
import urllib.parse
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="HTTPS/HTTP endpoint to POST to.")
    ap.add_argument("--header", action="append", default=[], help="Key: Value")
    args = ap.parse_args()

    # Validate URL scheme — only http/https are safe; reject file://, ftp://, etc.
    parsed_url = urllib.parse.urlparse(args.url)
    if parsed_url.scheme not in ("http", "https"):
        print(
            f"error: URL must use http or https scheme, got {parsed_url.scheme!r}",
            file=sys.stderr,
        )
        return 1
    if not parsed_url.netloc:
        print("error: URL is missing a host", file=sys.stderr)
        return 1

    raw = sys.stdin.read()
    if not raw.strip():
        print("error: no input on stdin — nothing to post", file=sys.stderr)
        return 1

    # Validate that stdin is JSON before attempting network I/O.
    try:
        json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: stdin is not valid JSON: {exc}", file=sys.stderr)
        return 1

    payload = raw.encode("utf-8")
    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, _, v = h.partition(":")
        if not k.strip():
            print(f"error: malformed --header value (no key): {h!r}", file=sys.stderr)
            return 1
        req.add_header(k.strip(), v.strip())

    try:
        with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except Exception as e:
        print(f"webhook error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
