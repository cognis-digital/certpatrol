"""CERTPATROL - TLS certificate lifecycle & rogue-issuance watch via Certificate Transparency.

Spirit of sslmate/certspotter: ingest Certificate Transparency monitor results,
detect certs issued for domains you own that you did NOT authorize, and flag
certificates approaching expiry.

Standard library only. Zero install.
"""
from .core import (
    Certificate,
    Finding,
    Watchlist,
    parse_certs,
    load_watchlist,
    analyze,
    name_covered,
    days_until,
)

TOOL_NAME = "certpatrol"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Certificate",
    "Finding",
    "Watchlist",
    "parse_certs",
    "load_watchlist",
    "analyze",
    "name_covered",
    "days_until",
]
