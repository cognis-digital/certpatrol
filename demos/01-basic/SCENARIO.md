# Demo: detect a rogue cert and an expiring cert

You monitor `greenwayenergycapital.com` in Certificate Transparency logs. Your
only authorized issuer is **Let's Encrypt**. `ct_export.json` is a CT monitor
dump containing four observed certificates.

## Run

```
python -m certpatrol watch --certs demos/01-basic/ct_export.json \
                           --watchlist demos/01-basic/watch.json --format table
```

JSON for automation / cron alerting:

```
python -m certpatrol watch --certs demos/01-basic/ct_export.json \
                           --watchlist demos/01-basic/watch.json --format json
```

## What CERTPATROL flags

1. **CRITICAL rogue_issuance** — a `*.greenwayenergycapital.com` wildcard cert
   issued by **WoSign CA Free SSL**, an issuer you never authorized and whose
   fingerprint is unknown. This is exactly the mis-issuance signal certspotter
   exists to catch.
2. **expiring / expired** — `mail.greenwayenergycapital.com` (Let's Encrypt,
   authorized) is near or past its `not_after`, so it surfaces as a lifecycle
   warning to renew before an outage.

The `someoneelse.example.org` cert is ignored — it does not touch a monitored
domain. The authorized, healthy apex cert produces no finding.

## Exit codes

- `0` no findings
- `2` findings present (wire this into CI/cron to alert)
- `1` bad usage / unreadable input
