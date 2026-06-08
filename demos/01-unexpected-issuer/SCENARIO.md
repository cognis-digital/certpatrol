# Scenario: Rogue cert issuance for a corporate API

Sectigo issued a cert for api.cognis.digital but the company only uses Let's Encrypt.

## Expected findings

- CP-NEW-001 (high)

## Why this matters

Pre-phishing setup. Revoke immediately via Sectigo + tighten CAA.
