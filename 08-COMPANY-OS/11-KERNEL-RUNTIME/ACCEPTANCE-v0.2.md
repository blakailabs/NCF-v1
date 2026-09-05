# Company Kernel Hardening v0.2 — Acceptance Report

**Date:** 2026-09-05  
**Branch:** `feature/company-kernel-hardening-v0.2`

## Result

**PASS**

GitHub Actions run `33998002023` completed successfully after one earlier integration-test failure was diagnosed and corrected.

## What the first failed run found

The initial restrictive-policy integration fixture used a $5,000 refund. The v0.1 capability layer already requires elevation above $250, so v0.2 correctly returned the base decision before the restrictive overlay was needed. The test incorrectly expected the v0.2 policy ID to appear.

The fixture was corrected so:

- base capability permits refunds up to $250;
- v0.2 policy requires elevation above $100;
- the integration test requests $200.

This proves the intended invariant: **v0.2 policy can reduce authority already granted by v0.1, but cannot expand it.**

## CI gates passed

```text
Compile kernel................................ PASS
Original v0.1 kernel tests.................... PASS
Session hash/auth/revocation.................. PASS
Restrictive-only policy validation............ PASS
Policy overlay integration.................... PASS
Process ownership binding..................... PASS
Tamper-evident audit verification............. PASS
Audit tamper detection........................ PASS
Secret lease hides secret value............... PASS
Sandboxed read-only live localhost device..... PASS
Restricted external data policy denial........ PASS
Common committed-secret pattern scan.......... PASS
```

The combined test suite executed **16 tests** successfully in the passing run.

## Safety boundary

No write-capable real provider was connected. The only non-mock I/O pattern exercised is a local read-only HTTP GET used to prove S0 device behavior under allowlisting and policy controls.

## Certification statement

Hardening v0.2 is accepted as a **reference security/control milestone**, not production security certification.
