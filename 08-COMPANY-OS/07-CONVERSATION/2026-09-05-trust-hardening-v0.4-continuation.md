# Company Operating System — Trust Hardening v0.4 Continuation

**Date:** 2026-09-05  
**Status:** Sanitized project continuation

## Direction

Work continued from Trust Layer v0.3 into the next release-blocking trust gaps rather than enabling a live write-capable provider.

## Work completed

A new child branch was created:

```text
feature/company-kernel-trust-hardening-v0.4
```

The v0.4 implementation added:

- durable one-time bootstrap state;
- atomic bootstrap completion and first-session issuance;
- restart behavior that no longer depends on retaining the original bootstrap environment secret;
- persistent signed-policy package contents;
- semantic-version rollback rejection;
- same-version content-substitution rejection;
- recursive delegation-chain verification;
- authorization-time delegation provenance verification;
- expiring event/queue claims;
- dead-letter handling;
- external OIDC identity broker contract;
- atomic OIDC nonce consumption and kernel-session issuance;
- remote HTTPS audit-anchor provider contract;
- external HTTPS vault-provider implementation;
- v0.4 server integration;
- dedicated restart, rollback, delegation, OIDC, remote-anchor, and vault tests.

## Engineering corrections made during implementation

Two trust issues were identified during review and corrected before the milestone was frozen:

1. A policy rollback ledger that stored only a version and digest would not restore active policy contents after restart. A persistent policy-package store was added.
2. Requiring the original bootstrap environment secret on every daemon restart would undermine one-time bootstrap semantics. Startup now requires the secret only when the ceremony has never been initialized.

OIDC login was also tightened so one-time nonce consumption and session issuance are one database transaction.

## Validation status

The repository contains dedicated v0.4 tests, but GitHub Actions remains affected by a branch-level startup failure that creates zero jobs before checkout/compilation/test execution. v0.4 is therefore implemented but release-blocked pending clean-environment execution.

No production S2/S3 business write provider was enabled.

## Next milestone

The next layer is **Company Kernel Action Safety v0.5**: resource reservations, replay/nonces, compensation/rollback, fail-closed audit commit, stronger approval semantics, and an explicit action-intent envelope.
