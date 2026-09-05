# Company Kernel Trust Hardening v0.4 — Acceptance Report

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-trust-hardening-v0.4`  
**Date:** 2026-09-05

## Current acceptance state

**IMPLEMENTED / RELEASE BLOCKED PENDING CLEAN EXECUTION**

v0.4 implements the next trust-hardening controls and includes dedicated unit/integration test coverage in the repository. A clean-environment execution remains release-blocking because GitHub Actions is still producing zero-job `startup_failure` records on the project branches.

## Implemented trust controls

```text
Durable one-time bootstrap.................... implemented
Bootstrap/session atomic transaction.......... implemented
Restart without original bootstrap secret..... implemented
Persistent signed policy contents............. implemented
Policy semantic-version rollback rejection.... implemented
Same-version content substitution rejection... implemented
Recursive delegation proof verification....... implemented
Process-bound tamper detection................ implemented
Expiring queue claim leases................... implemented
Dead-letter handling.......................... implemented
External OIDC identity broker contract........ implemented
OIDC nonce + session atomic transaction........ implemented
Remote HTTPS audit-anchor contract............. implemented
External HTTPS vault provider................. implemented
v0.4 runnable server integration............... implemented
```

## Test cases committed

The v0.4 test suite adds coverage for 20+ new trust cases, including:

- bootstrap replay after restart;
- wrong bootstrap secret;
- policy persistence after restart;
- policy rollback;
- same-version policy substitution;
- expired queue claim reclaim;
- expired acknowledgement rejection;
- dead-letter transitions;
- recursive delegation chain verification;
- proof-digest tampering;
- process-bound tampering;
- OIDC nonce replay;
- OIDC wrong audience;
- disabled external identity mapping;
- remote audit receipt mismatch;
- remote anchor cross-origin redirect;
- vault reference mismatch;
- vault cross-origin redirect;
- runtime vault bootstrap credential clearing.

## Validation inheritance

The last clean GitHub Actions run remains the v0.2 execution:

```text
Run 33998002023
16 tests................ PASS
Secret scan............. PASS
```

v0.3 independently validated 11/11 trust primitives in a separate reference harness.

v0.4 must still receive a clean execution of its committed test suite before release certification.

## Known limitations

- reference signed-policy code still uses HMAC for dependency-free contract validation; production requires asymmetric signing/HSM or equivalent verifier;
- external OIDC provider implementation must cryptographically verify tokens before returning claims;
- remote audit-anchor endpoint is a contract, not a deployed immutable transparency service;
- HTTPS vault provider still requires a runtime bootstrap credential and is not a substitute for protected-memory/HSM/mTLS credential handling;
- distributed resource reservations are not yet implemented;
- S2/S3 compensation/rollback orchestration is not yet implemented;
- multi-party authorization for highest-risk actions is not yet implemented;
- HA/failover and distributed queue coordination are not yet implemented.

## Release decision

**Do not enable a live S2/S3 business write provider yet.**

The next release gate is an Action Safety layer that adds resource reservations, durable replay protection, compensation/rollback contracts, fail-closed audit commit, and stronger approval semantics before the first sandboxed live write.
