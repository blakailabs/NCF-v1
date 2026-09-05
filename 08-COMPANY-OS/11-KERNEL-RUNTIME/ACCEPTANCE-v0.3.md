# Company Kernel Trust Layer v0.3 — Acceptance Report

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-trust-v0.3`  
**Date:** 2026-09-05

## Acceptance state

**REFERENCE PASS / RELEASE BLOCKED**

The trust primitives have independent validation, but the full v0.3 integration suite has not yet completed in a clean GitHub Actions job because Actions is currently producing `startup_failure` placeholders with zero jobs on this branch.

## Independently validated checks

```text
1. Signed policy verification................ PASS
2. Policy tamper rejection................... PASS
3. Atomic signed-policy activation........... PASS
4. Audit-anchor tamper detection............. PASS
5. Vault audience binding.................... PASS
6. Session rotation/replay rejection......... PASS
7. Bounded capability acceptance............. PASS
8. Child privilege escalation rejection...... PASS
9. Durable queue ownership/retry............. PASS
10. GitHub read-only GET behavior............ PASS
11. GitHub write API absence................. PASS
```

**Result:** `11 / 11 PASS`

## Repository integration tests committed

The repository additionally contains tests for:

- process-level capability-bound enforcement;
- delegate capability validation;
- signed policy overlay enforcement in the running TrustKernel;
- authorized durable event publish/consume/ack;
- audit anchoring through the TrustKernel;
- GitHub read-only adapter token isolation.

These tests remain release-blocking until they run in a clean environment.

## GitHub Actions status

The last known successful real runtime workflow is the v0.2 run:

```text
Run: 33998002023
16 tests: PASS
Secret scan: PASS
```

Subsequent v0.3 pushes are generating GitHub `BuildFailed / startup_failure` records with no jobs. Because no checkout, Python setup, compile step, or test process starts, those records are classified as CI infrastructure startup failures rather than failed runtime tests.

## Security/release classification

v0.3 is suitable for:

- architecture review;
- code review;
- adversarial design review;
- local/reference testing;
- continued trust-layer development.

v0.3 is **not** approved for:

- live payment writes;
- live banking operations;
- production email sends;
- CRM mutation;
- production code deployment;
- ad spend;
- accounting mutation;
- legally binding external actions.

## Blocking items before production trust certification

- durable bootstrap completion state;
- asymmetric policy signing and rollback protection;
- production vault implementation;
- remote immutable audit anchoring;
- expiring event claims/dead-letter behavior;
- external identity provider integration;
- clean-environment full test execution;
- formal/adversarial security review.
