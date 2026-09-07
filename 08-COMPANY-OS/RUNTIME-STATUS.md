# Company Operating System Runtime Status

**Updated:** 2026-09-07 01:47 UTC  
**Engineering branch:** `feature/company-kernel-ha-persistence-v0.8`  
**Draft PR:** #4 — Company Kernel HA Persistence Safety v0.8

## Project identity

**Project:** Company Operating System  
**Repository:** `blakailabs/NCF-v1`  
**Intended repository slug:** `blakailabs/Company-Operating-System`

NCF remains the constitutional governance layer inside the broader Company Operating System.

## State-sync discipline

This file is the canonical resumability checkpoint for active Company OS engineering.

Update it after each meaningful implementation or certification boundary with:

```text
branch/head commit
last certified test count/run
new committed-but-uncertified work
open risks/findings
production posture
next exact engineering step
PR state
```

A committed change is never described as certified until its exact-count CI run passes.

## Merged baseline

v0.7 was merged through PR #3 at:

```text
25382c018e8bf3cfe426940afc8f622b526ba191
```

The merged v0.7 baseline remains certified at **264 / 264** targeted tests.

## Evidence-first doctrine

```text
Reality first.
Structure second.
Automation third.
AI last.
```

Company OS distinguishes formal standards, authoritative implementation evidence, empirical research, proven production patterns and design heuristics. An analogy cannot become a kernel invariant merely because it is intuitive.

## v0.8 — HA Persistence Safety

Production HA readiness requires:

```text
backend capability contract
+ deployment/topology evidence
+ observed behavioral probes
+ independent trusted attestation
+ time-bounded certification lifecycle
```

### Certified HA evidence stack

The currently certified v0.8 stack includes:

```text
HA deployment-readiness contract
active multi-client/fault probe harness
digest-bound topology + probe evidence assembly
trusted deployment attestation contract
time-bounded certification lifecycle
backend-authoritative expiry checks
topology rollback protection
cluster identity continuity
evidence nonce replay protection
shared-state access gated by active certification
```

### Last certified checkpoint

```text
Run ID: 34056548949
Commit: c1b92423093ac1266b14e25e7624a702fdc4c7ff
Ran 325 tests in 21.091s
325 / 325 PASS
0 failures
0 errors
0 skipped
exact_test_count = true
successful = true
```

Exact certified surface:

```text
264  frozen v0.5-v0.7 regressions
 21  HA deployment-readiness tests
 15  HA certification lifecycle/runtime tests
 14  active HA probe-harness tests
 11  digest-bound HA evidence-pipeline tests
---
325 targeted tests
```

## Current committed but NOT YET certified work

Current branch head:

```text
255960f75703c5a2abf32edd11a7d6aaec43946c
```

New bootstrap boundary:

```text
kernel/ha_bootstrap_authority.py
tests/test_ha_bootstrap_authority_v08.py
```

Purpose: solve first-certification circular trust with a narrowly scoped external bootstrap permit rather than a generic uncertified-backend bypass.

The permit is bound to:

```text
single bootstrap purpose
backend_id
cluster_id
topology_epoch
evidence_digest
certification decision digest
attestation digest
authority identity/class
issue/expiry time
permit nonce
```

The coordinator derives the reserved bootstrap object key internally and exposes no caller-selected generic write destination.

### Adversarial bootstrap suite now committed

Tests cover:

```text
valid one-time initialization
same-permit idempotent replay
permit expiry
incorrect purpose
incorrect backend
incorrect cluster
incorrect topology epoch
incorrect evidence digest
authority-verifier identity mismatch
authority-verifier binding mismatch
same permit ID with altered content
crash after backend write before permit consumption
conflicting preexisting bootstrap state
non-production-ready certification
backend substitution using same backend_id but weaker capabilities
```

### Open findings being repaired before certification

Source review identified two issues before the bootstrap suite enters the exact-count validator:

1. **Replay/recovery classification:** bootstrap must explicitly distinguish a permit that existed before the current attempt from a newly reserved permit so first execution, consumed replay and crash recovery report correctly.
2. **Backend substitution:** matching `backend_id` is not sufficient. The raw bootstrap target must itself still satisfy the production capability contract; a weaker backend cannot impersonate a certified deployment merely by reusing the same identifier.

These findings are being fixed; **325/325 remains the authoritative certified count until the bootstrap suite passes CI.**

## PR state

PR #4 is the only open PR in `blakailabs/NCF-v1`.

```text
PR #4............................. OPEN / DRAFT
review comments................... NONE
inline change requests............ NONE
requested reviewers awaiting us... NONE
```

No unresolved external PR feedback currently blocks engineering.

## Explicit non-claims

```text
Real production HA backend.............. NOT ENABLED
Real topology control-plane adapter...... NOT ENABLED
Real chaos/partition environment......... NOT ENABLED
SQLite reference backend................ NOT PRODUCTION READY
Production bootstrap authority.......... REFERENCE CONTRACT ONLY
Production certification control plane.. REFERENCE ONLY
Production credentials.................. DENIED
Production write providers.............. DISABLED
Live production IdP..................... NOT ENABLED
Production asymmetric/HSM anchor trust.. PENDING
```

## Next exact step

Repair the two bootstrap findings, add the bootstrap adversarial module to `scripts/validate_v08.py`, calculate the new exact test count, run CI, repair any surfaced failures, and only then promote the bootstrap boundary into the certified v0.8 state and PR #4 description.
