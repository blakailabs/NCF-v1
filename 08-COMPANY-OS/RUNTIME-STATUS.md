# Company Operating System Runtime Status

**Updated:** 2026-09-07 02:58 UTC  
**Engineering branch:** `feature/company-kernel-ha-persistence-v0.8`  
**Draft PR:** #4 — Company Kernel HA Persistence Safety v0.8

## Project identity

**Project:** Company Operating System  
**Repository:** `blakailabs/NCF-v1`

NCF remains the constitutional governance layer inside the broader Company Operating System.

## State-sync discipline

This file is the canonical detailed resumability checkpoint for active Company OS engineering. Keep `08-COMPANY-OS/CURRENT-STATE.md` synchronized as the concise pickup file. A committed change is never described as certified until its exact-count CI run passes.

## Merged baseline

```text
v0.7 merge/base: 25382c018e8bf3cfe426940afc8f622b526ba191
v0.7 certification: 264 / 264 PASS
```

## Evidence-first doctrine

```text
Reality first.
Structure second.
Automation third.
AI last.
```

## v0.8 certified reference stack

```text
HA deployment-readiness contract
active multi-client/fault probes
digest-bound topology + probe evidence
trusted deployment attestation
time-bounded certification lifecycle
backend-authoritative expiry
topology rollback + cluster continuity + evidence replay protection
narrow external first-certification bootstrap authority
bootstrap-to-steady-state certification handoff
permanent first-bootstrap closure
closure-aware certified shared persistence
provider-neutral shared certification-plane state machine
```

## Shared certification plane — CERTIFIED REFERENCE CONTRACT

`kernel/shared_certification_plane.py` moves certification and handoff authority out of process-local lifecycle tables and models it as shared state over the existing HA storage primitives:

```text
shared object state
+ monotonic writer fence
+ CAS version
+ ordered journal version
+ backend-authoritative time
```

The deterministic plane state records:

```text
backend identity
cluster identity
highest topology epoch
active certification
PREPARED / ACTIVATED / CLOSED handoff lineage
permanent bootstrap_closed state
seen evidence nonce → evidence digest bindings
latest invalidation provenance
```

Mutations use `fenced_compare_and_swap_with_event`, binding each state change to a current fence plus object and journal versions. Cross-process readers observe the same active certificate, invalidation and bootstrap-closure state.

The plane rejects cluster identity changes, topology rollback, same-epoch conflicting evidence, evidence-nonce replay, stale certifier fences and certificate expiry. Higher topology epochs can supersede the prior certificate after the first-bootstrap lineage is CLOSED.

The current `SharedStateCertificationPlane` is deliberately a **reference adapter**. Its readiness result always includes `production_certification_plane_adapter_attestation`; therefore it cannot self-promote to production readiness merely because a test backend advertises all storage capabilities.

## Current certified checkpoint

```text
Run ID: 34077833585
Implementation/validator commit: 287d28850469a082d30a80a3649af363e494cda5
Ran 364 tests in 8.163s
364 / 364 PASS
0 failures
0 errors
0 skipped
compile_ok = true
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
 15  adversarial HA bootstrap-authority tests
 12  bootstrap-to-steady-state handoff tests
 12  shared certification-plane tests
---
364 targeted tests
```

Shared-plane tests cover cross-process visibility, concurrent activation conflict, same-evidence idempotency, higher-epoch supersession, rollback rejection, cluster conflict, invalidation visibility, expiry visibility, handoff closure visibility, stale-fence rejection, restart recovery and explicit non-production readiness of the reference adapter.

## PR state

```text
PR #4............................. OPEN / DRAFT
Keep draft while v0.8 production-boundary work continues.
```

## Explicit non-claims / production blockers

```text
Real production HA backend................ NOT ENABLED
Real topology control-plane adapter........ NOT ENABLED
Real chaos/partition environment........... NOT ENABLED
SQLite reference backend................... NOT PRODUCTION READY
Production bootstrap permit authority...... NOT CONNECTED
Production bootstrap one-time ledger....... NOT CONNECTED
Production shared certification plane...... NOT CONNECTED
Production certification-plane attestation. NOT IMPLEMENTED
Production credentials..................... DENIED
Production write providers................. DISABLED
Live production IdP........................ NOT ENABLED
Production asymmetric/HSM anchor trust...... PENDING
```

The 364/364 checkpoint certifies reference semantics and adversarial rejection behavior; it does not certify a real distributed database or production control plane.

## Next exact engineering step

Build the **production certification-plane adapter attestation contract**:

```text
shared-plane reference semantics
→ deployment-instance identity
→ independent adapter attestation
→ backend/cluster/implementation binding
→ capability and evidence binding
→ freshness/expiry
→ monotonic authority/key generation
→ replay/rollback protection
→ fail-closed production-ready decision
```

Do not enable a production backend, credentials or write provider while implementing this boundary.
