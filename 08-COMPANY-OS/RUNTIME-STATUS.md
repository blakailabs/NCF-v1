# Company Operating System Runtime Status

**Updated:** 2026-09-07 03:04 UTC  
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
first-certification bootstrap authority
bootstrap-to-steady-state handoff
permanent first-bootstrap closure
closure-aware certified shared persistence
shared certification-plane state machine
certification-plane adapter attestation contract
```

## Adapter attestation — CERTIFIED REFERENCE CONTRACT

`kernel/certification_plane_attestation.py` prevents correct reference semantics from being confused with a trusted production adapter deployment.

A concrete deployment identity binds:

```text
deployment_id
backend_id
cluster_id
adapter name/version
adapter implementation digest
backend capability digest
topology evidence digest
probe evidence digest
```

Independent adapter attestation additionally binds:

```text
attestation id + nonce
deployment digest
authority id/class
key id
authority generation
issued_at / expires_at
```

The certifier requires the underlying shared-backend capability contract, exact deployment identity, a trusted adapter release digest, capability/evidence digests, freshness/expiry, an independent verifier receipt, and a production-ready durable attestation trust store.

Authority/key rotation is monotonic. Older generations are rejected. Reused nonces with changed contents are rejected. A deployment cannot silently change backend or cluster identity under the same trust lineage.

`kernel/certification_plane_attestation_store.py` provides a restart-safe SQLite **reference** ledger for replay/rollback semantics. It deliberately reports `production_ready=False`; SQLite is not a production external release authority or distributed trust service.

The test suite contains a test-only trust-store double that reports ready solely to prove the certifier's positive contract path. It is not shipped or claimed as production infrastructure.

## Current certified checkpoint

```text
Run ID: 34078192031
Implementation/validator commit: 350e608859d3d96f841099ff5248652a68dd6ede
Ran 376 tests in 9.559s
376 / 376 PASS
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
 12  adapter-attestation tests
---
376 targeted tests
```

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
Production adapter attestation authority... NOT CONNECTED
SQLite reference adapter trust ledger...... NOT PRODUCTION READY
Production credentials..................... DENIED
Production write providers................. DISABLED
Live production IdP........................ NOT ENABLED
Production asymmetric/HSM anchor trust...... PENDING
```

The 376/376 checkpoint certifies reference contracts and adversarial rejection behavior; it does not certify a real distributed database, production release authority or production control plane.

## Next exact engineering step

Build **durable adapter enrollment + runtime revalidation**:

```text
verified adapter readiness
→ durable enrollment record
→ deployment + attestation + verifier receipt binding
→ monotonic enrollment generation
→ runtime guard re-derives current deployment identity
→ expiry/revocation checked on every certification-plane use
→ adapter/backend/cluster/capability/evidence drift fails closed
→ cross-process rotation/revocation visibility
```

Do not enable a production backend, credentials or write provider while implementing this boundary.
