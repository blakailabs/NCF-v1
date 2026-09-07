# Company Operating System Runtime Status

**Updated:** 2026-09-07 02:47 UTC  
**Engineering branch:** `feature/company-kernel-ha-persistence-v0.8`  
**Draft PR:** #4 — Company Kernel HA Persistence Safety v0.8

## Project identity

**Project:** Company Operating System  
**Repository:** `blakailabs/NCF-v1`

NCF remains the constitutional governance layer inside the broader Company Operating System.

## State-sync discipline

This file is the canonical detailed resumability checkpoint for active Company OS engineering. Keep `08-COMPANY-OS/CURRENT-STATE.md` synchronized as the concise pickup file.

A committed change is never described as certified until its exact-count CI run passes.

## Merged baseline

v0.7 was merged through PR #3 at:

```text
25382c018e8bf3cfe426940afc8f622b526ba191
264 / 264 PASS
```

## Evidence-first doctrine

```text
Reality first.
Structure second.
Automation third.
AI last.
```

Company OS distinguishes formal standards, authoritative implementation evidence, empirical research, proven production patterns and design heuristics. An analogy cannot become a kernel invariant merely because it is intuitive.

## v0.8 — HA Persistence Safety

The certified reference stack now requires:

```text
backend capability contract
+ independently sourced deployment/topology evidence
+ actively observed behavioral probes
+ trusted external attestation
+ time-bounded certification lifecycle
+ narrow first-certification bootstrap authority
+ bootstrap-to-steady-state certification handoff
+ closure-aware certified shared-state access
```

## Certified HA evidence and lifecycle stack

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
one-purpose external bootstrap permit contract
one-time bootstrap replay protection
crash-safe bootstrap recovery
bootstrap backend capability revalidation
bootstrap-to-steady-state handoff
digest-bound reserved shared certification-control object
permanent first-bootstrap closure guard
closure-aware CertifiedSharedPersistence
handoff concurrency convergence
activation-expiry recheck before closure
```

## Bootstrap-to-steady-state handoff — CERTIFIED REFERENCE CONTRACT

`kernel/ha_certification_handoff.py` verifies the exact reserved bootstrap object and its evidence/certification/authority binding before creating the deterministic shared certification-control object:

```text
/_cfhs/ha/certification/control/<backend-digest>
```

The flow is:

```text
verify exact bootstrap object
→ prepare idempotent handoff lineage
→ put/read-back exact shared certification-control object
→ activate the same evidence-bound certificate
→ recheck active certificate with backend-authoritative time
→ permanently close first-bootstrap authority
→ allow closure-aware CertifiedSharedPersistence
```

A certificate may become ACTIVE before the final closure transaction during crash recovery, but ordinary steady-state shared access remains denied because `HandoffCertifiedSharedPersistence` requires both an active certificate and a CLOSED handoff lineage.

`kernel/ha_handoff_guard.py` provides the bootstrap entry-point guard. After closure, even replaying the original first-bootstrap request is denied with `CFHS_HA_BOOTSTRAP_CLOSED`.

The reference handoff ledger is SQLite lifecycle machinery only. It does not claim to be the production shared certification control plane.

## Certified handoff adversarial surface

```text
successful handoff
idempotent repeated handoff
crash before shared activation
crash after shared activation before bootstrap closure
bootstrap object tampering
certificate/evidence mismatch
cluster mismatch
topology rollback
second first-bootstrap attempt after closure
concurrent handoff attempts
activation expiry during handoff
steady-state access denied until handoff fully complete
```

## Current certified checkpoint

Current synchronized branch-head certification:

```text
Run ID: 34077423653
Branch-head commit: 79d9bfc9dd61ccb05f98a61a421dc996d6c13ef8
Ran 352 tests in 8.030s
352 / 352 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

The handoff validator/code checkpoint was committed at `5fe41db3c519aafe583dd3d858c9d0755a9481c7`; the later branch head only added the pending-state checkpoint and passed the same exact 352-test validator.

Exact certified surface:

```text
264  frozen v0.5-v0.7 regressions
 21  HA deployment-readiness tests
 15  HA certification lifecycle/runtime tests
 14  active HA probe-harness tests
 11  digest-bound HA evidence-pipeline tests
 15  adversarial HA bootstrap-authority tests
 12  bootstrap-to-steady-state handoff tests
---
352 targeted tests
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
Production shared certification plane...... NOT IMPLEMENTED
Production credentials..................... DENIED
Production write providers................. DISABLED
Live production IdP........................ NOT ENABLED
Production asymmetric/HSM anchor trust...... PENDING
```

The 352/352 checkpoint certifies reference contracts, safety decisions, recovery behavior and adversarial rejection logic. It does not certify a real distributed database, real certification authority, real shared certification plane or real fault-control environment.

## Next exact engineering step

Build the **shared certification-plane contract** so certification/handoff authority is no longer modeled as process-local SQLite lifecycle state:

```text
provider-neutral shared certification-plane interface
→ transactional ACTIVE/SUPERSEDED/INVALIDATED certification records
→ durable handoff PREPARED/ACTIVATED/CLOSED lineage
→ atomic CAS/fencing semantics for concurrent certifiers
→ backend-authoritative expiry
→ bootstrap closure visible across processes
→ adapters remain fail-closed until a real HA implementation proves the contract
```

Do not enable a production backend, credentials or write provider while implementing this reference boundary.
