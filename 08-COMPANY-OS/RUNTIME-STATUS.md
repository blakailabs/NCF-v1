# Company Operating System Runtime Status

**Updated:** 2026-09-07 01:51 UTC  
**Engineering branch:** `feature/company-kernel-ha-persistence-v0.8`  
**Draft PR:** #4 — Company Kernel HA Persistence Safety v0.8

## Project identity

**Project:** Company Operating System  
**Repository:** `blakailabs/NCF-v1`  
**Intended repository slug:** `blakailabs/Company-Operating-System`

NCF remains the constitutional governance layer inside the broader Company Operating System.

## State-sync discipline

This file is the canonical detailed resumability checkpoint for active Company OS engineering.

Update it after each meaningful implementation or certification boundary with:

```text
branch / current engineering milestone
last certified implementation commit and CI run
exact test count
new committed-but-uncertified work
open findings and production blockers
PR/review state
next exact engineering step
```

A committed change is never described as certified until its exact-count CI run passes.

For fast pickup, also keep `08-COMPANY-OS/CURRENT-STATE.md` synchronized as the concise checkpoint.

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

Production HA readiness currently requires:

```text
backend capability contract
+ deployment/topology evidence
+ observed behavioral probes
+ independent trusted attestation
+ time-bounded certification lifecycle
+ narrow first-certification bootstrap authority
```

## Certified HA evidence and lifecycle stack

The certified v0.8 stack now includes:

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
```

## Bootstrap trust boundary — CERTIFIED REFERENCE CONTRACT

`kernel/ha_bootstrap_authority.py` solves first-certification circular trust without creating a generic uncertified-backend bypass.

A bootstrap permit is bound to:

```text
purpose = initialize_ha_certification_state_v08
backend_id
cluster_id
topology_epoch
evidence_digest
certification decision digest
attestation digest
authority identity/class
issued_at / expires_at
permit nonce
```

The coordinator exposes no caller-selected object key and may initialize only the internally derived reserved object:

```text
/_cfhs/ha/certification/bootstrap/<backend-digest>
```

Before use it revalidates that the target backend still satisfies the full production shared-state capability contract. A weaker backend cannot substitute itself merely by reusing the certified `backend_id`.

The reference permit-use ledger reserves the permit before the raw bootstrap write. If the process crashes after the backend write but before permit consumption, retry recognizes the existing reservation/state and completes without a second write.

The SQLite permit-use ledger remains a reference lifecycle implementation; production one-time enforcement must live in an independent certification authority/control plane or equivalently strong service.

## Adversarial bootstrap certification

The certified bootstrap suite covers:

```text
valid one-time initialization
same consumed permit replay is idempotent
permit expiry
incorrect purpose
incorrect backend
incorrect cluster
incorrect topology epoch
incorrect evidence digest
authority-verifier identity mismatch
authority-verifier binding mismatch
same permit ID reused with altered content
crash after backend write before permit consumption
conflicting preexisting bootstrap state
non-production-ready certification
same backend_id with weaker backend capabilities
```

Two source-review findings were repaired before certification:

1. replay/recovery classification now explicitly checks whether the permit existed before the current attempt;
2. the bootstrap target's production capability contract is revalidated before the exception is used.

## Current certified checkpoint

```text
Run ID: 34074237722
Implementation commit: e0a4acca56a954d64a9f1229d4f1173ff34435c8
Ran 340 tests in 8.031s
340 / 340 PASS
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
---
340 targeted tests
```

## PR state

PR #4 is the only open PR in `blakailabs/NCF-v1`.

```text
PR #4............................. OPEN / DRAFT
review comments................... NONE
inline change requests............ NONE
requested reviewers awaiting us... NONE
```

No unresolved external PR feedback currently blocks engineering.

## Explicit non-claims / production blockers

```text
Real production HA backend............... NOT ENABLED
Real topology control-plane adapter....... NOT ENABLED
Real chaos/partition environment.......... NOT ENABLED
SQLite reference backend................. NOT PRODUCTION READY
Production bootstrap permit authority..... NOT CONNECTED
Production bootstrap one-time ledger...... NOT CONNECTED
Production shared certification plane..... NOT IMPLEMENTED
Production credentials................... DENIED
Production write providers............... DISABLED
Live production IdP...................... NOT ENABLED
Production asymmetric/HSM anchor trust.... PENDING
```

The 340/340 checkpoint certifies reference contracts, safety decisions, recovery behavior and adversarial rejection logic. It does not certify a real distributed database, real certification authority, or real fault-control environment.

## Next exact engineering step

Build the **bootstrap-to-steady-state certification handoff**:

```text
externally authorized bootstrap object
→ verify exact bootstrapped certification binding
→ initialize durable shared HA certification-control state
→ activate the same evidence-bound certificate
→ close/revoke bootstrap initialization authority
→ require normal CertifiedSharedPersistence thereafter
```

The handoff must be idempotent, rollback-resistant, topology-epoch aware, crash-safe, and must not leave bootstrap authority reusable after steady-state activation.
