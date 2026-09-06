# Company Operating System Runtime Status

**Updated:** 2026-09-05 / 2026-09-06 UTC  
**Current branch:** `feature/company-kernel-live-adapter-safety-v0.6`

## Canonical project identity

**Project:** Company Operating System  
**Recommended GitHub slug:** `Company-Operating-System`  
**Historical repository slug:** `NCF-v1` — administrative rename pending

NCF remains the constitutional governance layer inside the broader Company Operating System project.

## Architecture implemented

```text
NCF constitutional governance
→ CDM company discovery contract
→ CFHS filesystem hierarchy
→ deterministic CFHS materializer
→ Company Kernel API
→ Company Kernel runtime v0.1
→ Kernel Hardening v0.2
→ Kernel Trust Layer v0.3
→ Kernel Trust Hardening v0.4
→ Kernel Action Safety v0.5
→ Kernel Live-Adapter Safety v0.6
```

## v0.1 — runnable kernel

Implemented durable principal/process/checkpoint/audit state, default-deny capabilities, contextual limits, human-approved elevation, mock devices, idempotency/resource ceilings and checkpoint/restart recovery.

## v0.2 — authenticated hardening

Implemented opaque hashed kernel sessions, expiration/revocation, process ownership/supervision, restrictive policy overlay, tamper-evident audit chain, secret lease abstraction and sandboxed S0 read-only HTTP.

Last clean GitHub Actions execution:

```text
Run 33998002023
Compile................ PASS
Combined tests......... PASS (16)
Secret scan............ PASS
```

## v0.3 — trust provenance

Implemented signed restrictive policy-package contracts, atomic activation, session rotation, capability bounds, durable delegation proofs, provider-neutral vault interface, durable event/queue ownership, independent audit anchors, GitHub read-only provider, one-time bootstrap and threat-model/adversarial test catalog.

Independent reference harness:

```text
Trust primitive checks........ 11 / 11 PASS
```

## v0.4 — trust hardening

Implemented restart-safe one-time bootstrap, atomic bootstrap/session issuance, signed-policy persistence and rollback protection, recursive delegation verification, delegation/process tamper detection, expiring queue claims/dead-letter handling, OIDC identity-broker contract, remote HTTPS audit-anchor contract, external HTTPS vault provider and runnable v0.4 wiring.

Acceptance remains:

```text
IMPLEMENTED
TEST COVERAGE COMMITTED
CLEAN-ENVIRONMENT EXECUTION REQUIRED
PRODUCTION WRITE RELEASE BLOCKED
```

## v0.5 — Action Safety

Frozen branch:

```text
feature/company-kernel-action-safety-v0.5
```

Implemented:

- stable semantic action intent;
- replay nonce bound to semantic action;
- atomic resource reservation/commit/release;
- kernel-derived resource requirements;
- operation-owned approval floors;
- explicit eligible approvers;
- requester self-approval rejection;
- compensation requirements;
- fail-closed audit PREPARE;
- durable execution-start marker;
- PENDING/EXECUTING lifecycle;
- crash recovery and conservative `UNKNOWN_SIDE_EFFECT` handling;
- device/provider/safety-profile binding;
- simulation-only consequential provider;
- deterministic v0.5 validator.

Validation surface:

```text
34 targeted tests across 4 v0.5 modules
```

The milestone is simulation-only and does not authorize a live provider.

## v0.6 — Live-Adapter Safety

Current branch:

```text
feature/company-kernel-live-adapter-safety-v0.6
```

### Canonical hardened runtime

```text
kernel.server_v06_hardened
→ TrustKernelV06ReleaseGate
```

`server_v06.py` remains the lower-level provider-shaped reference runtime. The hardened launcher is the canonical v0.6 safety entrypoint.

### Exact economic units

Implemented integer-only economic accounting:

```text
$10.25 USD → 1025 minor units
```

No rounding is permitted. NaN, infinity, zero/negative use, fractional count resources, sub-minor currency precision and out-of-range integer units are rejected.

Committed exact usage can be reversed only with provider compensation evidence.

### Provider-side idempotency

The sandbox provider persists a stable idempotency key and supports lookup:

```text
same key + same request → original provider action
same key + changed request → CFHS_IDEMPOTENCY_CONFLICT
```

Provider idempotency survives restart.

### Provider reconciliation

Provider outcomes are separated into:

```text
definite pre-persistence failure
provider-confirmed success
unknown transport outcome
compensated
```

Unknown outcome enters `RECONCILIATION_REQUIRED`; a second provider execute is blocked.

Provider lookup resolves the action to committed, not-executed or compensated truth.

### Post-provider failure hardening

Any generic exception after provider execution begins is treated as potentially consequential unless the provider gives a definite pre-persistence failure signal.

Fault models cover:

- provider success then audit failure;
- provider success then exact-resource commit failure;
- provider persistence then unexpected client exception;
- unexpected client failure before provider persistence.

The system reconciles from provider truth instead of retrying blindly.

### Session-proven approvals

Every counted S3 approval must have authenticated kernel-session provenance.

Approval evidence binds:

```text
session id
principal id
session lifetime
authentication class
session evidence digest
optional external identity/provider digest
```

Revoked or expired sessions cannot provide approval evidence. Raw approval rows without provenance do not release v0.6 provider actions.

### Anchored authorization evidence

Before provider preparation, the release authority is bound immutably to:

- semantic intent;
- actor/process;
- matched capability/policy;
- constraints;
- approval request;
- multi-party approval provenance digest.

The authorization checkpoint is appended to the tamper-evident chain and externally anchored before the provider-action PREPARE path proceeds.

### Anchored provider audit

Provider PREPARE and subsequent provider-action transitions are also chained and anchored.

The anchor receipt must confirm the exact audit-chain head supplied by the kernel. Missing/unavailable/mismatched anchor receipts fail closed.

### Semantic kernel replay

v0.6 adds a provider replay state machine independent of provider idempotency.

The nonce is now reserved **before provider-intent persistence**:

```text
RESERVED
→ PENDING
→ PREPARED
→ COMMITTED / FAILED_NOT_EXECUTED / RECONCILIATION_REQUIRED
→ COMMITTED / FAILED_NOT_EXECUTED / COMPENSATED
```

Same nonce + different semantic action is rejected.

Startup recovery handles the crash window between durable intent creation and replay attachment.

### Governed S3 compensation

The pre-freeze review determined that rollback must be governed as a consequential action itself.

The hardened runtime requires:

```text
committed original provider action
→ separately authorized compensation requester
→ immutable compensation intent
→ two independent approvers
→ session provenance for each approval
→ separate compensation authorization
→ anchored compensation authority evidence
→ provider idempotent compensation
→ exact resource reversal
→ original replay state COMPENSATED
```

A principal lacking base compensation authority cannot even open the approval workflow.

### Sandbox-only provider registry

Current provider registry:

```text
sandbox-payments
```

Production provider credentials are not accepted.

### v0.6 validation surface

Canonical validator:

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v06.py
```

Expected targeted surface:

```text
102 tests
11 modules
includes frozen v0.5 regression suites
```

The test design covers exact units, provider idempotency, provider lookup/reconciliation, post-provider failures, approval provenance, audit anchoring, kernel replay, replay crash recovery, end-to-end provider execution and governed S3 compensation.

**Execution status:** the test surface is committed but is not being represented as passed because GitHub Actions is still failing before job creation and the external container could not resolve GitHub for a clean clone.

## Current GitHub Actions blocker

GitHub continues to create synthetic runs with:

```text
name: ""
path: BuildFailed
conclusion: startup_failure
jobs: 0
```

The failure occurs before checkout, runner assignment, Python setup, compilation or tests.

This is treated as an execution-infrastructure blocker, not as a passing or failing code result.

## v0.6 acceptance

```text
Sandbox implementation................ ACCEPTED
Adversarial test design............... COMMITTED
Source-level pre-freeze review........ COMPLETED
Clean execution certification......... BLOCKED
Production provider release........... DENIED
Production credentials................ DENIED
```

See:

```text
11-KERNEL-RUNTIME/LIVE-ADAPTER-SAFETY-v0.6.md
11-KERNEL-RUNTIME/PREMORTEM-v0.6.md
11-KERNEL-RUNTIME/ACCEPTANCE-v0.6.md
```

## Remaining production blockers

- clean execution of the committed 102-test validator;
- CI on the exact release commit;
- operation-specific business identity/deduplication beyond caller replay nonce;
- one real provider's test-mode idempotency/lookup semantics;
- compensation unknown-outcome reconciliation;
- production cryptographic OIDC/MFA enforcement for sensitive approval classes;
- asymmetric/HSM-backed policy trust root;
- highly available independent immutable audit anchoring;
- distributed/fenced replay, resource and reconciliation state;
- exact-unit authority limits for financial policy thresholds;
- workload-identity/mTLS/HSM-backed secret delivery;
- provider webhook/event reconciliation;
- provider-side canary limits and external hard ceilings;
- migration/failover/incident runbooks.

## Global release gate

No production write-capable email, payment, banking, CRM, deployment, advertising, accounting or legal-signature provider should be enabled until:

```text
identity verified
+ recursive authority provenance verified
+ policy authenticity verified
+ business target identity bound
+ semantic replay reserved
+ provider idempotency supported
+ approval provenance satisfied
+ exact resource reservation acquired
+ release authority anchored
+ provider PREPARE anchored
+ provider reconciliation available
+ compensation governed/reconcilable when required
+ distributed ownership/fencing available for HA
```

## Next engineering milestone

Build **Company Kernel Distributed / Production Safety v0.7**.

Priority order:

1. define shared/fenced persistence interfaces for replay, exact resources, approvals, provider state and reconciliation;
2. add operation-specific business identity/idempotency contracts;
3. make compensation outcome reconciliation symmetrical with forward execution;
4. require production-grade external identity/MFA classes for selected S3 actions;
5. harden remote audit-anchor authentication/availability;
6. replace legacy floating financial authority limits with exact-unit policy constraints;
7. implement one real provider adapter in **test/sandbox mode only** with provider-side hard limits;
8. execute the full validator in a clean environment before accepting any production credential.
