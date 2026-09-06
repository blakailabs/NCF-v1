# Company Operating System Runtime Status

**Updated:** 2026-09-06 UTC  
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

## Completed milestones

### v0.1 — Runnable kernel

Durable principal/process/checkpoint/audit state, default-deny capabilities, contextual limits, human-approved elevation, mock devices, idempotency/resource ceilings and checkpoint/restart recovery.

### v0.2 — Authenticated hardening

Opaque hashed sessions, expiration/revocation, process ownership/supervision, restrictive policy overlay, tamper-evident audit chain, secret leases and sandboxed read-only HTTP.

Last clean v0.2 workflow:

```text
Run 33998002023
Compile................ PASS
Combined tests......... PASS (16)
Secret scan............ PASS
```

### v0.3 — Trust provenance

Signed restrictive policy packages, atomic activation, session rotation, capability bounds, durable delegation proofs, vault abstraction, event/queue ownership, audit anchors, GitHub read-only provider, one-time bootstrap and adversarial trust catalog.

### v0.4 — Trust hardening

Restart-safe bootstrap, policy rollback protection, recursive delegation verification, OIDC identity-broker contract, remote HTTPS audit-anchor contract, external vault provider and hardened trust/runtime wiring.

### v0.5 — Action Safety

Frozen branch:

```text
feature/company-kernel-action-safety-v0.5
```

Implemented semantic action intents, replay protection, kernel-derived resource reservations, approval floors, explicit eligible approvers, compensation requirements, fail-closed audit PREPARE, execution-start markers, crash recovery, conservative `UNKNOWN_SIDE_EFFECT`, device/provider binding and simulation-only consequential execution.

Validation surface:

```text
34 targeted tests across 4 v0.5 modules
```

### v0.6 — Live-Adapter Safety

Current branch:

```text
feature/company-kernel-live-adapter-safety-v0.6
```

Canonical hardened runtime:

```text
kernel.server_v06_hardened
→ TrustKernelV06ReleaseGate
```

Implemented:

- exact integer/minor-unit economic accounting;
- persistent provider-side idempotency and lookup;
- provider outcome reconciliation;
- post-provider failure hardening;
- authenticated approval-session provenance;
- optional verified external identity evidence;
- immutable authorization evidence;
- fail-closed authorization anchoring;
- fail-closed provider-action anchoring;
- kernel semantic replay independent of provider idempotency;
- replay nonce pre-reservation before provider-intent persistence;
- restart repair for replay/intents;
- sandbox-only provider registry;
- separately governed S3 compensation with its own intent, approvals, provenance and anchored authority.

Current provider registry:

```text
sandbox-payments
```

Production provider credentials are not accepted.

## v0.6 CI certification

Canonical validator:

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v06.py
```

Validator success requires:

```text
compile_ok == true
result.wasSuccessful() == true
tests_run == 102
```

Certified GitHub Actions run:

```text
Run ID: 34006498158
Commit: 3b8cc7a4d7fc3bb62beccd875ef0fbeffbd87fcd
Workflow: Company OS Kernel CI
Job: test
Step: Validate Live-Adapter Safety v0.6
Conclusion: SUCCESS
```

The current documentation-only v0.6 head also passed the same exact-count validator.

Current validation state:

```text
Compilation........................ PASS
Targeted safety tests.............. 102 / 102 PASS
Test modules....................... 11
v0.5 regression suites included.... YES
CI execution blocker............... RESOLVED
```

Issue #1 tracked the former GitHub Actions startup failure and is closed as completed.

Draft PR #2 (`Company Kernel Live-Adapter Safety v0.6`) is open against the frozen v0.5 branch.

## v0.6 acceptance

```text
Sandbox implementation................ ACCEPTED
Adversarial test coverage.............. 102 / 102 CI-CERTIFIED
Source-level pre-freeze review......... COMPLETED
Clean execution certification.......... PASS
Production provider release............ DENIED
Production credentials................. DENIED
```

Passing v0.6 CI certifies the sandbox architecture milestone; it does not authorize a production provider.

## Remaining production blockers

- operation-specific business identity/deduplication beyond caller replay nonce;
- one real provider's test-mode idempotency/lookup semantics;
- compensation unknown-outcome reconciliation;
- production cryptographic OIDC/MFA enforcement for sensitive approval classes;
- asymmetric/HSM-backed policy trust root;
- highly available independent immutable audit anchoring;
- distributed/fenced replay, resource, approval, provider-state and reconciliation ownership;
- exact-unit authority limits for financial policy thresholds;
- workload-identity/mTLS/HSM-backed secret delivery;
- provider webhook/event reconciliation;
- provider-side canary limits and external hard ceilings;
- migration/failover/incident runbooks.

## Global production release gate

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

1. shared/fenced persistence interfaces for replay, exact resources, approvals, provider state and reconciliation;
2. operation-specific business-object identity/idempotency contracts;
3. symmetrical compensation outcome reconciliation;
4. production-grade external identity/MFA classes for selected S3 actions;
5. hardened remote audit-anchor authentication/availability;
6. exact-unit financial authority limits;
7. one real provider adapter in test/sandbox mode only with provider-side hard limits;
8. distributed recovery, failover and incident drills before any production credential is accepted.
