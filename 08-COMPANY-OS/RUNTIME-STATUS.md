# Company Operating System Runtime Status

**Updated:** 2026-09-06 UTC  
**Current engineering branch:** `feature/company-kernel-distributed-safety-v0.7`

## Canonical project identity

**Project:** Company Operating System  
**Recommended GitHub slug:** `Company-Operating-System`  
**Historical repository slug:** `NCF-v1` — administrative rename still pending because the connected GitHub tool does not expose repository-name mutation.

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
→ Kernel Distributed / Production Safety v0.7 (active)
```

## Completed milestones

### v0.1 — Runnable kernel

Durable principal/process/checkpoint/audit state, default-deny capabilities, contextual limits, human-approved elevation, mock devices, idempotency/resource ceilings and checkpoint/restart recovery.

### v0.2 — Authenticated hardening

Opaque hashed sessions, expiration/revocation, process ownership/supervision, restrictive policy overlay, tamper-evident audit chain, secret leases and sandboxed read-only HTTP.

### v0.3 — Trust provenance

Signed restrictive policy packages, atomic activation, session rotation, capability bounds, durable delegation proofs, vault abstraction, event/queue ownership, audit anchors, GitHub read-only provider, one-time bootstrap and adversarial trust catalog.

### v0.4 — Trust hardening

Restart-safe bootstrap, policy rollback protection, recursive delegation verification, OIDC identity-broker contract, remote HTTPS audit-anchor contract, external vault provider and hardened trust/runtime wiring.

### v0.5 — Action Safety

Implemented semantic action intents, replay protection, kernel-derived resource reservations, approval floors, explicit eligible approvers, compensation requirements, fail-closed audit PREPARE, execution-start markers, crash recovery, conservative `UNKNOWN_SIDE_EFFECT`, device/provider binding and simulation-only consequential execution.

Validation surface:

```text
34 targeted tests across 4 v0.5 modules
```

### v0.6 — Live-Adapter Safety

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
- separately governed S3 compensation.

Certified validation:

```text
102 / 102 targeted safety tests PASS
11 test modules
exact test-count enforcement
GitHub Actions PASS
```

PR #2 (`Company Kernel Live-Adapter Safety v0.6`) was merged successfully into the frozen v0.5 lineage at merge commit:

```text
14c07be1aca2dc93e531f955a5bdf537f46bd0fc
```

Production provider release and production credentials remain denied.

## v0.7 — Distributed / Production Safety

Active branch:

```text
feature/company-kernel-distributed-safety-v0.7
```

v0.7 begins moving from single-kernel correctness to distributed ownership correctness.

### First implemented primitive: business-object identity

Each consequential operation can declare a versioned business identity contract defining the fields that identify the real-world object/action.

Example:

```text
payments.refund.target/v1
→ provider_account_id
→ charge_id
→ refund_reference
```

The kernel stores only identity digests/contract metadata, not raw business identity values.

Current invariants:

```text
same business identity + same semantic intent
→ idempotent

same business identity + different semantic intent
→ CFHS_BUSINESS_IDENTITY_CONFLICT

same semantic intent + different business identity
→ CFHS_BUSINESS_IDENTITY_CONFLICT
```

This closes the gap where a caller could attempt the same real-world action under a different replay nonce.

### Second implemented primitive: monotonic fencing

The reference fence store issues a monotonically increasing fencing token for each distributed business resource.

```text
epoch 1 → token 1
takeover → token 2
next takeover → token 3
```

An expired/stale owner cannot renew, release another owner's lease, or advance distributed business state after takeover.

A provider-side reference fence guard rejects tokens below the highest observed epoch, demonstrating the required external stale-owner rejection contract.

### Distributed action permit

The initial permit binds:

```text
business identity digest
identity contract/version
operation
semantic intent digest
provider id
fence resource
owner
lease id
monotonic fence token
lease expiration
```

State advancement requires the permit's fence to remain current and the business identity to remain bound to the same semantic intent/provider.

### v0.7 certification

Canonical validator:

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v07.py
```

Validator success requires:

```text
compile_ok == true
result.wasSuccessful() == true
tests_run == 130
```

Current certified surface:

```text
102 v0.5/v0.6 regression tests
+ 28 distributed-safety tests
= 130 / 130 PASS
```

Latest successful branch run:

```text
Run ID: 34007141355
Workflow: Company OS Kernel CI
Conclusion: SUCCESS
```

## Remaining v0.7 work

- shared/fenced persistence interface and production backend contract;
- atomic coordination among business identity, replay, exact resource reservation and fence ownership;
- fencing of approval ownership, provider execution ownership and reconciliation ownership;
- integrate `DistributedActionPermit` into the v0.6 provider execution gate before provider invocation;
- symmetric compensation unknown-outcome reconciliation;
- exact-unit financial authority thresholds;
- production external IdP/MFA authentication-class policy;
- hardened remote audit-anchor authentication/availability;
- provider webhook/event reconciliation;
- one real provider's business identity/fencing/idempotency semantics in test mode only;
- migration, partition, failover and incident drills.

## Global production release gate

No production write-capable email, payment, banking, CRM, deployment, advertising, accounting or legal-signature provider should be enabled until:

```text
identity verified
+ recursive authority provenance verified
+ policy authenticity verified
+ business target identity bound
+ semantic replay reserved
+ current distributed fence held
+ provider stale-fence rejection available
+ provider idempotency supported
+ approval provenance satisfied
+ exact resource reservation acquired
+ release authority anchored
+ provider PREPARE anchored
+ provider reconciliation available
+ compensation governed/reconcilable when required
+ distributed ownership/fencing available for HA
```

## Administrative repository rename

The repository should still be renamed:

```text
blakailabs/NCF-v1
→ blakailabs/Company-Operating-System
```

The current connected GitHub API surface cannot perform that admin mutation. See `/ADMIN-RENAME.md` for the exact GitHub Settings action and post-rename verification steps.

## Next v0.7 increment

Make fencing a required input to the existing provider-action/reconciliation lifecycle:

```text
BusinessObjectIdentity
→ DistributedActionPermit
→ provider-action PREPARE
→ provider invocation with fence token
→ provider stale-token enforcement
→ fenced reconciliation ownership
```

Only after that integration is certified should the project move to a real provider in test/sandbox mode.
