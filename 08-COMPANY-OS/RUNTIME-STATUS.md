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

Implemented exact economic accounting, persistent provider idempotency/lookup, provider reconciliation, post-provider failure hardening, authenticated approval provenance, anchored authorization/provider audit, semantic replay with pre-reservation/restart repair, sandbox-only provider execution and separately governed S3 compensation.

Certified validation:

```text
102 / 102 targeted safety tests PASS
11 test modules
exact test-count enforcement
GitHub Actions PASS
```

PR #2 (`Company Kernel Live-Adapter Safety v0.6`) was merged into the validated Company OS lineage at:

```text
14c07be1aca2dc93e531f955a5bdf537f46bd0fc
```

Production provider release and production credentials remain denied.

## v0.7 — Distributed / Production Safety

Active branch:

```text
feature/company-kernel-distributed-safety-v0.7
```

Draft PR:

```text
#3 — Company Kernel Distributed / Production Safety v0.7
```

### Business-object identity

Consequential operations can declare a versioned identity contract identifying the real-world target independently of replay nonce.

Reference refund identity:

```text
payments.refund.target/v1
→ provider_account_id
→ charge_id
→ refund_reference
```

The kernel persists only digests and contract metadata, not the raw identity values.

Invariants:

```text
same business identity + same semantic intent → idempotent
same business identity + different semantic intent → conflict
same semantic intent + different business identity → conflict
```

### Monotonic fencing

Each distributed business resource has a monotonically increasing ownership epoch:

```text
kernel A → token 1
lease expiry / takeover
kernel B → token 2
stale kernel A with token 1 → rejected
```

An expired/stale owner cannot renew, release another owner's lease, assert current ownership or advance state.

### Provider/gateway stale-fence enforcement

The provider boundary records the highest fence epoch observed for each provider/business resource and rejects lower tokens.

Fence metadata stays outside business arguments so a new ownership epoch does not alter the provider's v0.6 idempotency request digest.

### Fenced provider PREPARE

Provider policy now includes a versioned business-identity contract and fence TTL.

Before v0.6 provider PREPARE can complete, v0.7:

```text
validates full semantic arguments
→ verifies business identity binding
→ acquires/reuses an execution fence
→ executes v0.6 approval/authorization/resource/audit PREPARE
```

PREPARE failure releases the fence and leaves business state safely `BOUND`.

A second kernel cannot prepare the same action while the active lease remains valid.

### Fenced provider execution

Immediately before provider invocation, v0.7 requires:

```text
replay PREPARED
+ approval request matches anchored release evidence
+ full arguments match semantic intent
+ active permit belongs to this kernel instance
+ fence is current/unexpired
+ business identity still matches provider/intent
+ provider/gateway accepts fence token
```

Only then can the inherited v0.6 provider execution path run.

On terminal execution the fence is released. A stale kernel cannot execute after another kernel has taken over.

### Fenced reconciliation ownership

Unknown provider outcomes release the execution fence and set business/replay state to `RECONCILIATION_REQUIRED`.

Reconciliation then obtains a new higher ownership epoch before provider lookup:

```text
execution token 1
→ unknown
→ reconciliation token 2
→ provider/gateway accepts token 2
→ provider lookup
→ state reconciled
```

A competing reconciler is blocked by the active fence.

### Distributed compensation fail-closed boundary

v0.6 compensation remains regression-tested, but v0.7 currently blocks compensation because distributed compensation fencing and unknown-outcome reconciliation have not yet been implemented.

```text
CFHS_DISTRIBUTED_SAFETY_REQUIRED
```

### Runnable v0.7 server

Canonical reference launcher:

```bash
python -m kernel.server_v07 \
  --state-dir <state> \
  --config examples/kernel.config.json \
  --policy-dir examples/policies \
  --kernel-instance-id kernel-a
```

Default port: `8048`.

The server exposes `/v7/...` aliases over the hardened API, requires an explicit kernel instance ID, and continues to reject production credentials/providers.

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
tests_run == 147
```

Certified surface:

```text
102 v0.5/v0.6 regression tests
+ 28 distributed primitive tests
+ 17 distributed provider integration tests
= 147 / 147 PASS
```

Certified GitHub Actions run:

```text
Run ID: 34041276509
Ran 147 tests in 3.618s
147 PASS
0 failures
0 errors
0 skipped
exact_test_count = true
```

The subsequent runnable-server commits also passed the same validator step.

## Remaining v0.7 work

1. shared/fenced persistence interface and production backend contract;
2. atomic coordination among business identity reservation, semantic replay reservation, exact-resource reservation and ownership fence;
3. ownership/fencing contracts for approval mutation and additional shared kernel state;
4. distributed compensation execution and compensation unknown-outcome reconciliation;
5. exact-unit financial authority thresholds;
6. production external IdP/MFA authentication-class policy;
7. hardened remote audit-anchor authentication/availability;
8. provider webhook/event reconciliation;
9. one real provider's business identity/fencing/idempotency semantics in test mode only;
10. migration, network-partition, failover and incident drills.

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

Still pending:

```text
blakailabs/NCF-v1
→ blakailabs/Company-Operating-System
```

The connected GitHub API cannot perform the repository-name admin mutation. See `/ADMIN-RENAME.md`.

## Next v0.7 increment

Define the **shared/fenced persistence contract and transaction coordinator** so business identity, semantic replay, exact resource reservation and ownership fencing no longer behave as independently committed safety records.
