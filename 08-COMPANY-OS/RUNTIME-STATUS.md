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

### Canonical runtime

```text
kernel.server_v07
→ TrustKernelV07TransactionalProviderGate
→ RecoverableSQLiteFencedStateCoordinator
```

The canonical v0.7 runtime is now transaction-coordinated rather than fencing-only.

### Business-object identity

Consequential operations declare a versioned identity contract identifying the real-world target independently of replay nonce.

Reference refund identity:

```text
payments.refund.target/v1
→ provider_account_id
→ charge_id
→ refund_reference
```

The kernel persists digests and contract metadata rather than raw identity values.

```text
same business identity + same semantic intent → idempotent
same business identity + different semantic intent → conflict
same semantic intent + different business identity → conflict
```

### Monotonic ownership fencing

Each distributed business resource has a monotonically increasing ownership epoch:

```text
kernel A → token 1
lease expiry / takeover
kernel B → token 2
stale kernel A → rejected
```

Stale owners cannot renew, release a newer owner's lease, assert current ownership, transition distributed state or invoke the provider through the canonical gate.

### Provider/gateway stale-fence enforcement

The provider boundary records the highest observed fence epoch for a provider/business resource and rejects lower epochs.

Fence metadata remains outside business arguments so ownership changes do not alter the v0.6 provider-idempotency digest.

### Transaction-coordinated PREPARE

The canonical ordering is:

```text
approval provenance
→ authorization decision
→ authorization evidence anchor
→ distributed transaction PREPARE
    ├── verify business identity
    ├── verify semantic replay binding
    ├── reserve exact capacity
    ├── acquire ownership fence
    └── journal version 1
→ v0.6 provider PREPARE using the same exact reservation
```

Exact capacity and the ownership epoch are acquired atomically by the reference SQLite coordinator.

If authorization anchoring fails, no transaction/fence/resource reservation is created.

If provider PREPARE fails safely, the transaction is aborted, exact capacity and the fence are released, and retry may proceed under a higher fencing epoch while preserving history.

### Pre-execution failover

A dead PREPARED owner can be replaced after its lease expires:

```text
transaction T
kernel A / token 1 / exact reservation X
→ lease expires
kernel B / token 2 / same transaction T / same reservation X
```

No second exact reservation is created. The stale kernel cannot execute.

### Fenced provider execution

Immediately before invocation:

```text
replay PREPARED
+ anchored release evidence matches
+ arguments match immutable semantic intent
+ transaction PREPARED
+ current kernel owns transaction
+ fence is live/current
+ business target remains bound
+ provider/gateway accepts current epoch
```

The transaction transitions to `EXECUTING` before provider invocation.

### Reconciliation on the same transaction

Unknown provider outcomes remain attached to the same transaction ID:

```text
T / execution token 1
→ RECONCILIATION_REQUIRED
→ release execution epoch
→ T / reconciliation token 2
→ RECONCILING
→ provider lookup
→ COMMITTED | FAILED_NOT_EXECUTED | COMPENSATED
```

The versioned journal records every ownership/state epoch.

### Distributed compensation fail-closed boundary

v0.6 compensation remains regression-tested, but the canonical v0.7 runtime blocks compensation until it is transaction/fence/reconciliation safe:

```text
CFHS_DISTRIBUTED_SAFETY_REQUIRED
```

### Runnable v0.7 server

```bash
python -m kernel.server_v07 \
  --state-dir <state> \
  --config examples/kernel.config.json \
  --policy-dir examples/policies \
  --kernel-instance-id kernel-a
```

Default port: `8048`.

Production credentials/providers remain disabled.

### v0.7 certification

Canonical validator:

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v07.py
```

Exact-count certified surface:

```text
102  v0.5/v0.6 regression tests
 28  distributed primitive tests
 17  fenced provider integration tests
 17  transaction coordinator tests
  6  transaction recovery-hardening tests
 11  transactional provider integration tests
---
181 / 181 PASS
```

Canonical server certification:

```text
Run ID: 34043382712
Commit: 97b42f4136e7240710a3deeff8ae2e0f4729c52e
Ran 181 tests in 18.097s
181 PASS
0 failures
0 errors
0 skipped
exact_test_count = true
```

## Remaining v0.7 work

1. distributed compensation execution and compensation unknown-outcome reconciliation on the same transaction/fencing model;
2. production shared/fenced persistence backend contract and implementation preserving current semantics across hosts;
3. ownership/fencing for approval mutation and other shared kernel control-plane state;
4. exact-unit financial authority thresholds;
5. production external IdP/MFA authentication-class policy;
6. hardened remote audit-anchor authentication/availability;
7. provider webhook/event reconciliation;
8. one real provider's identity/fencing/idempotency semantics in test mode only;
9. migration, network-partition, failover and incident drills.

## Global production release gate

No production write-capable email, payment, banking, CRM, deployment, advertising, accounting or legal-signature provider should be enabled until:

```text
identity verified
+ recursive authority provenance verified
+ policy authenticity verified
+ business target identity bound
+ semantic replay reserved
+ transaction-coordinated exact capacity acquired
+ current distributed fence held
+ provider stale-fence rejection available
+ provider idempotency supported
+ approval provenance satisfied
+ release authority anchored
+ provider PREPARE anchored
+ provider reconciliation available
+ compensation governed/reconcilable when required
+ production shared ownership/fencing backend validated
```

## Administrative repository rename

Still pending:

```text
blakailabs/NCF-v1
→ blakailabs/Company-Operating-System
```

The connected GitHub API cannot perform that repository-name admin mutation. See `/ADMIN-RENAME.md`.

## Next v0.7 increment

Implement **distributed compensation safety** with independent compensation authority, compensation identity, a new fencing epoch, provider reversal idempotency, exact-resource reversal coordination and conservative reconciliation of uncertain compensation outcomes.
