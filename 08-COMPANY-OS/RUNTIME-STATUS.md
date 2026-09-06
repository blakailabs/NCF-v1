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

### v0.1–v0.4

Runnable kernel, authenticated hardening, trust provenance and trust hardening established deterministic identity/authority, policy, audit, secret, session, delegation and recovery foundations.

### v0.5 — Action Safety

Implemented semantic action intents, replay protection, kernel-derived resource reservations, approval floors, explicit approvers, compensation requirements, fail-closed audit PREPARE, crash recovery, conservative unknown-side-effect handling and simulated consequential execution.

### v0.6 — Live-Adapter Safety

Canonical runtime:

```text
kernel.server_v06_hardened
→ TrustKernelV06ReleaseGate
```

Implemented exact economic accounting, persistent provider idempotency/lookup, provider reconciliation, approval-session provenance, anchored release/provider evidence, semantic replay recovery and separately governed S3 compensation.

Certified:

```text
102 / 102 targeted tests PASS
```

PR #2 was merged into the validated Company OS lineage at:

```text
14c07be1aca2dc93e531f955a5bdf537f46bd0fc
```

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
→ TrustKernelV07DistributedCompensationFinalGate
→ RecoverableSQLiteFencedStateCoordinator
```

### Business-object identity

Consequential operations explicitly identify the real-world target independently of replay nonce.

```text
same business identity + same semantic intent → idempotent
same business identity + different semantic intent → conflict
same semantic intent + different business identity → conflict
```

Raw business identity values are not persisted by the distributed identity ledgers.

### Monotonic ownership fencing

Each business resource uses an increasing ownership epoch:

```text
kernel A / token 1
→ lease expiry / takeover
kernel B / token 2
→ stale kernel A rejected
```

The provider/gateway also rejects stale lower fencing epochs.

### Atomic transaction-coordinated PREPARE

Canonical ordering:

```text
approval provenance
→ authorization decision
→ authorization evidence anchor
→ distributed transaction PREPARE
    ├── verify business identity
    ├── verify semantic replay
    ├── reserve exact capacity
    ├── acquire ownership fence
    └── journal transaction version
→ provider PREPARE using the same exact reservation
```

The reference SQLite coordinator acquires exact capacity and the ownership epoch atomically.

Safe PREPARE aborts are retryable under a higher fencing epoch. A dead PREPARED owner can be replaced after lease expiry without double-reserving capacity.

### Fenced provider execution and reconciliation

Provider invocation requires the current transaction/fence and provider-side stale-token acceptance.

Unknown outcomes remain on the same transaction ID and reconcile under a newer ownership epoch.

### Distributed compensation

Compensation is now implemented on the same distributed transaction rather than being blocked.

It requires:

```text
committed original transaction
→ separate compensation intent
→ base reversal authority
→ independent multi-party approvals + session provenance
→ anchored compensation authorization evidence
→ immutable compensation identity
→ new compensation ownership epoch
→ provider/gateway fence acceptance
→ provider-idempotent reversal
```

Compensation identity binds the original business identity, provider, original provider action and compensation operation.

Definite provider rejection returns the original transaction safely to `COMMITTED`, releases the compensation fence and preserves committed exact usage for retry.

Successful reversal converges:

```text
exact resource state → COMPENSATED
provider state → COMPENSATED
semantic replay → COMPENSATED
business identity → COMPENSATED
distributed transaction → COMPENSATED
```

### Compensation unknown-outcome reconciliation

If provider reversal may have committed but the response is lost:

```text
COMPENSATING
→ COMPENSATION_RECONCILIATION_REQUIRED
→ release compensation epoch
→ exact usage remains committed locally
```

A new higher reconciliation epoch performs provider compensation lookup.

Provider proves reversal:

```text
→ finalize COMPENSATED everywhere
```

Provider proves no reversal:

```text
→ transaction returns COMMITTED
→ exact usage remains committed
→ same approved compensation can retry safely
```

Reconciliation-attempt history is retained across retries.

### Runnable v0.7 server

```bash
python -m kernel.server_v07 \
  --state-dir <state> \
  --config examples/kernel.config.json \
  --policy-dir examples/policies \
  --kernel-instance-id kernel-a
```

Default port: `8048`.

The server now exposes governed compensation request/execute plus:

```text
POST /v7/provider/compensation/reconcile
```

Production credentials/providers remain disabled.

### v0.7 certification

Canonical validator:

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v07.py
```

Exact-count certified surface:

```text
102  v0.5/v0.6 regressions
 28  distributed primitives
 17  fenced provider integration
 17  transaction coordinator
  6  transaction recovery hardening
 11  transactional provider integration
 11  distributed compensation
---
192 / 192 PASS
```

Canonical compensation-capable server certification:

```text
Run ID: 34044287513
Commit: 8c2d5fb1b901ce86b809ead454edae7e48a393e3
Ran 192 tests in 6.165s
192 PASS
0 failures
0 errors
0 skipped
exact_test_count = true
```

## Remaining v0.7 work

1. production shared/fenced persistence backend contract and implementation preserving current semantics across hosts;
2. ownership/fencing for approval mutation and other shared kernel control-plane state;
3. exact-unit financial authority thresholds;
4. production external IdP/MFA authentication-class policy;
5. hardened remote audit-anchor authentication/availability;
6. provider webhook/event reconciliation;
7. one real provider's identity/fencing/idempotency semantics in test mode only;
8. migration, network-partition, failover and incident drills.

## Global production release gate

No production write-capable provider is enabled until:

```text
identity verified
+ recursive authority provenance verified
+ policy authenticity verified
+ business target identity bound
+ semantic replay bound
+ transaction-coordinated exact capacity acquired
+ current distributed fence held
+ provider stale-fence rejection available
+ provider idempotency supported
+ approval provenance satisfied
+ release authority anchored
+ provider PREPARE anchored
+ forward reconciliation available
+ compensation independently governed/fenced/reconcilable
+ production shared ownership/fencing backend validated
```

## Administrative repository rename

Still pending:

```text
blakailabs/NCF-v1
→ blakailabs/Company-Operating-System
```

See `/ADMIN-RENAME.md`.

## Next v0.7 increment

Define and certify the **production shared/fenced persistence contract** so multiple hosts preserve the current transaction, replay, exact-resource, fencing and compensation invariants without relying on a single SQLite database.
