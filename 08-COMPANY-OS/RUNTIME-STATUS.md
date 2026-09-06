# Company Operating System Runtime Status

**Updated:** 2026-09-06 16:59 UTC  
**Current engineering branch:** `feature/company-kernel-distributed-safety-v0.7`  
**Draft PR:** #3 — `Company Kernel Distributed / Production Safety v0.7 — exact authority + distributed execution`

## Canonical project identity

**Project:** Company Operating System  
**Historical repository slug:** `blakailabs/NCF-v1`  
**Intended repository slug:** `blakailabs/Company-Operating-System`

NCF remains the constitutional governance layer inside the broader Company Operating System.

## Canonical runtime

```text
kernel.server_v07
→ TrustKernelV07ExactAuthorityFinalGate
→ TrustKernelV07ControlPlaneFinalGate
→ TrustKernelV07DistributedCompensationFinalGate
→ TrustKernelV07TransactionalProviderGate
→ RecoverableSQLiteFencedStateCoordinator
```

Canonical server promotion commit:

```text
f8765efefc8f76621be3cd3f849754436a55ea74
```

## v0.7 implemented safety layers

### Business-object identity + semantic replay

Consequential actions bind a versioned real-world business identity independently of caller replay nonce.

```text
same business identity + same semantic intent → idempotent
same business identity + different semantic intent → conflict
same semantic intent + different business identity → conflict
```

### Monotonic distributed fencing

Execution, reconciliation and compensation ownership phases use increasing fencing epochs. Stale kernels are rejected both at kernel state transitions and at the provider/gateway guard.

### Transaction-coordinated PREPARE

After approval provenance and anchored authorization evidence, the reference coordinator atomically binds:

```text
business identity
+ semantic replay
+ exact resource capacity
+ ownership fence
+ transaction/version journal
```

The provider PREPARE path must consume the same exact reservation ID.

### Forward reconciliation

Unknown provider outcomes remain on the same transaction ID and reconcile under a newer fencing epoch. Provider execution is not blindly retried while outcome is unknown.

### Distributed compensation

Compensation is a separately governed reversal phase of the original distributed transaction with:

```text
separate compensation intent
+ reversal authority
+ independent approvals/session provenance
+ anchored compensation authorization
+ compensation identity
+ new fencing epoch
+ provider idempotency
+ unknown-outcome reconciliation
```

Successful reversal converges exact accounting, provider state, replay state, business identity and distributed transaction to `COMPENSATED`.

### Shared/fenced persistence contract

`kernel/shared_state_backend.py` defines the cross-host persistence guarantees required for production correctness:

```text
serializable transactions
compare-and-swap
monotonic fencing
durable ordered journal
multi-connection visibility
synchronous durability
authoritative shared time
distributed quorum
```

The SQLite reference passes semantic conformance tests but explicitly remains **not production-ready** because it lacks authoritative distributed time and distributed quorum.

### Fenced approval control plane

Approval mutation is now versioned and fenced. Approval row, authenticated session provenance, approval-request status and mutation journal commit atomically under one monotonic control-plane epoch.

The canonical v0.7 gate rejects plain unproven approval mutation.

### Exact financial authority

Financial authority now uses the same exact integer units as accounting.

Reference standing refund authority:

```text
USD $250.00
= 25,000 minor units
```

Rules:

```text
$250.00 → ALLOW under standing authority
$250.01 → ELEVATION_REQUIRED
sub-minor precision → REJECT
NaN / infinite amount → REJECT
legacy float-only elevation → cannot bypass exact authority
matching exact-unit elevation → may authorize within elevated unit ceiling
```

## v0.7 certification

Canonical validator:

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v07.py
```

Current exact-count surface:

```text
102  v0.5/v0.6 regression tests
 28  distributed primitive tests
 17  fenced provider integration tests
 17  distributed transaction coordinator tests
  6  transaction recovery-hardening tests
 11  transactional provider-gate tests
 11  distributed compensation tests
 13  shared-backend contract tests
  9  fenced approval-control tests
  8  exact financial-authority tests
---
222 targeted tests
```

Corrected exact-authority candidate:

```text
Run ID: 34045382906
Commit: 2f8ef6e3dd769b7203fc4a8fa5ca738166414b56
222 / 222 PASS
0 failures
0 errors
0 skipped
exact_test_count = true
```

Canonical server certification:

```text
Run ID: 34045682513
Commit: f8765efefc8f76621be3cd3f849754436a55ea74
Ran 222 tests in 5.736s
222 / 222 PASS
0 failures
0 errors
0 skipped
exact_test_count = true
```

## Current production posture

```text
Business-object identity................ IMPLEMENTED
Semantic replay safety.................. IMPLEMENTED
Monotonic distributed fencing........... IMPLEMENTED
Transactional PREPARE................... IMPLEMENTED
Forward outcome reconciliation.......... IMPLEMENTED
Distributed compensation................ IMPLEMENTED
Compensation reconciliation............. IMPLEMENTED
Shared persistence contract............. IMPLEMENTED / REFERENCE ONLY
Fenced approval control plane........... IMPLEMENTED
Exact financial authority............... IMPLEMENTED
Canonical v0.7 certification............ 222 / 222 PASS
Production HA persistence backend....... PENDING
Production IdP / MFA policy............. PENDING
Production remote anchor hardening...... PENDING
Production provider event reconciliation PENDING
Production credentials.................. DENIED
Production write providers.............. DISABLED
Real provider test mode................. NOT YET ENABLED
```

## Remaining v0.7 work

1. implement and certify a real shared/HA persistence backend preserving the tested fencing/CAS/journal semantics across hosts;
2. extend shared control-plane ownership/versioning beyond approval mutation where needed;
3. production external IdP/MFA authentication-class requirements for S3 actions, approvals, elevations and compensation;
4. hardened remote audit-anchor authentication, availability and reconciliation;
5. provider webhook/event reconciliation;
6. validate one real provider's business identity/fencing/idempotency semantics in test mode only;
7. migration, network-partition, failover and incident drills.

## Global production release gate

No production write-capable provider is enabled until the applicable path has:

```text
verified identity / authentication class
+ recursive authority provenance
+ authentic policy
+ exact financial authority where applicable
+ business-object identity binding
+ semantic replay binding
+ transaction-coordinated exact capacity
+ current distributed fence
+ provider stale-fence protection
+ provider idempotency
+ session-proven approvals
+ anchored release/provider evidence
+ forward reconciliation
+ governed/fenced/reconcilable compensation where required
+ production shared/HA backend certification
```

## Administrative repository rename

Still pending:

```text
blakailabs/NCF-v1
→ blakailabs/Company-Operating-System
```

See `/ADMIN-RENAME.md`.

## Next logical v0.7 increment

Implement **production identity / MFA authentication-class policy** while preserving the existing 222-test regression surface. Production credentials remain disabled throughout that work.
