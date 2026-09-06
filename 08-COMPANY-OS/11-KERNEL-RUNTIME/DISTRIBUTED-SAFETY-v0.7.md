# Company Kernel Distributed / Production Safety v0.7

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-distributed-safety-v0.7`  
**Status:** active engineering milestone; production credentials remain disabled

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

## Canonical distributed action path

```text
BusinessObjectIdentity
→ semantic replay binding
→ session-proven approvals
→ authorization decision
→ anchored authorization evidence
→ exact financial authority where applicable
→ distributed transaction PREPARE
    ├── exact resource capacity
    ├── current ownership fence
    └── versioned transaction journal
→ provider PREPARE using same exact reservation
→ transaction/fence revalidation
→ provider/gateway stale-fence guard
→ provider execution
→ terminal state OR forward reconciliation
→ separately governed compensation when required
→ new compensation fence epoch
→ provider-idempotent reversal
→ COMPENSATED OR compensation reconciliation
```

## Business-object identity

Consequential operations declare a versioned identity contract for the real-world target independently of replay nonce.

Reference refund identity:

```text
payments.refund.target/v1
→ provider_account_id
→ charge_id
→ refund_reference
```

```text
same identity + same semantic intent → idempotent
same identity + different semantic intent → conflict
same semantic intent + different identity → conflict
```

Raw business identity values are not persisted by the distributed identity ledgers.

## Monotonic fencing

Each distributed ownership phase receives a monotonically increasing epoch:

```text
kernel A → token 1
lease expires / ownership changes
kernel B → token 2
kernel A token 1 → stale / rejected
```

The provider/gateway guard independently rejects lower epochs after observing a newer token.

## Transaction-coordinated PREPARE

Before provider PREPARE, approval/authorization evidence is established and the distributed coordinator atomically binds:

```text
business identity
+ semantic replay
+ exact resource reservation
+ ownership fence
+ transaction version/journal
```

The inherited provider runtime must consume the same exact reservation ID. Reservation mismatch fails closed.

Safe provider-PREPARE failure releases exact capacity and the ownership epoch while preserving history. Retry proceeds on the same transaction ID under a higher fence.

If a PREPARED kernel dies, a new owner can take over only after lease expiry and reuses the existing reservation rather than double-reserving capacity.

## Forward execution and reconciliation

Immediately before provider execution the canonical gate verifies:

```text
replay state
anchored release evidence
immutable arguments
transaction status
current kernel ownership
live/current fence
business identity binding
provider/gateway fence acceptance
```

Unknown provider outcomes remain on the same transaction ID:

```text
T / execution token N
→ RECONCILIATION_REQUIRED
→ release execution epoch
→ T / reconciliation token N+1
→ provider lookup
→ COMMITTED | FAILED_NOT_EXECUTED | COMPENSATED
```

Blind provider retry is prohibited while outcome remains unknown.

## Distributed compensation

Compensation is a governed phase of the original transaction, not an unaudited callback.

It requires:

```text
original transaction COMMITTED
→ separate compensation intent
→ reversal authority
→ independent approvals/session provenance
→ anchored compensation authorization
→ immutable compensation identity
→ new compensation ownership epoch
→ provider/gateway fence acceptance
→ provider-idempotent reversal
```

Compensation identity binds the original business identity, provider, original provider action and compensation operation.

### Definite failure

```text
COMPENSATING
→ provider proves not executed
→ transaction returns COMMITTED
→ compensation fence released
→ committed exact usage remains
→ same approved compensation may retry later
```

### Successful compensation

```text
provider reversal confirmed
→ exact resource state COMPENSATED
→ provider state COMPENSATED
→ replay state COMPENSATED
→ business identity COMPENSATED
→ distributed transaction COMPENSATED
```

### Unknown compensation outcome

A lost transport response does not reverse local accounting early:

```text
COMPENSATING / token N
→ COMPENSATION_RECONCILIATION_REQUIRED
→ release token N
→ exact usage remains committed
→ acquire reconciliation token N+1
→ provider compensation lookup
```

Provider proves reversal → finalize `COMPENSATED` everywhere.

Provider proves no reversal → return transaction to `COMMITTED`; the same approved compensation remains safely retryable.

Reconciliation-attempt history is retained across retries.

## Shared/fenced persistence contract

`kernel/shared_state_backend.py` defines the guarantees required of a production cross-host backend:

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

The SQLite reference validates semantics across independent connections but explicitly fails production certification because it lacks authoritative shared time and distributed quorum.

This is intentional: SQLite is the reference contract implementation, not the production HA datastore.

## Fenced approval control plane

Approval mutations now receive monotonic control-plane epochs.

The following commit atomically under one approval mutation:

```text
action_approvals row
+ authenticated session provenance
+ approval request status
+ control version
+ approval mutation journal
```

Stale owners cannot mutate the workflow after takeover. Replayed approval from the same authenticated session is idempotent but versioned. Approval provenance cannot be replaced by a different session.

The canonical v0.7 runtime rejects plain approval mutation lacking authenticated session provenance.

## Exact financial authority

Financial authority uses the same exact integer representation as accounting.

Reference refund standing authority:

```text
currency: USD
minor exponent: 2
max_units: 25000
$250.00 = 25,000 units
```

Canonical behavior:

```text
$250.00 → ALLOW
$250.01 → ELEVATION_REQUIRED
$250.001 → REJECT (sub-minor precision)
NaN / infinity → REJECT
legacy float-only elevation → does not satisfy exact authority
matching exact-unit elevation → ALLOW up to elevated unit ceiling
```

This prevents floating-point authorization thresholds from weakening exact accounting.

## API

Runnable reference server:

```bash
python -m kernel.server_v07 \
  --state-dir <state> \
  --config examples/kernel.config.json \
  --policy-dir examples/policies \
  --kernel-instance-id kernel-a
```

Default port: `8048`.

Governed compensation reconciliation endpoint:

```text
POST /v7/provider/compensation/reconcile
```

Health reports exact financial authority, fenced approval control, distributed compensation, provider registry and the explicit non-production shared-backend status.

## v0.7 certification

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

Canonical server promotion:

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

## Current production decision

```text
Business-object identity................ IMPLEMENTED
Semantic replay safety.................. IMPLEMENTED
Monotonic fencing....................... IMPLEMENTED
Provider stale-fence guard.............. IMPLEMENTED
Atomic transaction PREPARE.............. IMPLEMENTED
Forward reconciliation.................. IMPLEMENTED
Distributed compensation................ IMPLEMENTED
Compensation reconciliation............. IMPLEMENTED
Shared persistence contract............. IMPLEMENTED / REFERENCE ONLY
Fenced approval control plane........... IMPLEMENTED
Exact financial authority............... IMPLEMENTED
Canonical v0.7 certification............ 222 / 222 PASS
Production HA persistence backend....... PENDING
Production external IdP/MFA............. PENDING
Remote audit-anchor production hardening PENDING
Provider event/webhook reconciliation... PENDING
Production credentials.................. DENIED
Production write providers.............. DISABLED
Real provider test mode................. NOT YET ENABLED
```

## Remaining v0.7 work

1. implement and certify a real shared/HA persistence backend preserving the tested contract across hosts;
2. extend shared ownership/versioning to additional shared control-plane mutations where necessary;
3. define production external IdP/MFA authentication-class requirements for S3 actions, approvals, elevations and compensation;
4. harden remote audit-anchor authentication/availability/reconciliation;
5. add provider webhook/event reconciliation;
6. validate one real provider's identity/fencing/idempotency semantics in test mode only;
7. execute migration, network-partition, failover and incident drills.

## Next v0.7 increment

Implement **production identity / MFA authentication-class policy** while preserving the entire 222-test regression surface. Production credentials remain disabled throughout this work.
