# Company Kernel Distributed / Production Safety v0.7

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-distributed-safety-v0.7`  
**Base milestone:** merged Live-Adapter Safety v0.6  
**Status:** active engineering milestone; production credentials remain disabled

## Canonical runtime

```text
kernel.server_v07
→ TrustKernelV07DistributedCompensationFinalGate
→ RecoverableSQLiteFencedStateCoordinator
```

The canonical provider path now covers both forward execution and governed reversal:

```text
BusinessObjectIdentity
→ semantic replay binding
→ anchored approval / authorization evidence
→ atomic distributed transaction PREPARE
    ├── exact resource capacity
    └── ownership fencing epoch
→ provider PREPARE
→ current transaction epoch revalidation
→ provider/gateway stale-fence guard
→ provider invocation
→ terminal state OR reconciliation
→ same transaction ID + higher reconciliation epoch
→ independent compensation authority / approvals
→ compensation identity
→ new compensation fencing epoch
→ provider-idempotent reversal
→ COMPENSATED OR compensation reconciliation
```

## Business-object identity

Consequential operations declare a versioned contract identifying the real-world target independently of replay nonce.

Reference refund identity:

```text
payments.refund.target/v1
→ provider_account_id
→ charge_id
→ refund_reference
```

Raw identity values are not persisted by the distributed identity ledgers.

```text
same business identity + same semantic intent → idempotent
same business identity + different semantic intent → conflict
same semantic intent + different business identity → conflict
```

## Monotonic fencing

Each distributed business resource receives a monotonically increasing ownership epoch:

```text
kernel A → token 1
lease expires / ownership changes
kernel B → token 2
stale kernel A → rejected
```

A provider/gateway guard independently rejects lower epochs after observing a newer token. Fence metadata stays outside provider business arguments so ownership changes do not alter provider idempotency digests.

## Transaction-coordinated PREPARE

Authorization/approval evidence is established before economic/ownership resources are acquired:

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
→ provider PREPARE using the same exact reservation
```

Exact capacity and the ownership epoch are acquired atomically by the reference SQLite coordinator.

If provider PREPARE fails safely:

```text
PREPARED token 1
→ exact capacity released
→ fence released
→ ABORTED
→ retry
→ same transaction ID
→ new reservation
→ token 2
```

If a PREPARED kernel dies, a new kernel can take over only after lease expiry, under a strictly higher token while reusing the existing exact reservation.

## Forward execution and reconciliation

Immediately before provider invocation the canonical gate revalidates the transaction owner/fence, immutable arguments, business identity, anchored release evidence, replay state, and provider stale-fence guard.

Unknown outcomes stay on the same transaction:

```text
T / execution token 1
→ RECONCILIATION_REQUIRED
→ release execution epoch
→ T / reconciliation token 2
→ provider lookup
→ COMMITTED | FAILED_NOT_EXECUTED | COMPENSATED
```

The transaction journal preserves every version, owner and fence epoch.

## Distributed compensation safety

Distributed compensation is now implemented rather than blocked.

The reversal is treated as another consequential action with independent governance:

```text
original transaction COMMITTED
→ separate compensation intent
→ requester must possess reversal authority
→ independent multi-party approvals + session provenance
→ compensation authorization evidence anchored
→ immutable compensation identity
→ new compensation fencing epoch
→ provider/gateway accepts current token
→ provider-idempotent reversal
```

Compensation identity binds:

```text
original business identity
provider
original provider action id
compensation operation
```

### Definite reversal failure

```text
COMPENSATING
→ provider proves not executed
→ transaction returns COMMITTED
→ fence released
→ exact used units remain committed
→ same approved compensation can retry later under a higher fence
```

### Successful reversal

```text
COMMITTED
→ COMPENSATING / token N
→ provider confirms reversal
→ exact committed units become COMPENSATED
→ provider/replay state COMPENSATED
→ business identity COMPENSATED
→ transaction COMPENSATED
→ fence released
```

All canonical state converges on the same terminal truth.

### Unknown compensation outcome

Local accounting is not reversed merely because the transport response was lost:

```text
COMPENSATING / token N
→ outcome unknown
→ COMPENSATION_RECONCILIATION_REQUIRED
→ fence released
→ exact used units remain committed
```

Reconciliation then acquires a newer fence:

```text
same transaction T
→ COMPENSATION_RECONCILING / token N+1
→ provider compensation lookup
```

If the provider proves compensation persisted:

```text
→ exact usage reversed
→ replay/provider/business identity COMPENSATED
→ T = COMPENSATED
```

If the provider proves no compensation exists:

```text
→ T returns COMMITTED
→ exact usage remains committed
→ approved compensation remains safely retryable
```

Reconciliation-attempt history is retained. A later uncertain retry may reopen the same semantic compensation case without erasing the earlier `CONFIRMED_NOT_EXECUTED` result.

## Canonical API additions

The hardened `/v7/...` API inherits the governed compensation request/execute endpoints and adds:

```text
POST /v7/provider/compensation/reconcile
```

The reconciliation request identifies the original `intent_id` and the approved `compensation_intent_id`.

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
 17  transaction coordinator tests
  6  transaction recovery-hardening tests
 11  transactional provider integration tests
 11  distributed compensation tests
---
192 targeted tests
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

The compensation tests cover independent approvals, authorization-anchor failure, definite provider rejection, safe retry, higher compensation fencing epochs, reversal idempotency, response-loss reconciliation, provider-not-executed reconciliation, reconciliation retry/history, immutable compensation arguments, exact accounting convergence and business-identity convergence.

## What v0.7 still does not claim

The SQLite coordinator remains a **reference transactional contract**, not a production HA datastore.

Still pending:

1. production shared/fenced persistence backend preserving certified semantics across hosts;
2. ownership/fencing for approval mutation and other shared kernel control-plane state;
3. exact-unit financial authority thresholds;
4. production external IdP/MFA authentication-class requirements;
5. hardened remote audit-anchor authentication/availability;
6. provider webhook/event reconciliation;
7. one real provider's identity/fencing/idempotency semantics in test mode only;
8. migration, network-partition, failover and incident drills.

## Production decision

```text
Business-object identity................ IMPLEMENTED
Monotonic fencing....................... IMPLEMENTED
Provider stale-fence guard.............. IMPLEMENTED
Atomic exact-capacity + fence PREPARE.... IMPLEMENTED
Fenced provider execution............... IMPLEMENTED
Fenced provider reconciliation.......... IMPLEMENTED
Versioned distributed transaction........ IMPLEMENTED
Retryable safe abort / takeover.......... IMPLEMENTED
Distributed compensation governance...... IMPLEMENTED
Compensation fencing..................... IMPLEMENTED
Compensation idempotency................. IMPLEMENTED
Compensation unknown-outcome reconcile... IMPLEMENTED
Compensation attempt history............. IMPLEMENTED
Canonical compensation-capable server.... IMPLEMENTED
v0.7 certification....................... 192 / 192 PASS
Shared HA persistence backend............ PENDING
Production credentials................... DENIED
Production write providers............... DISABLED
Real provider test mode.................. NOT YET ENABLED
```

## Next v0.7 increment

Define and certify the **production shared/fenced persistence contract** so multiple hosts can preserve the same transaction, replay, reservation, fencing and compensation invariants without relying on one SQLite database.
