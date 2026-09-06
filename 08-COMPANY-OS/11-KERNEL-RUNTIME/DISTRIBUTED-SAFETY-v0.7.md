# Company Kernel Distributed / Production Safety v0.7

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-distributed-safety-v0.7`  
**Base milestone:** merged Live-Adapter Safety v0.6  
**Status:** active engineering milestone; production credentials remain disabled

## Purpose

v0.6 proved provider-shaped consequential execution on a single durable kernel reference runtime.

v0.7 is moving the kernel from **single-kernel correctness** toward **distributed ownership correctness**.

The canonical provider path now is:

```text
BusinessObjectIdentity
→ semantic replay binding
→ anchored approval / authorization evidence
→ atomic distributed transaction PREPARE
    ├── exact resource capacity
    └── ownership fencing epoch
→ v0.6 provider PREPARE using the same exact reservation
→ current transaction epoch revalidation
→ provider/gateway stale-fence guard
→ provider invocation
→ terminal state OR reconciliation required
→ same transaction ID + higher reconciliation fencing epoch
```

## Business-object identity

Each consequential operation declares a versioned identity contract describing the real-world target independently of caller replay nonce.

Reference refund contract:

```text
payments.refund.target/v1
→ provider_account_id
→ charge_id
→ refund_reference
```

The identity digest binds contract ID, contract version, operation and a digest of the declared identity fields. Raw business identity values are not persisted by the reference distributed ledgers.

### Semantic binding rule

```text
same business identity + same semantic intent
→ idempotent

same business identity + different semantic intent
→ CFHS_BUSINESS_IDENTITY_CONFLICT

same semantic intent + different business identity
→ CFHS_BUSINESS_IDENTITY_CONFLICT
```

This prevents the same real-world action from becoming a second action merely because a caller supplied a new replay nonce.

## Monotonic fencing

Each distributed business resource receives a monotonically increasing ownership epoch:

```text
kernel A → token 1
lease expires / ownership changes
kernel B → token 2
kernel A resumes with token 1 → stale / rejected
```

Tokens never decrease or get reused for a later ownership epoch.

The reference SQLite implementation persists the last issued epoch separately from the active lease, so clean release, retry and takeover all advance the token.

## Provider-side stale-fence rejection

Kernel-side ownership checks are insufficient if a stale kernel can still reach an external provider with valid credentials.

v0.7 therefore models an independent provider/gateway guard:

```text
highest provider-observed fence = 8
request arrives with fence = 7
→ CFHS_STALE_FENCE
```

The fence token intentionally remains outside the provider's business arguments. This preserves v0.6 provider idempotency: changing ownership epochs does not change the semantic provider request digest.

A production provider must either support equivalent fencing/precondition semantics or sit behind a gateway that does.

## Distributed transaction coordinator

The canonical v0.7 provider gate now uses `RecoverableSQLiteFencedStateCoordinator` through `TrustKernelV07TransactionalProviderGate`.

The transaction binds:

```text
transaction id
semantic intent digest
replay nonce
business identity digest
provider id
business resource key
kernel owner id
lease id
fence token
fence expiration
exact resource pool
exact units
exact reservation id
purpose: EXECUTE | RECONCILE
status
monotonic version
```

### Atomic PREPARE boundary

Before a provider PREPARE can exist, the coordinator verifies the immutable business identity and semantic replay bindings and then acquires, inside one SQLite transaction:

```text
exact resource capacity
+
current distributed ownership epoch
+
durable transaction/version journal entry
```

The inherited v0.6 provider coordinator must consume the **same exact reservation ID**. Any reservation mismatch fails closed.

This removes the prior gap where resource reservation and ownership fencing could be committed independently during PREPARE.

### Authorization ordering

The canonical ordering is:

```text
approval provenance
→ authorization decision
→ authorization evidence anchor
→ distributed transaction PREPARE
→ provider PREPARE anchor
```

If authorization anchoring fails, no distributed transaction, exact reservation or fence is created.

## Retryable safe abort

A provider PREPARE failure before execution can safely abort the distributed transaction:

```text
PREPARED token 1
→ safe provider-PREPARE failure
→ exact capacity released
→ fence released
→ transaction ABORTED
→ retry
→ same transaction ID
→ new exact reservation
→ token 2
→ PREPARED
```

The prior transaction history is retained in the versioned journal.

Retry cannot silently change the immutable business/replay/provider/resource bindings or exact-unit amount.

## Pre-execution takeover

If a kernel dies while holding a PREPARED transaction, another kernel may take over only after the prior lease expires.

```text
kernel A PREPARED / token 1 / reservation X
→ lease expires
→ kernel B takeover / token 2 / same reservation X
```

The resource is not reserved a second time. Kernel A becomes stale and cannot transition or invoke the provider.

## Provider execution

Immediately before provider execution, the canonical gate requires:

```text
replay state = PREPARED
prepared approval request matches anchored release evidence
full provider arguments match semantic intent
transaction status = PREPARED
transaction owner = current kernel instance
transaction fence is current and unexpired
business identity still matches semantic intent/provider
provider/gateway accepts the current fencing token
```

The transaction then advances to `EXECUTING` before the provider call.

Terminal outcomes advance the same transaction to:

```text
COMMITTED
FAILED_NOT_EXECUTED
RECONCILIATION_REQUIRED
```

The ownership epoch is released after the terminal execution decision.

## Fenced reconciliation ownership

Unknown provider outcomes remain attached to the same distributed transaction ID.

Reconciliation obtains a new ownership epoch:

```text
transaction T / execution token 1
→ provider outcome unknown
→ T = RECONCILIATION_REQUIRED
→ execution epoch released
→ reconciliation takes T with token 2
→ T = RECONCILING
→ provider/gateway accepts token 2
→ provider lookup
→ T = COMMITTED | FAILED_NOT_EXECUTED | COMPENSATED
```

Only one active reconciler may own the transaction's business resource. Competing reconciliation fails with `CFHS_FENCE_BUSY`.

A stale execution owner cannot mutate the transaction after reconciliation takeover.

## Versioned transaction journal

Every distributed transaction mutation receives a monotonically increasing transaction version and a journal entry containing:

```text
transaction id
version
fence token
owner
from state
to state
event digest
timestamp
```

The journal preserves retry/takeover/reconciliation history rather than overwriting prior ownership epochs.

## Distributed compensation policy

v0.6 compensation remains fully regression-tested as a single-kernel safety mechanism, but the canonical v0.7 runtime **blocks compensation** until compensation receives equivalent transaction/fencing and unknown-outcome reconciliation guarantees.

Attempts return:

```text
CFHS_DISTRIBUTED_SAFETY_REQUIRED
```

This is deliberate fail-closed behavior.

## Canonical runnable v0.7 server

```bash
python -m kernel.server_v07 \
  --state-dir <state> \
  --config examples/kernel.config.json \
  --policy-dir examples/policies \
  --kernel-instance-id kernel-a
```

Default port:

```text
8048
```

Canonical gate:

```text
TrustKernelV07TransactionalProviderGate
```

Health reports the canonical gate, kernel instance ID, distributed controls, sandbox provider registry, compensation block, audit/anchor health and bootstrap status.

Production credentials remain disabled.

## v0.7 certification surface

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
 11  transactional provider-gate integration tests
---
181 targeted tests
```

Canonical server commit certification:

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

Important integration coverage includes:

- business identity versus semantic replay immutability;
- exact resource capacity + ownership fence atomic PREPARE;
- rollback of both capacity and fence when PREPARE prerequisites fail;
- anchored authorization before transactional resource/fence acquisition;
- one exact reservation shared by transaction and v0.6 provider state;
- safe PREPARE abort and higher-epoch retry;
- dead PREPARED-owner takeover after expiration without double reservation;
- stale-owner execution rejection after takeover;
- provider/gateway stale-token rejection;
- same transaction ID through execution and reconciliation;
- higher reconciliation epoch;
- versioned journal history;
- nontransactional PREPARE bypass rejection;
- distributed compensation fail-closed behavior.

## What v0.7 does not claim yet

The canonical SQLite coordinator is a **reference transactional contract**, not a production HA database.

Still pending:

1. production shared/fenced persistence backend interface and implementation preserving these semantics across hosts;
2. distributed compensation execution and compensation unknown-outcome reconciliation;
3. ownership/fencing for approval mutation and other shared kernel control-plane state;
4. exact-unit financial authority thresholds;
5. production external IdP/MFA authentication-class requirements;
6. hardened remote audit-anchor authentication/availability;
7. provider webhook/event reconciliation;
8. one real provider's identity/fencing/idempotency semantics in test mode only;
9. migration, network-partition, failover and incident drills.

## Production decision

```text
Business-object identity................ IMPLEMENTED
Monotonic fencing....................... IMPLEMENTED
Provider stale-fence guard.............. IMPLEMENTED
Fenced provider PREPARE................. IMPLEMENTED
Fenced provider execution............... IMPLEMENTED
Fenced reconciliation ownership......... IMPLEMENTED
Atomic exact-capacity + fence PREPARE.... IMPLEMENTED
Versioned distributed transaction........ IMPLEMENTED
Retryable safe abort..................... IMPLEMENTED
Pre-execution takeover................... IMPLEMENTED
Canonical transactional v0.7 server...... IMPLEMENTED
v0.7 certification....................... 181 / 181 PASS
Distributed compensation................. BLOCKED / PENDING
Shared HA persistence backend............ PENDING
Production credentials................... DENIED
Production write providers............... DISABLED
Real provider test mode.................. NOT YET ENABLED
```

## Next v0.7 increment

Implement **distributed compensation safety** on the same transaction/fencing model, including compensation business identity, independent authority/approval evidence, a new compensation ownership epoch, provider reversal idempotency and unknown-outcome reconciliation.
