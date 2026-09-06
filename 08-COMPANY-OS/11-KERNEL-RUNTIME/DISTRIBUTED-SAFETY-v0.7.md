# Company Kernel Distributed / Production Safety v0.7

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-distributed-safety-v0.7`  
**Base milestone:** merged Live-Adapter Safety v0.6  
**Status:** active engineering milestone; production credentials remain disabled

## Purpose

v0.6 proved provider-shaped consequential execution on a single durable kernel reference runtime.

v0.7 begins the transition from **single-kernel correctness** to **distributed ownership correctness**.

The first safety boundary is now implemented end to end:

```text
BusinessObjectIdentity
→ DistributedActionPermit
→ fenced provider PREPARE
→ current fence revalidation
→ provider/gateway stale-token guard
→ provider invocation
→ terminal state / reconciliation
→ separately fenced reconciliation epoch
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

The identity digest binds contract ID, contract version, operation and the digest of the declared identity fields. Raw business identity values are not stored by the distributed identity ledgers.

### Semantic binding rule

```text
same business identity + same semantic intent
→ idempotent

same business identity + different semantic intent
→ CFHS_BUSINESS_IDENTITY_CONFLICT

same semantic intent + different business identity
→ CFHS_BUSINESS_IDENTITY_CONFLICT
```

This closes the gap where the same real-world action could be resubmitted under a new replay nonce and appear unrelated.

## Monotonic fencing

Each distributed business resource receives a monotonically increasing ownership epoch:

```text
kernel A owns action → token 1
lease expires
kernel B takes over → token 2
kernel A resumes with token 1 → stale / rejected
```

Tokens do not decrease or get reused for later ownership epochs.

The reference SQLite implementation persists the last issued epoch separately from the active lease so a clean release still causes the next owner to receive a higher token.

## Provider-side stale-fence rejection

Kernel ownership checks alone are insufficient if a stale kernel can still reach a provider with valid credentials.

v0.7 therefore models an independent provider/gateway guard:

```text
highest provider-observed fence = 8
request arrives with fence = 7
→ CFHS_STALE_FENCE
```

The fence token is intentionally **not added to the provider's business arguments**. That preserves v0.6 provider idempotency: ownership epochs can change without changing the semantic provider request digest.

A production provider must either support equivalent precondition/fencing semantics or sit behind a gateway that does.

## Durable distributed provider permit

The permit history binds:

```text
business identity digest
identity contract/version
operation
semantic intent digest
provider id
business resource key
kernel instance owner
lease id
fence token
lease expiration
purpose: EXECUTE | RECONCILE
status: ACTIVE | RELEASED | STALE
```

A provider action cannot execute merely because its v0.6 replay state is PREPARED. It must also have an active, unexpired permit owned by the current kernel instance.

## Provider PREPARE integration

The v0.7 provider policy now declares both the business identity contract and fence TTL.

During provider PREPARE:

1. complete arguments must still match the immutable semantic intent;
2. business identity must remain bound to that semantic intent/provider;
3. the kernel acquires or reuses a current execution fence;
4. v0.6 authorization, approval provenance, exact-resource reservation and audit PREPARE execute normally;
5. if PREPARE fails, the distributed fence is released and the business object remains `BOUND`.

A second kernel cannot prepare the same business action while the active execution fence remains valid.

After lease expiry, another kernel may take over and receives a strictly higher fencing token.

## Provider execution integration

Immediately before provider execution, v0.7 requires:

```text
replay state = PREPARED
prepared approval request still matches anchored release evidence
full provider arguments still match semantic intent
active permit belongs to this kernel instance
permit fence is still current/unexpired
business identity still matches semantic intent/provider
provider/gateway accepts fence token
```

Only after those checks does the inherited v0.6 provider execution path run.

Business state then follows the provider result:

```text
BOUND
→ EXECUTING
→ COMMITTED
or FAILED_NOT_EXECUTED
or RECONCILIATION_REQUIRED
```

Terminal execution permits are released. A stale kernel cannot invoke the sandbox provider after another kernel has taken over.

## Fenced reconciliation ownership

An uncertain provider outcome releases the execution fence and places both replay and business identity into `RECONCILIATION_REQUIRED`.

Reconciliation then acquires a **new ownership epoch**:

```text
execution token 1
→ unknown outcome
→ execution fence released
→ reconciliation token 2
→ provider/gateway accepts token 2
→ provider lookup
→ business/replay/resource state reconciled
```

Only one active reconciler may hold the business resource fence. A competing reconciler fails with `CFHS_FENCE_BUSY`.

The reconciliation fence is released after the provider truth is applied.

## Distributed compensation policy

v0.6 compensation remains fully tested as a single-kernel safety mechanism, but the v0.7 distributed runtime **blocks compensation** until compensation receives the same fencing and unknown-outcome reconciliation guarantees.

Attempts return:

```text
CFHS_DISTRIBUTED_SAFETY_REQUIRED
```

This is intentional fail-closed behavior, not a missing fallback.

## Runnable v0.7 server

Canonical distributed reference launcher:

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

The server exposes `/v7/...` aliases for the hardened provider API and requires an explicit stable kernel instance ID.

Health reports:

- distributed safety version;
- kernel instance ID;
- registered sandbox providers;
- distributed controls;
- compensation distributed-safety block;
- audit/anchor health;
- bootstrap status.

Production credentials remain disabled.

## v0.7 validation surface

Canonical validator:

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v07.py
```

Certified exact-count surface:

```text
102 v0.5/v0.6 regression tests
+ 28 distributed primitive tests
+ 17 distributed provider integration tests
= 147 targeted tests
```

Certified GitHub Actions result:

```text
Ran 147 tests
147 PASS
0 failures
0 errors
0 skipped
exact_test_count = true
```

The integration tests specifically verify:

- business identity is bound before provider intent duplication;
- same business identity under a different nonce/semantic action is rejected;
- provider PREPARE acquires an execution fence;
- PREPARE failure releases the fence;
- a competing kernel cannot prepare under an active lease;
- takeover after expiry receives a higher token;
- the stale kernel cannot execute after takeover;
- the takeover kernel can execute and commit;
- the provider/gateway rejects the old token after a newer epoch is observed;
- timeout releases the execution fence and enters business reconciliation;
- reconciliation uses a new higher fence and commits provider truth;
- a competing reconciler is blocked;
- bypassing distributed PREPARE cannot reach the provider;
- altered arguments cannot acquire a fence;
- compensation is blocked until distributed integration;
- status exposes business identity and permit history.

## What remains inside v0.7

The first distributed provider execution boundary is complete. v0.7 is not yet a production distributed database/runtime.

Still pending:

1. shared/fenced persistence interface and production backend contract;
2. atomic coordination among business identity reservation, replay reservation, exact-resource reservation and fence ownership;
3. fencing/ownership contracts for approval mutation and other shared state beyond provider execution/reconciliation;
4. distributed compensation execution and compensation unknown-outcome reconciliation;
5. exact-unit financial authority thresholds;
6. production external identity/MFA authentication-class requirements;
7. hardened remote audit-anchor authentication/availability;
8. provider webhook/event reconciliation;
9. one real provider's business identity/fencing/idempotency semantics in test mode only;
10. migration, network-partition, failover and incident drills.

## Production decision

```text
Business-object identity.............. IMPLEMENTED
Monotonic fencing..................... IMPLEMENTED
Provider stale-fence guard............ IMPLEMENTED
Fenced provider PREPARE............... IMPLEMENTED
Fenced provider execution............. IMPLEMENTED
Fenced reconciliation ownership....... IMPLEMENTED
Runnable v0.7 reference server........ IMPLEMENTED
v0.7 certification.................... 147 / 147 PASS
Distributed compensation.............. BLOCKED / PENDING
Shared HA persistence................. PENDING
Production credentials................ DENIED
Production write providers............ DISABLED
Real provider test mode................ NOT YET ENABLED
```

## Next v0.7 increment

Define the **shared/fenced persistence contract** and transaction coordinator so the currently separate safety records—business identity, replay, exact resource reservation and ownership fence—can be committed/recovered under one distributed transaction/epoch model.
