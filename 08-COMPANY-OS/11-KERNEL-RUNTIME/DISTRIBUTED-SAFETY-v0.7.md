# Company Kernel Distributed / Production Safety v0.7

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-distributed-safety-v0.7`  
**Base milestone:** merged Live-Adapter Safety v0.6  
**Status:** active engineering milestone; production credentials remain disabled

## Purpose

v0.6 proved provider-shaped consequential execution on a single durable kernel reference runtime.

v0.7 begins the transition from **single-kernel correctness** to **distributed ownership correctness**.

The first two primitives are intentionally coupled:

1. **Business-object identity** answers: *what real-world object/action are we actually trying to affect?*
2. **Fencing** answers: *which kernel execution epoch currently owns the right to affect it?*

A replay nonce alone cannot answer either question.

## Threat being addressed

Without business identity:

```text
same refund
+ different caller replay nonce
→ can appear to be a new action
```

Without fencing:

```text
kernel A acquires work
→ kernel A pauses/network partitions
→ kernel B takes over
→ kernel A resumes with still-valid credentials
→ both can attempt the side effect
```

v0.7 begins closing both classes of failure.

## Business-object identity contract

Each consequential operation declares a versioned identity contract.

Example:

```text
contract: payments.refund.target/v1
operation: payments.refund
identity fields:
  provider_account_id
  charge_id
  refund_reference
```

The business identity digest binds:

```text
contract id
+ contract version
+ operation
+ digest(identity field values)
```

Raw identity values are not persisted by the reference ledger.

### Semantic binding rule

```text
one business-object identity
→ one semantic intent
```

Same business identity + same semantic intent is idempotent.

Same business identity + different semantic intent fails with:

```text
CFHS_BUSINESS_IDENTITY_CONFLICT
```

Likewise, one semantic intent cannot silently be rebound to a different business identity.

### Why amount is not automatically identity

A generic kernel cannot guess which arguments define business uniqueness.

For example, changing `amount` may or may not represent a new legitimate refund depending on the provider/business contract. Therefore each application/provider operation must explicitly declare its identity fields rather than letting the kernel infer them.

## Fencing contract

Each distributed action obtains a monotonic fencing token for its business-object resource.

```text
resource epoch 1 → fence token 1
lease expires / ownership changes
resource epoch 2 → fence token 2
```

Tokens never decrease or get reused for a later ownership epoch.

A stale owner carrying token `1` must fail after token `2` becomes current, even if the stale owner still possesses valid credentials.

### Reference states

The reference SQLite store persists:

```text
resource key
last issued token
current token
owner
lease id
acquired time
expiration
```

The SQLite backend is a **contract/reference implementation**, not the intended HA production store.

A production shared backend must preserve equivalent atomicity, monotonicity and stale-owner rejection semantics.

## Provider-side fencing

Kernel-side ownership checks are not sufficient if a stale kernel can still call an external provider directly.

The provider boundary therefore needs a stale-token rejection contract:

```text
provider has observed token 8
request arrives with token 7
→ reject CFHS_STALE_FENCE
```

A production provider must either support an equivalent fencing/precondition primitive or be placed behind a gateway that enforces it.

Credentials alone are never proof of current distributed ownership.

## Distributed action permit

The initial v0.7 permit binds:

```text
business identity digest
business identity contract/version
operation
semantic intent digest
provider id
fence resource
fence owner
lease id
monotonic fence token
lease expiration
```

Before advancing the business state, the guard revalidates:

1. the fence is still current and unexpired;
2. the business identity is still bound to the same semantic intent/provider.

A stale permit cannot advance state after another owner takes over.

## Initial state model

Business-object action state:

```text
BOUND
→ EXECUTING
→ COMMITTED
```

Failure/recovery branches:

```text
BOUND → FAILED_NOT_EXECUTED
EXECUTING → FAILED_NOT_EXECUTED
EXECUTING → RECONCILIATION_REQUIRED
RECONCILIATION_REQUIRED → COMMITTED
RECONCILIATION_REQUIRED → FAILED_NOT_EXECUTED
RECONCILIATION_REQUIRED → COMPENSATED
COMMITTED → COMPENSATED
```

## v0.7 validation surface

Canonical validator:

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v07.py
```

Expected surface:

```text
102 v0.5/v0.6 regression tests
+ 28 distributed-safety tests
= 130 targeted tests
```

The validator fails if the exact test count is not 130.

## Initial adversarial coverage

The first v0.7 suite covers:

- deterministic identity derivation;
- contract-version isolation;
- operation isolation;
- missing/null/non-finite identity rejection;
- dotted identity paths;
- duplicate identity-field policy rejection;
- identity-to-semantic-action immutability;
- semantic-intent-to-identity immutability;
- no raw business identity value persistence;
- first fencing epoch;
- active-owner contention;
- lease renewal;
- expired-lease non-revival;
- monotonic token takeover;
- stale owner assertion/release rejection;
- token monotonicity after clean release;
- provider stale-token rejection;
- distributed action state advancement only under current ownership;
- stale distributed permit rejection after takeover.

## What this does not claim yet

This is not yet a distributed database implementation.

Still pending inside v0.7:

- shared production fence/replay/resource persistence interface and backend contract;
- atomic coordination between business identity, replay, resource reservation and fence ownership;
- fencing of approval/provider/reconciliation ownership;
- compensation unknown-outcome reconciliation;
- exact-unit authority thresholds;
- production external identity/MFA policy requirements;
- real provider test-mode business identity/fencing semantics;
- migration/failover/partition drills.

## Production decision

```text
v0.7 primitives...................... IN DEVELOPMENT
Production credentials............... DENIED
Production write providers........... DISABLED
Real provider test mode............... NOT YET ENABLED
```

The next v0.7 increment should add a shared/fenced persistence interface and make the existing v0.6 provider-action/reconciliation lifecycle consume a `DistributedActionPermit` before any provider invocation.
