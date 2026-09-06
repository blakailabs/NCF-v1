# Company Kernel Action Safety v0.5

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-action-safety-v0.5`  
**Date:** 2026-09-05 / 2026-09-06 UTC

## Purpose

Action Safety v0.5 governs the boundary between an authorized decision and a consequential external side effect.

The core question is no longer only:

> Is this principal/process authorized?

It is also:

> Can this authorized action be executed exactly once, inside resource limits, with required approvals, durable intent, pre-action audit evidence, and a safe recovery path when the runtime or provider fails halfway through?

v0.5 remains **simulation-only**. It intentionally does not enable live payment, email, CRM, advertising, banking, accounting, deployment, or legal-signature writes.

## Action Safety transaction path

```text
ACTION INTENT
      ↓
TRUST/KERNEL AUTHORIZATION
      ↓
SEMANTIC REPLAY CHECK
      ↓
REQUIRED APPROVALS
      ↓
COMPENSATION CONTRACT (S1/S2)
      ↓
ATOMIC RESOURCE RESERVATION
      ↓
DURABLE AUDIT PREPARE
      ↓
EXECUTION-START MARKER
      ↓
SIMULATED PROVIDER INVOCATION
      ↓
AUDIT COMMIT
      ↓
RESOURCE COMMIT
      ↓
REPLAY COMMIT
```

## Stable Action Intent

Every consequential operation receives an immutable semantic intent containing:

- actor identity;
- originating process;
- operation;
- resource;
- side-effect class (`S0`–`S3`);
- human-readable purpose;
- digest of raw arguments rather than persisted raw arguments;
- replay nonce;
- approval floor;
- evidence references;
- kernel-derived resource reservations.

The stable intent digest intentionally excludes ephemeral fields such as the generated `intent_id`, creation timestamp, and approval-request ID. A retry can therefore be recognized as the same semantic operation even when it uses a fresh in-memory intent object.

## Semantic Replay Protection

A replay nonce is bound to the stable semantic intent digest.

```text
same nonce + same committed semantic intent
        → REPLAYED
        → provider is NOT invoked again

same nonce + different semantic intent
        → CFHS_IDEMPOTENCY_CONFLICT
```

Unknown-side-effect and failed states remain closed to automatic re-execution.

## Kernel-Owned Resource Reservations

Resource reservations are no longer trusted from the caller.

Each consequential device operation declares its action-safety policy in kernel configuration, including:

```text
resource_pool_id
resource_amount_argument
minimum_approvals
```

For example, the simulated refund operation declares:

```text
pool: refund-budget
amount source: arguments.amount
minimum approvals: 2
```

The kernel derives the reservation from the bound operation. If a caller supplies a resource request, it must exactly equal the derived request; it cannot substitute `$1` of reservation for a `$100` operation.

Multiple resource reservations are performed atomically. A failure in any requested pool leaves all pools unchanged.

## Approval Floor

The approval requirement belongs to kernel/device policy, not the agent.

An S3 action cannot lower its configured approval floor by requesting `required_approvals=0`.

Approval requests require explicit eligible principals. The requester cannot approve its own request, duplicate approvals do not increase the count, and an otherwise powerful principal does not count unless it is explicitly eligible for that request.

The reference payment/refund operation currently requires two independent approvers.

## Compensation

S2 operations must have a compensation plan declared before execution and must supply a compensation callback.

If a provider call or post-call audit step fails, the coordinator attempts compensation. Successful compensation releases reserved resources and prevents the failed operation from being counted as committed consumption.

If compensation itself fails, the operation moves into an explicit uncertainty/failure state and conservative resource accounting is used.

**Important production limitation:** v0.5 records compensation intent but does not yet cryptographically bind the declared compensation action to a separately authorized real provider/device operation. A live S2 adapter remains prohibited until that binding exists.

## Fail-Closed Pre-Action Audit

No provider invocation occurs until an action audit `PREPARED` record has been durably written.

If audit preparation fails:

- the provider is not called;
- reservations are released;
- the replay state is closed as a pre-execution failure.

The execution-start marker is persisted immediately before the provider callback.

That marker allows restart recovery to distinguish:

```text
audit prepared + execution not started
        → safe pre-execution recovery

execution started + no trustworthy terminal result
        → UNKNOWN_SIDE_EFFECT
```

## Crash Consistency

v0.5 introduces a durable action-intent index and startup recovery manager.

Intent lifecycle:

```text
PENDING
  ↓ execution attempt
EXECUTING
  ↓
COMMITTED | FAILED | UNKNOWN_SIDE_EFFECT
```

A merely-created `PENDING` intent survives restart and is not treated as a crash artifact.

Startup recovery only scans `EXECUTING` intents.

### Recovery matrix

| Durable state at restart | Recovery |
|---|---|
| Intent exists, execution never began | keep `PENDING` |
| replay/resource reserved, no execution-start marker | release reservations; pre-execution failure |
| audit `PREPARED`, no execution-start marker | fail audit safely; release reservations |
| execution-start marker, no terminal audit | `UNKNOWN_SIDE_EFFECT`; conservative resource accounting |
| audit `COMMITTED`, resource/replay bookkeeping incomplete | complete local resource/replay commit from audit evidence |
| replay already `COMMITTED` | no provider retry; finish any local bookkeeping |

## Device Binding

An intent is durably bound to:

- exact `device_id`;
- operation;
- resource path;
- side-effect class;
- provider identity;
- action-safety profile.

Execution fails if the caller substitutes a different device or if the bound provider/safety configuration changes after the intent was created.

This prevents a valid approval for one operation from being replayed against a different provider or weaker safety configuration.

## Simulation Runtime

`server_v05.py` exposes the Action Safety flow through a simulated consequential adapter.

The adapter deliberately performs no live business side effect.

Supported simulation behavior includes:

- success;
- provider failure after invocation begins;
- compensation success;
- compensation failure;
- restart recovery.

Health output explicitly reports:

```text
simulation_only: true
```

## Test Matrix Committed

The v0.5 repository tests cover, among other cases:

- semantic intent stability;
- nonce conflict;
- committed replay without provider reinvocation;
- atomic multi-resource reservation;
- resource exhaustion;
- resource-pool limit protection;
- requester self-approval rejection;
- ineligible-approver rejection;
- insufficient approval-count rejection;
- caller attempt to lower the S3 approval floor;
- caller attempt to under-reserve resources;
- device substitution;
- S2 compensation requirements;
- compensation success;
- compensation failure;
- S3 uncertain provider outcome;
- audit prepare failure;
- audit commit failure;
- crash before audit;
- crash after audit prepare but before provider invocation;
- crash after execution starts;
- crash after provider/audit success but before resource commit;
- crash after resource commit but before replay commit;
- pending-intent restart behavior;
- startup batch reconciliation;
- full simulated S3 flow: agent intent → two independent approvals → v0.4 trust authorization → v0.5 action-safety execution.

## CI Infrastructure Blocker

GitHub Actions currently creates a synthetic workflow record with:

```text
path: BuildFailed
conclusion: startup_failure
jobs: 0
```

This occurs before checkout, runner assignment, compilation, or test execution—even after the legacy workflows were replaced with a minimal single-job workflow.

This is being treated as a GitHub Actions repository/account/backend startup issue, not as a passing or failing result for the v0.5 code.

## Production Release Blockers

The following must be completed before a live S2/S3 provider is permitted:

1. clean-environment execution of the committed test suite;
2. provider-bound, independently authorized compensation actions;
3. fail-closed action audit integrated with the tamper-evident/external anchor trust path, not only local SQLite;
4. financial/resource accounting represented with production-safe exact units rather than generic floating-point reference units;
5. distributed reservation/replay coordination for multi-kernel deployment;
6. cryptographically strong approval provenance tied to external identity sessions;
7. explicit reconciliation workflow for `UNKNOWN_SIDE_EFFECT`;
8. sandboxed first live provider with non-production credentials and hard external limits.

## v0.5 Safety Decision

**No live consequential business writes are enabled or approved by v0.5.**

The milestone establishes the transaction/recovery semantics required before such writes can be considered.
