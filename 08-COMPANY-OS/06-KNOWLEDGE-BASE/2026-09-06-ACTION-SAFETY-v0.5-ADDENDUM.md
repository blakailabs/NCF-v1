# Company Operating System Knowledge Base — Action Safety v0.5

**Date:** 2026-09-06 UTC

## Milestone decision

Action Safety v0.5 establishes the transaction boundary required between kernel authorization and consequential external action.

The milestone remains simulation-only. Live S2/S3 business writes remain prohibited.

## Canonical design decisions

### Authorization is necessary but not sufficient

A principal/process may be authorized for an operation and still be prevented from executing until Action Safety proves:

```text
semantic intent
+ replay protection
+ approval requirements
+ resource reservation
+ compensation requirements
+ durable audit preparation
```

### Action identity is semantic

Replay identity must not depend on ephemeral attempt fields. The stable action digest therefore binds actor/process/action/resource/purpose/argument digest/replay nonce/approval floor/evidence/resource requirements while excluding generated attempt identifiers and timestamps.

### Safety policy belongs to the kernel/device definition

The caller cannot decide how much resource to reserve or how many approvals an S3 action requires.

Operation metadata now owns:

```text
resource_pool_id
resource_amount_argument
minimum_approvals
```

The kernel derives the actual reservation and enforces the approval floor.

### Device identity is part of the approved intent

A valid intent cannot be pointed at another device or provider after approval.

The durable binding includes:

```text
device
operation
resource
side-effect class
provider
safety profile
```

### Crash recovery requires knowing whether execution actually started

An audit `PREPARED` record alone does not prove a provider call began.

v0.5 therefore persists a separate execution-start marker immediately before the provider callback.

```text
PREPARED + no execution marker
→ safe pre-execution recovery

execution marker + no terminal provider/audit evidence
→ UNKNOWN_SIDE_EFFECT
```

### Pending intent is not failed execution

Created intents remain `PENDING`. Startup recovery scans only `EXECUTING` intents. This permits approvals or compensation preparation to span a restart without incorrectly failing the request.

### Committed audit is recovery evidence

If the provider result and audit commit succeeded but resource/replay bookkeeping was interrupted, committed audit evidence may be used to finish local bookkeeping without invoking the provider again.

### Unknown means closed

`UNKNOWN_SIDE_EFFECT` is not automatically retryable. The system conservatively accounts the reserved resource and blocks replay until a reconciliation process establishes the real external outcome.

## Defects discovered during adversarial review

The v0.5 review process found and corrected:

- partial reservation leakage;
- ephemeral replay identity;
- approval/digest circularity;
- unrestricted approver counting;
- missing provider-uncertainty semantics;
- inability to distinguish pre-provider from post-provider crash;
- pending-intent restart misclassification;
- post-audit bookkeeping recovery gap;
- S3 approval-floor override;
- caller resource under-reservation;
- device/provider substitution;
- stale crash test lifecycle assumptions.

## Current CI infrastructure condition

GitHub Actions creates synthetic `BuildFailed` / `startup_failure` runs with zero jobs before the real workflow starts. The repository now contains one canonical v0.5 validator command, but GitHub's workflow backend condition remains external to the runtime.

## Next milestone

**Company Kernel Live-Adapter Safety v0.6** should make the Action Safety contract provider-realistic while remaining sandbox-only:

- exact financial units;
- provider-bound compensation;
- provider idempotency/reconciliation;
- action audit tied to external anchoring;
- externally verified approval provenance;
- explicit unknown-outcome reconciliation workflow.
