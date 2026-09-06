# Company Kernel Live-Adapter Safety v0.6

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-live-adapter-safety-v0.6`  
**Status:** Sandbox-only implementation milestone  
**Date:** 2026-09-05 / 2026-09-06 UTC

## Purpose

v0.5 proved that an authorized consequential action needs replay protection, resource reservation, approval, audit preparation, compensation and crash recovery.

v0.6 makes that boundary look like a real external provider without permitting a production provider.

The design question is:

> If the provider can accept, reject, commit, time out, later reveal the truth, or reverse an action, can the Company Kernel keep its economic state, authority evidence and retry behavior consistent without accidentally executing twice?

The v0.6 answer is implemented against a durable **sandbox provider only**.

## Canonical hardened runtime

```bash
python -m kernel.server_v06_hardened \
  --state-dir <state> \
  --config examples/kernel.config.json \
  --policy-dir examples/policies
```

The hardened launcher uses `TrustKernelV06ReleaseGate`.

Production providers and production credentials are not registered and are rejected.

## Final v0.6 action path

```text
SEMANTIC PROVIDER INTENT
        ↓
KERNEL REPLAY NONCE PRE-RESERVATION
        ↓
DURABLE PROVIDER INTENT
        ↓
REPLAY RESERVATION ATTACHED TO INTENT
        ↓
MULTI-PARTY APPROVALS
        ↓
AUTHENTICATED SESSION PROVENANCE
        ↓
BASE AUTHORIZATION / POLICY CONSTRAINTS
        ↓
IMMUTABLE AUTHORIZATION EVIDENCE
        ↓
TAMPER-EVIDENT CHAIN APPEND
        ↓
AUDIT-ANCHOR RECEIPT REQUIRED
        ↓
EXACT INTEGER RESOURCE RESERVATION
        ↓
PROVIDER-ACTION AUDIT PREPARE
        ↓
SECOND AUDIT-ANCHOR RECEIPT REQUIRED
        ↓
PROVIDER IDEMPOTENT EXECUTE
        ↓
PROVIDER RECEIPT
        ↓
ANCHORED PROVIDER STATUS
        ↓
EXACT RESOURCE COMMIT
        ↓
KERNEL REPLAY COMMIT
```

Any uncertain provider outcome is diverted to reconciliation instead of provider re-execution.

## Exact economic units

v0.6 does not use generic floating-point values to settle economic resources.

For USD with two minor digits:

```text
$10.25 → 1025 integer minor units
$0.01  → 1 integer minor unit
```

No rounding is permitted.

Rejected inputs include:

- `NaN`;
- positive or negative infinity;
- zero/negative economic usage;
- currency precision below the configured minor unit;
- fractional count resources;
- values beyond signed 64-bit exact-unit storage.

A committed resource reservation can be reversed only after provider compensation evidence is available.

## Provider-side idempotency

Each provider call receives a stable provider idempotency key derived from:

```text
semantic intent digest
+ provider id
+ operation
```

Provider behavior:

```text
same key + same request
→ return original provider action
→ do not execute again

same key + different request
→ CFHS_IDEMPOTENCY_CONFLICT
```

The sandbox provider persists idempotency state across restart.

## Kernel semantic replay

Provider idempotency is not sufficient by itself.

The kernel also binds the caller replay nonce to one semantic intent.

The nonce is now reserved **before provider-intent persistence**.

```text
RESERVED
   ↓ durable intent exists
PENDING
   ↓ authority/audit/resource prepare
PREPARED
   ↓
COMMITTED
or
FAILED_NOT_EXECUTED
or
RECONCILIATION_REQUIRED
   ↓ reconciliation
COMMITTED / FAILED_NOT_EXECUTED / COMPENSATED
```

A different semantic action cannot take over the reserved nonce.

### Replay crash recovery

If a process dies after nonce reservation but before intent persistence:

```text
nonce = RESERVED
intent = absent
```

The reservation survives restart and a same-semantic retry may complete creation.

If a process dies after intent persistence but before replay attachment:

```text
nonce = RESERVED
intent = durable
```

Startup recovery finds the exact semantic provider intent and attaches it, producing `PENDING` without creating another intent.

Ordinary caught authorization/validation failure with no durable intent safely removes the unattached reservation.

## Provider outcome reconciliation

v0.6 distinguishes definite failure from uncertain transport outcome.

### Definite provider failure

If the provider proves the action was rejected before persistence:

```text
provider action: absent
exact reservation: released
kernel state: FAILED_NOT_EXECUTED
```

### Provider committed, response lost

If the provider persisted the action but the response disappeared:

```text
provider action: possibly committed
kernel: RECONCILIATION_REQUIRED
retry execute: blocked
```

The kernel asks the provider for the idempotency key.

```text
provider says SUCCEEDED
→ exact resource commit
→ COMMITTED_RECONCILED

provider says NOT FOUND
→ exact reservation release
→ FAILED_NOT_EXECUTED_RECONCILED

provider says COMPENSATED
→ exact resource reversal/release
→ COMPENSATED_RECONCILED
```

## Post-provider local failures

A provider can succeed while local bookkeeping fails afterward.

v0.6 explicitly fault-models:

- provider success followed by audit persistence failure;
- provider success followed by exact-resource commit failure;
- unexpected client exception after provider persistence;
- unexpected client exception before provider persistence.

Once the provider execute call starts, generic exceptions are treated as potentially consequential unless the provider gives a definite pre-persistence failure signal.

The action enters reconciliation and no second execute call is permitted.

## Approval provenance

A counted S3 approval is not only a principal name.

Every counted approval must be bound to a live kernel session with:

- session ID;
- principal ID;
- session creation/expiration;
- authentication class;
- session-evidence digest;
- optional verified external identity/provider evidence.

Revoked or expired sessions cannot generate approval evidence.

Raw v0.5 approval rows without v0.6 session provenance do not release a provider action.

## Authorization evidence

Before provider PREPARE, the exact authorization that releases the action is stored immutably.

It binds:

- semantic intent digest;
- authorized actor;
- authorized process;
- matched capability/policy identifiers;
- constraints;
- approval request ID;
- multi-party approval provenance digest.

This evidence is appended to the tamper-evident chain and anchored before economic reservation/provider PREPARE proceeds.

A later attempt cannot replace the approval request or authorization evidence for the prepared action.

## Provider-action audit anchoring

Provider PREPARE and subsequent provider-action status transitions are also appended and anchored.

The anchor receipt must confirm the **exact audit chain head** supplied by the kernel.

A missing, unavailable or dishonest anchor fails closed.

The caller cannot select a different anchor or skip the checkpoint.

## Device/provider safety binding

The action remains bound to:

```text
device id
provider id
operation
resource
side-effect class
sandbox-only flag
exact-resource policy
compensation operation
```

Configuration substitution after intent creation is rejected.

## Governed compensation

The pre-freeze review identified that rollback is itself a consequential economic action.

The hardened runtime therefore does **not** allow a wildcard owner authority to immediately reverse an S3 action.

Compensation now requires a separate semantic compensation intent containing:

- original semantic intent digest;
- original provider action ID;
- compensation device/operation;
- exact compensation arguments digest;
- requesting principal/process;
- independent approval count.

The reference refund-reversal operation requires two independent approvals.

Final compensation path:

```text
COMMITTED ORIGINAL ACTION
        ↓
AUTHORIZED PRINCIPAL REQUESTS COMPENSATION
        ↓
SEPARATE COMPENSATION INTENT
        ↓
TWO INDEPENDENT APPROVERS
        ↓
SESSION PROVENANCE FOR BOTH
        ↓
SEPARATE COMPENSATION AUTHORIZATION
        ↓
ANCHORED COMPENSATION AUTHORITY EVIDENCE
        ↓
PROVIDER IDEMPOTENT COMPENSATION
        ↓
EXACT USED UNITS REVERSED
        ↓
ORIGINAL REPLAY STATE = COMPENSATED
```

A principal that does not possess the base compensating-operation authority cannot even open the compensation approval workflow.

## Canonical validation command

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v06.py
```

The validator compiles the runtime/test surface and targets **102 tests across 11 modules**, including the frozen v0.5 regression surface.

The test suites cover:

- exact-unit conversion/accounting;
- provider idempotency;
- provider restart persistence;
- provider timeout/reconciliation;
- post-provider local failure;
- session-proven approvals;
- external-identity evidence binding;
- authorization anchoring;
- provider audit anchoring;
- device/provider/profile substitution;
- kernel replay state;
- replay pre-reservation/restart attachment;
- S3 compensation governance;
- end-to-end sandbox provider flows.

**Important:** the 102 tests are committed and the validator expects them; this document does not claim they have executed successfully in GitHub Actions. The current Actions backend fails before job creation.

## Safety decision

```text
Sandbox provider-shaped execution........ IMPLEMENTED
Exact economic units...................... IMPLEMENTED
Provider reconciliation................... IMPLEMENTED
Session-proven S3 approvals............... IMPLEMENTED
Anchored release evidence................. IMPLEMENTED
Governed S3 compensation.................. IMPLEMENTED
Production provider registry.............. NOT PRESENT
Production credentials.................... NOT ACCEPTED
Production write release.................. NOT APPROVED
```
