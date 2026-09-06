# Company Kernel Live-Adapter Safety v0.6 — Acceptance Report

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-live-adapter-safety-v0.6`  
**Base:** `feature/company-kernel-action-safety-v0.5`  
**Date:** 2026-09-05 / 2026-09-06 UTC

## Acceptance state

```text
IMPLEMENTATION......................... ACCEPTED FOR SANDBOX MILESTONE
ADVERSARIAL TEST DESIGN................ ACCEPTED / COMMITTED
SOURCE-LEVEL PRE-FREEZE REVIEW......... COMPLETED
CLEAN EXECUTION CERTIFICATION.......... BLOCKED BY ENVIRONMENT/CI
PRODUCTION PROVIDER RELEASE............ DENIED
PRODUCTION CREDENTIAL ACCEPTANCE....... DENIED
```

v0.6 is deliberately a sandbox architecture milestone, not a production release.

## Scope delivered

The milestone adds provider-realistic safety around the v0.5 consequential-action kernel:

```text
exact integer economic units
provider-side idempotency
provider lookup/reconciliation
post-provider failure hardening
session-proven multi-party approvals
optional verified external identity evidence
immutable authorization evidence
fail-closed authorization anchoring
fail-closed provider-action anchoring
kernel semantic replay state
replay nonce pre-reservation before intent persistence
restart attachment for replay/intents
sandbox provider runtime
separately governed S3 compensation
```

## Canonical release gate

The hardened entrypoint is:

```text
kernel.server_v06_hardened
```

which instantiates:

```text
TrustKernelV06ReleaseGate
```

The release gate composes:

```text
v0.5 trust/action safety
→ exact-unit provider safety
→ replay nonce pre-reservation
→ durable semantic provider intent
→ session-proven approvals
→ anchored authorization evidence
→ exact resource reservation
→ anchored provider PREPARE/result
→ provider idempotency
→ reconciliation on uncertainty
→ separately approved/anchored S3 compensation
```

## Canonical validation surface

Command:

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v06.py
```

The validator currently targets **102 safety tests across 11 modules**:

```text
test_action_safety_v05
test_action_crash_recovery_v05
test_action_reconciliation_v05
test_server_v05_integration

test_live_adapter_safety_v06
test_v06_trust_bindings
test_provider_action_hardening_v06
test_server_v06_integration
test_provider_execution_gate_v06
test_provider_compensation_gate_v06
test_provider_replay_restart_v06
```

The v0.5 modules are retained as regression coverage.

## What the test design targets

### Economic accounting

- exact USD minor-unit conversion;
- no rounding below minor unit;
- NaN/infinity rejection;
- whole-count enforcement;
- integer reservation/commit/release;
- exact reversal after proven compensation;
- hard-limit enforcement;
- immutable unit definition.

### Provider idempotency/reconciliation

- same provider key/same request returns original action;
- same provider key/different request conflicts;
- idempotency survives restart;
- definite provider failure creates no provider action;
- provider commit then timeout is recoverable through lookup;
- unexpected exception after provider persistence enters reconciliation;
- unexpected exception before provider persistence reconciles to not-executed;
- reconciliation state blocks a second provider execute.

### Authority/provenance

- live kernel session required for approval evidence;
- revoked/expired sessions rejected;
- wrong principal/bearer rejected;
- every counted approval requires provenance;
- external verified identity evidence can be bound;
- approval provenance is immutable;
- different approval provenance cannot replace prepared release evidence.

### Audit anchoring

- authorization release is appended/anchored before provider PREPARE;
- provider PREPARE/status transitions are appended/anchored;
- repeated same checkpoint does not duplicate a successful anchor receipt;
- unavailable anchor fails closed;
- dishonest/mismatched anchor head fails closed.

### Kernel replay

- same nonce/same semantic provider intent reuses original intent;
- same nonce/different amount/purpose conflicts;
- nonce is reserved before provider-intent persistence;
- reservation-only crash survives restart;
- durable-intent-before-replay-attachment crash is repaired on restart;
- different semantics cannot take over an unattached reservation;
- ordinary denied pre-persistence creation releases the unattached reservation;
- replay state follows PREPARED → RECONCILIATION_REQUIRED → COMMITTED;
- replay state follows COMMITTED → COMPENSATED.

### S3 compensation

- principal without base reversal authority cannot open compensation workflow;
- S3 compensation approval floor cannot be lowered;
- compensation cannot execute before approvals;
- approvals without session provenance do not count;
- approved compensation arguments cannot be changed;
- compensation authorization anchor failure prevents reversal;
- fully governed compensation reverses provider state and exact resource usage;
- repeated same compensation request reuses its intent/request.

## Security defects found and corrected during v0.6 development

The pre-freeze build/review cycle identified and corrected:

1. floating/generic economic accounting unsuitable for real money;
2. non-finite numeric values escaping ordinary parsing;
3. missing provider-side persistent idempotency;
4. missing provider truth lookup after transport timeout;
5. generic exceptions after provider execution being too easy to misclassify as retryable;
6. provider success followed by local audit/resource failure requiring reconciliation;
7. counted S3 approvals lacking authenticated-session provenance;
8. approval provenance being replaceable without immutable binding;
9. provider PREPARE/status not independently anchored;
10. authorization evidence not independently anchored before provider preparation;
11. kernel replay nonce not initially protecting semantic provider intent independently of provider idempotency;
12. S3 compensation initially relying on base owner authority without its own approval workflow;
13. principals being able to request compensation workflows they lacked authority to execute;
14. compensation intent partial-unique DDL being expressed with invalid inline SQLite syntax; corrected to a partial unique index;
15. provider replay nonce initially binding after intent persistence, leaving a crash window; corrected to pre-reservation plus restart attachment.

## CI/execution certification status

GitHub Actions continues to create synthetic runs with the pattern:

```text
name: ""
path: BuildFailed
conclusion: startup_failure
jobs: 0
```

The failure occurs before checkout, runner assignment, Python setup, compilation or tests.

The latest observed v0.6 validator push continued to receive the same zero-job startup failure.

An external container clone was also unavailable because that runtime could not resolve GitHub DNS.

Therefore:

> The committed validator/test surface is **not being represented as passed**.

No test result is being inferred from static review.

## Pre-mortem release blockers

The detailed pre-mortem is recorded in `PREMORTEM-v0.6.md`.

Major blockers before production include:

- clean execution of the 102-test committed validator;
- CI from the exact release commit;
- operation-specific business identity/deduplication beyond caller nonce;
- production provider test-mode idempotency/lookup semantics;
- compensation unknown-outcome reconciliation;
- production external IdP/MFA verification policy;
- asymmetric/HSM-backed policy trust;
- highly available remote immutable audit anchoring;
- distributed/fenced replay/resource/reconciliation state;
- exact-unit policy constraints for financial authority limits;
- production workload identity/secret delivery;
- provider webhook/event-state reconciliation;
- external provider-side hard ceilings/canary controls.

## Final milestone decision

```text
v0.6 sandbox architecture.............. ACCEPT
v0.6 source-level security review...... ACCEPT WITH DOCUMENTED BLOCKERS
v0.6 test execution certification...... NOT YET AVAILABLE
Merge as production-ready.............. DO NOT
Enable real payment/email/CRM writes... DO NOT
Accept production provider secrets..... DO NOT
```

The next logical engineering milestone is **Distributed / Production Safety v0.7**, beginning with shared/fenced action state and one real provider's test-mode semantics—not additional autonomous-agent features.
