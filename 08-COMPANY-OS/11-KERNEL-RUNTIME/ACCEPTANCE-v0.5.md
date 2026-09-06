# Company Kernel Action Safety v0.5 — Acceptance Report

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-action-safety-v0.5`  
**Date:** 2026-09-05 / 2026-09-06 UTC

## Acceptance state

**IMPLEMENTED / ADVERSARIAL TEST COVERAGE COMMITTED / EXECUTION CERTIFICATION BLOCKED BY GITHUB ACTIONS STARTUP FAILURE**

v0.5 is not production-approved and does not enable live consequential business writes.

## Implemented controls

```text
Stable semantic action intent................ implemented
Replay nonce bound to semantic action......... implemented
Committed replay without provider reinvoke.... implemented
Atomic multi-resource reservation............. implemented
Kernel-derived operation resource policy...... implemented
Caller under-reservation rejection............ implemented
Kernel-owned S3 approval floor................ implemented
Explicit eligible approvers................... implemented
Requester self-approval rejection............. implemented
S2 compensation-plan requirement.............. implemented
Fail-closed pre-action audit prepare........... implemented
Execution-start durable marker................ implemented
Crash-safe action-intent index................. implemented
PENDING vs EXECUTING lifecycle................. implemented
Pre-provider crash recovery.................... implemented
Unknown-side-effect conservative recovery...... implemented
Post-audit bookkeeping recovery................ implemented
Exact device/provider/safety-profile binding... implemented
Simulation-only consequential provider......... implemented
Startup reconciliation......................... implemented
Deterministic v0.5 validation script........... implemented
```

## Adversarial test suites committed

The canonical v0.5 validator runs these four suites:

```text
test_action_safety_v05
test_action_crash_recovery_v05
test_action_reconciliation_v05
test_server_v05_integration
```

The suites contain **34 targeted test methods** covering the Action Safety transaction boundary, including replay, resource reservation, approvals, compensation, provider uncertainty, crash recovery, restart behavior, and the end-to-end simulated S3 workflow.

Canonical command:

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v05.py
```

The validator compiles `kernel/` and `tests/`, runs the four targeted suites, and emits a machine-readable `V0.5_VALIDATION_SUMMARY` object.

## Security defects found and corrected during v0.5 review

The build/review process identified and corrected multiple issues before milestone freeze:

1. partial multi-resource reservation could leak if a later pool failed;
2. action replay identity initially depended on ephemeral intent fields;
3. approval binding initially had a circular digest problem;
4. approver counting initially lacked an explicit eligible-principal boundary;
5. provider failure after side-effect initiation required an explicit unknown-outcome state;
6. a crash after audit `PREPARED` but before provider invocation needed to be distinguishable from a post-provider crash;
7. pending intents were initially at risk of being treated as crashed executions after restart;
8. post-audit resource/replay bookkeeping failure needed recoverability from committed audit evidence;
9. an S3 caller could otherwise attempt to lower its approval requirement;
10. caller-supplied resource reservation amounts could otherwise understate the real operation;
11. a valid intent could otherwise be pointed at a different device/provider;
12. crash-recovery test fixtures were updated to model the actual `PENDING → EXECUTING` lifecycle rather than weakening production semantics.

## GitHub Actions execution blocker

Every current workflow dispatch/push is being replaced by a synthetic GitHub Actions run with the following characteristics:

```text
name: ""
path: BuildFailed
conclusion: startup_failure
jobs: 0
```

The condition persisted after:

- simplifying workflow triggers;
- removing branch path filters;
- creating a fresh minimal workflow;
- deleting the prior v0.2/v0.3 workflow files;
- creating a single new Company OS workflow;
- reducing the workflow to one canonical validator command.

The failure occurs before checkout, runner assignment, Python setup, compilation, or any test process. It is therefore **not evidence that the v0.5 tests failed**, but it also means the tests cannot be certified as passed through GitHub Actions.

The latest branch pushes continue to create the same zero-job synthetic `BuildFailed` run.

## Last known successful GitHub Actions execution

The last known real Company Kernel Actions job remains the v0.2 run:

```text
Run: 33998002023
Compile........................ PASS
Combined tests................. PASS (16)
Committed secret scan.......... PASS
```

v0.3 also received an independent reference-harness result of 11/11 trust primitive checks before the current GitHub Actions backend condition became the dominant CI blocker.

## Production blockers retained deliberately

v0.5 does **not** authorize a live S2/S3 adapter. Before live consequential writes, the following remain required:

- clean execution of the canonical v0.5 validator in an isolated environment;
- production asymmetric policy-signature verification;
- real OIDC/IdP verification and approval-session provenance;
- provider-bound compensation with separate authorization;
- action-audit prepare/commit integrated with the external immutable anchor path;
- exact production financial units rather than generic floating reference units;
- distributed reservation and replay coordination for HA/multi-kernel deployments;
- explicit operator reconciliation workflow for `UNKNOWN_SIDE_EFFECT`;
- first real provider limited to sandbox/non-production credentials and hard external ceilings.

## Acceptance decision

```text
Architecture / implementation........ ACCEPTED FOR CONTINUED DEVELOPMENT
Adversarial test coverage............ ACCEPTED / COMMITTED
GitHub Actions execution............. BLOCKED BEFORE JOB CREATION
Live consequential provider.......... NOT APPROVED
Production security certification.... NOT APPROVED
```
