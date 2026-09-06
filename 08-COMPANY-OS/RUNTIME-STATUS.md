# Company Operating System Runtime Status

**Updated:** 2026-09-05 / 2026-09-06 UTC  
**Current branch:** `feature/company-kernel-action-safety-v0.5`

## Canonical project identity

**Project:** Company Operating System  
**Recommended GitHub slug:** `Company-Operating-System`  
**Historical repository slug:** `NCF-v1` — administrative rename pending

NCF remains the constitutional governance layer inside the broader Company Operating System project.

## Architecture implemented

```text
NCF constitutional governance
→ CDM company discovery contract
→ CFHS filesystem hierarchy
→ deterministic CFHS materializer
→ Company Kernel API
→ Company Kernel runtime v0.1
→ Kernel Hardening v0.2
→ Kernel Trust Layer v0.3
→ Kernel Trust Hardening v0.4
→ Kernel Action Safety v0.5
```

## v0.1 — runnable kernel

Implemented:

- durable principal/process/checkpoint/audit state;
- default-deny capabilities;
- contextual amount/resource limits;
- `ALLOW`, `DENY`, `ELEVATION_REQUIRED`;
- narrow human-approved elevation;
- mock S2/S3 devices;
- idempotency/resource ceilings;
- checkpoint/restart recovery.

## v0.2 — authenticated hardening

Implemented:

- opaque kernel sessions;
- session hashing/expiration/revocation;
- process ownership/supervision binding;
- restrictive-only policy overlay;
- tamper-evident audit chain;
- secret lease abstraction;
- sandboxed S0 read-only HTTP adapter.

Last clean GitHub Actions execution:

```text
Run 33998002023
Compile................ PASS
Combined tests......... PASS (16)
Secret scan............ PASS
```

## v0.3 — trust provenance

Implemented:

- canonical internal project identity: **Company Operating System**;
- signed restrictive policy-package contract;
- atomic activation;
- session rotation;
- process capability bounds;
- durable delegation proofs;
- provider-neutral vault interface;
- durable event/queue ownership semantics;
- independent audit-anchor abstraction;
- GitHub read-only provider with no write API;
- one-time bootstrap endpoint;
- threat model/adversarial test catalog.

Independent reference harness:

```text
Trust primitive checks........ 11 / 11 PASS
```

## v0.4 — trust hardening

Implemented:

- durable restart-safe one-time bootstrap;
- atomic bootstrap completion/session issuance;
- persistent signed-policy contents;
- semantic-version rollback protection;
- same-version substitution rejection;
- recursive delegation-chain verification;
- delegation/process-bound tamper detection;
- authorization-time provenance verification;
- expiring event claims/dead-letter handling;
- external OIDC identity broker contract;
- atomic OIDC nonce/session issuance;
- remote HTTPS audit-anchor contract;
- external HTTPS vault provider;
- runnable v0.4 server;
- restart/rollback/delegation/identity/anchor/vault tests committed.

Acceptance:

```text
IMPLEMENTED
TEST COVERAGE COMMITTED
CLEAN-ENVIRONMENT EXECUTION REQUIRED
PRODUCTION WRITE RELEASE BLOCKED
```

## v0.5 — Action Safety

Implemented on `feature/company-kernel-action-safety-v0.5`:

### Action intent and replay

- stable semantic action-intent digest;
- raw argument digest rather than raw argument persistence in the intent envelope;
- replay nonce bound to semantic action;
- committed replay returns without invoking the provider again;
- nonce reuse with a different semantic action is rejected.

### Kernel-owned resource safety

- durable resource pools;
- atomic multi-resource reservation;
- reservation commit/release;
- hard-limit enforcement;
- operation-level `action_safety` policy;
- reservation amount derived by the kernel from the bound operation and action arguments;
- caller under-reservation/substitution rejected;
- resource safety profile frozen into the action binding.

### Approval safety

- operation/kernel-owned minimum approval floor;
- S3 refund example requires two approvals;
- caller cannot lower the floor to zero;
- explicit eligible approvers;
- requester self-approval rejected;
- duplicate approval does not increase the count;
- otherwise-powerful principal does not count unless explicitly eligible.

### Compensation safety

- S2 compensation-plan requirement;
- S1/S2 compensation callback requirement;
- compensation success releases conservative resource reservation;
- compensation failure creates explicit failure/uncertainty state.

### Fail-closed action audit

- durable action `PREPARED` record before provider invocation;
- durable execution-start marker immediately before provider callback;
- audit result commit after provider result;
- audit evidence can recover interrupted resource/replay bookkeeping.

### Crash consistency

- durable action-intent index;
- `PENDING → EXECUTING → terminal` lifecycle;
- pending intents survive restart without being treated as failed execution;
- startup recovery scans only in-flight `EXECUTING` actions;
- crash before provider invocation releases resources safely;
- crash after provider invocation begins becomes `UNKNOWN_SIDE_EFFECT` when no trustworthy result exists;
- audit-committed actions repair unfinished resource/replay bookkeeping;
- replay state can be repaired from committed audit evidence after resource/replay commit interruption.

### Device/provider binding

Action intent is durably bound to:

```text
device_id
operation
resource
side-effect class
provider
operation action-safety profile
```

Device/provider/policy substitution after intent creation is rejected.

### Simulation runtime

`server_v05.py` provides the full Action Safety path using a simulated consequential adapter only.

```text
agent intent
→ independent approvals
→ v0.4 trust authorization
→ replay check
→ resource reservation
→ audit prepare
→ simulation invocation
→ audit/resource/replay commit
```

No live business side effect is performed.

### v0.5 validation surface

Canonical validator:

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v05.py
```

It compiles the runtime/tests and executes four targeted suites containing 34 Action Safety test methods:

```text
test_action_safety_v05
test_action_crash_recovery_v05
test_action_reconciliation_v05
test_server_v05_integration
```

## Current GitHub Actions blocker

GitHub is replacing workflow executions with a synthetic run:

```text
name: ""
path: BuildFailed
conclusion: startup_failure
jobs: 0
```

The condition persists after the branch was reduced to a single minimal workflow and canonical validation command. The run fails before checkout, runner assignment, Python setup, compilation, or test execution.

Accordingly:

```text
v0.5 implementation.................. COMPLETE FOR MILESTONE
v0.5 adversarial test coverage....... COMMITTED
v0.5 GitHub Actions execution........ BLOCKED BEFORE JOB CREATION
v0.5 live-provider authorization..... DENIED
```

## Production release blockers before any real S2/S3 provider

- clean isolated execution of the v0.5 validation suite;
- production asymmetric policy-signature/HSM verifier;
- cryptographically verified OIDC/IdP identity and approval-session provenance;
- provider-bound compensation actions with separate authorization;
- fail-closed action audit integrated with the external immutable anchor path;
- production-safe exact financial/resource units rather than generic floating reference units;
- distributed resource reservation and replay state for multi-kernel/HA deployments;
- explicit operator reconciliation workflow for `UNKNOWN_SIDE_EFFECT`;
- sandboxed provider credentials and hard external provider ceilings;
- security/adversarial certification of the complete live adapter boundary.

## Release gate

No production write-capable email, payment, banking, CRM, deployment, advertising, accounting, or legal-signature provider should be enabled until:

```text
identity verified
+ recursive authority provenance verified
+ policy authenticity verified
+ device/provider identity bound
+ approval floor satisfied
+ resource reservation acquired
+ compensation bound/authorized when required
+ fail-closed audit prepared
+ replay state protected
+ external audit anchoring available
+ crash/unknown-outcome reconciliation available
```

## Next engineering milestone

Build **Company Kernel Live-Adapter Safety v0.6** without enabling production writes yet:

1. bind compensation plans to explicit authorized compensating device operations;
2. replace generic financial reference units with exact integer/minor-unit accounting;
3. integrate action PREPARE/COMMIT with tamper-evident/external audit anchoring;
4. bind approvals to externally verified identity/session evidence;
5. add a first provider adapter in sandbox/test mode only;
6. enforce provider-side idempotency keys and provider result reconciliation;
7. implement explicit `UNKNOWN_SIDE_EFFECT` operator/reconciliation workflow;
8. execute the full adversarial suite in a clean environment before any production credential is accepted.
