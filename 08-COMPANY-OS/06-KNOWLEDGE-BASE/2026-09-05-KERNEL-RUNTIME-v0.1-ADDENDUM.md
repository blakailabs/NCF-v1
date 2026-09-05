# Company OS Knowledge Base — Company Kernel Runtime v0.1 Addendum

**Date:** 2026-09-05

## Milestone reached

The first runnable Company Kernel reference implementation now exists.

It is not merely an API contract: the runtime executes a durable authorization and process-control loop using Python's standard library and SQLite.

## Proven behaviors

- principal registry persists across runtime instances;
- capability matching is deterministic;
- missing authority defaults to `DENY`;
- contextual amount limits can return `ELEVATION_REQUIRED`;
- an authorized human can approve a narrow, expiring elevation;
- elevated authority can permit the otherwise-blocked action;
- resource ceilings deny work after the configured limit;
- device invocations are idempotent when an idempotency key is reused;
- every authorization/elevation/device/process/checkpoint action generates audit state;
- process checkpoints survive restart and are recoverable from durable state.

## Safety boundary

All current devices are mocks. The kernel does not yet send real messages, move money, access live SaaS accounts, or lease real secrets.

This is intentional: governance behavior is being proven before consequential external connectivity is added.

## Canonical control loop

```text
USER-SPACE REQUEST
        ↓
PRINCIPAL
        ↓
CAPABILITY
        ↓
CONTEXT / RESOURCE POLICY
        ↓
ALLOW | DENY | ELEVATION_REQUIRED
        ↓
[human-approved narrow elevation if required]
        ↓
DEVICE BROKER
        ↓
AUDIT + DURABLE STATE
        ↓
CHECKPOINT / RECOVERY
```

## Acceptance results

Six automated tests passed, including default deny, elevation, idempotency, resource ceilings, approver restrictions, and restart recovery.

The HTTP daemon also returned `READY`, `ALLOW` for a permitted mail action, and `ELEVATION_REQUIRED` for a refund above the agent's normal amount limit.

## Current status

The project has now progressed through:

```text
NCF constitutional framework
→ CDM discovery contract
→ CFHS representation
→ deterministic CFHS materializer
→ Company Kernel API contract
→ runnable Company Kernel v0.1
```

## Next engineering boundary

Do not connect consequential production systems yet.

The next hardening layer should add authenticated kernel sessions, executable policy documents from `/etc/policy`, stronger process ownership/bounding semantics, tamper-evident audit chains, a secret broker abstraction, and a sandboxed read-only live device adapter before any write-capable real provider is introduced.
