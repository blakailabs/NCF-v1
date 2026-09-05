# Minimal Company Kernel Runtime v0.1

**Status:** Runnable reference implementation  
**Date:** 2026-09-05

## Purpose

This runtime is the first executable Company Kernel implementation behind the CFHS/NCF Company OS architecture. It is deliberately small enough to audit and test while proving the constitutional control loop.

## Implemented kernel primitives

- durable principal registry
- default-deny capability authorization
- contextual policy constraints
- resource ceilings
- process table and lifecycle state
- elevation request/approval with expiration
- mock device broker
- idempotency records
- durable audit records
- checkpoints and restart recovery
- HTTP control plane

## Proven control loop

```text
USER-SPACE REQUEST
       ↓
PRINCIPAL LOOKUP
       ↓
CAPABILITY MATCH
       ↓
CONTEXT / RESOURCE POLICY
       ↓
ALLOW | DENY | ELEVATION_REQUIRED
       ↓
[temporary human-approved authority when required]
       ↓
MOCK DEVICE BROKER
       ↓
AUDIT RECORD
       ↓
CHECKPOINT / DURABLE STATE
```

## Demonstrated acceptance scenario

1. Human owner spawns an AI-owned process.
2. AI agent invokes `mail.send` within its daily resource ceiling → **ALLOW**.
3. AI agent requests a $5,000 refund with a normal maximum of $250 → **ELEVATION_REQUIRED**.
4. Agent creates a narrowly scoped elevation request.
5. Human owner approves the request for a short TTL.
6. Same $5,000 refund request → **ALLOW** and mock device invocation succeeds.
7. Unavailable/unauthorized device operation fails safely.
8. Process writes a durable checkpoint.
9. Kernel is reconstructed from the same SQLite state.
10. Checkpoint and audit history remain available after restart.

## Important boundary

This is a functioning kernel **MVP/reference implementation**, not a production financial or security kernel. All device adapters are mocks. Production hardening remains necessary before connecting consequential live systems.
