# Company Operating System Knowledge Base — Kernel Trust v0.3

**Date:** 2026-09-05

## Project identity decision

The canonical project name is now **Company Operating System**.

NCF remains the constitutional governance layer within the Company Operating System rather than the repository/project identity itself.

Recommended GitHub slug:

```text
Company-Operating-System
```

The historical `NCF-v1` slug remains temporarily because the connected GitHub tooling does not expose repository rename administration.

## New trust-layer decisions

### Authority must have provenance

The kernel now treats authority as something that must be traceable through principal capability, process bounds, restrictive policy, signed policy provenance, and delegation proofs.

### Policy authenticity precedes policy execution

A policy package must verify before it can become active. Package activation is atomic. The trust layer cannot use policy to manufacture `ALLOW` authority.

### Child processes cannot exceed parent authority

Delegated process authority is an intersection of:

```text
parent effective authority
∩ child principal base authority
∩ requested child capability bounds
```

Anything outside that intersection is rejected.

### Delegation becomes durable evidence

Delegation records include parent/child process IDs, delegator/delegate identities, bounded capabilities, creation time, and a digest so the origin of authority can be reconstructed.

### Session rotation invalidates prior authority token

A replacement session is issued and the previous bearer token becomes unusable.

### Secrets are provider objects, not configuration values

The kernel now exposes a provider-neutral vault contract. Public leases contain references and scope but never secret contents.

### Company IPC must be durable and owned

The event bus now has claim ownership, acknowledgements, retry/release, and attempt counters. A consumer cannot acknowledge another consumer's claimed message.

### Audit integrity requires a trust boundary outside the main database

The audit chain now supports independent anchor providers. The current file anchor proves the contract only; production must move the anchor outside the kernel's writable security boundary.

### First provider-specific integration remains read-only

GitHub is implemented as the first provider-specific adapter with GET-only behavior and no write API surface.

## Validation

An independent harness passed 11/11 trust checks covering signed policies, tamper detection, session replay prevention, capability escalation, queue ownership, vault audience binding, and read-only GitHub behavior.

The full repository integration suite is committed but blocked from release certification by GitHub Actions startup failures that occur before any job is created.

## Next trust milestone

Company Kernel Trust Hardening v0.4 should close the known trust gaps before any live S2/S3 write provider is considered.
