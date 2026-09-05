# Company OS Knowledge Base — Kernel Hardening v0.2 Addendum

**Date:** 2026-09-05

## Milestone reached

The Company Kernel now has a second runnable layer focused on identity, policy restriction, audit integrity, secret leasing, and safe read-only external access.

## Canonical decisions added

### Authenticated identity replaces caller-asserted identity

HTTP callers no longer establish their identity by sending an actor header. An opaque bearer session is issued by the kernel, stored only as a hash, expires automatically, and may be revoked.

### Process identity is bounded

A principal may act through a process only if it owns the process or holds an explicit process-supervision capability. Process IDs are therefore no longer merely tracing metadata; they are part of the authority boundary.

### Policy overlays are restrictive-only

Executable `/etc/policy`-style documents may return only:

```text
DENY
ELEVATION_REQUIRED
```

They cannot return `ALLOW` or manufacture authority missing from the capability layer. This creates a monotonic security model: later policy layers can tighten access but cannot bypass lower-layer denial.

### Audit integrity is now verifiable

The hardened layer mirrors important events into a SHA-256 linked append-only chain. Mutation or broken linkage causes verification failure. This is tamper-evident, not yet externally anchored or tamper-proof.

### Secrets are leased to adapters

The public lease response contains a lease handle, reference, audience, and expiry—but not the underlying secret value. Resolution occurs only inside the adapter boundary.

### First external-device class remains S0

The first live I/O pattern is deliberately read-only HTTP. It is GET-only, host-allowlisted, response-bounded, timeout-bounded, and refuses caller-controlled authentication headers. Restricted data can be denied by policy before the request is sent.

## Engineering lesson from CI

The first integration run failed because the test used an action already restricted more tightly by the base capability layer. The code behavior was correct; the fixture was wrong.

The test was corrected so the v0.2 policy threshold is more restrictive than the v0.1 capability threshold. The next run passed all 16 tests and the committed-secret scan.

This failure is preserved as part of the project record because it demonstrates the intended security layering:

```text
BASE DENY / ELEVATION
        ↓
CANNOT BE RELAXED BY v0.2 POLICY

BASE ALLOW
        ↓
v0.2 MAY ALLOW TO STAND
OR TIGHTEN TO DENY / ELEVATION
```

## Current stack

```text
NCF constitutional governance
→ CDM discovery
→ CFHS representation
→ CFHS materializer
→ Kernel API contract
→ Kernel runtime v0.1
→ Kernel hardening v0.2
```

## Next engineering milestone

Before any write-capable live provider, build the next trust boundary:

- signed/anchored audit checkpoints;
- real secret-vault provider interface;
- scoped adapter sandboxing;
- policy schema/signatures/versioning;
- session rotation and stronger bootstrap ceremony;
- process capability bounding/inheritance;
- durable event/queue semantics;
- read-only real provider connector with zero write scopes;
- threat-model and adversarial test suite.
