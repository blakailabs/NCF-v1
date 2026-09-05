# Company Kernel Trust Layer v0.3

**Project:** Company Operating System  
**Status:** Reference trust-layer implementation  
**Date:** 2026-09-05

## Purpose

v0.3 moves the Company Kernel from hardened execution toward **provable trust**. The central question is no longer only “is this action allowed?” but also:

- where did the authority come from?
- was the policy authentic?
- can a child process gain more authority than its parent?
- can a session be replayed after rotation?
- can an audit trail be rewritten without detection?
- can a secret escape its intended adapter?
- can durable work be claimed or acknowledged by the wrong process?

## Trust primitives implemented

### Signed restrictive policy packages

Policy packages now support integrity signatures through a provider-neutral package envelope.

The dependency-free reference implementation uses `HMAC-SHA256-REFERENCE` only to prove package verification semantics. Production should replace this with asymmetric signatures backed by a signing service or HSM.

A signed package contains:

```text
package id
version
policies
signature algorithm
signing key id
signature value
```

The trust layer rejects:

- unknown signing keys;
- modified package contents;
- unsupported signature algorithms;
- unsigned/malformed packages;
- policies that attempt to create `ALLOW` authority.

Package installation is atomic: every package verifies before the active set is replaced.

### Monotonic authority

Authority remains monotonic:

```text
lower layer ALLOW
      ↓
trust layer may keep ALLOW
or tighten to:
DENY / ELEVATION_REQUIRED

lower layer DENY
      ↓
trust layer cannot turn it into ALLOW
```

### Parent/child capability bounding

A parent process may spawn a child with narrower authority, but never broader authority.

A delegated child capability must be covered by both:

1. the delegating process/principal's effective authority; and
2. the child principal's own base capability set.

The child process stores its capability bounds in process metadata. Trust-layer authorization applies those bounds after normal principal authorization.

### Delegation proofs

Bounded process creation writes a durable delegation proof containing:

```text
parent process
child process
delegator
delegate
capability set
creation time
proof digest
```

This makes the authority chain reconstructable.

### Session rotation

A valid session can be rotated into a replacement session. The old token is revoked as part of rotation and can no longer authenticate.

### One-time bootstrap ceremony

The v0.3 daemon no longer prints a privileged owner session at startup.

A bootstrap secret must be supplied outside the repository and presented to `/v3/bootstrap`. The daemon then issues the initial owner session.

**Current limitation:** the one-time-used marker is process-local in the reference server. A production implementation must persist bootstrap completion so a restart cannot reopen the ceremony with the same bootstrap secret.

### Vault-provider secret abstraction

The trust layer introduces a provider-neutral vault contract.

A lease exposes only:

```text
lease id
provider reference
audience
expiration
```

The underlying secret is resolved only inside the intended adapter boundary. Wrong-audience resolution is denied.

The committed `MemoryVaultProvider` is test/reference-only and must not be used for production secret storage.

### Durable event bus

A SQLite-backed durable event/queue primitive now supports:

```text
publish
poll / claim
acknowledge
release / retry
attempt counting
consumer ownership
```

One process cannot acknowledge a message claimed by another process.

### Audit anchoring abstraction

The existing tamper-evident audit chain can now be checkpointed into an independent anchor provider.

The reference `FileAuditAnchorProvider` stores a second hash-linked anchor chain outside the kernel database.

This proves the anchoring contract but is not truly external trust. Production should anchor checkpoints to a remote append-only transparency service, object-lock store, ledger, or equivalent system outside the kernel's writable trust boundary.

### First concrete real-provider adapter

`GitHubReadOnlyAdapter` is the first concrete provider-specific device contract.

It exposes only:

```text
GET repository metadata
GET branches
GET repository contents
```

There are intentionally no methods for:

```text
POST
PUT
PATCH
DELETE
create issue
merge
write file
```

Optional GitHub authentication can enter the adapter only through an audience-bound secret lease.

## v0.3 control path

```text
ONE-TIME BOOTSTRAP
        ↓
AUTHENTICATED SESSION
        ↓
PROCESS OWNERSHIP
        ↓
PRINCIPAL CAPABILITY
        ↓
RESTRICTIVE POLICY v0.2
        ↓
SIGNED POLICY PACKAGE v0.3
        ↓
PROCESS CAPABILITY BOUND
        ↓
ALLOW / DENY / ELEVATION_REQUIRED
        ↓
DEVICE / EVENT / KERNEL ACTION
        ↓
AUDIT CHAIN
        ↓
AUDIT ANCHOR
```

## Validation performed

An independent local harness validated 11 core trust checks:

```text
signed policy verification................ PASS
policy tamper rejection................... PASS
atomic signed-policy install.............. PASS
audit-anchor tamper detection............. PASS
vault audience binding.................... PASS
session rotation/replay rejection......... PASS
bounded capability acceptance............. PASS
child privilege escalation rejection...... PASS
durable queue ownership/retry............. PASS
GitHub read-only GET behavior............. PASS
GitHub write API absence.................. PASS
```

Additional repository integration tests have been committed for bounded child processes, signed policy runtime overlays, durable authorized IPC, and audit anchoring.

## CI infrastructure note

GitHub Actions is currently creating `BuildFailed / startup_failure` workflow placeholders with **zero jobs** for new branch pushes. This occurs before compilation or test execution and therefore is not being interpreted as a runtime test failure.

The previously established v0.2 runtime did complete a real GitHub Actions job successfully. v0.3 must receive a clean GitHub Actions or equivalent clean-environment run before release certification.

## Production boundaries still closed

v0.3 does not authorize production write access to:

- email;
- payments or banking;
- CRM mutation;
- code deployment;
- advertising;
- accounting;
- legal-signature systems;
- customer-data export.

The project remains in reference/runtime validation mode.
