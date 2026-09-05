# Company Kernel Hardening v0.2

**Status:** Reference hardening layer  
**Date:** 2026-09-05

## Purpose

v0.2 hardens the runnable v0.1 Company Kernel before any consequential live provider is connected.

## New controls

### 1. Authenticated kernel sessions

The v0.1 HTTP proof trusted an actor header. v0.2 no longer does.

Bearer sessions are opaque random values. Only their SHA-256 hashes are persisted. Sessions expire and can be revoked. The authenticated session determines the principal identity.

### 2. Process ownership/bounding

An authenticated principal may operate through a process only when:

- it owns that process; or
- it has explicit `kernel.process.supervise` authority.

The bootstrap kernel process is owner-only in the reference daemon.

### 3. Executable policy documents

JSON policy documents are loaded from a policy directory analogous to `/etc/policy`.

In v0.2 these documents are **restrictive-only**. They may return:

```text
DENY
ELEVATION_REQUIRED
```

They may not return `ALLOW` or create new authority. Base authority still originates from the kernel capability model.

`DENY` outranks `ELEVATION_REQUIRED`.

### 4. Tamper-evident audit chain

Important hardened decisions are mirrored to append-only JSONL records where every entry includes the SHA-256 hash of the previous record.

Verification can detect:

- modification of a record;
- deletion/reordering that breaks the chain;
- incorrect previous-record linkage.

This is tamper-evident, not yet tamper-proof. Production should anchor hashes outside the writable runtime boundary.

### 5. Secret broker abstraction

The reference secret broker consumes opaque references such as:

```text
secret://env/NAME
```

A lease response contains only:

- lease ID;
- secret reference;
- audience;
- expiration.

The secret value is resolved only inside a permitted adapter and is never returned by the public lease operation.

### 6. Sandboxed read-only HTTP device

The first non-mock device pattern is deliberately S0/read-only.

Controls include:

- GET only;
- explicit host allowlist;
- HTTPS required outside localhost tests;
- URL userinfo forbidden;
- private/loopback/link-local/reserved network targets rejected in normal mode;
- bounded response size;
- short timeout;
- no caller-supplied Authorization header;
- policy/data-classification checks before invocation.

## Hardened request path

```text
BEARER SESSION
     ↓
AUTHENTICATED PRINCIPAL
     ↓
PROCESS OWNERSHIP / SUPERVISION CHECK
     ↓
V0.1 CAPABILITY AUTHORIZATION
     ↓
V0.2 RESTRICTIVE POLICY
     ↓
ALLOW | DENY | ELEVATION_REQUIRED
     ↓
READ-ONLY DEVICE / CORE ACTION
     ↓
CORE AUDIT + HASH-CHAIN AUDIT
```

## Safety boundary

v0.2 does **not** authorize connecting write-capable production email, payment, banking, CRM, code-deployment, or advertising systems.

The first permitted live-provider class should remain read-only until authentication, audit, policy, secret handling, and process isolation receive additional review.
