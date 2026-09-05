# Company Operating System Knowledge Base — Trust Hardening v0.4

**Date:** 2026-09-05

## Milestone

Trust Hardening v0.4 closes major restart and provenance gaps left by v0.3 without enabling any production business write provider.

## Canonical decisions

### Bootstrap is durable state

Bootstrap is no longer a process-memory flag. The ceremony is persisted and can be completed only once. Initial session issuance and completion are one transaction.

After first initialization, the original bootstrap secret is not required merely to restart the kernel.

### Policy state must survive restart

A signed policy is not truly active if it disappears when the daemon restarts. v0.4 therefore persists complete package contents, version, digest, key id, and install time.

Lower semantic versions are rejected, and the same version cannot be replaced with different content.

### Delegation provenance is recursively verifiable

Authority provenance must survive more than one parent/child hop. The kernel can now reconstruct and verify a delegated process chain to its root, detect cycles, verify proof digests, compare process metadata to proofs, and enforce narrowing at each hop.

### Queue ownership requires leases

A durable queue claim is no longer permanent. Claims expire. Expired work can be reclaimed. Messages that repeatedly fail move to a dead-letter state with a reason.

### External identity is a verification boundary

The kernel does not treat JWT payloads as identity. A provider boundary must cryptographically verify an OIDC token before claims reach the broker. The broker independently enforces issuer, audience, subject mapping, expiry, and one-time nonce semantics.

Nonce consumption and kernel-session issuance are atomic.

### Audit trust must leave the kernel host

A remote HTTPS audit-anchor contract now exists. A receipt must confirm the exact audit head that was submitted and redirects cannot escape the configured origin.

### Vault resolution is kernel/provider infrastructure

A provider-neutral HTTPS vault implementation now exists. Vault bootstrap credentials are runtime-injected, not repository data. Returned references must match the requested provider reference.

## Current trust boundary

The Company Operating System now supports:

```text
verified/session identity
→ process ownership
→ recursive delegation proof
→ principal capability
→ restrictive policy
→ signed rollback-protected policy
→ process capability bound
→ governed action
→ audit chain
→ external anchor contract
```

## Known release blockers

Do not enable live S2/S3 business writes until resource reservations, cluster-safe replay protection, compensation/rollback, fail-closed audit commit, and stronger/multi-party approvals exist and pass clean-environment adversarial certification.

## Next milestone

**Company Kernel Action Safety Layer v0.5**.
