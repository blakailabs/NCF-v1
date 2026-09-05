# Company Kernel Trust Hardening v0.4

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-trust-hardening-v0.4`  
**Date:** 2026-09-05

## Purpose

v0.4 closes restart, rollback, delegation, queue, external-identity, audit-anchor, and vault-provider trust gaps identified in v0.3. It does not expand business authority and does not enable a live write-capable business provider.

## Controls implemented

### Durable one-time bootstrap

Bootstrap state is persisted in SQLite. The initial privileged session and the transition from `PENDING` to `COMPLETED` are committed in one database transaction.

Once completed:

- presenting the original bootstrap secret again is denied;
- restarting the kernel does not reopen the ceremony;
- the original bootstrap environment variable is no longer required for normal restarts.

The bootstrap secret is stored only as a SHA-256 digest.

### Persistent signed-policy state and rollback protection

Signed restrictive policy packages now persist their complete active contents, version, digest, key id, and installation time.

The store rejects:

- versions lower than the highest installed version;
- same-version replacement with different content;
- untrusted signing keys;
- signature mismatch;
- malformed semantic versions;
- policy effects other than `DENY` or `ELEVATION_REQUIRED`.

Active policy contents restore after kernel restart.

The reference signature algorithm remains dependency-free HMAC for contract validation. Production still requires asymmetric signing/HSM-backed provenance.

### Recursive delegation verification

The kernel can walk a delegated process chain back to its root and verify every hop.

Verification checks:

- no process cycle;
- child has a delegation proof;
- proof parent equals process parent;
- proof delegate equals process owner;
- proof digest is intact;
- process metadata digest matches the proof;
- process capability bounds equal proof capabilities;
- each child capability set is bounded by its parent's delegated set.

The v0.4 authorization path verifies delegated provenance before privileged authorization.

### Expiring queue claims and dead letters

Durable IPC now supports claim leases.

A message claim:

- expires automatically;
- may be reclaimed after expiry;
- cannot be acknowledged after its claim expires;
- counts delivery attempts;
- moves to a dead-letter state after the configured maximum attempts;
- records a dead-letter reason.

This prevents abandoned worker claims from permanently wedging the company event bus.

### External OIDC identity broker contract

The kernel now has a provider boundary for cryptographically verified OIDC claims.

The broker itself refuses to trust unsigned JWT payloads. A provider implementation must verify token signatures before returning claims.

The kernel then enforces:

- issuer;
- audience;
- subject;
- expiration;
- one-time nonce;
- explicit subject → Company Kernel principal mapping;
- mapping active/disabled status;
- maximum session TTL.

Nonce consumption and kernel-session creation occur in one transaction.

The committed `StaticVerifiedClaimsProvider` is test-only and is not a production identity provider.

### Remote audit-anchor provider contract

`HTTPSAuditAnchorProvider` can send the current audit head to one configured HTTPS origin and require a receipt that confirms the same hash.

Controls include:

- HTTPS only;
- no URL-embedded credentials;
- same-origin redirect enforcement;
- response-size limits;
- short timeout;
- optional audience-bound token lease;
- receipt ID required;
- returned audit hash must match the submitted head.

This is infrastructure-only external writing: it exists to move audit trust outside the kernel host, not to perform a business action.

### External HTTPS vault provider

`HTTPSVaultProvider` implements the provider-neutral vault interface over one pinned HTTPS origin.

Controls include:

- runtime-injected bootstrap credential only;
- no credential in repository configuration;
- GET-only secret resolution;
- same-origin redirect enforcement;
- response-size limits;
- requested provider reference must be echoed by the vault;
- secret bytes are transported base64-encoded and returned only to the broker/adapter boundary;
- bootstrap credential can be cleared after setup.

Production deployments should prefer protected credential handles/mTLS/HSM integration rather than long-lived Python byte strings.

## v0.4 authorization/trust path

```text
EXTERNAL / BOOTSTRAP IDENTITY
          ↓
AUTHENTICATED KERNEL SESSION
          ↓
PROCESS OWNERSHIP
          ↓
RECURSIVE DELEGATION PROOF
          ↓
PRINCIPAL CAPABILITY
          ↓
RESTRICTIVE POLICY v0.2
          ↓
SIGNED + ROLLBACK-PROTECTED POLICY v0.4
          ↓
PROCESS CAPABILITY BOUND
          ↓
ALLOW / DENY / ELEVATION_REQUIRED
          ↓
DEVICE / IPC / KERNEL ACTION
          ↓
AUDIT CHAIN
          ↓
REMOTE-ANCHOR CONTRACT
```

## Test coverage committed

New v0.4 tests cover:

- bootstrap single-use behavior across restart;
- wrong bootstrap secret without consuming ceremony;
- signed policy restore after restart;
- policy rollback rejection;
- same-version content substitution rejection;
- expiring queue claims;
- expired-claim acknowledgement rejection;
- dead-letter transition;
- recursive delegation-chain verification;
- delegation-digest tampering;
- process-bound tampering;
- OIDC one-time nonce/session issuance;
- OIDC audience mismatch;
- disabled external identity mapping;
- remote audit receipt matching;
- remote anchor cross-origin redirect rejection;
- external vault resolution;
- vault reference mismatch;
- vault cross-origin redirect rejection;
- vault bootstrap-credential clearing.

## Safety boundary

v0.4 still does not enable a real production S2/S3 business write provider.

Payments, banking, live email sends, CRM mutation, ad spend, deployment, accounting mutation, and legally binding actions remain closed.
