# Company Operating System Runtime Status

**Updated:** 2026-09-05  
**Current branch:** `feature/company-kernel-trust-hardening-v0.4`

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
→ Kernel hardening v0.2
→ Kernel Trust Layer v0.3
→ Kernel Trust Hardening v0.4
```

## v0.1 — runnable kernel

Implemented:

- durable principal/process/checkpoint/audit state;
- default-deny capabilities;
- contextual amount/resource limits;
- `ALLOW`, `DENY`, `ELEVATION_REQUIRED`;
- narrow human-approved elevation;
- mock S2/S3 devices;
- idempotency and resource ceilings;
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

- internally renamed project identity to **Company Operating System**;
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
- threat model and adversarial test catalog.

Independent reference harness:

```text
Trust primitive checks........ 11 / 11 PASS
```

Full v0.3 CI remains release-blocked because GitHub Actions is currently producing `startup_failure` placeholders with zero jobs before checkout or test execution.

## v0.4 — trust hardening

Implemented on `feature/company-kernel-trust-hardening-v0.4`:

- durable restart-safe one-time bootstrap state;
- bootstrap completion and initial session issuance in one SQLite transaction;
- restart no longer requires the original bootstrap secret after first initialization;
- persistent signed-policy contents across restart;
- semantic-version rollback protection;
- same-version content-substitution rejection;
- recursive delegation-chain verification;
- delegation proof/process-bound tamper detection;
- authorization-time verification of delegated provenance;
- expiring durable queue claim leases;
- dead-letter transition and reason tracking;
- external OIDC identity broker contract;
- one-time OIDC nonce consumption and kernel-session creation in one transaction;
- remote HTTPS audit-anchor provider contract;
- external HTTPS vault-provider implementation;
- runnable v0.4 server wiring;
- dedicated v0.4 restart/rollback/delegation/identity/anchor/vault tests committed.

## v0.4 acceptance status

```text
IMPLEMENTED
TEST COVERAGE COMMITTED
CLEAN-ENVIRONMENT EXECUTION REQUIRED
PRODUCTION WRITE RELEASE BLOCKED
```

The GitHub Actions startup problem remains separate from runtime correctness: affected workflow records contain zero jobs and fail before checkout/compile/test.

## Remaining trust gaps before live S2/S3 business writes

- production asymmetric policy-signature verifier/HSM integration;
- production cryptographic OIDC provider implementation and MFA/IdP configuration;
- deployed remote immutable audit-anchor service;
- protected vault bootstrap credential handling such as mTLS/HSM/workload identity;
- distributed resource reservations;
- durable replay/nonces across clustered kernels;
- compensation/rollback orchestration;
- fail-closed audit commit for consequential actions;
- multi-party approval for selected S3 actions;
- distributed queue coordination/HA/failover;
- clean-environment adversarial certification.

## Release gate

No production write-capable email, payment, banking, CRM, deployment, advertising, accounting, or legal-signature provider should be enabled until:

```text
identity verified
+ recursive authority provenance verified
+ signed policy authenticity verified
+ secret scope bounded
+ audit commit guaranteed
+ external audit anchor available
+ replay protection available
+ resource reservation available
+ compensation/rollback defined
+ approval requirements satisfied
```

## Next engineering milestone

Build the **Company Kernel Action Safety Layer v0.5**:

1. durable resource reservation/commit/release;
2. consequential-action replay/nonces;
3. compensation and rollback contracts;
4. fail-closed audit transaction semantics;
5. multi-party approval policies for selected S3 actions;
6. action intent/evidence envelope;
7. adversarial tests for partial failure and duplicate execution;
8. only after certification, evaluate the first sandboxed real S2 write adapter.
