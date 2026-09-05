# Company Operating System Runtime Status

**Updated:** 2026-09-05  
**Current branch:** `feature/company-kernel-trust-v0.3`

## Canonical project identity

**Project:** Company Operating System  
**Recommended GitHub slug:** `Company-Operating-System`  
**Historical repository slug:** `NCF-v1` (administrative rename pending)

NCF remains the constitutional governance layer inside the broader Company Operating System project.

## Implemented and validated foundations

- CDM machine contract v0.1
- deterministic CFHS materializer v0.1
- staged/atomic materialization behavior for new targets
- inline-secret rejection and opaque `secret://` references
- Company Kernel API contract v0.1
- OpenAPI 3.1 contract
- minimal CDM → CFHS reference materialization

## Company Kernel runtime v0.1

- runnable kernel daemon
- durable SQLite principal/process/checkpoint/audit state
- default-deny capabilities
- contextual amount/resource limits
- `ALLOW`, `DENY`, and `ELEVATION_REQUIRED`
- human-approved narrow, expiring elevation
- mock S2/S3 device broker
- idempotency
- resource ceilings
- checkpoint/restart recovery

## Kernel hardening v0.2

- authenticated opaque kernel sessions
- session hashing, expiration, and revocation
- process ownership/supervision binding
- restrictive-only executable JSON policy overlay
- tamper-evident SHA-256 audit chain
- environment-backed secret-broker reference abstraction
- sandboxed S0 read-only HTTP adapter
- GitHub Actions validation

### v0.2 validation

GitHub Actions run `33998002023` passed:

```text
Compile kernel................ PASS
Combined kernel tests......... PASS (16 tests)
Committed secret scan......... PASS
```

## Kernel Trust Layer v0.3

Implemented on `feature/company-kernel-trust-v0.3`:

- canonical repository/project identity updated internally to **Company Operating System**
- signed restrictive policy package contract
- package integrity verification
- atomic signed-policy activation
- trusted signing-key registry abstraction
- session rotation with old-token revocation
- parent/child capability bounding
- process-level capability bounds enforced after principal authorization
- durable delegation proofs with proof digests
- provider-neutral vault interface
- audience-bound vault secret leases
- durable SQLite event/queue subsystem
- claim/ack/release/retry ownership semantics
- independent audit-anchor provider abstraction
- hash-linked reference audit-anchor chain
- concrete GitHub read-only provider adapter
- no write methods on the GitHub provider adapter
- one-time bootstrap endpoint that does not print privileged sessions at startup
- explicit threat model and adversarial test catalog
- end-to-end TrustKernel integration tests committed

### Independent v0.3 primitive validation

A separate local harness validated **11/11** trust checks:

```text
Signed policy verification................ PASS
Policy tamper rejection................... PASS
Atomic policy activation.................. PASS
Audit-anchor tamper detection............. PASS
Vault audience binding.................... PASS
Session rotation/replay rejection......... PASS
Bounded capability acceptance............. PASS
Child privilege escalation rejection...... PASS
Durable queue ownership/retry............. PASS
GitHub read-only GET behavior............. PASS
GitHub write API absence.................. PASS
```

### Current CI limitation

GitHub is currently creating `BuildFailed / startup_failure` workflow placeholders with **zero jobs** for the v0.3 branch. These failures occur before checkout, compilation, or tests and are therefore tracked as CI infrastructure/startup failures, not software test failures.

The v0.3 integration tests remain release-blocking until they receive a clean CI or equivalent clean-environment execution.

## Known v0.3 trust limitations

- reference policy signing uses dependency-free HMAC; production requires asymmetric signing/HSM or equivalent
- reference audit anchor is independent of the kernel database but still local; production requires remote immutable anchoring
- reference `MemoryVaultProvider` is test-only; production requires a real vault provider
- bootstrap completion is process-local in the current reference daemon and must become durable before production
- queue claim leases do not yet expire automatically
- no external IdP/OIDC/MFA
- no distributed resource reservation/cgroup-equivalent runtime
- no live rollback/compensation engine
- no HA/failover/rescue implementation
- no write-capable production provider is enabled

## Release gate for any live S2/S3 provider

No production write-capable email, payment, banking, CRM, code-deployment, advertising, accounting, or legal-signature provider may be enabled until all of the following are proven:

```text
identity verified
+ process authority bounded
+ policy authenticity verified
+ secret scope bounded
+ audit commit available
+ external audit anchor available
+ replay/idempotency protection available
+ resource reservation available
+ rollback/compensation defined
+ approval path defined where required
```

## Next engineering milestone

Build **Company Kernel Trust Hardening v0.4**:

1. durable one-time bootstrap ceremony;
2. asymmetric signed/versioned policy packages with rollback protection;
3. real vault-provider interface implementation;
4. remote/immutable audit-anchor provider;
5. expiring queue claims + dead-letter handling;
6. recursive delegation-proof verification across process trees;
7. external identity/OIDC contract;
8. clean-environment adversarial certification run;
9. only then evaluate the first sandboxed real S2 write adapter.
