# Company Kernel Distributed / Production Safety v0.7

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-distributed-safety-v0.7`  
**Status:** active engineering milestone; production credentials/providers remain disabled

## Canonical runtime

```text
kernel.server_v07
→ TrustKernelV07ProductionIdentityFinalGate
→ TrustKernelV07ExactAuthorityFinalGate
→ TrustKernelV07ControlPlaneFinalGate
→ TrustKernelV07DistributedCompensationFinalGate
→ TrustKernelV07TransactionalProviderGate
→ RecoverableSQLiteFencedStateCoordinator
```

Canonical identity-policy server promotion:

```text
8f11e0f0d3021055b8378a34c597553e80a68452
```

## Canonical consequential-action path

```text
BusinessObjectIdentity
→ semantic replay binding
→ authenticated/session-proven approvals
→ production authentication-class checks when enabled
→ authorization decision
→ anchored authorization evidence
→ exact financial authority where applicable
→ distributed transaction PREPARE
    ├── exact resource capacity
    ├── current ownership fence
    └── versioned transaction journal
→ provider PREPARE using same exact reservation
→ transaction/fence revalidation
→ provider/gateway stale-fence guard
→ provider execution
→ terminal state OR forward reconciliation
→ independently governed compensation when required
→ compensation identity + new fence epoch
→ provider-idempotent reversal
→ COMPENSATED OR compensation reconciliation
```

## Distributed safety already certified

v0.7 includes business-object identity, semantic replay binding, monotonic fencing, provider stale-fence rejection, transaction-coordinated PREPARE, exact-resource reservation, versioned transaction journals, forward outcome reconciliation, distributed compensation, compensation reconciliation and attempt history, a shared persistence contract, a fenced approval control plane, and exact minor-unit financial authority.

## Production identity / MFA authentication class

The canonical runtime now includes an explicit production authentication-class policy in `kernel/production_identity.py`.

The checked-in reference config intentionally remains:

```text
security.production_identity.mode = sandbox
```

This means the code contains and tests the production enforcement contract without claiming that a real production identity provider is connected.

When `mode = production`, consequential human authority requires:

```text
verified external identity provenance
+ allowed provider ID
+ allowed issuer
+ required AMR factors (for example MFA)
+ allowed ACR when configured
+ auth_time within configured freshness window
+ valid non-revoked kernel session bound to the same principal
```

### Approval mutation

In production mode, kernel-session-only approval is rejected. The external identity must satisfy provider, issuer, MFA/ACR and freshness policy **before** the fenced approval mutation is committed.

### S3 release defense in depth

S3 PREPARE rechecks all counted approval provenance. This blocks weak approvals that might have been injected through a lower-level/legacy path before any distributed transaction/fence/resource PREPARE occurs.

### Compensation

Production-mode compensation requires strong identity for the requester/executor and revalidates the compensation approval provenance before release.

### Elevations

Production exact-authority elevation approval is session-aware and records an immutable assurance digest. A direct/core-only approved elevation without the v0.7 identity record is not trusted for production exact-authority release.

### Authentication freshness

`auth_time` is mandatory in production mode. Authentication older than the configured maximum produces `CFHS_REAUTHENTICATION_REQUIRED`; missing/invalid identity class produces `CFHS_AUTHENTICATION_CLASS_REQUIRED`; insufficient MFA/ACR produces `CFHS_MFA_REQUIRED`.

### Identity privacy boundary

No raw bearer or ID token is stored by the production-identity assurance layer. Policy status exposes only safe metadata and digests.

## Shared persistence boundary

`kernel/shared_state_backend.py` defines the production cross-host semantics:

```text
serializable transactions
compare-and-swap
monotonic fencing
durable ordered journal
multi-connection visibility
synchronous durability
authoritative shared time
distributed quorum
```

The SQLite implementation is a semantic reference only and explicitly fails production certification for authoritative shared time and distributed quorum.

## Exact financial authority

Reference standing refund authority:

```text
USD $250.00 = 25,000 minor units
```

```text
$250.00 → ALLOW
$250.01 → ELEVATION_REQUIRED
sub-minor precision → REJECT
NaN/infinity → REJECT
legacy float-only elevation → cannot bypass exact authority
matching exact-unit + trusted elevation → may ALLOW within elevated ceiling
```

## Runnable API

Reference server:

```bash
python -m kernel.server_v07 \
  --state-dir <state> \
  --config examples/kernel.config.json \
  --policy-dir examples/policies \
  --kernel-instance-id kernel-a
```

Default port: `8048`.

Identity-aware v0.7 endpoints include:

```text
POST /v7/provider/compensation/approvals/request
POST /v7/provider/compensate
POST /v7/provider/compensation/reconcile
POST /v7/elevations/approve
```

The regular action approval endpoint is inherited through the v7→v6 compatibility router and reaches the canonical identity-aware `approve_action_with_session` method.

## v0.7 certification

Canonical validator:

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v07.py
```

Exact-count surface:

```text
222  prior v0.5/v0.6/v0.7 regression + distributed-safety tests
 11  production identity / MFA adversarial tests
---
233 targeted tests
```

Candidate certification:

```text
Run ID: 34048498715
Commit: 731ba9b8ac03a3ca090dd71d45d1daddf54f9687
233 / 233 PASS
0 failures
0 errors
0 skipped
exact_test_count = true
```

Canonical server certification:

```text
Run ID: 34048565980
Commit: 8f11e0f0d3021055b8378a34c597553e80a68452
Ran 233 tests in 7.084s
233 / 233 PASS
0 failures
0 errors
0 skipped
exact_test_count = true
```

## Current production decision

```text
Business-object identity................ IMPLEMENTED
Semantic replay safety.................. IMPLEMENTED
Monotonic fencing....................... IMPLEMENTED
Provider stale-fence guard.............. IMPLEMENTED
Atomic transaction PREPARE.............. IMPLEMENTED
Forward reconciliation.................. IMPLEMENTED
Distributed compensation................ IMPLEMENTED
Compensation reconciliation............. IMPLEMENTED
Shared persistence contract............. IMPLEMENTED / REFERENCE ONLY
Fenced approval control plane........... IMPLEMENTED
Exact financial authority............... IMPLEMENTED
Production identity/MFA policy.......... IMPLEMENTED / SANDBOX CONFIG
Canonical v0.7 certification............ 233 / 233 PASS
Production HA persistence backend....... PENDING
Live production IdP integration......... NOT ENABLED
Remote audit-anchor production hardening PENDING
Provider event/webhook reconciliation... PENDING
Production credentials.................. DENIED
Production write providers.............. DISABLED
Real provider test mode................. NOT YET ENABLED
```

## Remaining v0.7 work

1. harden remote audit anchoring for authenticated, replay-safe, multi-endpoint operation and receipt reconciliation;
2. implement/certify a real shared/HA persistence backend preserving the tested contract across hosts;
3. extend shared ownership/versioning to additional control-plane mutations where necessary;
4. integrate a real workforce IdP later in a controlled environment without repository credentials;
5. add provider webhook/event reconciliation;
6. validate one real provider's identity/fencing/idempotency semantics in test mode only;
7. execute migration, network-partition, failover and incident drills.

## Next v0.7 increment

Harden the **remote audit-anchor production contract** while preserving all 233 currently certified tests. No production credentials or live provider writes are authorized by this work.
