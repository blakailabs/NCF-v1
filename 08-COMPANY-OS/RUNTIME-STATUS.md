# Company Operating System Runtime Status

**Updated:** 2026-09-06 17:26 UTC  
**Current engineering branch:** `feature/company-kernel-distributed-safety-v0.7`  
**Draft PR:** #3 — Company Kernel Distributed / Production Safety v0.7

## Canonical project identity

**Project:** Company Operating System  
**Historical repository slug:** `blakailabs/NCF-v1`  
**Intended repository slug:** `blakailabs/Company-Operating-System`

NCF remains the constitutional governance layer inside the broader Company Operating System.

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

## Implemented v0.7 safety layers

```text
Business-object identity................ IMPLEMENTED
Semantic replay safety.................. IMPLEMENTED
Monotonic distributed fencing........... IMPLEMENTED
Transactional PREPARE................... IMPLEMENTED
Forward outcome reconciliation.......... IMPLEMENTED
Distributed compensation................ IMPLEMENTED
Compensation reconciliation............. IMPLEMENTED
Shared persistence contract............. IMPLEMENTED / REFERENCE ONLY
Fenced approval control plane........... IMPLEMENTED
Exact financial authority............... IMPLEMENTED
Production identity/MFA policy.......... IMPLEMENTED / SANDBOX CONFIG
Canonical v0.7 certification............ 233 / 233 PASS
```

### Production identity / MFA policy

The canonical runtime now contains an explicit authentication-class policy boundary.

Checked-in reference configuration remains:

```text
mode: sandbox
```

Therefore this milestone **does not claim a live production IdP**.

When a deployment explicitly enables `mode: production`, human consequential actions require policy-conforming external identity provenance:

```text
allowed identity provider
+ allowed issuer
+ required AMR factors (MFA)
+ allowed ACR when configured
+ recent auth_time
+ live matching kernel session
```

Production-mode enforcement applies to:

```text
action approval mutation
S3 PREPARE release
compensation requester
compensation execution
compensation approval release
exact-authority elevation approval/use
```

Kernel-session-only approval is rejected in production mode. Weak provenance manually injected below the canonical approval path is rechecked at S3 PREPARE and fails closed. Legacy/core-only elevation approval is not trusted for production exact-authority release.

Raw bearer/IdP tokens are not stored in the new assurance records.

### Exact financial authority

Reference standing refund authority remains:

```text
USD $250.00 = 25,000 minor units
```

A matching exact-unit elevation is required above the standing ceiling. Float-only elevation cannot bypass the exact-unit boundary.

### Shared/fenced persistence contract

The reference backend contract requires:

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

The SQLite reference validates semantics but is explicitly **not production-ready** because it lacks authoritative distributed time and distributed quorum.

## v0.7 certification

Canonical validator:

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v07.py
```

Current exact-count surface:

```text
222  prior v0.5/v0.6/v0.7 regression and distributed-safety tests
 11  production identity / MFA adversarial tests
---
233 targeted tests
```

Production-identity candidate:

```text
Run ID: 34048498715
Commit: 731ba9b8ac03a3ca090dd71d45d1daddf54f9687
Ran 233 tests in 7.701s
233 / 233 PASS
0 failures
0 errors
0 skipped
exact_test_count = true
```

Canonical server promotion:

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

The new tests cover kernel-session rejection in production mode, trusted provider/issuer checks, MFA/ACR requirements, authentication freshness, injected weak-provenance rejection, compensation requester identity, MFA-bound elevation approval, rejection of unproven direct elevation approval, strong exact-authority elevation, and safe policy-status reporting.

## Current production posture

```text
Production HA persistence backend....... PENDING
Live production IdP integration......... NOT ENABLED
Remote audit-anchor production hardening PENDING
Provider event/webhook reconciliation... PENDING
Real provider test mode................. NOT YET ENABLED
Production credentials.................. DENIED
Production write providers.............. DISABLED
```

## Remaining v0.7 work

1. harden the remote audit-anchor contract for authenticated, replay-safe, multi-endpoint operation and receipt reconciliation;
2. implement/certify a real shared/HA persistence backend preserving the tested fencing/CAS/journal semantics across hosts;
3. extend shared control-plane ownership/versioning beyond approval mutation where required;
4. integrate a real workforce IdP in a later controlled environment without adding production credentials to this repository;
5. add provider webhook/event reconciliation;
6. validate one real provider's identity/fencing/idempotency semantics in test mode only;
7. execute migration, network-partition, failover and incident drills.

## Global production release gate

No production write-capable provider is enabled until the applicable path has:

```text
verified production authentication class
+ recursive authority provenance
+ authentic policy
+ exact financial authority where applicable
+ business-object identity binding
+ semantic replay binding
+ transaction-coordinated exact capacity
+ current distributed fence
+ provider stale-fence protection
+ provider idempotency
+ strong session-proven approvals
+ authenticated/available audit anchoring
+ forward reconciliation
+ governed/fenced/reconcilable compensation where required
+ production shared/HA backend certification
```

## Administrative repository rename

Still pending:

```text
blakailabs/NCF-v1
→ blakailabs/Company-Operating-System
```

See `/ADMIN-RENAME.md`.

## Next logical v0.7 increment

Harden the **remote audit-anchor production contract** while preserving the full 233-test regression surface. Production credentials and live providers remain disabled throughout that work.
