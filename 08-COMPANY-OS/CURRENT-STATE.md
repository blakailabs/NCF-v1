# Company Operating System — Current State

**Use this file first when resuming engineering.**
Detailed status: `08-COMPANY-OS/RUNTIME-STATUS.md`

## Active milestone

```text
Repository: blakailabs/NCF-v1
Branch: feature/company-kernel-production-infrastructure-v0.9
Milestone: Company Kernel Production Infrastructure v0.9
Status: ACTIVE
```

## Merged certified baseline

```text
v0.8 PR: #4
v0.8 merge commit: eb47c7cfa9ab223f8e60847e651f2387edff0b08
Final synchronized-head CI: 34083972113
Certified head: ef1f8b24bc20a34762f026bb802dfd35b4d2ef4e
415 / 415 PASS
```

## Current v0.9 certified checkpoint

```text
CI run: 34084379611
Certified validator/head: b8683d5a8c4a407cd7437d7736db50771dc9bf1c
427 / 427 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

Exact surface:

```text
415 frozen v0.8 regression tests
 12 production-infrastructure v0.9 contract tests
---
427 targeted tests
```

## What v0.9 now certifies

```text
provider-neutral production infrastructure evidence bundle
exact deployment/provider/adapter/backend/cluster identity binding
required HA capability claim surface
required certification evidence phases
external verifier required
provider self-certification forbidden
external verifier independence required
verifier receipt + production trust-store provenance required
credential source class restricted to external identity/secret systems
secret-like material rejected from evidence metadata
evidence freshness + expiry enforced
positive authority generation required
frozen v0.8 safety baseline preserved
```

## Production posture

```text
Production credentials..................... DENIED
Production write providers................. DISABLED
Real production HA backend................ NOT CONNECTED
Real topology source....................... NOT CONNECTED
Real chaos controller...................... NOT CONNECTED
Production bootstrap authority............. NOT CONNECTED
Production shared certification plane...... NOT DEPLOYED
Production adapter attestation authority... NOT CONNECTED
Production adapter enrollment authority.... NOT CONNECTED
Production durable trust stores............ NOT CONNECTED
Production IdP............................. NOT CONNECTED
Production asymmetric/HSM anchor trust..... NOT CONNECTED
```

The 427-test checkpoint certifies the **contract for production infrastructure**, not a live production deployment.

## Next exact engineering step

Implement the first concrete adapter beneath the neutral contract only after selecting an actual deployment target. The first target should be the shared-state backend because topology, chaos, certification-plane and runtime evidence depend on it.

Until a provider/deployment target is selected, no provider-specific implementation can be truthfully completed or certified.

## Standing sync rule

After every meaningful implementation or CI boundary: update `RUNTIME-STATUS.md`, this file, `PRODUCTION-INFRASTRUCTURE-v0.9.md`, and the active PR. Never call committed work certified without exact-count CI evidence.
