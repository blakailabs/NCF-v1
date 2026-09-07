# Company Operating System Runtime Status

**Engineering branch:** `feature/company-kernel-production-infrastructure-v0.9`  
**Milestone:** Company Kernel Production Infrastructure v0.9

## Project identity

**Project:** Company Operating System  
**Repository:** `blakailabs/NCF-v1`

NCF remains the constitutional governance layer inside the broader Company Operating System.

## State-sync discipline

`RUNTIME-STATUS.md` is the canonical detailed resumability checkpoint. `CURRENT-STATE.md` is the concise pickup file. A committed change is never called certified until exact-count CI passes.

## Merged baseline

```text
v0.8 PR #4........................ MERGED
v0.8 merge commit................. eb47c7cfa9ab223f8e60847e651f2387edff0b08
v0.8 final synchronized-head CI.... 34083972113
v0.8 certified head................ ef1f8b24bc20a34762f026bb802dfd35b4d2ef4e
415 / 415 PASS
```

## Evidence-first doctrine

```text
Reality first.
Structure second.
Automation third.
AI last.
```

## v0.9 provider-neutral production contract — CERTIFIED

`kernel/production_infrastructure_v09.py` defines the first production-infrastructure certification boundary. It does not connect or impersonate a provider. It defines the evidence a real provider adapter must produce before the kernel can treat it as production-ready.

### Evidence identity

The bundle binds:

```text
deployment_id
provider_id
adapter name/version/implementation digest
backend_id
cluster_id
capability digest
topology evidence digest
probe evidence digest
release attestation digest
trust-store identity
authority identity/class/generation
credential source class
observed_at / valid_until
evidence nonce
required capability claims
required certification phases
```

### Certified rejection rules

```text
missing external verifier → deny
provider self-certification → deny
verifier not independent → deny
verifier digest mismatch → deny
missing required HA capability → deny
missing fault/partition evidence phase → deny
stale/expired evidence → deny
invalid credential source class → deny
secret-like material in evidence metadata → deny
non-positive authority generation → deny
```

The positive contract path requires an independent verifier receipt and production trust-store provenance.

## Current certified checkpoint

```text
Run ID: 34084379611
Implementation/validator head: b8683d5a8c4a407cd7437d7736db50771dc9bf1c
Ran 427 tests in 6.709s
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
415 frozen v0.8 tests
 12 production-infrastructure v0.9 tests
---
427 targeted tests
```

## Production posture

```text
Real production HA backend................ NOT CONNECTED
Real topology control-plane adapter........ NOT CONNECTED
Real chaos/partition environment........... NOT CONNECTED
Production bootstrap authority............. NOT CONNECTED
Production shared certification plane...... NOT DEPLOYED
Production adapter attestation authority... NOT CONNECTED
Production adapter enrollment authority.... NOT CONNECTED
Production durable trust stores............ NOT CONNECTED
Live production IdP........................ NOT CONNECTED
Production asymmetric/HSM anchor trust..... NOT CONNECTED
Production credentials..................... DENIED
Production write providers................. DISABLED
```

## Boundary between completed and blocked work

The **provider-neutral contract** can be and now is implemented/certified in-repository.

A **concrete provider adapter** cannot be truthfully completed until an actual deployment target is selected because provider APIs, topology semantics, transaction guarantees, identity plumbing, fault controls and trust mechanisms are deployment-specific evidence sources.

## Next exact engineering step

Select the first real shared-state deployment target, then implement its adapter beneath the v0.9 neutral contract. Do not alter the contract to make a weak provider pass; the provider must satisfy the contract or remain non-production.
