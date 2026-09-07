# Company Kernel HA Persistence Safety v0.8

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-ha-persistence-v0.8`  
**Base:** `25382c018e8bf3cfe426940afc8f622b526ba191`  
**Repository implementation:** COMPLETE  
**Production deployment:** NOT ENABLED / external integration pending

## Evidence-first rule

```text
Reality first.
Structure second.
Automation third.
AI last.
```

## Final certified v0.8 trust chain

```text
backend capability contract
→ independent topology/deployment evidence
→ active behavioral/fault probes
→ trusted deployment attestation
→ time-bounded certification
→ one-time bootstrap authority
→ bootstrap-to-steady-state handoff
→ permanent first-bootstrap closure
→ shared certification-plane state
→ adapter/deployment attestation
→ durable adapter enrollment
→ per-operation deployment revalidation
→ independent enrollment authority authorization
→ shared external-authority activation receipt
→ production runtime guard
```

## Production enrollment authority

`kernel/certification_plane_enrollment_authority.py` prevents adapter enrollment from being promoted by a caller-controlled generation or an untrusted local authority.

Production enrollment authorization binds:

```text
purpose
deployment id + digest
adapter readiness digest
release attestation digest
release verifier receipt
release trust-store identity
enrollment generation
enrollment authority id/class/key/generation
authorization nonce
issued_at / expires_at
```

Reference authority stores report non-production readiness. Authorization expiry, purpose substitution, digest substitution, verifier mismatch, nonce replay and authority-generation rollback all fail closed.

## Production runtime wiring

`kernel/certification_plane_production_runtime.py` closes the remaining direct-enrollment bypass.

### External-authority activation receipt

A valid shared enrollment is necessary but insufficient for the production runtime. The runtime also requires a shared activation receipt created only after the independent enrollment authority gate succeeds.

The receipt binds:

```text
deployment_id
deployment_digest
enrollment_generation
authorization_digest
authority_id
authority_class
authority_generation
key_id
activated_at
```

It is stored under a deterministic reserved path and updated with the shared backend's fencing, CAS and ordered-journal primitives.

### Guard conjunction

Every exposed production certification-plane operation requires:

```text
current deployment identity
        ↓ exact digest match
ACTIVE + unexpired enrollment
        ↓ exact generation/deployment match
external-authority activation receipt
        ↓
underlying certified shared certification plane
```

Therefore direct writes to the enrollment registry cannot unlock production runtime access.

### Crash/retry/rotation behavior

```text
enrollment committed but activation receipt missing → deny
exact authorized retry → idempotently establish/reuse receipt
tampered receipt → deny
direct enrollment rotation → old receipt becomes stale
authorized rotation → enrollment + receipt advance together
lower enrollment generation → reject
lower authority generation → reject
cross-process reader → observes same receipt
restart → preserves receipt
enrollment revocation → deny even when receipt remains present
```

## Final exact certification

```text
Run ID: 34083804714
Implementation/validator commit: 37d0daa2ecca984a7b51b1e2b7166b56913178da
Ran 415 tests in 7.289s
415 / 415 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

Certified incremental surface:

```text
264  frozen v0.5-v0.7 regression surface
151  v0.8 HA/readiness/bootstrap/certification/runtime trust tests
---
415 targeted tests
```

The v0.8 surface now covers HA deployment evidence, active fault probes, bounded certification, bootstrap trust, handoff, shared certification state, adapter attestation, runtime enrollment, independent enrollment authority and final authority-receipt runtime wiring.

## Milestone completion boundary

The **repository implementation is complete**. The remaining work requires real external infrastructure and should not be represented by reference booleans, SQLite test stores, test doubles or checked-in secrets.

## External production prerequisites

```text
real distributed/consensus backend
real topology source
real chaos/fault controller
production bootstrap certification authority
production shared certification-plane deployment
production adapter attestation authority + trust store
production enrollment authority + trust store
production identity/IdP integration
production asymmetric/HSM-backed anchor trust
production credential delivery
production provider integrations / writes
```

Until those are connected and independently certified:

```text
production credentials = DENIED
production write providers = DISABLED
production runtime = NOT ENABLED
SQLite/reference stores = NOT PRODUCTION READY
```

## Next milestone

Freeze v0.8 after the final documentation-synchronized exact-count CI. Begin production infrastructure adapter and deployment-certification work on a new feature branch. Do not weaken the v0.8 contracts to accommodate a provider; adapters must satisfy the contracts instead.
