# Company Kernel HA Persistence Safety v0.8

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-ha-persistence-v0.8`  
**Base:** merged v0.7 checkpoint `25382c018e8bf3cfe426940afc8f622b526ba191`  
**Status:** active draft PR #4; no real production HA backend or production credentials enabled

## Purpose

v0.8 distinguishes semantic contracts from deployed HA guarantees. Company OS does not certify HA from capability flags or configuration claims alone.

```text
backend capability contract
+ independently sourced topology/deployment evidence
+ active behavioral/fault probes
+ trusted deployment attestation
+ time-bounded certification lifecycle
+ narrow first-certification bootstrap authority
+ bootstrap-to-steady-state handoff
+ shared certification-plane state
+ independent adapter/deployment attestation
```

## Evidence-first rule

```text
Reality first.
Structure second.
Automation third.
AI last.
```

## Certified HA foundations

`kernel/ha_persistence.py` defines deployment evidence and readiness. `kernel/ha_certification_runtime.py` defines bounded certification lifecycle. The active probe harness generates observed multi-client/fault evidence, and `kernel/ha_evidence_pipeline.py` binds independently sourced topology and probe reports by digest.

Certified controls include backend/cluster identity, topology epoch, quorum, synchronous durability, authoritative time, split-brain protection, evidence replay protection, attestation freshness and fail-closed certification.

## First-certification bootstrap and handoff

`kernel/ha_bootstrap_authority.py` solves first-certification circular trust with a narrowly bound external one-time permit. `kernel/ha_certification_handoff.py` verifies that bootstrap object, initializes exact shared certification-control state, activates the same evidence-bound certificate, rechecks expiry using backend-authoritative time, and permanently closes first-bootstrap authority.

`kernel/ha_handoff_guard.py` denies all future first-bootstrap calls after closure. `HandoffCertifiedSharedPersistence` prevents an ACTIVE-before-CLOSED crash window from unlocking ordinary shared-state access.

## Shared certification plane

`kernel/shared_certification_plane.py` is the provider-neutral reference state machine for globally visible certification authority. Every non-idempotent transition is guarded by a current writer fence and committed through `fenced_compare_and_swap_with_event` using the expected shared-object version and expected ordered-journal version.

The plane provides cross-process visibility for active certification, invalidation, topology epoch and permanent bootstrap closure, while rejecting stale writer fences, cluster identity drift, topology rollback, same-epoch conflicting evidence and evidence-nonce replay.

The reference shared-plane adapter remains non-production by itself.

## Certification-plane adapter attestation

`kernel/certification_plane_attestation.py` adds the independent trust boundary for a concrete shared certification-plane deployment.

### Deployment identity

A deployment is digest-bound to:

```text
deployment_id
backend_id
cluster_id
adapter_name
adapter_version
adapter_implementation_digest
backend_capabilities_digest
topology_evidence_digest
probe_evidence_digest
```

The adapter implementation digest is treated as a release identity, not a self-asserted version label. The backend capabilities digest prevents an adapter from being attested against one semantic capability set and then executed against another.

### Independent attestation

Adapter attestation binds:

```text
attestation_id
deployment_digest
authority_id / authority_class
key_id
authority_generation
attestation_nonce
issued_at / expires_at
```

`CertificationPlaneAdapterAttestationVerifier` is an external verifier boundary. A production verifier should validate asymmetric/HSM-backed release or supply-chain evidence outside the deployment being certified.

The certifier verifies exact attestation/deployment digests, authority/key/generation bindings, verifier receipt presence, issuance/verification windows and expiration.

### Replay and authority rollback

Attestation nonces cannot be reused for changed content. Adapter authority/key rotation requires a monotonic generation advance. Lower generations are rejected, and authority/key changes within the same generation are conflicts.

A deployment lineage cannot silently change backend or cluster identity.

### Durable reference trust ledger

`kernel/certification_plane_attestation_store.py` persists accepted deployment identity, authority generation, key identity, attestation digest, verifier receipt and nonce history across restart.

This SQLite trust ledger exists only to certify durability/replay semantics. It deliberately reports:

```text
production_ready = false
reason = sqlite_reference_trust_store_not_production_authority
```

Therefore the repository still contains no production adapter trust authority.

### Production-readiness conjunction

A certification-plane adapter readiness decision can become positive only when all of these agree:

```text
shared backend semantic capability contract
+ exact concrete deployment identity
+ trusted adapter name/release digest
+ exact backend capability digest
+ topology/probe evidence bindings
+ fresh independent adapter attestation
+ external verifier receipt
+ production-ready durable attestation trust store
```

The tests use a test-only trust-store double with `production_ready=True` solely to prove this conjunction. That double is not production infrastructure and does not change the production posture of the repository.

## Current certification

```text
Run ID: 34078192031
Implementation/validator commit: 350e608859d3d96f841099ff5248652a68dd6ede
Ran 376 tests in 9.559s
376 / 376 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

Exact surface:

```text
264  frozen v0.5-v0.7 regressions
 21  HA production-readiness tests
 15  certification lifecycle/runtime tests
 14  active conformance probe-harness tests
 11  digest-bound evidence-pipeline tests
 15  bootstrap-authority adversarial tests
 12  bootstrap-to-steady-state handoff tests
 12  shared certification-plane tests
 12  adapter-attestation tests
---
376 targeted tests
```

Adapter-attestation adversarial surface:

```text
missing adapter attestation
stale adapter attestation
wrong backend identity
wrong cluster identity
wrong adapter implementation digest
tampered backend-capability binding
attestation replay across deployment identities
monotonic authority/key rotation
older authority-generation rollback
restart recovery of accepted identity/generation
reference trust store remains non-production
positive readiness requires semantics + verifier + production-grade trust store
```

## What 376/376 does NOT certify

```text
Real distributed SQL/consensus backend............ NOT ENABLED
Actual provider topology source.................... NOT CONNECTED
Actual chaos/partition controller.................. NOT CONNECTED
Production external bootstrap authority............ NOT CONNECTED
Production permit single-use control plane......... NOT CONNECTED
Production shared certification-plane adapter...... NOT CONNECTED
Production adapter attestation authority........... NOT CONNECTED
SQLite reference adapter trust ledger.............. NOT PRODUCTION READY
Production credentials............................. DISABLED
Production writes.................................. DISABLED
```

## Next boundary — runtime adapter enrollment

The attestation decision is currently evaluated at certification time. The next boundary must ensure runtime control-plane use cannot drift away from the deployment that was attested.

```text
verified adapter readiness
→ durable enrollment bound to deployment + attestation + verifier receipt
→ monotonic enrollment generation
→ runtime re-derive current deployment identity
→ check enrollment freshness/revocation on every guarded operation
→ fail closed on adapter/backend/cluster/capability/topology/probe drift
→ cross-process rotation and revocation visibility
```

No production credentials, backend or provider writes are enabled by this work.
