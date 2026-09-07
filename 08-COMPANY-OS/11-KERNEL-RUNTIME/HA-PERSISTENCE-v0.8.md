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

`kernel/ha_bootstrap_authority.py` solves first-certification circular trust with a narrowly bound external one-time permit. It may initialize only the deterministic bootstrap object and revalidates target backend capabilities before use.

`kernel/ha_certification_handoff.py` verifies that bootstrap object, initializes exact shared certification-control state, activates the same evidence-bound certificate, rechecks expiry using backend-authoritative time, and permanently closes first-bootstrap authority.

`kernel/ha_handoff_guard.py` denies all future first-bootstrap calls after closure. `HandoffCertifiedSharedPersistence` prevents an ACTIVE-before-CLOSED crash window from unlocking ordinary shared-state access.

## Shared certification plane

`kernel/shared_certification_plane.py` is the provider-neutral reference state machine for globally visible certification authority.

### State model

The shared object records:

```text
contract + backend identity
cluster identity
highest topology epoch
active certification record
handoff lineage
bootstrap_closed
seen evidence nonces and evidence digests
last invalidation
```

Deterministic paths:

```text
state  /_cfhs/ha/certification/plane/<backend-digest>
fence  /_cfhs/ha/certification/plane-fence/<backend-digest>
stream ha-certification-plane:<backend-digest>
```

### Transaction model

Every non-idempotent transition is guarded by a current writer fence and committed through the shared backend's `fenced_compare_and_swap_with_event` primitive:

```text
assert current fence
+ expected shared-object version
+ expected ordered-journal version
→ atomically update plane state
→ atomically append transition event
```

A stale certifier cannot mutate after fence takeover. Competing same-epoch certifications cannot both become authoritative. Independent processes see the same active certification, invalidation and bootstrap closure state.

### Lifecycle semantics

Initial lineage:

```text
PREPARED
→ certification ACTIVATED
→ handoff CLOSED
→ bootstrap_closed = true
```

Steady-state recertification then allows a higher topology epoch to supersede the active certificate without reopening first-bootstrap authority.

The plane rejects:

```text
cluster identity drift
topology rollback
same-epoch conflicting evidence
evidence-nonce reuse for different evidence
stale writer fences
activation without prepared initial handoff
closure without matching active certificate
closure after certificate expiry
steady-state use before bootstrap closure
```

`require_active()` uses backend-authoritative time and fails closed on missing or expired certification.

### Production-readiness boundary

`SharedStateCertificationPlane` is intentionally marked `reference_adapter_only = True`.

Even when its test backend advertises the full shared-state capability contract, `readiness()` remains false because the adapter lacks:

```text
production_certification_plane_adapter_attestation
```

This prevents reference semantics from being confused with a production deployment. A later production adapter must independently prove deployment-instance identity and adapter trust in addition to the already-certified shared-state semantics.

## Current certification

```text
Run ID: 34077833585
Implementation/validator commit: 287d28850469a082d30a80a3649af363e494cda5
Ran 364 tests in 8.163s
364 / 364 PASS
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
---
364 targeted tests
```

Shared-plane adversarial surface:

```text
cross-process active-certificate visibility
concurrent same-epoch activation conflict
same-evidence idempotency
higher-epoch supersession
lower-epoch rollback rejection
cluster identity conflict
cross-process invalidation visibility
backend-authoritative expiry visibility
shared handoff closure visibility
stale certifier fence rejection
control-plane restart recovery
reference adapter cannot claim production readiness
```

## What 364/364 does NOT certify

```text
Real distributed SQL/consensus backend............ NOT ENABLED
Actual provider topology source.................... NOT CONNECTED
Actual chaos/partition controller.................. NOT CONNECTED
Production external bootstrap authority............ NOT CONNECTED
Production permit single-use control plane......... NOT CONNECTED
Production shared certification-plane adapter...... NOT CONNECTED
Production adapter attestation..................... NOT IMPLEMENTED
Production credentials............................. DISABLED
Production writes.................................. DISABLED
```

## Next boundary — adapter attestation

A production certification plane must prove more than correct state-machine semantics. The next contract will bind a concrete deployment instance and adapter implementation to independent trust evidence:

```text
deployment-instance identity
+ adapter implementation digest/version
+ backend + cluster identity
+ shared-state capabilities
+ independent authority/key generation
+ fresh attestation receipt
+ replay/rollback protection
→ production certification-plane adapter readiness
```

No production credentials, backend or provider writes are enabled by this work.
