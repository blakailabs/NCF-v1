# Company Kernel HA Persistence Safety v0.8

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-ha-persistence-v0.8`  
**Base:** merged v0.7 checkpoint `25382c018e8bf3cfe426940afc8f622b526ba191`  
**Status:** active draft PR #4; no real production HA backend or production credentials enabled

## Purpose

v0.8 distinguishes a semantic backend contract from a deployed HA system. Company OS does not certify HA from capability flags or configuration claims alone.

Production readiness requires:

```text
backend capability contract
+ independently sourced topology/deployment evidence
+ actively observed behavioral probes
+ trusted external attestation
+ time-bounded certification lifecycle
+ narrow first-certification bootstrap authority
+ bootstrap-to-steady-state certification handoff
```

## Evidence-first rule

```text
Reality first.
Structure second.
Automation third.
AI last.
```

Universal distributed-systems properties are kept distinct from Company OS release policy. Minimum voting-member/failure-domain counts are release policy; read models are explicitly represented as quorum, leader-linearizable or serializable-transaction semantics.

## HA production-readiness contract

`kernel/ha_persistence.py` models backend/cluster identity, monotonic topology epoch, voting membership, health/failure domains, consensus protocol, write quorum, read consistency, synchronous commit/acks, authoritative time, lease time, split-brain protection, behavioral probes and independent attestation.

## Certification lifecycle

`kernel/ha_certification_runtime.py` prevents HA readiness from becoming a timeless boolean.

```text
ACTIVE
→ SUPERSEDED by higher topology epoch
→ INVALIDATED explicitly
→ unusable after valid_until
```

Rules include cluster-identity continuity, topology rollback protection, evidence-nonce replay protection, same-epoch conflict protection and backend-authoritative expiry checks.

`CertifiedSharedPersistence` refuses shared-state access without a current active certification.

The SQLite certification ledger is reference lifecycle machinery only; it is not claimed as the production HA control plane.

## Active conformance probes

`ResilientHAConformanceProbeHarness` generates evidence from observed multi-client behavior.

Required probe identities:

```text
serializable_transaction
compare_and_swap
monotonic_fencing
ordered_journal
multi_connection_visibility
synchronous_durability
authoritative_time
quorum_loss_fail_closed
stale_owner_rejected_after_takeover
network_partition_single_writer
```

Fault probes require a separate `HAChaosController`. Missing chaos control produces BLOCKED evidence rather than a false pass.

## Digest-bound topology + probe evidence

`kernel/ha_evidence_pipeline.py` combines an independently sourced `HATopologySnapshot` with the active probe report. The final evidence nonce is derived from topology, topology-source receipt and probe-report digests; callers cannot choose a nonce that disconnects certification from observed source material.

## First-certification bootstrap authority

`kernel/ha_bootstrap_authority.py` solves first-certification circular trust using a narrow external permit rather than a generic uncertified-backend bypass.

Permit binding includes:

```text
purpose = initialize_ha_certification_state_v08
backend_id
cluster_id
topology_epoch
evidence_digest
certification_decision_digest
attestation_digest
authority_id / authority_class
issued_at / expires_at
permit_nonce
```

The coordinator exposes no caller-selected object key and may initialize only:

```text
/_cfhs/ha/certification/bootstrap/<backend-digest>
```

Before use, it revalidates the target backend's production capability contract. The one-time permit ledger reserves before write and supports idempotent crash recovery after write/before consume.

## Bootstrap-to-steady-state handoff

`kernel/ha_certification_handoff.py` turns the narrow externally authorized bootstrap state into steady-state certification authority without creating an access window between activation and bootstrap closure.

### Exact bootstrap verification

The handoff reconstructs `HABootstrapBinding` from the production-ready certification and deployment evidence, derives the canonical bootstrap object key, reads the object, verifies its exact stored digest, and verifies the following fields against the binding/result:

```text
contract/status
backend_id
cluster_id
topology_epoch
evidence_digest
certification_decision_digest
attestation_digest
binding_digest
permit_digest
authority_receipt_digest
```

Tampered or mismatched bootstrap state fails closed before activation.

### Shared certification-control object

The only handoff control destination is deterministic:

```text
/_cfhs/ha/certification/control/<backend-digest>
```

Its value binds:

```text
backend + cluster + topology
evidence nonce + evidence digest
certification decision digest
attestation digest
bootstrap object + bootstrap state digest
permit digest + authority receipt digest
handoff digest
```

The object is written with put-if-absent and then read back exactly. Conflicting preexisting state fails closed.

### Handoff lifecycle

The reference lifecycle is:

```text
PREPARED
→ control object bound
→ certificate ACTIVE
→ ACTIVATED
→ active certificate expiry rechecked with backend-authoritative time
→ CLOSED
```

Retries with the exact same handoff are idempotent. Cluster identity changes, topology rollback, changed bootstrap state, changed control state or changed certification identity are rejected.

A crash can occur after the control write or after certificate activation and retry safely converges to the same state.

### No activation-before-closure access window

An ACTIVE certificate alone is not sufficient during this transition.

`HandoffCertifiedSharedPersistence` requires:

```text
handoff status == CLOSED
AND
normal active certification check passes using backend-authoritative time
```

Therefore a crash after activation but before closure cannot unlock ordinary shared-state access.

### Permanent first-bootstrap closure

`kernel/ha_handoff_guard.py` wraps the bootstrap entry point. Once the handoff lineage is CLOSED, further first-bootstrap calls—including replay of the original permit—fail with `CFHS_HA_BOOTSTRAP_CLOSED`.

The SQLite handoff ledger remains a reference lifecycle implementation only. Production closure authority must be durable and globally visible in the production shared certification plane or an equivalently strong independent control plane.

## Certified adversarial surfaces

Bootstrap authority attacks:

```text
one-time initialization
consumed-permit replay
expired permit
wrong purpose/backend/cluster/topology/evidence
verifier authority/binding mismatch
same permit ID + altered content
crash after backend write / before consume
conflicting preexisting bootstrap state
non-production-ready certification
same backend ID + weaker capability contract
```

Steady-state handoff attacks:

```text
successful handoff
idempotent repeated handoff
crash before shared activation
crash after shared activation before bootstrap closure
bootstrap object tampering
certificate/evidence mismatch
cluster mismatch
topology rollback
second first-bootstrap attempt after closure
concurrent handoff attempts
activation expiry during handoff
steady-state access denied until handoff fully complete
```

## Current certification

```text
Run ID: 34077423653
Branch-head commit: 79d9bfc9dd61ccb05f98a61a421dc996d6c13ef8
Ran 352 tests in 8.030s
352 / 352 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

The handoff validator/code checkpoint was committed at `5fe41db3c519aafe583dd3d858c9d0755a9481c7`; the later synchronized head passed the same exact validator.

Exact surface:

```text
264  frozen v0.5-v0.7 regressions
 21  HA production-readiness tests
 15  HA certification lifecycle/runtime guard tests
 14  active conformance probe-harness tests
 11  digest-bound evidence-pipeline tests
 15  bootstrap-authority adversarial tests
 12  bootstrap-to-steady-state handoff tests
---
352 targeted tests
```

## What 352/352 does NOT certify

```text
A real distributed SQL/consensus backend.......... NOT ENABLED
Actual provider topology source.................... NOT CONNECTED
Actual chaos/partition controller.................. NOT CONNECTED
Production external bootstrap authority............ NOT CONNECTED
Production permit single-use control plane......... NOT CONNECTED
Production shared certification control plane...... NOT IMPLEMENTED
Production credentials............................. DISABLED
Production writes.................................. DISABLED
```

Reference tests prove contracts, recovery semantics and rejection behavior; they do not upgrade SQLite or simulated control-plane components to production infrastructure.

## Next boundary — shared certification plane

The next v0.8 boundary is to replace process-local/reference lifecycle authority with a provider-neutral shared certification-plane contract.

Required shape:

```text
shared certification-plane interface
→ transactional certification ACTIVE/SUPERSEDED/INVALIDATED state
→ durable PREPARED/ACTIVATED/CLOSED handoff lineage
→ CAS/fencing for competing certifiers
→ backend-authoritative expiry
→ globally visible bootstrap closure
→ fail-closed adapter certification before any production use
```

No production backend, credentials or write providers are enabled by this work.
