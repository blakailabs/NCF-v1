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

`kernel/ha_evidence_pipeline.py` combines an independently sourced `HATopologySnapshot` with the active probe report.

Topology source provenance includes:

```text
source_id
source_class
source_receipt_digest
```

Accepted source classes:

```text
provider_control_plane
cluster_consensus
independent_observer
```

The final evidence nonce is derived from topology, topology-source receipt and probe-report digests. Callers cannot choose a nonce that disconnects certification from observed source material.

## First-certification bootstrap authority

`kernel/ha_bootstrap_authority.py` addresses the circular trust problem: the first shared HA certificate cannot require an already-active shared certificate simply to initialize its own control state.

The solution is a narrow external permit—not a generic bypass.

### Permit binding

```text
purpose = initialize_ha_certification_state_v08
backend_id
cluster_id
topology_epoch
evidence_digest
certification_decision_digest
attestation_digest
authority_id
authority_class
issued_at
expires_at
permit_nonce
```

Accepted reference authority classes:

```text
external_certification_authority
independent_release_authority
```

A production verifier is expected to validate the permit outside the uncertified backend using asymmetric/HSM/mTLS-backed trust or an equivalent independently controlled mechanism.

### Narrow raw backend surface

Before first certification, the coordinator receives only:

```text
capabilities()
read()
put_if_absent()
```

It does not expose generic CAS, fencing, journal mutation or caller-selected application writes.

The only allowed destination is internally derived:

```text
/_cfhs/ha/certification/bootstrap/<backend-digest>
```

### Backend substitution defense

The coordinator does not accept `backend_id` equality as sufficient proof. Before the bootstrap exception is used, the target backend must still satisfy the full production shared-state capability contract.

Thus a weaker backend cannot impersonate the certified target simply by reusing the same identifier.

This does not yet replace the need for a stronger production deployment-instance identity/attestation mechanism; it closes the direct capability-downgrade substitution path in the reference boundary.

### One-time and crash-safe permit semantics

The permit-use ledger reserves the exact permit/binding before the raw backend write.

```text
verify external permit
→ reserve one-time permit
→ derive reserved object key/state
→ put-if-absent
→ read-after-write verify exact state
→ consume permit
```

If the process crashes after the backend write but before permit consumption, retry reuses the existing RESERVED permit and exact backend object. It does not issue a second bootstrap write.

A consumed permit replay is idempotent only for the same permit and exact initialized state. Reusing the same permit ID with changed content is rejected as an idempotency conflict.

The SQLite permit ledger is a reference implementation of these semantics only. Production one-time enforcement must live in an independent certification authority/control plane or equivalently strong service.

## Bootstrap adversarial surface

Certified attacks include:

```text
one-time initialization
consumed-permit replay
expired permit
wrong purpose
wrong backend
wrong cluster
wrong topology epoch
wrong evidence digest
verifier authority mismatch
verifier binding mismatch
same permit ID + altered content
crash after backend write / before consume
conflicting preexisting bootstrap state
non-production-ready certification
same backend ID + weaker capability contract
```

Two pre-certification source findings were repaired rather than weakening tests:

1. bootstrap replay/recovery now explicitly distinguishes whether permit state existed before the current attempt;
2. the target backend capability contract is revalidated at bootstrap time.

## Current certification

```text
Run ID: 34074237722
Implementation commit: e0a4acca56a954d64a9f1229d4f1173ff34435c8
Ran 340 tests in 8.031s
340 / 340 PASS
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
 15  HA certification lifecycle/runtime guard tests
 14  active conformance probe-harness tests
 11  digest-bound evidence-pipeline tests
 15  bootstrap-authority adversarial tests
---
340 targeted tests
```

## What 340/340 does NOT certify

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

Reference tests prove contracts, recovery semantics and rejection behavior; they do not upgrade SQLite or a simulated authority to production infrastructure.

## Next boundary — bootstrap to steady state

The next v0.8 boundary is the handoff from narrowly bootstrapped control state into normal certified shared persistence.

Required shape:

```text
externally authorized bootstrap object
→ verify exact bootstrap binding and authority receipt
→ initialize durable shared certification-control record
→ activate same evidence-bound certificate
→ mark bootstrap authority CLOSED/CONSUMED
→ reject any future first-bootstrap attempt
→ require normal CertifiedSharedPersistence for subsequent control/runtime state
```

The handoff must be idempotent, topology-rollback resistant, crash-safe and fail closed if bootstrap state, active certification state or evidence bindings disagree.
