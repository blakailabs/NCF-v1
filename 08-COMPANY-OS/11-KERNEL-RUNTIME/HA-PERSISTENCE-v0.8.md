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
```

## Evidence-first rule

```text
Reality first.
Structure second.
Automation third.
AI last.
```

Universal distributed-systems properties are kept distinct from Company OS release policy. For example, minimum voting-member/failure-domain counts are release policy; read models are represented explicitly as quorum, leader-linearizable or serializable-transaction semantics.

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

Ordinary probes exercise client operations directly. Fault probes require a separate `HAChaosController` so the storage client cannot self-assert that a partition or quorum loss occurred.

No chaos controller means the relevant probes are BLOCKED, no positive probe evidence is emitted, and production certification remains incomplete.

Per-probe exceptions are preserved as negative evidence instead of aborting the complete run.

## Digest-bound topology + probe evidence

`kernel/ha_evidence_pipeline.py` introduces `HATopologySnapshot` and `HAEvidenceAssembler`.

A topology snapshot includes the operational HA fields plus source provenance:

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

The assembler requires:

```text
topology backend_id == probe report backend_id
valid topology source receipt digest
known/unique probe identities
bounded topology/probe observation skew
blocked/failed/missing probe propagation
```

The final `HADeploymentEvidence.evidence_nonce` is derived from:

```text
SHA256(
  topology_digest
  + topology_source_receipt_digest
  + probe_report_digest
)
```

Callers cannot choose a nonce that disconnects certification from the observed source material.

A blocked probe is omitted from positive `HAProbeEvidence` and recorded as an assembly blocker. A failed probe remains explicit negative evidence and causes the certifier to deny production readiness.

## Current certification

```text
Run ID: 34056548949
Commit: c1b92423093ac1266b14e25e7624a702fdc4c7ff
Ran 325 tests in 21.091s
325 / 325 PASS
0 failures
0 errors
0 skipped
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
---
325 targeted tests
```

## What 325/325 does NOT certify

```text
A real distributed SQL/consensus backend.......... NOT ENABLED
Actual provider topology source.................... NOT CONNECTED
Actual chaos/partition controller.................. NOT CONNECTED
Production shared certification control plane...... NOT IMPLEMENTED
Production credentials............................. DISABLED
Production writes.................................. DISABLED
```

Reference tests prove the contracts and rejection behavior; they do not upgrade SQLite or any simulated target to production HA.

## Next boundary — bootstrap trust without circularity

Production certification state ultimately must live in a shared control plane, but the first certification cannot require an already-active certification merely to initialize itself.

The next design therefore uses a **narrow external bootstrap permit**, not a general bypass.

The permit must be:

```text
short lived
one time
independently verified
bound to exact backend_id
bound to exact cluster_id
bound to exact topology_epoch
bound to exact evidence_digest
bound to exact certification_digest
bound to a single bootstrap purpose
replay protected
```

It may authorize only initialization of the reserved HA-certification control state. It must never authorize arbitrary application/kernel writes.
