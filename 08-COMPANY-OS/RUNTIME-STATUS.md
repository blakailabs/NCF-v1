# Company Operating System Runtime Status

**Updated:** 2026-09-06 19:49 UTC  
**Engineering branch:** `feature/company-kernel-ha-persistence-v0.8`  
**Milestone:** Company Kernel HA Persistence Safety v0.8

## Project identity

**Project:** Company Operating System  
**Repository:** `blakailabs/NCF-v1`  
**Intended repository slug:** `blakailabs/Company-Operating-System`

NCF remains the constitutional governance layer inside the broader Company Operating System.

## Merged baseline

v0.7 distributed/production-safety checkpoint was merged through PR #3 at:

```text
25382c018e8bf3cfe426940afc8f622b526ba191
```

The merged v0.7 baseline remains certified at **264 / 264 targeted tests**.

## v0.8 engineering doctrine

Company OS now carries an explicit evidence-first architecture doctrine:

```text
Reality first.
Structure second.
Automation third.
AI last.
```

Major architecture decisions distinguish formal standards, authoritative implementation evidence, empirical research, proven production patterns, and design heuristics/analogies. An analogy is not permitted to become a kernel invariant merely because it is intuitive.

See:

```text
08-COMPANY-OS/11-KERNEL-RUNTIME/EVIDENCE-AND-STRUCTURE-DOCTRINE.md
```

## v0.8 — HA Persistence Safety

Current work deliberately separates four concepts that must not be collapsed into a single `production_ready=true` flag:

```text
backend capability contract
+ deployment/topology evidence
+ observed behavioral probes
+ independent trusted attestation
```

### HA deployment evidence

`kernel/ha_persistence.py` requires evidence for:

```text
backend and cluster identity
monotonic topology epoch
voting-member topology
failure domains
healthy voting quorum
consensus protocol
write quorum
explicit read-consistency model
synchronous commit
synchronous replica acknowledgements
authoritative backend time
backend/consensus lease time
split-brain protection
behavioral probe results
independent attestation
```

Company OS currently applies a default release policy of at least three voting members and three failure domains. Those counts are **Company OS release policy**, not a claim that every consensus database universally requires the same topology.

Read consistency is explicitly modeled rather than forced into one database architecture:

```text
quorum
leader_linearizable
serializable_transaction
```

### Required behavioral probes

A production HA candidate must provide fresh evidence for:

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

The current certification model does not allow self-asserted backend capability flags to substitute for deployment and behavioral evidence.

### Trusted deployment attestation

Production-readiness requires a fresh independently verified attestation bound to the exact deployment evidence digest.

Accepted reference verification classes are:

```text
provider_control_plane
cluster_consensus_attestation
independent_observer
```

Missing, stale, failed, incomplete or digest-mismatched attestation fails closed.

### Certification lifecycle

`kernel/ha_certification_runtime.py` adds time-bounded and rollback-resistant certification semantics.

Rules include:

```text
only fully production-ready evidence may become ACTIVE
certificate lifetime is bounded by the oldest supporting evidence
cluster identity cannot silently change
topology epoch cannot move backward
same epoch cannot bind different evidence
evidence nonce cannot be reused for different evidence
higher topology epoch supersedes the prior certificate
certification can be explicitly invalidated
expired certification loses authority immediately
```

The certification guard checks time through `backend.authoritative_now()` rather than through the caller/client clock.

### Guarded shared persistence

`CertifiedSharedPersistence` refuses shared-state access unless the backend currently holds an active, unexpired HA certification.

This gate applies to:

```text
reads
writes / put-if-absent
compare-and-swap
fence acquisition/assertion/renewal/release
ordered journals
atomic fenced mutation
```

Invalidation or certificate expiry causes subsequent operations to fail closed.

## Explicit non-claims

The v0.8 certification ledger currently uses SQLite **only as a reference implementation of certification lifecycle semantics**. It is not the production HA control plane.

Likewise, the v0.7 SQLite shared-state backend remains explicitly not production-ready because it lacks authoritative distributed time and distributed quorum.

```text
Real production HA backend.............. NOT ENABLED
SQLite reference backend................ NOT PRODUCTION READY
Production credentials.................. DENIED
Production write providers.............. DISABLED
Live production IdP..................... NOT ENABLED
Production asymmetric/HSM anchor trust.. PENDING
```

## v0.8 certification

Canonical command:

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v08.py
```

Current exact-count checkpoint:

```text
264  frozen v0.5-v0.7 regression tests
 21  HA deployment-readiness tests
 15  HA certification lifecycle/runtime guard tests
---
300 targeted tests
```

Latest certified run:

```text
Run ID: 34055983029
Commit: f0dc98080ed28b60c4d0c717c1e8c1b7f2e6cdcd
Ran 300 tests in 6.246s
300 / 300 PASS
0 failures
0 errors
0 skipped
exact_test_count = true
successful = true
```

## Next v0.8 increment

Build the **active HA conformance/probe harness** so certification evidence for transaction isolation, CAS, fencing, journal ordering, multi-client visibility, authoritative time, quorum-loss behavior, stale-owner takeover and network-partition single-writer behavior is generated from observed tests rather than hand-assembled booleans.

Chaos/partition evidence must come through an explicit independent fault-control interface; absence of that interface leaves production certification incomplete rather than being treated as a pass.
