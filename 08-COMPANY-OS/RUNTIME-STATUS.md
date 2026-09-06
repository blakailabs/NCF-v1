# Company Operating System Runtime Status

**Updated:** 2026-09-06 20:05 UTC  
**Engineering branch:** `feature/company-kernel-ha-persistence-v0.8`  
**Draft PR:** #4 — Company Kernel HA Persistence Safety v0.8

## Project identity

**Project:** Company Operating System  
**Repository:** `blakailabs/NCF-v1`  
**Intended repository slug:** `blakailabs/Company-Operating-System`

NCF remains the constitutional governance layer inside the broader Company Operating System.

## Merged baseline

v0.7 was merged through PR #3 at:

```text
25382c018e8bf3cfe426940afc8f622b526ba191
```

The merged v0.7 baseline remains certified at **264 / 264** targeted tests.

## Evidence-first doctrine

```text
Reality first.
Structure second.
Automation third.
AI last.
```

Company OS distinguishes formal standards, authoritative implementation evidence, empirical research, proven production patterns and design heuristics. An analogy cannot become a kernel invariant merely because it is intuitive.

## v0.8 — HA Persistence Safety

Production HA readiness requires four separate layers:

```text
backend capability contract
+ deployment/topology evidence
+ observed behavioral probes
+ independent trusted attestation
```

### Certification lifecycle

HA certification is time-bounded by the oldest supporting evidence, checked with backend-authoritative time, may be invalidated, cannot roll topology backward, cannot silently change cluster identity, and gates all shared-state operations.

### Active behavioral evidence

`ResilientHAConformanceProbeHarness` generates observed evidence for:

```text
controlled serializable conflict
multi-client compare-and-swap
monotonic fencing
ordered journal / stale append rejection
cross-client visibility
durability after reconnect/failover
authoritative time
stale-owner rejection after takeover
quorum-loss fail-closed behavior
network-partition single-writer behavior
```

Quorum-loss and partition claims require an independent `HAChaosController`. Without it those probes are BLOCKED and production certification remains incomplete.

### Digest-bound evidence assembly

`HAEvidenceAssembler` now combines two distinct observed sources:

```text
independent topology snapshot
+
active probe report
```

The topology source must declare an accepted source class and provide a source receipt digest. Topology and probe backend identities must match and their observations must fall inside a bounded time window.

The final evidence nonce is derived—not caller chosen—from:

```text
topology snapshot digest
+ topology-source receipt digest
+ probe-report digest
```

Blocked, failed or missing probes propagate into the assembled evidence and cannot become positive evidence by omission.

Accepted topology source classes currently are:

```text
provider_control_plane
cluster_consensus
independent_observer
```

The assembled evidence is compatible with the existing independent-attestation and certification-lifecycle gates.

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

Exact-count surface:

```text
264  frozen v0.5-v0.7 regressions
 21  HA deployment-readiness tests
 15  HA certification lifecycle/runtime tests
 14  active HA probe-harness tests
 11  digest-bound HA evidence-pipeline tests
---
325 targeted tests
```

## Explicit non-claims

```text
Real production HA backend.............. NOT ENABLED
Real topology control-plane adapter...... NOT ENABLED
Real chaos/partition environment......... NOT ENABLED
SQLite reference backend................ NOT PRODUCTION READY
Production certification control plane.. REFERENCE ONLY
Production credentials.................. DENIED
Production write providers.............. DISABLED
Live production IdP..................... NOT ENABLED
Production asymmetric/HSM anchor trust.. PENDING
```

The passing reference tests certify contracts, evidence binding and detection logic—not a real distributed database cluster.

## Next v0.8 increment

Solve the **first-certification bootstrap trust problem** without circular trust. The first production HA certificate must not require an already-certified backend to authorize storing itself, and bootstrap must not become an unrestricted bypass. The planned boundary is a short-lived, one-time external certification-authority permit bound to one backend, cluster, topology epoch, evidence digest and certification digest.
