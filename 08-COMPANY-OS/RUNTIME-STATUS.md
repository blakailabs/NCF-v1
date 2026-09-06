# Company Operating System Runtime Status

**Updated:** 2026-09-06 19:57 UTC  
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

### Deployment/certification rules

The current v0.8 model requires backend and cluster identity, monotonic topology epoch, policy-acceptable voting/failure-domain layout, healthy quorum, explicit consensus/read semantics, synchronous commit/acks, authoritative backend time, split-brain protection, fresh probe evidence and trusted attestation.

Certification is time-bounded by its oldest supporting evidence, may be invalidated, cannot roll topology backward, and is checked using backend-authoritative time.

`CertifiedSharedPersistence` denies shared-state operations without an active unexpired HA certificate.

### Active conformance probe harness

v0.8 now generates behavioral evidence from observed operations rather than accepting probe booleans from configuration.

The canonical reference runner is:

```text
ResilientHAConformanceProbeHarness
```

Actively observed probes cover:

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

Quorum-loss and network-partition probes require a **separate `HAChaosController`**. If that controller is absent, those probes are `BLOCKED`; no positive `HAProbeEvidence` is emitted and production certification remains incomplete.

Per-probe exceptions become explicit negative evidence instead of aborting the whole run. Failure of authoritative backend time remains fatal because trustworthy evidence timestamps cannot then be established.

### Negative controls

The harness tests deliberately verify detection of:

```text
serializable stale-snapshot double commit
stale CAS acceptance
stale fence acceptance
stale journal append acceptance
cross-connection invisibility
acknowledged data missing after failover
regressing authoritative time
ineffective quorum-loss fault
minority partition writer / split brain
individual probe exceptions
```

## Current certification

```text
Run ID: 34056407002
Commit: 4a0d17b4cae2e72b95ba6b404c12bf49a980fe2a
Ran 314 tests in 6.399s
314 / 314 PASS
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
 15  HA certification lifecycle/runtime guard tests
 14  active probe-harness tests
---
314 targeted tests
```

## Explicit non-claims

```text
Real production HA backend.............. NOT ENABLED
Real chaos/partition environment......... NOT ENABLED
SQLite reference backend................ NOT PRODUCTION READY
Production credentials.................. DENIED
Production write providers.............. DISABLED
Live production IdP..................... NOT ENABLED
Production asymmetric/HSM anchor trust.. PENDING
```

The passing reference chaos tests validate the **probe contract and detection logic**, not a real distributed database deployment.

## Next v0.8 increment

Bind active probe reports to an independently sourced topology snapshot so `HADeploymentEvidence` is assembled from observed, digest-bound sources rather than manually supplied topology/probe fields. Then feed that assembled evidence through the existing trusted-attestation and certification lifecycle gates.
