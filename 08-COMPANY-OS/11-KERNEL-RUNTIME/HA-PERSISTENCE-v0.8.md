# Company Kernel HA Persistence Safety v0.8

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-ha-persistence-v0.8`  
**Base:** merged v0.7 checkpoint `25382c018e8bf3cfe426940afc8f622b526ba191`  
**Status:** active engineering milestone; no real production HA backend or production credentials enabled

## Purpose

v0.8 addresses a critical distinction left explicit in v0.7:

> A backend interface can satisfy a semantic contract in tests without the deployed system being highly available or safe under real distributed failure.

Therefore Company OS does not certify HA from capability flags alone.

Production readiness requires four independently meaningful layers:

```text
1. backend capability contract
2. deployment/topology evidence
3. observed behavioral probes
4. trusted deployment attestation
```

A failure in any layer keeps production shared persistence disabled.

## Evidence-first architecture

This milestone follows `EVIDENCE-AND-STRUCTURE-DOCTRINE.md`:

```text
Reality first.
Structure second.
Automation third.
AI last.
```

The HA design distinguishes universal distributed-systems requirements from Company OS release policy. For example, minimum voter/failure-domain counts are policy choices; read-consistency models are represented explicitly so leader-linearizable systems are not incorrectly forced into quorum-read semantics.

## Backend capability contract

The inherited v0.7 shared persistence contract requires:

```text
serializable transactions
compare-and-swap
monotonic fencing
durable ordered journal
multi-connection visibility
synchronous durability
authoritative time
distributed quorum
```

Those properties are necessary but no longer sufficient for production certification.

## Deployment evidence

`kernel/ha_persistence.py` defines `HADeploymentEvidence`.

Evidence binds:

```text
backend_id
cluster_id
topology_epoch
observation time
member identities
voting membership
member health
failure domains
consensus protocol
write quorum
read consistency mode/read quorum
synchronous commit policy
synchronous acknowledgement count
authoritative time source
lease time source
split-brain protection
behavioral probe set
evidence issuer
evidence nonce
```

## Read consistency

Accepted evidence models:

```text
quorum
leader_linearizable
serializable_transaction
```

For quorum reads, read/write quorum intersection must be demonstrated.

For leader-linearizable or serializable-transaction reads, a valid linearizable read path must be present without pretending that every read requires majority quorum.

## Behavioral probes

Required fresh probe evidence:

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

The first v0.8 implementation validates the structure and freshness of those probes. The next increment will actively generate them through a conformance harness.

## Trusted attestation

Deployment evidence must be independently attested and bound to the exact evidence digest.

Accepted reference verification classes:

```text
provider_control_plane
cluster_consensus_attestation
independent_observer
```

Attestation must be fresh and complete. Missing, failed, stale, digest-mismatched or unsupported attestation fails production certification.

## Certification lifecycle

`kernel/ha_certification_runtime.py` prevents HA readiness from becoming a timeless boolean.

`SQLiteHACertificationLedger` models lifecycle rules:

```text
ACTIVE
→ SUPERSEDED by higher topology epoch
or
→ INVALIDATED
or
→ unusable after valid_until
```

The SQLite ledger is a **reference implementation of lifecycle semantics only**. Equivalent production certification state must ultimately live behind a certified shared control-plane backend.

### Rollback protection

```text
cluster ID change................ REJECT
lower topology epoch............. REJECT
same epoch + different evidence.. REJECT
same nonce + different evidence.. REJECT
higher epoch..................... SUPERSEDE
same nonce + same evidence........ IDEMPOTENT
```

### Evidence-bounded lifetime

`valid_until` is derived from the oldest supporting:

```text
deployment observation
behavioral probe observation
trusted attestation verification
```

plus the configured maximum evidence age.

A certificate cannot outlive the evidence that justified it.

## Authoritative time

The guarded runtime uses:

```text
backend.authoritative_now()
```

for certification validity checks.

Client wall-clock time cannot become lease/certification authority in production HA mode.

## Guarded shared persistence

`CertifiedSharedPersistence` places an HA certificate check in front of every shared-state operation.

```text
operation request
→ obtain backend-authoritative time
→ require ACTIVE, unexpired HA certificate
→ only then call shared backend
```

Covered operations include reads, writes, CAS, fencing, journals and atomic fenced mutations.

If certification is invalidated or expires, subsequent access stops immediately.

## SQLite remains a negative-control reference

The existing SQLite shared backend deliberately fails the production capability contract because it lacks:

```text
authoritative distributed time
distributed quorum
```

Perfect-looking deployment evidence cannot override those missing capabilities.

This prevents evidence/configuration from falsely upgrading a non-HA backend.

## Current certification

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

Exact-count surface:

```text
264  frozen v0.5-v0.7 regression tests
 21  HA production-readiness tests
 15  certification lifecycle/runtime guard tests
---
300 targeted tests
```

## What 300/300 does NOT certify

```text
A real Postgres/Cockroach/Spanner/etc. cluster..... NOT TESTED
Actual network-partition behavior.................. NOT TESTED
Actual quorum-loss behavior........................ NOT TESTED
Actual provider control-plane attestation.......... NOT CONNECTED
Production certification shared control plane...... NOT IMPLEMENTED
Production credentials............................. DISABLED
Production writes.................................. DISABLED
```

The 300-test checkpoint certifies the **contract, decision rules and reference lifecycle behavior**, not a real production cluster.

## Next increment

Implement a provider-neutral **active conformance/probe harness** that produces `HAProbeEvidence` from observed behavior.

Non-destructive probes should actively exercise transaction isolation, CAS, fencing, journal ordering, multi-client visibility and backend time.

Partition/quorum probes must require a separate explicit chaos/fault controller. If a backend cannot provide controlled fault evidence, those probes remain missing and production certification remains denied.
