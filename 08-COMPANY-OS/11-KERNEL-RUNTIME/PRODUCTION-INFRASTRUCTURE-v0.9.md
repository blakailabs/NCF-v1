# Company Kernel Production Infrastructure v0.9

**Base:** merged v0.8 commit `eb47c7cfa9ab223f8e60847e651f2387edff0b08`  
**Branch:** `feature/company-kernel-production-infrastructure-v0.9`  
**Active PR:** #5  
**Provider sequence:** Spanner first → YugabyteDB second → production identity/authorities/HSM → deployment automation

## Goal

Connect real infrastructure to the Company Kernel without weakening the certified v0.8 safety contracts.

The kernel remains provider-neutral. Provider-specific adapters live beneath the contract and must satisfy it rather than redefine it.

## Frozen v0.8 baseline

```text
v0.8 synchronized CI: 34083972113
415 / 415 PASS
```

## Neutral v0.9 contract

`kernel/production_infrastructure_v09.py` defines the machine-verifiable evidence boundary for any real provider.

Required HA capability surface:

```text
serializable_transactions
compare_and_swap
monotonic_fencing
ordered_journal
synchronous_durability
authoritative_shared_time
distributed_quorum
split_brain_protection
```

Required certification evidence phases:

```text
static_deployment_identity
live_capability_probes
multi_client_consistency
fault_partition_probes
external_attestation
bootstrap_certification
steady_state_activation
runtime_enrollment_activation
restart_cross_process_recovery
```

No caller/provider assertion such as `production_ready=true` is accepted as evidence.

## Spanner v0.9.1 — first concrete provider contract

Implemented in `kernel/spanner_backend_v091.py` and documented in `SPANNER-v0.9.1.md`.

The adapter binds:

```text
provider = google-cloud-spanner
project / instance / database
instance configuration
database dialect
adapter version
schema digest
backend and cluster identity
external credential-source class
```

The shared-state schema reserves:

```text
cfhs_shared_objects
cfhs_shared_fences
cfhs_shared_journal
```

GoogleSQL uses commit-timestamp-enabled TIMESTAMP columns. PostgreSQL dialect remains a separate implementation identity.

The operation contract requires strong reads plus read-write transactions for CAS, persistent monotonic fencing, ordered journals, and a **single transaction** for fence assertion + object CAS + journal append.

## Spanner security posture

```text
embedded credentials........................ DENIED
secret:// external credential reference...... REQUIRED for live integration
emulator production certification............ PERMANENTLY DENIED
live reads.................................... DISABLED BY DEFAULT
live writes................................... DISABLED BY DEFAULT
```

The emulator may support development/API testing but cannot produce production durability, IAM/TLS, topology, or fault evidence.

## Current exact certification

```text
CI run: 34086008840
Implementation/validator head: e3ee98bca57d2f4c69bbc5c750fecb68e321d55f
441 / 441 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

Exact surface:

```text
415 frozen v0.8 regressions
 12 neutral production-infrastructure tests
 14 Spanner v0.9.1 contract tests
---
441 targeted tests
```

## Live Spanner certification still required

The 441 checkpoint certifies the **kernel ↔ Spanner contract**, not a real deployment.

A live target must provide observed evidence for:

```text
S1 exact project/instance/database identity
S2 installed schema identity
S3 strong multi-client visibility
S4 serializability/external consistency
S5 stale CAS rejection
S6 monotonic fencing and takeover
S7 ordered journal
S8 atomic fenced CAS + journal
S9 commit-timestamp ordering
S10 acknowledged-write durability/restart
S11 topology/instance-configuration evidence
S12 independent fault/quorum evidence or preserved BLOCKED result
S13 external release/deployment attestation
S14 neutral v0.9 production certification
```

## Portability sequence

Do not move to YugabyteDB merely because the Spanner contract compiles. Move after Spanner live certification succeeds, or after Spanner is explicitly disqualified and its negative evidence is preserved. YugabyteDB must then satisfy the same neutral contract without Spanner-specific exceptions.

## Later stack

After two persistence implementations prove portability:

```text
production external identity / MFA
bootstrap + adapter attestation authorities
runtime enrollment authority
asymmetric/HSM/KMS anchor trust
deployment provisioning and evidence automation
```

## Current external blocker

A real Spanner project/instance/database and approved external credential path are not connected. Production credentials and writes remain disabled. No repository-only change may fabricate the missing live evidence.
