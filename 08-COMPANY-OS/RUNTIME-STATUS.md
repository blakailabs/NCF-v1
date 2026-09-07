# Company Operating System Runtime Status

**Engineering branch:** `feature/company-kernel-production-infrastructure-v0.9`  
**Active PR:** #5 — OPEN / DRAFT  
**Milestone:** Company Kernel Production Infrastructure v0.9  
**Provider sequence:** Spanner → YugabyteDB → production identity/authorities/HSM → deployment automation

## Project identity

**Project:** Company Operating System  
**Repository:** `blakailabs/NCF-v1`

## State-sync discipline

`RUNTIME-STATUS.md` is the canonical detailed resumability checkpoint. `CURRENT-STATE.md` is the concise pickup file. A committed change is never called certified until exact-count CI passes.

## Merged baseline

```text
v0.8 PR #4........................ MERGED
v0.8 merge commit................. eb47c7cfa9ab223f8e60847e651f2387edff0b08
v0.8 final synchronized-head CI.... 34083972113
415 / 415 PASS
```

## Evidence-first doctrine

```text
Reality first.
Structure second.
Automation third.
AI last.
```

## Provider-neutral production infrastructure contract

`kernel/production_infrastructure_v09.py` remains the provider-neutral certification boundary. It requires exact deployment identity, required HA capabilities/evidence phases, external verification, independent trust provenance, fresh evidence, approved external credential-source classes and no provider self-certification.

## Spanner v0.9.1 contract — CERTIFIED

`kernel/spanner_backend_v091.py` is the first concrete provider contract beneath v0.9.

### Bound deployment identity

```text
provider = google-cloud-spanner
project_id
instance_id
database_id
instance_config
database_dialect
adapter_version
schema digest
credential source class
```

### Schema contract

```text
cfhs_shared_objects
cfhs_shared_fences
cfhs_shared_journal
```

GoogleSQL uses commit-timestamp-enabled TIMESTAMP columns. PostgreSQL dialect has a separate schema identity and is never silently substituted for GoogleSQL.

### Required runtime semantics

```text
strong reads
read-write serializable/external-consistency transactions
exact object version CAS
monotonic persistent fence tokens
ordered journal versions
single transaction for fence assertion + object CAS + journal append
commit timestamp as authoritative transaction-order evidence
production service only for durability/topology certification
```

### Credential and emulator controls

```text
embedded credentials........................ DENIED
credential reference must be secret://....... REQUIRED for live integration
workload/managed/external/HSM identity........ ALLOWED CLASSES
Spanner emulator production certification.... PERMANENTLY DENIED
live reads.................................... DISABLED BY DEFAULT
live writes................................... DISABLED BY DEFAULT
```

## Current exact certification

```text
Run ID: 34086008840
Implementation/validator head: e3ee98bca57d2f4c69bbc5c750fecb68e321d55f
Ran 441 tests in 10.607s
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
415 frozen v0.8 tests
 12 neutral production infrastructure tests
 14 Spanner adapter contract tests
---
441 targeted tests
```

## What 441 does and does not mean

**Certified:** kernel ↔ Spanner contract, schema identity, credential rules, emulator exclusion, evidence generation rules, and neutral-certifier compatibility.

**Not certified:** any actual GCP project, Spanner instance/database, workload identity, IAM policy, live transaction behavior, topology, durability under failure, or external attestation.

## Live Spanner certification boundary

A real deployment must supply observed evidence for:

```text
S1 exact project/instance/database identity
S2 installed schema identity
S3 multi-client visibility
S4 serializability/external consistency
S5 stale CAS rejection
S6 monotonic fencing + takeover
S7 ordered journal
S8 atomic fenced CAS + journal
S9 commit timestamp ordering
S10 restart/durability evidence
S11 topology/instance-configuration evidence
S12 independently controlled fault/quorum evidence or explicit BLOCKED state
S13 external release/deployment attestation
S14 neutral v0.9 certification
```

## Production posture

```text
Real Spanner deployment...................... NOT CONNECTED
Spanner credentials.......................... DENIED
Spanner live reads/writes.................... DISABLED
Independent Spanner topology evidence........ NOT CONNECTED
Independent fault controller................. NOT CONNECTED
External verifier/trust store................ NOT CONNECTED
YugabyteDB portability certification......... WAITING ON SPANNER
Production IdP/authorities/HSM................ WAITING
Deployment automation........................ WAITING
```

## Next exact engineering action

Connect the first real Spanner deployment target. Until the project/instance/database and approved external credential path exist, any claim of live Spanner certification would be fabricated. Once connected, run the live evidence phases in order and either certify Spanner or preserve the failing/blocked evidence before moving to YugabyteDB.
