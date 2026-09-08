# Company Operating System Runtime Status

**Engineering branch:** `feature/company-kernel-production-infrastructure-v0.9`  
**Active PR:** #5 — OPEN / DRAFT / NOT MERGED  
**Milestone:** Company Kernel Production Infrastructure v0.9  
**Provider sequence:** Spanner → YugabyteDB → production identity/authorities/HSM → deployment automation

## State-sync discipline

`RUNTIME-STATUS.md` is the canonical detailed resumability checkpoint. `CURRENT-STATE.md` is the concise pickup file. **Committed is not certified.** A new head becomes authoritative only after exact-count GitHub Actions passes.

## Merged baseline

```text
v0.8 PR #4........................ MERGED
v0.8 merge commit................. eb47c7cfa9ab223f8e60847e651f2387edff0b08
v0.8 final synchronized-head CI... 34083972113
415 / 415 PASS
```

## Evidence-first doctrine

```text
Reality first.
Structure second.
Automation third.
AI last.
```

## v0.9 certified implementation checkpoint

```text
CI run............................. 34273678953
implementation/validator head...... e96d133f9cdb3311642e415aad9ebe5610bc90b0
465 / 465 PASS
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
 12 neutral production-infrastructure tests
 14 Spanner adapter-contract tests
 12 Spanner live-orchestrator tests
 12 pre-GCP runtime/evidence tests
---
465 targeted tests
```

## Spanner v0.9.1 provider contract

The Spanner layer binds exact project/instance/database/config/dialect identity, GoogleSQL/PostgreSQL schema identity, commit timestamps, strong reads, serializable read-write transactions, CAS, monotonic fencing, ordered journals, and a single transaction for fence assertion + object CAS + journal append. Emulator use is permanently excluded from production certification.

## Pre-GCP infrastructure package

Terraform is checked in under `11-KERNEL-RUNTIME/deploy/spanner-cert/` for the fixed certification target:

```text
project: cfhs-kernel-cert
instance: kernel-ha-cert-01
database: cfhs-cert
deployment: company-kernel-cert-spanner-01
instance config: regional-us-central1
environment: cert
production: false
```

The module enables Spanner, creates the certification instance/database and installs `cfhs_shared_objects`, `cfhs_shared_fences`, and `cfhs_shared_journal`. Project creation/billing attachment remains an external administrative prerequisite.

## Keyless runtime boundary

`kernel/spanner_pre_gcp_v091.py` now defines the runtime-reference and evidence-artifact boundary before a GCP account is connected.

Controls:

```text
fixed cert target identity.................... REQUIRED
wrong project/instance/database/config........ FAIL CLOSED
live flag..................................... explicit true/false only
live mode without WIF references.............. DENIED
embedded/secret-like identity material........ DENIED
service-account identity...................... external principal reference only
live channels................................. DISABLED BY DEFAULT
runtime digest................................ binds WIF provider + target identity
certification artifact........................ digest-bound
production-ready artifact..................... all ordered S1-S14 PASS required
```

No credential values are stored in the repository. The adapter receives only a runtime credential reference when live mode is explicitly enabled with complete external identity references.

## Live Spanner certification boundary

Observed real-deployment evidence remains required for:

```text
S1 deployment identity
S2 schema identity
S3 multi-client visibility
S4 serializability/external consistency
S5 stale CAS rejection
S6 monotonic fencing/takeover
S7 ordered journal
S8 atomic fenced CAS + journal
S9 commit timestamp ordering
S10 durability/restart
S11 topology evidence
S12 independent fault/quorum evidence or explicit BLOCKED
S13 external attestation
S14 neutral v0.9 certification
```

PASS requires evidence. FAIL/BLOCKED requires a reason. The first negative phase stops dependent later phases. Negative evidence is preserved in the report/artifact digest.

## Production posture

```text
Production credentials........................ DENIED
Production provider writes.................... DISABLED
Real GCP project............................... NOT CONNECTED
Real Spanner deployment....................... NOT CONNECTED
Spanner live integration...................... DISABLED
WIF trust..................................... NOT CONNECTED
Independent topology/fault evidence........... NOT CONNECTED
External verifier/trust store................. NOT CONNECTED
YugabyteDB portability certification.......... WAITING ON SPANNER
Production IdP/authorities/HSM................ WAITING
```

## Current production blockers

1. `cfhs-kernel-cert` must exist with billing under authorized GCP administration.
2. GitHub→GCP Workload Identity Federation must be established without static service-account keys.
3. Terraform must be applied and deployed schema independently verified.
4. A concrete Google Cloud Spanner SDK/live transaction driver must execute S1-S14 against the real target.
5. S12 requires independent fault/quorum evidence; absence must remain BLOCKED.
6. S13/S14 require external attestation/verifier trust, not provider self-assertion.

## Next exact engineering action

While GCP is unavailable, implement the concrete provider SDK boundary and S1-S14 live probe-driver mappings behind the existing disabled runtime gate. Unit/fake-client tests may validate transaction/retry/error mapping, but those results must never be labeled live Spanner certification.
