# Company Operating System — Current State

**Use this file first when resuming engineering.**  
Detailed status: `08-COMPANY-OS/RUNTIME-STATUS.md`

## Active milestone

```text
Repository: blakailabs/NCF-v1
Branch: feature/company-kernel-production-infrastructure-v0.9
PR: #5 — OPEN / DRAFT / NOT MERGED
Milestone: Company Kernel Production Infrastructure v0.9
Provider sequence: Spanner → YugabyteDB → identity/authorities/HSM → deployment automation
Status: ACTIVE — PRE-GCP BOUNDARY
```

## Merged certified baseline

```text
v0.8 PR #4: MERGED
v0.8 merge: eb47c7cfa9ab223f8e60847e651f2387edff0b08
v0.8 final CI: 34083972113
415 / 415 PASS
```

## Current certified checkpoint

```text
CI run: 34273678953
Certified implementation/validator head: e96d133f9cdb3311642e415aad9ebe5610bc90b0
465 / 465 PASS
0 failures / 0 errors / 0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

Exact surface:

```text
415 frozen v0.8 regressions
 12 neutral production-infrastructure tests
 14 Spanner v0.9.1 adapter tests
 12 Spanner S1-S14 orchestrator tests
 12 pre-GCP runtime/evidence tests
---
465 targeted tests
```

## Implemented before GCP exists

```text
provider-neutral production evidence contract
Spanner deployment + schema identity contract
14-stage live-certification orchestrator
Terraform certification environment package
fixed certification naming/target contract
keyless Workload Identity runtime-reference contract
wrong-project/instance/database fail-closed checks
secret-like runtime identity material rejection
live channels require explicit enablement + complete keyless identity refs
digest-bound certification evidence artifact
negative evidence preserved; emulator cannot certify production
```

## Fixed certification target

```text
project: cfhs-kernel-cert
instance: kernel-ha-cert-01
database: cfhs-cert
deployment: company-kernel-cert-spanner-01
instance config: regional-us-central1
```

## Production posture

```text
Production credentials................ DENIED
Production provider writes............ DISABLED
Real GCP project....................... NOT CONNECTED
Real Spanner deployment............... NOT CONNECTED
Spanner live integration............... DISABLED
Workload Identity Federation........... NOT CONNECTED
Independent fault/topology evidence.... NOT CONNECTED
External verifier/trust store.......... NOT CONNECTED
YugabyteDB............................. WAITING ON SPANNER LIVE CERT/DISQUALIFICATION
```

## Next exact engineering step

Continue deployment-agnostic work: implement the concrete Google Cloud Spanner SDK boundary/live transaction driver and map S1-S14 probes to it without enabling credentials or network writes. When the GCP project exists, connect WIF, apply Terraform, verify schema identity, and execute the same probe driver against the real certification database.

Do **not** call Spanner live-certified until observed real-deployment evidence passes all required phases. Do **not** begin YugabyteDB certification until Spanner passes or is explicitly disqualified with preserved negative evidence.
