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
Status: ACTIVE — PRE-GCP SDK BOUNDARY
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
CI run: 34274158578
Certified implementation/validator head: 091d62be9444c8b82eb3f9e73d17a1727107ffa6
477 / 477 PASS
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
 12 Spanner SDK boundary/probe-driver tests
---
477 targeted tests
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
provider SDK isolated behind kernel-owned protocol
S1-S14 mapped to concrete provider SDK operations
network, mutation, fault and external-authority permissions independently gated
provider observations cannot self-declare PASS/FAIL/BLOCKED
provider evidence secret material rejected
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

Implement the provider-specific transaction semantics layer behind the SDK boundary: typed strong reads, read-write transaction outcomes, retryable-abort classification, commit timestamp extraction, CAS/fence/journal observation records, and atomic fenced-CAS+journal result validation. Keep it client-injected and network-disabled in repository tests.

When the GCP project exists, connect WIF, apply Terraform, bind the real Google Cloud Spanner client to this boundary, verify schema identity, and execute S1-S14.

Do **not** call Spanner live-certified until observed real-deployment evidence passes all required phases. Do **not** begin YugabyteDB certification until Spanner passes or is explicitly disqualified with preserved negative evidence.
