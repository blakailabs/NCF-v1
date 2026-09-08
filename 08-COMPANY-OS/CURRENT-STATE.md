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
Status: PRE-GCP ENGINEERING COMPLETE — WAITING ON REAL GCP
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
CI run: 34279270746
Certified implementation/validator head: 00ef54e94b3a0e322401e9a7617a956a72a0a3d8
521 / 521 PASS
0 failures / 0 errors / 0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

A prior 521 run (`34279165876`, head `1ad6a955...`) correctly failed with four preflight-constructor errors. The defect was fixed at `00ef54e...`; only the later green run is certified.

## Implemented before GCP exists

```text
provider-neutral production evidence contract
Spanner deployment + schema identity contract
14-stage S1-S14 live-certification orchestrator
Terraform certification environment package
fixed certification naming/target contract
keyless Workload Identity runtime-reference contract
digest-bound certification evidence artifact
provider SDK protocol and probe-driver mapping
transaction semantics: strong reads / ABORTED / timestamps / CAS / fencing / journals
injectable Spanner client transaction adapter
lazy google-cloud-spanner transport boundary
ADC/WIF-only authentication boundary; no credential arguments
emulator denied for live certification
real atomic commit-result evidence intentionally not synthesized
certification preflight bound to repo/ref/environment/WIF readiness
manual GitHub certification workflow: preflight → plan → explicit apply
apply requires `APPLY-CERT-SPANNER` confirmation
```

## Fixed certification target

```text
project: cfhs-kernel-cert
instance: kernel-ha-cert-01
database: cfhs-cert
deployment: company-kernel-cert-spanner-01
instance config: regional-us-central1
environment: cert
```

## What is genuinely blocked on GCP now

```text
Create/confirm GCP project + billing........... EXTERNAL
Configure GitHub→GCP Workload Identity........ EXTERNAL
Terraform plan/apply against real project...... EXTERNAL
Bind/verify real Spanner commit result API..... LIVE ONLY
Execute observed S1-S14 probes................. LIVE ONLY
S12 independent fault/quorum evidence.......... LIVE/EXTERNAL
S13 external release attestation............... EXTERNAL
S14 neutral production certification........... AFTER S1-S13
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

## Next exact action when GCP is ready

1. Create/confirm `cfhs-kernel-cert` and attach billing.
2. Configure WIF variables/identity for `blakailabs/NCF-v1` with no static service-account key.
3. Run the manual Spanner workflow in **preflight** mode.
4. Run **plan** and inspect the Terraform plan.
5. Only after explicit authorization, run **apply** with `APPLY-CERT-SPANNER`.
6. Verify deployed schema and complete the real commit-result binding.
7. Execute S1-S14 and preserve PASS/FAIL/BLOCKED evidence exactly.

Do **not** call Spanner live-certified until observed real-deployment evidence passes all required phases. Do **not** begin YugabyteDB certification until Spanner passes or is explicitly disqualified with preserved negative evidence.
