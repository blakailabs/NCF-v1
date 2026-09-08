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
CI run............................. 34279270746
implementation/validator head...... 00ef54e94b3a0e322401e9a7617a956a72a0a3d8
521 / 521 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

A prior exact 521 run (`34279165876`, head `1ad6a955...`) failed with four constructor errors in the new preflight object. That failure was retained as negative engineering evidence, fixed, and replaced only after the exact green run above.

## Exact certified surface

```text
415 frozen v0.8 regressions
 12 neutral production-infrastructure tests
 14 Spanner backend-contract tests
 12 Spanner live-orchestrator tests
 12 pre-GCP runtime/evidence tests
 12 Spanner SDK-boundary tests
 16 transaction-semantics tests
 12 injectable client-adapter tests
 10 Google Spanner transport-boundary tests
  6 certification-preflight tests
---
521 targeted tests
```

## Pre-GCP engineering — complete

The repository now contains all architecture that can be responsibly completed without a real Google Cloud control plane or real Spanner database:

```text
provider-neutral production evidence contract........ COMPLETE
Spanner identity/schema contract..................... COMPLETE
S1-S14 certification orchestrator.................... COMPLETE
Terraform cert environment........................... COMPLETE
fixed target/runtime identity controls............... COMPLETE
keyless WIF runtime-reference controls............... COMPLETE
certification evidence artifact...................... COMPLETE
SDK protocol + probe mapping......................... COMPLETE
transaction semantics................................ COMPLETE
injectable kernel client adapter..................... COMPLETE
lazy Google Spanner transport boundary............... COMPLETE
certification preflight.............................. COMPLETE
manual WIF Terraform workflow........................ COMPLETE
```

## Google Spanner transport boundary

`kernel/google_spanner_transport_v091.py` lazily imports `google.cloud.spanner` only when a connection is explicitly requested. It accepts project/instance/database identity but no credential JSON, private key, token, or arbitrary credentials object. Runtime authentication is therefore outside the repository via ADC/WIF.

Controls:

```text
emulator in certification transport........ DENIED
unconnected transport access................. DENIED
unknown write operation...................... DENIED
strong read observation...................... SUPPORTED
stale-CAS observation........................ SUPPORTED
fence transaction boundary................... SUPPORTED / live validation required
atomic fenced-CAS+journal final evidence...... BLOCKED UNTIL REAL COMMIT RESULT BINDING
```

The last item is deliberate. The code refuses to synthesize a provider commit result before the actual Spanner transaction API and deployed schema can be observed. This is now a real-cloud boundary, not an unfinished local architecture task.

## GitHub→GCP certification workflow

`.github/workflows/spanner-cert-gcp.yml` is manual-only and supports:

```text
preflight
plan
apply
```

Security posture:

```text
contents permission........................ read
OIDC permission............................ id-token: write
static service-account JSON................ NOT USED
GitHub environment......................... cert
concurrency lock........................... ENABLED
apply confirmation......................... APPLY-CERT-SPANNER required
Terraform plan before apply................ REQUIRED
```

Expected environment/repository variables are external references only:

```text
GCP_WORKLOAD_IDENTITY_PROVIDER
CFHS_GCP_EXTERNAL_PRINCIPAL_REFERENCE
GCP_TERRAFORM_SERVICE_ACCOUNT
```

## Fixed certification target

```text
project: cfhs-kernel-cert
instance: kernel-ha-cert-01
database: cfhs-cert
deployment: company-kernel-cert-spanner-01
instance config: regional-us-central1
environment: cert
production: false
```

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

PASS requires evidence. FAIL/BLOCKED requires a reason. Negative evidence cannot be promoted or rewritten as success.

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

## Remaining blockers are now genuinely external/live

1. Create/confirm `cfhs-kernel-cert` and attach billing.
2. Establish GitHub→GCP Workload Identity Federation without static keys.
3. Run preflight, then Terraform plan, then explicitly authorized apply.
4. Verify deployed schema and bind the real SDK transaction commit result/timestamp behavior.
5. Execute S1-S14 against the real database.
6. S12 must obtain independent fault/quorum evidence or remain BLOCKED.
7. S13/S14 require external attestation/verifier trust.

## Next exact engineering action

**No further provider behavior should be fabricated locally.** When GCP is available, begin with the manual certification workflow in `preflight` mode. After live Spanner is certified or explicitly disqualified, begin YugabyteDB portability certification using the same neutral kernel requirements.
