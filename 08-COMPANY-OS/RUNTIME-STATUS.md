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

## v0.9 certified synchronized checkpoint

```text
CI run............................. 34279527021
certified synchronized head........ 84f45b612848e81e9ff1301ad2626e8aced5771c
521 / 521 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

A prior exact 521 run (`34279165876`, head `1ad6a955...`) failed with four constructor errors in the new preflight object. That failure was retained as negative engineering evidence, fixed, and replaced only after exact green runs. The certified head above includes the implementation and the previous state/status synchronization.

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

The repository contains all architecture that can be responsibly completed without a real Google Cloud control plane or real Spanner database:

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

`kernel/google_spanner_transport_v091.py` lazily imports `google.cloud.spanner` only when a connection is explicitly requested. It accepts project/instance/database identity but no credential JSON, private key, token, or arbitrary credentials object. Runtime authentication remains outside the repository via ADC/WIF.

```text
emulator in certification transport........ DENIED
unconnected transport access................. DENIED
unknown write operation...................... DENIED
strong read observation...................... SUPPORTED
stale-CAS observation........................ SUPPORTED
fence transaction boundary................... SUPPORTED / live validation required
atomic fenced-CAS+journal final evidence...... BLOCKED UNTIL REAL COMMIT RESULT BINDING
```

The last item is deliberate: final provider commit evidence cannot be synthesized before the actual Spanner transaction API and deployed schema are observed.

## GitHub→GCP certification workflow

`.github/workflows/spanner-cert-gcp.yml` is manual-only and supports `preflight`, `plan`, and `apply`.

```text
contents permission........................ read
OIDC permission............................ id-token: write
static service-account JSON................ NOT USED
GitHub environment......................... cert
concurrency lock........................... ENABLED
apply confirmation......................... APPLY-CERT-SPANNER required
Terraform plan before apply................ REQUIRED
```

External references only:

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

Observed real-deployment evidence remains required for S1-S14: deployment identity, schema identity, multi-client visibility, serializability/external consistency, stale CAS rejection, monotonic fencing/takeover, ordered journal, atomic fenced CAS+journal, commit timestamp ordering, durability/restart, topology evidence, independent fault/quorum evidence, external attestation, and neutral v0.9 certification.

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

## Remaining blockers are genuinely external/live

1. Create/confirm `cfhs-kernel-cert` and attach billing.
2. Establish GitHub→GCP Workload Identity Federation without static keys.
3. Run preflight, Terraform plan, then explicitly authorized apply.
4. Verify deployed schema and bind real SDK transaction commit result/timestamp behavior.
5. Execute S1-S14 against the real database.
6. S12 must obtain independent fault/quorum evidence or remain BLOCKED.
7. S13/S14 require external attestation/verifier trust.

## Next exact engineering action

**No further provider behavior should be fabricated locally.** When GCP is available, begin with the manual certification workflow in `preflight` mode. After live Spanner is certified or explicitly disqualified, begin YugabyteDB portability certification against the same neutral kernel requirements.
