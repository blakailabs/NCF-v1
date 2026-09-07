# Company Kernel HA Persistence Safety v0.8

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-ha-persistence-v0.8`  
**Base:** `25382c018e8bf3cfe426940afc8f622b526ba191`  
**Status:** active draft PR #4; no production HA backend, credentials or writes enabled

## Evidence-first rule

```text
Reality first.
Structure second.
Automation third.
AI last.
```

## Certified v0.8 trust chain

```text
backend capability contract
→ independent topology/deployment evidence
→ active behavioral/fault probes
→ trusted deployment attestation
→ time-bounded certification
→ one-time bootstrap authority
→ bootstrap-to-steady-state handoff
→ shared certification-plane state
→ adapter/deployment attestation
→ durable runtime adapter enrollment
→ per-operation deployment revalidation
```

## Runtime adapter enrollment

`kernel/certification_plane_enrollment.py` prevents a successful adapter attestation from becoming stale paperwork disconnected from runtime.

A shared enrollment binds:

```text
deployment_id + deployment_digest
attestation_digest
verifier_receipt_digest
trust_store_id
monotonic enrollment generation
enrolled_at / valid_until
ACTIVE or REVOKED state
```

`EnrolledCertificationPlaneRuntime` re-resolves current deployment identity before every exposed certification-plane operation. The exact current deployment digest must still equal the enrolled digest.

Because deployment identity itself includes backend ID, cluster ID, adapter name/version, adapter implementation digest, backend capability digest, topology evidence digest and probe evidence digest, any of those runtime changes fail closed until a new trusted enrollment generation is established.

### Runtime safety rules

```text
missing enrollment → deny
revoked enrollment → deny
expired enrollment → deny
adapter implementation drift → deny
backend capability drift → deny
cluster drift → deny
topology/probe evidence drift → deny
older enrollment generation → deny
higher enrollment generation → controlled rotation
cross-process revocation → immediate deny
restart → preserve enrollment/revocation state
```

Expiry uses backend-authoritative time. Enrollment mutations use shared fences and the existing shared backend's CAS + ordered-journal primitives.

## Current certification

```text
Run ID: 34078721471
Implementation/validator commit: 6979539bb7a21bbebcb4c93a68d1a250fc55d221
Ran 388 tests in 73.815s
388 / 388 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

Exact incremental surface:

```text
376 prior certified tests
 12 runtime adapter-enrollment adversarial tests
---
388 targeted tests
```

The new 12 tests cover missing enrollment, guarded success, readiness/deployment mismatch, adapter implementation drift, backend capability drift, cluster drift, topology/probe drift, authoritative-time expiry, cross-process revocation, monotonic rotation, generation rollback and restart persistence.

## Production non-claims

```text
Real distributed production backend............... NOT ENABLED
Real topology source............................... NOT CONNECTED
Real chaos controller.............................. NOT CONNECTED
Production bootstrap authority..................... NOT CONNECTED
Production shared certification plane.............. NOT CONNECTED
Production adapter attestation authority........... NOT CONNECTED
Production adapter enrollment authority............ NOT CONNECTED
Reference stores................................... NOT PRODUCTION READY
Production credentials............................. DISABLED
Production writes.................................. DISABLED
```

## Next boundary

Implement the production adapter-enrollment authority/runtime wiring contract. A real implementation must preserve the certified enrollment semantics while adding independently trusted authority and deployment plumbing; reference/local stores must remain unable to self-promote to production readiness.
