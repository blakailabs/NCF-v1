# Company Kernel Live-Adapter Safety v0.6 — Acceptance Report

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-live-adapter-safety-v0.6`  
**Base:** `feature/company-kernel-action-safety-v0.5`  
**Date:** 2026-09-06 UTC

## Acceptance state

```text
IMPLEMENTATION......................... ACCEPTED FOR SANDBOX MILESTONE
ADVERSARIAL TEST COVERAGE.............. 102 / 102 CI-CERTIFIED
SOURCE-LEVEL PRE-FREEZE REVIEW......... COMPLETED
CLEAN EXECUTION CERTIFICATION.......... PASS
PRODUCTION PROVIDER RELEASE............ DENIED
PRODUCTION CREDENTIAL ACCEPTANCE....... DENIED
```

v0.6 is a certified sandbox architecture milestone, not a production release.

## Scope delivered

```text
exact integer economic units
provider-side idempotency
provider lookup/reconciliation
post-provider failure hardening
session-proven multi-party approvals
optional verified external identity evidence
immutable authorization evidence
fail-closed authorization anchoring
fail-closed provider-action anchoring
kernel semantic replay state
replay nonce pre-reservation before intent persistence
restart attachment/recovery for replay/intents
sandbox provider runtime
separately governed S3 compensation
```

## Canonical release gate

```text
kernel.server_v06_hardened
→ TrustKernelV06ReleaseGate
```

The gate composes:

```text
v0.5 trust/action safety
→ exact-unit provider safety
→ semantic replay pre-reservation
→ durable provider intent
→ session-proven approvals
→ anchored authorization evidence
→ exact resource reservation
→ anchored provider PREPARE/result
→ provider idempotency
→ reconciliation on uncertainty
→ separately approved/anchored S3 compensation
```

## Certified validation surface

Canonical command:

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v06.py
```

Validator success requires:

```text
compile_ok == true
result.wasSuccessful() == true
tests_run == 102
```

Certified GitHub Actions run:

```text
Run ID: 34006498158
Commit: 3b8cc7a4d7fc3bb62beccd875ef0fbeffbd87fcd
Workflow: Company OS Kernel CI
Job: test
Step: Validate Live-Adapter Safety v0.6
Conclusion: SUCCESS
```

The validator covers 102 targeted safety tests across 11 modules, including all frozen v0.5 regression suites.

Coverage includes:

- exact financial/count units and hard limits;
- provider idempotency and restart persistence;
- provider timeout/result lookup/reconciliation;
- post-provider local failure recovery;
- authenticated approval provenance;
- optional external identity evidence;
- fail-closed authorization/provider audit anchoring;
- semantic replay conflicts and restart repair;
- device/provider/profile substitution resistance;
- end-to-end sandbox provider execution;
- separately governed S3 compensation.

## Security defects corrected during v0.6

1. generic floating economic accounting;
2. non-finite numeric values escaping normal parsing;
3. missing persistent provider idempotency;
4. missing provider truth lookup after transport timeout;
5. post-provider exceptions being too easy to misclassify as retryable;
6. provider success followed by local audit/resource failure;
7. counted approvals without authenticated-session provenance;
8. replaceable approval provenance;
9. unanchored provider PREPARE/status transitions;
10. unanchored release authority;
11. missing independent kernel semantic replay;
12. S3 compensation initially weaker than forward execution;
13. compensation requesters lacking base execution authority;
14. invalid SQLite partial-unique expression, corrected to a partial index;
15. replay nonce initially attached after intent persistence, corrected to pre-reservation plus restart attachment.

## Production blockers remaining

Clean v0.6 CI is no longer a blocker. The remaining blockers are production/distributed architecture requirements:

- operation-specific business-object identity and deduplication beyond caller nonce;
- one real provider's test-mode idempotency/lookup contract;
- compensation unknown-outcome lookup/reconciliation;
- production external IdP/MFA enforcement policy;
- asymmetric/HSM-backed policy trust;
- highly available remote immutable audit anchoring;
- distributed/fenced replay, resource, approval, provider-state and reconciliation ownership;
- exact-unit financial authority thresholds;
- workload-identity/mTLS/HSM-backed secret delivery;
- provider webhook/event-state reconciliation;
- external provider hard ceilings and canary limits;
- migration/failover/incident runbooks.

See `PREMORTEM-v0.6.md` for the detailed production threat analysis.

## Final milestone decision

```text
v0.6 sandbox architecture.............. ACCEPT
v0.6 source/security review............ ACCEPT
v0.6 test execution certification...... PASS — 102 / 102
Merge as sandbox milestone............. APPROVED
Merge as production-ready.............. DO NOT
Enable real production writes.......... DO NOT
Accept production provider secrets..... DO NOT
```

The next engineering milestone is **Company Kernel Distributed / Production Safety v0.7**, beginning with fenced/shared state and operation-specific business-object identity.
