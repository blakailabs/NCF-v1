# Draft PR — Company Kernel Live-Adapter Safety v0.6

> GitHub PR creation is currently blocked by the connected GitHub account requirement: **At least one email address must be verified**. This file preserves the intended PR package until that account-level blocker is resolved.

## Intended PR

**Head:** `feature/company-kernel-live-adapter-safety-v0.6`  
**Base:** `feature/company-kernel-action-safety-v0.5`  
**State:** Draft / release-blocked

## Title

`Company Kernel Live-Adapter Safety v0.6`

## Summary

This change advances the Company Operating System from frozen Action Safety v0.5 to Live-Adapter Safety v0.6 while remaining strictly sandbox-only.

It does not enable any production payment, email, CRM, banking, advertising, deployment, accounting or legal-signature provider.

## Canonical hardened runtime

```text
kernel.server_v06_hardened
→ TrustKernelV06ReleaseGate
```

The release gate adds:

- exact integer/minor-unit economic accounting;
- persistent provider-side idempotency and lookup;
- explicit provider outcome reconciliation;
- fail-closed post-provider failure handling;
- authenticated approval-session provenance;
- optional verified external identity evidence binding;
- immutable authorization evidence;
- fail-closed authorization anchoring before provider PREPARE;
- fail-closed provider-action transition anchoring;
- semantic kernel replay independent of provider idempotency;
- replay nonce pre-reservation before provider-intent persistence;
- restart attachment when intent persistence succeeds before replay attachment;
- sandbox-only provider registry;
- separately governed S3 compensation with its own semantic intent, two approvals, session provenance and anchored authority.

## Provider action lifecycle

```text
semantic provider intent
→ replay nonce RESERVED
→ durable intent
→ replay attached / PENDING
→ independent approvals
→ authenticated session provenance
→ immutable authorization evidence
→ authorization anchor
→ exact resource reservation
→ provider PREPARE anchor
→ idempotent provider execute
→ provider receipt
→ anchored result
→ exact resource/replay commit
```

Unknown outcome:

```text
provider execute began
→ transport/local state uncertain
→ RECONCILIATION_REQUIRED
→ execute retry blocked
→ provider lookup
→ committed / not-executed / compensated resolution
```

## Governed S3 compensation

```text
committed original action
→ authorized compensation requester
→ separate compensation intent
→ 2 independent approvers
→ session provenance
→ separate compensation authorization
→ authorization anchor
→ provider idempotent compensation
→ exact resource reversal
→ original replay = COMPENSATED
```

A principal without base compensation authority cannot open this workflow.

## Validation surface

Canonical command:

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v06.py
```

Expected committed surface:

```text
102 targeted safety tests
11 modules
includes frozen v0.5 regression suites
```

The test surface is **not represented as passed** because GitHub Actions currently fails before job creation.

Observed pattern:

```text
name: ""
path: BuildFailed
conclusion: startup_failure
jobs: 0
```

Example observed run: `34004159902`.

## Review documents

- `LIVE-ADAPTER-SAFETY-v0.6.md`
- `PREMORTEM-v0.6.md`
- `ACCEPTANCE-v0.6.md`
- `../../RUNTIME-STATUS.md`

## Production blockers

Do not merge as production-ready or accept production provider credentials until the production gates in `PREMORTEM-v0.6.md` and `ACCEPTANCE-v0.6.md` are satisfied.

Major blockers include:

- clean validator execution from the exact release commit;
- operation-specific business identity beyond caller nonce;
- real provider test-mode idempotency/lookup semantics;
- compensation unknown-outcome reconciliation;
- production OIDC/MFA policy enforcement;
- asymmetric/HSM-backed policy trust;
- highly available independent audit anchoring;
- distributed/fenced replay/resource/reconciliation state;
- exact-unit financial authority constraints;
- production workload identity/secret delivery;
- provider webhook/event reconciliation;
- provider-side hard ceilings and canary controls.

## Intended review decision

Review architecture and safety invariants only.

Keep the PR draft/release-blocked until the canonical validator executes cleanly from the exact branch commit and the CI/account blockers are resolved or an equivalent reproducible clean-environment result is available.
