# Company Operating System — Action Safety v0.5 Continuation

**Date:** 2026-09-06 UTC  
**Status:** Sanitized project continuation

## Direction

Development continued from Trust Hardening v0.4 into the consequential-action boundary without enabling a live business provider.

## Branch

```text
feature/company-kernel-action-safety-v0.5
```

## Work completed

v0.5 introduced:

- stable semantic action intents;
- replay nonce protection;
- atomic resource reservation/commit/release;
- multi-party approval ledger;
- explicit eligible approvers;
- S2 compensation requirements;
- fail-closed action audit preparation;
- execution-start durable markers;
- crash-safe intent index;
- startup reconciliation;
- conservative `UNKNOWN_SIDE_EFFECT` handling;
- simulated consequential adapter;
- exact device/provider/safety-profile binding;
- kernel-derived operation resource requirements;
- operation/kernel-owned approval floors;
- deterministic targeted validation entrypoint.

## Important corrections made during review

The review cycle identified and repaired multiple safety weaknesses before milestone freeze:

1. resource reservations became atomic across multiple pools;
2. replay identity was changed from ephemeral attempt identity to stable semantic identity;
3. approval binding was redesigned to avoid circular digest dependency;
4. eligible approvers became explicit;
5. provider exceptions after execution begins gained unknown-outcome semantics;
6. audit preparation was separated from provider-execution start with a durable execution marker;
7. pending intents were separated from in-flight intents for restart recovery;
8. committed audit evidence became a source for recovering interrupted resource/replay bookkeeping;
9. S3 approval floors moved into kernel/device policy and cannot be lowered by the caller;
10. resource reservation amounts moved into kernel/device policy and cannot be understated by the caller;
11. the exact device, provider, operation, resource, side-effect class, and safety profile became bound to the intent;
12. crash-recovery fixtures were corrected to follow the real `PENDING → EXECUTING` lifecycle.

## CI investigation

The branch was reduced to a single minimal GitHub Actions workflow with one canonical validation command.

GitHub still creates a synthetic run with:

```text
path: BuildFailed
conclusion: startup_failure
jobs: 0
```

The failure occurs before checkout or runner/job creation. The repository therefore records v0.5 as implementation-complete with adversarial tests committed, while clean execution certification remains externally blocked.

## Safety decision

No production write-capable provider is enabled.

The simulated S3 path exists to prove the control flow without creating a real-world side effect.

## Next milestone

**Company Kernel Live-Adapter Safety v0.6**:

- exact financial units;
- provider-side idempotency/reconciliation;
- provider-bound compensation;
- externally anchored action audit;
- verified approval-session evidence;
- unknown-outcome reconciliation workflow;
- first sandbox/test provider only after those controls exist.
