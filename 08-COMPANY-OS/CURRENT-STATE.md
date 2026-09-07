# Company Operating System — Current State

**Use this file first when resuming engineering.**  
Detailed status: `08-COMPANY-OS/RUNTIME-STATUS.md`

## Active milestone

```text
Repository: blakailabs/NCF-v1
Branch: feature/company-kernel-ha-persistence-v0.8
Draft PR: #4
Milestone: Company Kernel HA Persistence Safety v0.8
```

## Last certified checkpoint

```text
CI run: 34077554747
Certified synchronized head: 9e576b747f917d29bc36a5e51f15325648c8f407
352 / 352 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

## Current candidate — NOT YET CERTIFIED

```text
Shared certification-plane implementation: 65cf3917bb56cb3cf36708ec85b0abb328290cd2
Adversarial test commit: 05a8ae1f2d09dbcf314df8391fa73b54d108b535
364-test validator commit: 287d28850469a082d30a80a3649af363e494cda5
Expected exact count: 364
Status: awaiting exact-count CI certification
```

Candidate adds a provider-neutral shared certification-plane reference contract using the existing shared backend's fenced CAS + ordered journal primitives. It keeps the adapter explicitly reference-only and therefore unable to self-certify as production-ready.

Candidate test surface:

```text
cross-process active-certificate visibility
concurrent activation conflict
same-evidence idempotency
higher-epoch supersession
lower-epoch rollback rejection
cluster identity conflict
invalidation visibility
certificate expiry visibility
shared handoff closure visibility
stale certifier fence rejection
control-plane restart recovery
reference/local-only adapter cannot claim production readiness
```

**Do not call the shared certification plane certified until GitHub Actions confirms 364/364 with 0 failures/errors/skips.**

## What is already certified in v0.8

```text
HA deployment-readiness contract
active multi-client/fault probe harness
digest-bound topology + probe evidence assembly
trusted deployment attestation contract
time-bounded certification lifecycle
backend-authoritative expiry checks
topology rollback protection
cluster identity continuity
evidence nonce replay protection
shared-state access gated by active certification
narrow external first-certification bootstrap permit
one-time permit replay protection
crash-safe bootstrap retry
bootstrap target capability revalidation
bootstrap-to-steady-state certification handoff
digest-bound shared certification-control object
crash-safe handoff before/after activation
permanent first-bootstrap closure guard
closure-aware CertifiedSharedPersistence
concurrent handoff convergence
activation-expiry recheck before closure
```

## PR state

```text
Only open PR: #4
PR #4 state: OPEN / DRAFT
Keep draft while v0.8 production-boundary work continues.
```

## Production posture

```text
Production credentials................... DENIED
Production write providers............... DISABLED
Real production HA backend............... NOT ENABLED
Real topology source..................... NOT CONNECTED
Real chaos controller.................... NOT CONNECTED
Production bootstrap authority........... NOT CONNECTED
Production one-time permit ledger........ NOT CONNECTED
Production shared certification plane.... NOT IMPLEMENTED
Reference shared certification adapter... NOT PRODUCTION READY
```

## Next exact action

```text
1. inspect exact-count CI for the 364-test candidate
2. repair failures without weakening prior guarantees
3. if 364/364 passes, sync RUNTIME-STATUS.md
4. sync this CURRENT-STATE.md to the certified run/commit
5. sync HA-PERSISTENCE-v0.8.md and PR #4
6. verify final documentation-synchronized branch-head CI
```

## Standing sync rule

After every meaningful implementation or CI boundary:

```text
1. update RUNTIME-STATUS.md
2. update CURRENT-STATE.md
3. update milestone architecture doc when semantics changed
4. update the active PR description/checkpoint
5. never call committed work certified without exact-count CI evidence
```
