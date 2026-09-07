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
Final synchronized CI run: 34078376797
Certified synchronized head: 128baf67cc5df9cc2917750bdeb2487ec961490b
376 / 376 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

## Current candidate — NOT YET CERTIFIED

```text
Runtime enrollment implementation: f7f427a1d084151b122241c0529c2dce1e712aee
Adversarial tests: 3512dd004716610a117536f228b70c3193542b09
388-test validator: 6979539bb7a21bbebcb4c93a68d1a250fc55d221
Expected exact count: 388
Status: awaiting exact-count CI certification
```

Candidate adds durable adapter enrollment and runtime revalidation. Every exposed guarded certification-plane operation re-resolves current deployment identity and checks shared enrollment status, backend-authoritative expiry, generation, revocation and exact deployment digest.

Candidate adversarial surface:

```text
no enrollment denies runtime access
valid enrollment allows guarded access
readiness/deployment mismatch denied
adapter implementation drift denied
backend capability drift denied
cluster drift denied
topology/probe evidence drift denied
enrollment expiry denied
cross-process revocation immediately visible
monotonic enrollment rotation
older enrollment generation rollback denied
restart preserves enrollment/revocation state
```

**Do not call runtime enrollment certified until GitHub Actions confirms 388/388 with 0 failures/errors/skips.**

## Already certified v0.8 stack

```text
HA deployment readiness + active probes
digest-bound evidence + trusted attestation
time-bounded certification lifecycle
bootstrap authority + handoff + permanent closure
shared certification-plane state machine
fenced CAS + ordered-journal certification mutations
adapter deployment attestation
release/capability/topology/probe digest bindings
authority generation + nonce replay protection
durable reference attestation trust ledger semantics
```

## Production posture

```text
Production credentials................... DENIED
Production write providers............... DISABLED
Real production HA backend............... NOT ENABLED
Real topology source..................... NOT CONNECTED
Real chaos controller.................... NOT CONNECTED
Production bootstrap authority........... NOT CONNECTED
Production shared certification plane.... NOT CONNECTED
Production adapter attestation authority. NOT CONNECTED
Production adapter enrollment authority.. NOT CONNECTED
Reference stores......................... NOT PRODUCTION READY
```

## Next exact action

```text
1. inspect exact-count CI for 388-test candidate
2. repair failures without weakening prior guarantees
3. only if 388/388 passes, promote enrollment to certified
4. sync RUNTIME-STATUS.md + this file + HA-PERSISTENCE-v0.8.md + PR #4
5. verify documentation-synchronized branch-head CI
```
