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
CI run: 34078721471
Certified implementation/validator commit: 6979539bb7a21bbebcb4c93a68d1a250fc55d221
388 / 388 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

Runtime enrollment implementation: `f7f427a1d084151b122241c0529c2dce1e712aee`  
Adversarial tests: `3512dd004716610a117536f228b70c3193542b09`

## What is certified in v0.8

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
durable adapter enrollment bound to verified readiness
monotonic enrollment generation
backend-authoritative enrollment expiry
runtime deployment revalidation on every guarded operation
cross-process enrollment revocation visibility
adapter/backend/cluster/capability/topology/probe drift fail closed
restart-safe enrollment and revocation state
```

## Runtime-enrollment adversarial surface

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

## Next exact engineering step

Build the production adapter-enrollment authority boundary and runtime wiring without enabling live credentials or production writes.

## Standing sync rule

After every meaningful implementation or CI boundary: update `RUNTIME-STATUS.md`, this file, the milestone architecture doc, and PR #4. Never call committed work certified without exact-count CI evidence.
