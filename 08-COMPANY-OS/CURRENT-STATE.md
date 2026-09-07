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
CI run: 34078192031
Certified implementation/validator commit: 350e608859d3d96f841099ff5248652a68dd6ede
376 / 376 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

Adapter attestation contract: `b979cc9c56134640470a8b9f95a3f0ded91b4cbb`  
Durable reference trust ledger: `6dba3782fc631090cadb5a90bcc1ad681edfffd4`  
Adversarial tests: `7a34a291501b869781ca8c1fc8008b2a3eb68ace`

## What is certified in v0.8

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
bootstrap authority + one-time replay protection
bootstrap-to-steady-state handoff
permanent first-bootstrap closure
closure-aware certified persistence
shared certification-plane state machine
cross-process certification/invalidation/closure visibility
fenced CAS + ordered-journal certification mutations
deployment-bound certification-plane adapter attestation
adapter implementation release digest binding
backend capability digest binding
topology + probe evidence digest binding
attestation freshness/expiry
authority/key generation rollback protection
attestation nonce replay protection
durable restart-safe reference trust ledger semantics
production-ready decision requires external verifier + production-grade trust store
```

## Adapter-attestation adversarial surface

```text
missing adapter attestation rejected
stale adapter attestation rejected
wrong backend identity rejected
wrong cluster identity rejected
wrong adapter implementation digest rejected
tampered capability binding rejected
attestation replay across deployments rejected
authority/key rotation requires monotonic generation
older authority generation rejected
restart preserves accepted adapter identity/generation
reference trust store keeps adapter non-production
production-ready decision requires semantics + external verification + production trust store
```

The positive production-readiness path uses a **test-only trust-store double** solely to prove the contract. No shipped reference store or real deployment has been promoted to production-ready.

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
Production shared certification plane.... NOT CONNECTED
Production adapter attestation authority. NOT CONNECTED
SQLite reference adapter trust ledger.... NOT PRODUCTION READY
```

## Next exact engineering step

Build **durable adapter enrollment + runtime revalidation** so a one-time attestation decision cannot become stale paperwork disconnected from the running control plane:

```text
verified adapter readiness decision
→ durable enrollment record bound to deployment + attestation + verifier receipt
→ monotonic enrollment generation
→ runtime control-plane guard checks current deployment identity
→ runtime guard checks enrollment freshness and revocation
→ changed adapter/backend/cluster/capabilities/evidence fails closed
→ rotation/revocation visible across processes
```

Required next test themes:

```text
no enrollment denies runtime access
valid enrollment allows reference runtime path only under test policy
wrong deployment digest denied
changed adapter implementation denied
changed backend capability digest denied
cluster drift denied
topology/probe evidence drift denied
enrollment expiry denied
cross-process revocation visibility
monotonic enrollment rotation
older enrollment generation rollback denied
restart preserves enrollment/revocation state
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
