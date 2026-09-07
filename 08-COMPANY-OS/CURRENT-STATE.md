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
Final synchronized CI run: 34077965760
Certified synchronized head: 6300d6174b7dc39d95864eb1cd4ee1a6f9582783
364 / 364 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

## Current candidate — NOT YET CERTIFIED

```text
Adapter attestation contract: b979cc9c56134640470a8b9f95a3f0ded91b4cbb
Durable reference trust ledger: 6dba3782fc631090cadb5a90bcc1ad681edfffd4
Adversarial tests: 7a34a291501b869781ca8c1fc8008b2a3eb68ace
376-test validator: 350e608859d3d96f841099ff5248652a68dd6ede
Expected exact count: 376
Status: awaiting exact-count CI certification
```

Candidate adapter readiness requires all of:

```text
shared backend semantic capability contract
exact deployment-instance identity
backend + cluster identity binding
trusted adapter name + implementation release digest
backend capability digest binding
topology evidence digest binding
probe evidence digest binding
fresh independent adapter attestation
verified authority/key/generation binding
production-ready durable attestation trust store
nonce replay protection
authority-generation rollback protection
```

The included SQLite attestation trust ledger is reference-only and explicitly reports NOT production-ready. A test-only production-ready trust-store double proves the contract path; it is not production infrastructure.

Candidate adversarial tests:

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

**Do not call adapter attestation certified until GitHub Actions confirms 376/376 with 0 failures/errors/skips.**

## Already certified v0.8 stack

```text
HA deployment-readiness contract
active multi-client/fault probe harness
digest-bound topology + probe evidence assembly
trusted deployment attestation contract
time-bounded certification lifecycle
bootstrap authority + replay protection
bootstrap-to-steady-state handoff
permanent first-bootstrap closure
closure-aware certified persistence
shared certification-plane state machine
cross-process certification/invalidation/closure visibility
fenced CAS + ordered-journal certification mutations
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
Reference adapter trust ledger........... NOT PRODUCTION READY
```

## Next exact action

```text
1. inspect exact-count CI for the 376-test candidate
2. repair failures without weakening trust boundaries
3. if 376/376 passes, sync RUNTIME-STATUS.md
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
