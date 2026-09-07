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
CI run: 34077833585
Certified implementation/validator commit: 287d28850469a082d30a80a3649af363e494cda5
364 / 364 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

Shared certification-plane implementation: `65cf3917bb56cb3cf36708ec85b0abb328290cd2`  
Adversarial tests: `05a8ae1f2d09dbcf314df8391fa73b54d108b535`

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
shared-state access gated by active certification
narrow external first-certification bootstrap permit
one-time permit replay protection
crash-safe bootstrap retry
bootstrap target capability revalidation
bootstrap-to-steady-state certification handoff
digest-bound shared certification-control object
permanent first-bootstrap closure guard
closure-aware CertifiedSharedPersistence
provider-neutral shared certification-plane state machine
cross-process active-certification visibility
fenced certification-plane writers
atomic certification CAS + ordered journal
shared invalidation visibility
shared handoff closure visibility
shared topology supersession/rollback protection
backend-authoritative shared certificate expiry
```

## Shared certification-plane adversarial tests

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
Reference shared certification adapter... NOT PRODUCTION READY
```

## Next exact engineering step

Build the **production certification-plane adapter attestation contract**:

```text
reference shared-plane semantics
→ deployment-instance identity
→ independent adapter attestation
→ exact backend/cluster binding
→ capability + topology + probe evidence binding
→ attestation freshness/expiry
→ adapter-key / authority rotation semantics
→ fail closed if adapter or deployment identity changes
→ still no live production credentials or backend enabled
```

Required next test themes:

```text
missing adapter attestation rejected
stale adapter attestation rejected
wrong backend identity rejected
wrong cluster identity rejected
wrong adapter implementation digest rejected
tampered capability binding rejected
attestation replay across deployments rejected
authority/key rotation with monotonic generation
older authority generation rejected
restart preserves accepted adapter identity
reference adapter remains non-production without external attestation
production-ready decision requires both shared-plane semantics and verified adapter attestation
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
