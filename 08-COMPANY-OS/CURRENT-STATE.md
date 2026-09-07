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
CI run: 34077423653
Certified branch-head commit: 79d9bfc9dd61ccb05f98a61a421dc996d6c13ef8
352 / 352 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

The handoff validator/code checkpoint was `5fe41db3c519aafe583dd3d858c9d0755a9481c7`. Documentation-sync commits may follow; always verify the latest branch-head CI before merge.

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
crash-safe handoff before/after activation
permanent first-bootstrap closure guard
closure-aware CertifiedSharedPersistence
concurrent handoff convergence
activation-expiry recheck before closure
```

## Certified handoff adversarial tests

```text
successful handoff
idempotent repeated handoff
crash before shared activation
crash after shared activation before bootstrap closure
bootstrap object tampering
certificate/evidence mismatch
cluster mismatch
topology rollback
second first-bootstrap attempt after closure
concurrent handoff attempts
activation expiry during handoff
steady-state access denied until handoff fully complete
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
```

## Next exact engineering step

Build the **shared certification-plane contract**:

```text
provider-neutral shared certification-plane interface
→ transactional ACTIVE/SUPERSEDED/INVALIDATED certification records
→ durable PREPARED/ACTIVATED/CLOSED handoff lineage
→ atomic CAS/fencing semantics for concurrent certifiers
→ backend-authoritative expiry
→ bootstrap closure visible across processes
→ fail-closed adapter certification before production use
```

Required next test themes:

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

## Standing sync rule

After every meaningful implementation or CI boundary:

```text
1. update RUNTIME-STATUS.md
2. update CURRENT-STATE.md
3. update milestone architecture doc when semantics changed
4. update the active PR description/checkpoint
5. never call committed work certified without exact-count CI evidence
```
