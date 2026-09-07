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

## Last certified implementation

```text
CI run: 34074237722
Implementation commit: e0a4acca56a954d64a9f1229d4f1173ff34435c8
340 / 340 PASS
0 failures
0 errors
0 skipped
```

Documentation/state-sync commits may follow the certified implementation commit without changing runtime behavior; always verify the latest branch-head CI before merge.

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
```

## Bootstrap adversarial tests

```text
valid one-time initialization
consumed permit replay
expiry
wrong purpose
wrong backend
wrong cluster
wrong topology epoch
wrong evidence digest
authority-verifier identity mismatch
authority-verifier binding mismatch
altered-content permit replay
crash after backend write before consume
conflicting preexisting bootstrap state
non-production-ready certification
same backend_id with weaker backend capabilities
```

## PR state

```text
Only open PR: #4
PR #4 state: OPEN / DRAFT
Review comments: none
Inline change requests: none
Requested reviewers awaiting action: none
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

Build **bootstrap-to-steady-state certification handoff**:

```text
verify reserved bootstrap object
→ verify exact evidence/certification/authority binding
→ create durable shared certification-control record
→ activate same certificate
→ permanently close first-bootstrap authority for that backend/cluster lineage
→ require CertifiedSharedPersistence for subsequent operations
```

Required tests:

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

## Standing sync rule

After every meaningful implementation or CI boundary:

```text
1. update RUNTIME-STATUS.md
2. update CURRENT-STATE.md
3. update milestone architecture doc when semantics changed
4. update the active PR description/checkpoint
5. never call committed work certified without exact-count CI evidence
```
