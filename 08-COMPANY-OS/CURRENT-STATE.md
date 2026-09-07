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

A later synchronized 340-test branch head also passed CI run `34074386673`.

## Current candidate — NOT YET CERTIFIED

```text
Candidate validator commit: 5fe41db3c519aafe583dd3d858c9d0755a9481c7
Expected exact count: 352
New test module: test_ha_certification_handoff_v08
Status: awaiting exact-count CI certification
```

Candidate implementation adds:

```text
bootstrap-to-steady-state certification handoff
digest-bound reserved shared certification-control object
crash recovery before activation
crash recovery after activation but before closure
permanent first-bootstrap closure guard
closure-aware CertifiedSharedPersistence
handoff cluster continuity
topology rollback protection
concurrent handoff convergence
activation-expiry recheck before closure
```

Candidate adversarial tests:

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

**Do not call the handoff certified until GitHub Actions confirms 352/352 with 0 failures/errors/skips.**

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
```

## PR state

```text
Only open PR: #4
PR #4 state: OPEN / DRAFT
Keep draft until candidate CI and status sync are complete.
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

## Next exact action

```text
1. run/inspect exact-count CI for the 352-test candidate
2. repair any handoff failures without weakening prior guarantees
3. once 352/352 is green, sync RUNTIME-STATUS.md
4. sync this CURRENT-STATE.md to the certified run/commit
5. sync HA-PERSISTENCE-v0.8.md and PR #4
6. verify final branch-head CI after documentation sync
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
