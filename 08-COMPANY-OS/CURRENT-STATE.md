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
CI run: 34083328094
Certified implementation/validator commit: 8fca2e1385f41d7012a956fbe01a0d67f03694ca
403 / 403 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

The 403 checkpoint certifies the independent production adapter-enrollment authority boundary.

## Current candidate — NOT YET CERTIFIED

```text
Production runtime wiring implementation: fdecf6be057f578b189f8e8217e5cc0d20046643
Adversarial tests: ce393a49c1e3bb6023de82be3f720c416b22df13
415-test validator: 37d0daa2ecca984a7b51b1e2b7166b56913178da
Expected exact count: 415
Status: awaiting exact-count CI certification
```

Candidate closes the direct-enrollment bypass by requiring a shared, fenced, journaled external-authority activation receipt in addition to ordinary enrollment. Production runtime rechecks both on every guarded operation.

Candidate test surface:

```text
direct registry enrollment cannot unlock production runtime
authority activation receipt unlocks guarded runtime
exact authority activation retry is idempotent
enrollment-before-receipt crash gap remains denied and recovers safely
tampered activation receipt fails closed
direct enrollment rotation makes old activation stale
authorized rotation updates activation and runtime
enrollment-generation rollback rejected
authority-generation rollback rejected
cross-process activation receipt visibility
restart preserves authority activation receipt
enrollment revocation overrides existing activation receipt
```

**Do not call production runtime wiring certified until GitHub Actions confirms 415/415 with 0 failures/errors/skips.**

## Already certified v0.8 stack

```text
HA deployment readiness + active probes
digest-bound evidence + trusted attestation
time-bounded certification lifecycle
bootstrap authority + handoff + permanent closure
shared certification-plane state machine
adapter deployment attestation
durable runtime adapter enrollment
independent enrollment authority
exact readiness/deployment/attestation/provenance authorization binding
authority generation + authorization nonce replay protection
authority-selected enrollment generation
reference authority cannot self-promote
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
Production runtime....................... NOT ENABLED
Reference stores......................... NOT PRODUCTION READY
```

## Next exact action

```text
1. inspect 415-test CI
2. repair any exposed invariant without weakening the gate
3. if 415/415 passes, promote production runtime wiring to certified
4. sync RUNTIME-STATUS.md + this file + HA-PERSISTENCE-v0.8.md + PR #4
5. verify documentation-synchronized branch-head CI
6. close v0.8 implementation work as COMPLETE / external deployment pending
```
