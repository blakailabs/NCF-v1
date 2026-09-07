# Company Operating System — Current State

**Use this file first when resuming engineering.**
Detailed status: `08-COMPANY-OS/RUNTIME-STATUS.md`

## Active milestone

```text
Repository: blakailabs/NCF-v1
Branch: feature/company-kernel-ha-persistence-v0.8
Draft PR: #4
Milestone: Company Kernel HA Persistence Safety v0.8
Repository implementation status: COMPLETE
External production deployment status: PENDING
```

## Last certified checkpoint

```text
CI run: 34083804714
Certified implementation/validator commit: 37d0daa2ecca984a7b51b1e2b7166b56913178da
415 / 415 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

## Certified v0.8 trust chain

```text
HA deployment readiness + active probes
digest-bound topology/probe evidence + independent attestation
time-bounded certification lifecycle
one-time bootstrap authority
bootstrap-to-steady-state handoff + permanent bootstrap closure
shared certification-plane state machine
adapter/deployment attestation
runtime adapter enrollment + per-operation deployment revalidation
independent production enrollment authority
exact readiness/deployment/attestation/provenance authorization binding
authority-generation and nonce replay protection
authority-selected enrollment generation
shared external-authority activation receipt
production runtime requires enrollment + matching activation receipt
direct registry enrollment cannot unlock production runtime
activation/enrollment rotation and rollback controls
cross-process/restart-safe activation visibility
enrollment revocation overrides activation
```

## v0.8 repository work complete

All planned in-repository HA persistence and runtime trust boundaries for v0.8 are implemented and exact-count certified. There is no remaining reference-semantics task in this milestone.

This does **not** mean production infrastructure is deployed or certified.

## External deployment/integration blockers

```text
Real production HA backend................ NOT ENABLED
Real topology source....................... NOT CONNECTED
Real chaos controller...................... NOT CONNECTED
Production bootstrap authority............. NOT CONNECTED
Production shared certification plane...... NOT DEPLOYED
Production adapter attestation authority... NOT CONNECTED
Production adapter enrollment authority.... NOT CONNECTED
Production durable trust stores............ NOT CONNECTED
Production identity/IdP plumbing........... NOT CONNECTED
Production asymmetric/HSM anchor trust..... PENDING
Production credentials..................... DENIED
Production write providers................. DISABLED
Reference SQLite/local stores.............. NOT PRODUCTION READY
```

These are deployment/infrastructure prerequisites, not unfinished v0.8 reference-contract semantics.

## PR state

```text
PR #4: OPEN / DRAFT
Do not merge without explicit user intent.
```

## Next action after final synchronized-head CI

Once this documentation-sync head passes the same exact 415-test gate, v0.8 can be treated as a stable implementation checkpoint. The next engineering milestone should begin on a new feature branch and focus on real provider-neutral production infrastructure adapters and deployment certification rather than adding more reference bypass layers to v0.8.

## Standing sync rule

After every meaningful implementation or CI boundary: update `RUNTIME-STATUS.md`, this file, the milestone architecture doc, and the active PR. Never call committed work certified without exact-count CI evidence.
