# Company Operating System — Current State

**Use this file first when resuming engineering.**
Detailed status: `08-COMPANY-OS/RUNTIME-STATUS.md`

## Active milestone

```text
Repository: blakailabs/NCF-v1
Branch: feature/company-kernel-production-infrastructure-v0.9
PR: #5 — OPEN / DRAFT
Milestone: Company Kernel Production Infrastructure v0.9
Provider sequence: Spanner → YugabyteDB → identity/authorities/HSM → deployment automation
Status: ACTIVE
```

## Merged certified baseline

```text
v0.8 PR #4: MERGED
v0.8 merge: eb47c7cfa9ab223f8e60847e651f2387edff0b08
v0.8 final CI: 34083972113
415 / 415 PASS
```

## Current certified checkpoint — Spanner contract

```text
CI run: 34086008840
Certified implementation/validator head: e3ee98bca57d2f4c69bbc5c750fecb68e321d55f
441 / 441 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

Exact surface:

```text
415 frozen v0.8 regressions
 12 neutral production-infrastructure tests
 14 Spanner v0.9.1 contract tests
---
441 targeted tests
```

## What is now implemented

```text
provider-neutral production evidence contract
Spanner deployment identity contract
Spanner GoogleSQL + PostgreSQL schema plans
commit-timestamp-backed ordering schema
single-transaction fenced CAS + journal requirement
external credential-reference-only rule
emulator permanently barred from production certification
live read/write probe channels disabled by default
Spanner evidence template feeding neutral certifier
```

## Critical distinction

The **Spanner adapter contract is certified against the kernel**. A **live Spanner deployment is not yet certified**, because no real GCP project/instance/database, external credential path, topology evidence, or live fault/probe environment is connected.

## Production posture

```text
Production credentials................ DENIED
Spanner live reads.................... DISABLED
Spanner live writes................... DISABLED
Real Spanner deployment............... NOT CONNECTED
Spanner topology evidence............. NOT CONNECTED
Independent Spanner fault control..... NOT CONNECTED
External Spanner verifier/trust store. NOT CONNECTED
YugabyteDB adapter.................... WAITING FOR SPANNER LIVE CERTIFICATION
Production IdP/authorities/HSM........ WAITING
Deployment automation................. WAITING
```

## Next exact engineering step

Connect a real Spanner deployment target and execute the live certification phases defined in `SPANNER-v0.9.1.md`:

```text
project + instance + database identity
schema verification
multi-client consistency
serializability
CAS
fencing
ordered journal
atomic fenced CAS + journal
commit timestamp ordering
durability/restart
topology evidence
fault/quorum evidence
external attestation
neutral v0.9 certification
```

Do **not** begin YugabyteDB certification until Spanner has either passed live certification or been explicitly disqualified with preserved negative evidence.
