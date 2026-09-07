# Company Operating System — Current State

**Use this file first when resuming engineering.**
Detailed status: `08-COMPANY-OS/RUNTIME-STATUS.md`

## Active milestone

```text
Repository: blakailabs/NCF-v1
Branch: feature/company-kernel-production-infrastructure-v0.9
Milestone: Company Kernel Production Infrastructure v0.9
Status: ACTIVE
```

## Merged certified baseline

```text
v0.8 PR: #4
v0.8 merge commit: eb47c7cfa9ab223f8e60847e651f2387edff0b08
Final synchronized-head CI: 34083972113
Certified head: ef1f8b24bc20a34762f026bb802dfd35b4d2ef4e
415 / 415 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

## v0.9 purpose

Move from certified reference/runtime contracts to real provider-neutral production infrastructure adapters and deployment evidence **without weakening any v0.8 invariant**.

The provider must satisfy the kernel contract; the kernel contract must not be weakened to fit a provider.

## v0.9 workstreams

```text
1. production shared-state backend adapter boundary
2. real topology/source-of-truth adapter boundary
3. real chaos/fault-controller boundary
4. production bootstrap authority integration contract
5. production certification-plane deployment adapter
6. production adapter-attestation authority/trust-store integration
7. production enrollment-authority/trust-store integration
8. production identity/IdP integration boundary
9. asymmetric/HSM-backed anchor trust integration
10. deployment certification + evidence bundle
```

## Non-negotiable production gate

No infrastructure adapter becomes production-ready because of configuration booleans, test doubles, reference stores, or caller assertions. Production readiness requires observed behavior, independently verifiable evidence, external trust, exact deployment identity binding, and fresh certification.

## Production posture at v0.9 start

```text
Production credentials..................... DENIED
Production write providers................. DISABLED
Real production HA backend................ NOT CONNECTED
Real topology source....................... NOT CONNECTED
Real chaos controller...................... NOT CONNECTED
Production bootstrap authority............. NOT CONNECTED
Production shared certification plane...... NOT DEPLOYED
Production adapter attestation authority... NOT CONNECTED
Production adapter enrollment authority.... NOT CONNECTED
Production durable trust stores............ NOT CONNECTED
Production IdP............................. NOT CONNECTED
Production asymmetric/HSM anchor trust..... NOT CONNECTED
```

## Next exact engineering step

Define the provider-neutral **Production Infrastructure Adapter Contract v0.9** and its certification evidence schema before selecting or connecting a concrete infrastructure provider. Preserve the full 415-test v0.8 suite as the frozen regression baseline.

## Standing sync rule

After every meaningful implementation or CI boundary: update `RUNTIME-STATUS.md`, this file, the active milestone architecture doc, and the active PR. Never call committed work certified without exact-count CI evidence.
