# Company Operating System Runtime Status

**Engineering branch:** `feature/company-kernel-production-infrastructure-v0.9`  
**Milestone:** Company Kernel Production Infrastructure v0.9

## Project identity

**Project:** Company Operating System  
**Repository:** `blakailabs/NCF-v1`

NCF remains the constitutional governance layer inside the broader Company Operating System.

## State-sync discipline

`RUNTIME-STATUS.md` is the canonical detailed resumability checkpoint. `CURRENT-STATE.md` is the concise pickup file. A committed change is never called certified until exact-count CI passes.

## Merged certified baseline

```text
v0.8 PR #4........................ MERGED
v0.8 merge commit................. eb47c7cfa9ab223f8e60847e651f2387edff0b08
final synchronized-head CI........ 34083972113
certified v0.8 head................ ef1f8b24bc20a34762f026bb802dfd35b4d2ef4e
415 / 415 PASS
0 failures / 0 errors / 0 skipped
```

## Evidence-first doctrine

```text
Reality first.
Structure second.
Automation third.
AI last.
```

## v0.8 frozen invariants carried into v0.9

```text
fail-closed shared-state capability contract
independent topology + active fault evidence
time-bounded certification
one-time bootstrap authority
bootstrap-to-steady-state handoff
permanent bootstrap closure
shared certification-plane state
adapter/deployment attestation
runtime enrollment + revalidation
independent enrollment authority
shared external-authority activation receipt
production runtime requires enrollment + activation receipt
no reference/test-double self-promotion
```

These are regression requirements. v0.9 adapters must satisfy them rather than bypass or weaken them.

## v0.9 mission

Create the production infrastructure boundary that can connect real systems to the certified kernel contracts while preserving provider neutrality and evidence-based readiness.

## v0.9 planned adapter surfaces

```text
ProductionSharedStateBackendAdapter
ProductionTopologySourceAdapter
ProductionChaosControllerAdapter
ProductionBootstrapAuthorityAdapter
ProductionCertificationPlaneAdapter
ProductionAdapterAttestationAuthorityAdapter
ProductionEnrollmentAuthorityAdapter
ProductionIdentityProviderAdapter
ProductionAnchorTrustAdapter
ProductionDeploymentEvidenceBundle
```

## Certification doctrine for real adapters

A real adapter is not production-ready merely because it is configured or reachable. Certification must prove:

```text
exact deployment identity
provider/release identity
capability evidence
observed behavioral probes
fault/partition behavior where applicable
authoritative time behavior
quorum/topology behavior
durable trust-store provenance
external authority verification
credential source class without committing secrets
freshness/expiry
rollback/replay protection
restart + cross-process persistence
```

## Production posture at milestone start

```text
Real production HA backend................ NOT CONNECTED
Real topology control-plane adapter........ NOT CONNECTED
Real chaos/partition environment........... NOT CONNECTED
Production bootstrap authority............. NOT CONNECTED
Production shared certification plane...... NOT DEPLOYED
Production adapter attestation authority... NOT CONNECTED
Production adapter enrollment authority.... NOT CONNECTED
Production durable trust stores............ NOT CONNECTED
Live production IdP........................ NOT CONNECTED
Production asymmetric/HSM anchor trust..... NOT CONNECTED
Production credentials..................... DENIED
Production write providers................. DISABLED
```

## Current certification state

The active v0.9 branch inherits the merged v0.8 code. Until a v0.9 validator is introduced, the **415-test v0.8 suite remains the exact frozen regression gate**.

## Next exact engineering step

Implement `PRODUCTION-INFRASTRUCTURE-v0.9.md` plus the provider-neutral adapter/evidence contract and adversarial contract tests. Do not select a concrete provider by assumption; provider-specific adapters must be separate implementations beneath the neutral contract.
