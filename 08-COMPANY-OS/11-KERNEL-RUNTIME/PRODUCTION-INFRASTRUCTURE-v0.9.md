# Company Kernel Production Infrastructure v0.9

**Base:** merged v0.8 commit `eb47c7cfa9ab223f8e60847e651f2387edff0b08`  
**Branch:** `feature/company-kernel-production-infrastructure-v0.9`  
**Status:** provider-neutral contract certified; concrete provider integration pending target selection

## Goal

Connect real infrastructure to the Company Kernel without weakening the certified v0.8 safety contracts.

The kernel remains provider-neutral. A provider integration is an adapter beneath the contract, not a source of truth for the contract itself.

## Frozen v0.8 baseline

The v0.8 synchronized head `ef1f8b24bc20a34762f026bb802dfd35b4d2ef4e` passed exact-count CI run `34083972113` at **415/415** with zero failures, errors or skips.

That entire surface remains a required regression baseline for v0.9.

## First certified v0.9 checkpoint

```text
CI run: 34084379611
Validator/head: b8683d5a8c4a407cd7437d7736db50771dc9bf1c
427 / 427 PASS
0 failures
0 errors
0 skipped
compile_ok = true
exact_test_count = true
successful = true
```

Exact incremental surface:

```text
415 frozen v0.8 tests
 12 provider-neutral production-infrastructure tests
---
427 targeted tests
```

## Implemented contract

`kernel/production_infrastructure_v09.py` defines a provider-neutral machine-verifiable production evidence bundle plus external-verifier certification gate.

A concrete adapter candidate must bind:

```text
deployment_id
provider_id
adapter_name
adapter_version
adapter_implementation_digest
backend_id
cluster_id
capability_digest
topology_evidence_digest
probe_evidence_digest
release_attestation_digest
trust_store_id
authority_id + authority_class + authority_generation
credential_source_class
observed_at
valid_until
evidence_nonce
required capability claims
required evidence phases
```

## Required HA capability surface

```text
serializable_transactions
compare_and_swap
monotonic_fencing
ordered_journal
synchronous_durability
authoritative_shared_time
distributed_quorum
split_brain_protection
```

## Required certification evidence phases

```text
static_deployment_identity
live_capability_probes
multi_client_consistency
fault_partition_probes
external_attestation
bootstrap_certification
steady_state_activation
runtime_enrollment_activation
restart_cross_process_recovery
```

## Certified fail-closed rules

```text
missing external verifier → deny
provider self-certification → deny
non-independent verifier → deny
verifier digest mismatch → deny
missing HA capability → deny
missing required evidence phase → deny
stale/expired evidence → deny
invalid credential source class → deny
secret-like material in evidence metadata → deny
invalid authority generation → deny
```

Positive readiness requires an independent verifier receipt and production trust-store provenance.

## Adapter contract families still to connect to real infrastructure

### 1. Shared-state backend
Must demonstrate serializable transactions, CAS/version checks, monotonic fencing, ordered journals, synchronous durability, authoritative shared time, distributed quorum/topology evidence, and split-brain protection.

### 2. Topology source
Must independently report cluster identity, voting members, failure domains, health, quorum/read model, write acknowledgement model, topology epoch and observation timestamps.

### 3. Chaos/fault controller
Must independently induce quorum loss, node/leader loss, network partitions and recovery. Missing or ineffective fault control is BLOCKED/FAIL, never PASS.

### 4. Bootstrap authority
Must issue narrow, short-lived, one-purpose permits bound to backend, cluster, topology epoch, evidence, attestation and certification decision.

### 5. Certification-plane deployment
Must implement the certified shared state machine on real shared persistence while preserving fencing, journal atomicity, rollback protection, replay protection and permanent bootstrap closure.

### 6. Adapter attestation authority
Must verify exact adapter implementation/release identity and bind capability, topology and probe evidence using trust external to the deployment under certification.

### 7. Enrollment authority
Must independently authorize enrollment generation and bind readiness, deployment, release attestation and provenance.

### 8. Identity provider
Must provide production external identity/MFA assurance compatible with the existing production identity policy without persisting raw authentication tokens.

### 9. Anchor trust
Must replace reference HMAC trust with independently managed asymmetric or HSM/KMS-backed trust appropriate to the deployment threat model.

## Secret-handling rule

No production keys, tokens, credentials or private key material may be committed. Only secret references/identifiers may appear in repository configuration or evidence metadata.

## Provider-neutral implementation rule

A concrete provider must live behind the neutral interface. Provider-specific behavior may strengthen guarantees but must never weaken the minimum contract.

## Current completion boundary

The provider-neutral repository work that can be completed without inventing a deployment target is now implemented and certified.

The next step is inherently deployment-specific: choose the first real shared-state backend target and implement its adapter. Until a target is selected, a concrete adapter cannot be truthfully implemented or production-certified.

## Production posture

```text
production credentials = DENIED
production write providers = DISABLED
real production infrastructure = NOT CONNECTED
reference/test infrastructure = NOT PRODUCTION READY
```
