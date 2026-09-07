# Company Kernel Production Infrastructure v0.9

**Base:** merged v0.8 commit `eb47c7cfa9ab223f8e60847e651f2387edff0b08`  
**Branch:** `feature/company-kernel-production-infrastructure-v0.9`  
**Status:** active architecture milestone

## Goal

Connect real infrastructure to the Company Kernel without weakening the certified v0.8 safety contracts.

The kernel remains provider-neutral. A provider integration is an adapter beneath the contract, not a source of truth for the contract itself.

## Frozen v0.8 baseline

The v0.8 synchronized head `ef1f8b24bc20a34762f026bb802dfd35b4d2ef4e` passed exact-count CI run `34083972113` at **415/415** with zero failures, errors or skips.

That entire surface is a required regression baseline for v0.9.

## Adapter contract families

### 1. Shared-state backend
Must demonstrate serializable transactions, CAS/version checks, monotonic fencing, ordered journals, synchronous durability, authoritative shared time, distributed quorum/topology evidence, and split-brain protection.

### 2. Topology source
Must independently report cluster identity, voting members, failure domains, health, quorum/read model, write acknowledgement model, topology epoch and observation timestamps. Evidence must be digest-bound to the deployment being certified.

### 3. Chaos/fault controller
Must be an independent control boundary capable of inducing quorum loss, node/leader loss, network partitions and recovery. A missing or ineffective controller produces BLOCKED/FAIL evidence, never PASS.

### 4. Bootstrap authority
Must issue narrow, short-lived, one-purpose permits bound to backend, cluster, topology epoch, evidence, attestation and certification decision. It must not expose a generic persistence bypass.

### 5. Certification-plane deployment
Must implement the shared certification-plane state machine on a real shared backend while preserving fencing, ordered-journal atomicity, topology rollback protection, evidence nonce replay protection and permanent bootstrap closure.

### 6. Adapter attestation authority
Must verify exact adapter implementation/release identity and bind backend capabilities, topology evidence and probe evidence. Production trust must be external to the deployment under certification.

### 7. Enrollment authority
Must independently authorize enrollment generation and bind readiness, deployment, release attestation and provenance. Reference/local trust stores cannot self-promote.

### 8. Identity provider
Must provide production external identity/MFA assurance compatible with the existing v0.7 production identity policy. Raw authentication tokens must not be persisted in kernel state.

### 9. Anchor trust
Must replace reference HMAC trust with independently managed asymmetric or HSM/KMS-backed signing/verification appropriate for the deployment threat model.

## Production Infrastructure Evidence Bundle

Every concrete adapter candidate must produce a machine-verifiable bundle containing at minimum:

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
credential_source_class (metadata only; never secret material)
observed_at
valid_until
evidence_nonce
```

The bundle must be canonicalized and digest-bound. Caller-supplied booleans such as `production_ready=true` are not evidence.

## Certification phases

```text
P0 contract validation
P1 static deployment identity + release provenance
P2 live capability probes
P3 multi-client consistency probes
P4 fault/partition probes
P5 external attestation
P6 bootstrap certification
P7 steady-state activation
P8 runtime enrollment + external authority activation
P9 restart/cross-process recovery
P10 bounded production certification
```

Failure, blocked evidence, expiry, identity drift, rollback or conflicting same-generation state fails closed.

## Secret-handling rule

No production keys, tokens, credentials or private key material may be committed to the repository. Configuration may contain secret references/identifiers only. Runtime integrations must obtain credentials through an external credential-delivery mechanism.

## Provider-neutral implementation rule

A concrete provider must live behind the neutral interface. Provider-specific behavior may strengthen guarantees but must never weaken the minimum contract.

Examples of acceptable implementation targets may include distributed SQL/consensus stores, cloud KMS/HSM systems, enterprise identity providers and external topology/fault-control systems, but no provider is selected by this specification.

## v0.9 completion criteria

The repository portion of v0.9 is complete only when:

```text
provider-neutral adapter interfaces exist
machine-verifiable evidence schemas exist
certification coordinator exists
negative/adversarial contract fixtures exist
frozen 415-test v0.8 regression surface still passes
new v0.9 tests are exact-count gated
reference adapters remain non-production
no secrets are committed
real provider adapters, when present, cannot self-certify
status docs and PR are synchronized to the last exact CI checkpoint
```

Actual production readiness additionally requires a real deployment to satisfy the contract. A repository-only implementation cannot truthfully certify infrastructure that has not been connected and observed.
