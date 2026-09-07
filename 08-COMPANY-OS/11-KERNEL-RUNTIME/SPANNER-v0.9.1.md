# Company Kernel Spanner Adapter v0.9.1

**Parent milestone:** Production Infrastructure v0.9  
**Provider:** Google Cloud Spanner  
**Status:** provider-specific contract implemented; live deployment not connected

## Why Spanner is first

Spanner is the first concrete target because the Company Kernel requires strong transaction ordering, distributed consistency, authoritative shared time and fault-tolerant shared persistence. Spanner's production service provides serializable/external-consistency transaction semantics and TrueTime-backed commit ordering, giving the kernel a strong substrate to test rather than forcing the application layer to invent a distributed clock.

## Non-claim

This adapter contract does not certify a live Spanner deployment. It does not instantiate credentials, connect to a Google Cloud project, create an instance/database, or enable production writes.

```text
production credentials = DENIED
live reads = DISABLED by default
live writes = DISABLED by default
Spanner emulator = NEVER production-certifiable
```

## Contract implementation

`kernel/spanner_backend_v091.py` defines:

```text
SpannerDeploymentConfig
SpannerAdapterReadiness
SpannerSchemaPlan
SpannerProductionAdapterV091
```

The deployment identity binds project, instance, database, instance configuration, database dialect and adapter version.

## Shared-state schema

The adapter reserves three logical tables:

```text
cfhs_shared_objects
cfhs_shared_fences
cfhs_shared_journal
```

The GoogleSQL schema uses commit-timestamp-enabled TIMESTAMP columns for object updates, fence updates and journal commits. PostgreSQL-dialect schema is separately represented so database dialect becomes part of implementation identity rather than being silently translated.

## Required operation mappings

```text
read
  → strong row read

put_if_absent
  → read-write transaction
  → insert iff absent
  → same digest is idempotent
  → different digest conflicts

compare_and_swap
  → read-write transaction
  → exact version check
  → version + 1 on commit

acquire_fence
  → read-write transaction
  → inspect current lease/expiry
  → persistent last_token + 1

assert_fence
  → exact token + owner + lease + unexpired
  → checked inside mutation transaction

release_fence
  → exact current lease required
  → clear active lease without rewinding last_token

append_event
  → read-write transaction
  → exact stream version
  → append version + 1

fenced_compare_and_swap_with_event
  → ONE Spanner read-write transaction
  → fence assertion
  → object CAS
  → ordered journal append
  → atomic commit

authoritative_time
  → Spanner commit timestamp / TrueTime-backed commit ordering
```

## Emulator rule

The Spanner emulator is useful for API/schema development but is intentionally barred from production certification. It is not accepted as evidence for production durability, authentication/IAM, TLS, distributed topology, or production fault semantics.

## Credential rule

Only external credential-source classes are allowed:

```text
workload_identity
managed_identity
external_secret_manager
hsm_kms_identity
```

Repository configuration may store a `secret://...` reference only. Embedded service-account JSON, API keys, bearer tokens or private key material are denied.

## Live certification phases

The next phase, once a real GCP deployment target exists, is:

```text
S1 exact project/instance/database identity
S2 schema installation verification
S3 strong multi-client visibility
S4 transaction serializability probes
S5 stale CAS rejection
S6 monotonic fencing/takeover probes
S7 ordered journal probes
S8 atomic fenced CAS + journal probe
S9 commit-timestamp monotonicity/ordering evidence
S10 acknowledged-write durability across process restart
S11 regional/topology evidence
S12 fault/quorum behavior using an independent fault-control boundary
S13 external release/deployment attestation
S14 neutral v0.9 production evidence certification
```

A blocked fault-control phase remains BLOCKED. It is never converted into PASS because Spanner is a managed service.

## Portability plan

After Spanner satisfies the kernel under live evidence, implement YugabyteDB beneath the same neutral v0.9 contract. The goal is not merely two supported databases; it is evidence that the Company Kernel's persistence model is genuinely provider-neutral.
