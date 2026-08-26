# Company OS Knowledge Base

**Version:** 0.1
**Updated:** 2026-08-26
**Scope:** NCF Company OS / CFHS / Company Kernel / CDM

## Canonical thesis

The Company OS is not an AI org chart and not a bundle of autonomous agents. It is a governed operating layer for a company built from universal operating-system primitives.

```text
Real Company
    ↓
CDM — discovers and verifies reality
    ↓
CFHS — represents the company in a universal namespace
    ↓
Company Kernel — controls identity, authority, resources, devices, state, and execution
    ↓
Applications — implement business/domain semantics
    ↓
Processes and AI agents — perform authorized work
```

## Prime architectural rule

> AI is a user-space workload. Authority belongs to the kernel.

LLMs may reason, recommend, plan, and request actions. They do not bypass deterministic policy enforcement.

## Why the operating-system analogy matters

Earlier thinking organized the company around departments and objectives. The architecture was corrected by using an actual operating system as the north star.

An OS begins with primitives: identity, permissions, files/namespaces, processes, scheduling, services, resources, devices/interfaces, configuration, packages, events/IPC, logs/audit, persistence, and recovery.

Departments such as Sales, Marketing, Finance, and HR are applications, not kernel primitives.

## CFHS root

```text
/
├── bin/
├── boot/
├── dev/
├── etc/
├── home/
├── lib/
├── mnt/
├── opt/
├── proc/
├── root/
├── run/
├── sbin/
├── srv/
├── sys/
├── tmp/
├── usr/
└── var/
```

### Root semantics

- `/boot` — startup/recovery manifest and trust roots
- `/bin` — essential commands
- `/sbin` — privileged administrative commands
- `/etc` — company configuration and policy
- `/lib` — essential runtime libraries
- `/usr` — static user-space software, schemas, skills
- `/opt` — business applications/packages
- `/home` — human and agent workspaces
- `/root` — break-glass administrator workspace
- `/dev` — controlled external interfaces
- `/mnt` — mounted external repositories/systems
- `/proc` — live process view
- `/run` — transient runtime state
- `/sys` — kernel/control-plane state
- `/srv` — outward-served content
- `/tmp` — disposable scratch space
- `/var` — persistent mutable state, logs, queues, checkpoints, archives

## Company Kernel

Trusted responsibilities:

- identity
- authorization
- capabilities
- policy
- process lifecycle
- scheduler
- resource limits
- device broker
- secret broker
- namespace/mount manager
- IPC/event bus
- persistence
- audit
- observability
- package verification
- recovery

User-space responsibilities include AI agents, LLMs, CRM, accounting, marketing, sales, support, workflows, industry packages, and custom applications.

## Authorization doctrine

Authority combines:

1. owner/group/object permissions;
2. fine-grained capabilities;
3. contextual policy;
4. hierarchical resource ceilings;
5. temporary elevation for exceptional actions.

Observed technical access is not equivalent to legitimate business authority.

## Device model

External systems are abstracted through `/dev` contracts, for example:

```text
/dev/mail/gmail
/dev/payments/stripe
/dev/crm/salesforce
/dev/code/github
```

Processes receive permitted operations, not raw credentials.

## Secret model

Secrets are represented by opaque references:

```text
secret://mail/google
secret://payments/stripe
```

Raw secret values must not be placed in manifests, logs, examples, repositories, or LLM context.

## Process model

```text
DECLARED → CREATING → READY → RUNNING → COMPLETED
                               ├→ WAITING
                               ├→ BLOCKED
                               └→ PAUSED
```

Failure states include `FAILED`, `CANCELLED`, `TERMINATED`, and `TIMED_OUT`.

Processes may spawn children but cannot grant children authority outside the parent bounding set.

## IPC model

Four kernel-mediated primitives:

```text
CALL
EVENT
QUEUE
SIGNAL
```

Events preserve `trace_id`, `correlation_id`, and `causation_id` so business actions can be reconstructed as causal chains.

## Side-effect model

- S0 — read only
- S1 — reversible
- S2 — compensatable
- S3 — irreversible/consequential

Higher side-effect classes require stronger authorization, auditing, checkpointing, and often human approval.

## CDM

The Company Discovery Manifest is the installer/discovery contract for CFHS.

### Discovery sequence

```text
OBSERVE → CORROBORATE → INFER → ASK → CONFIRM
```

### Lifecycle

```text
INIT → DECLARE → CONNECT → DISCOVER → INGEST → NORMALIZE
→ CORRELATE → INFER → RESOLVE → CLASSIFY → MAP
→ VALIDATE → MATERIALIZE → BOOT-TEST → CERTIFY
```

### Evidence authority

```text
A5 legally authoritative
A4 system of record
A3 authorized human declaration
A2 official company document
A1 behavioral observation
A0 inference
```

Confidence is tracked separately from authority.

### High-impact rule

Legal identity, ownership, regulated data classification, source-of-truth assignments, deletion/retention rules, financial authority, contract-signing authority, privileged credential scope, and autonomous spending authority cannot become canonical from inference alone.

### CDM certification

```text
CDM-0 DISCOVERED
CDM-1 MAPPED
CDM-2 BOOTABLE
CDM-3 OPERABLE
CDM-4 GOVERNED
CDM-5 AUTONOMY-READY
```

## Machine Contract Package v0.1

The source package provides JSON Schemas, connector contracts, scan profiles, discovery questions, artifact requests, inference rules, mapping DSL/rules, operational validation rules, certification profiles/tests/fixtures, a sample manifest, and a validator.

It explicitly separates schema validity from operational/certification validity. A structurally valid manifest is not automatically safe to boot or automate.

## Mapping doctrine

Mapping modes:

```text
COPY
MOVE
MOUNT
REFERENCE
GENERATE
VIRTUALIZE
IGNORE
ARCHIVE
```

External repositories should normally be mounted rather than duplicated unless canonical import is intentionally required.

Media uses canonical asset identity plus metadata and virtual views instead of duplicating one photo into many physical folders.

## Completeness doctrine

Completeness is scoped, evidence-based, and multidimensional.

An explicit unknown is better than an invented fact.

A company is not complete because all fields contain values. It is complete for a declared scope when critical identities, systems, authority, data classification, sources of truth, processes, dependencies, recovery, audit, and escalation are resolved sufficiently for that certification level.

## Relationship to NCF

NCF remains the constitutional governance model. Company OS provides an experimental runtime substrate.

- NCF Authority → kernel capabilities/policy/elevation
- NCF Identity → principals and `/etc/identity`
- NCF Tools → `/dev` device contracts
- NCF Workflows → processes/services
- NCF Registries → logical CFHS/application records
- NCF Approvals → `/etc/approvals` + elevation records
- NCF Observability → kernel logs/metrics/traces/audit
- NCF Certification → CDM readiness + NCF governance certification

## Decisions that should not be casually reversed

1. Do not put departments at filesystem root.
2. Do not let LLMs execute as kernel/trusted policy components.
3. Do not give agents raw credentials.
4. Do not equate technical permission with business authority.
5. Do not silently convert inference into canonical company truth.
6. Do not hide contradictions to improve completeness scores.
7. Do not require every external dataset to be copied into the OS; mounting/reference is first-class.
8. Do not use folders as the only asset taxonomy; use metadata and virtual collections.
9. Do not make a single model/vendor foundational to the architecture.
10. Do not claim autonomy readiness until governance, recovery, and audit gates pass.

## Current status

- AI-native Company OS research: drafted
- CFHS v0.1: drafted
- Company Kernel v0.1: drafted
- CDM v0.1: drafted
- Machine contract package v0.1: generated and validated
- Reference runtime/materializer: not yet implemented

## Next engineering milestone

Build a reference implementation that ingests `company.cdm.yaml`, validates it, computes certification, materializes the logical CFHS namespace, exposes virtual `/dev`, `/proc`, `/sys`, and `/run`, implements authorization/device brokering, runs a low-risk process, produces a complete audit chain, demonstrates denied/elevated authority, and demonstrates restart/checkpoint/recovery.
