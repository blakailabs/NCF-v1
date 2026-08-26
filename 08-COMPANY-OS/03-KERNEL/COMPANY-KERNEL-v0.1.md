# Company Kernel Specification v0.1

**Status:** Foundational Draft

## Purpose

The Company Kernel is the trusted deterministic runtime that mediates authority and execution for a Company OS.

## Kernel responsibilities

- identity management
- authorization
- capability management
- policy enforcement
- process management
- scheduling
- resource control
- device brokering
- secret brokering
- filesystem namespace
- mount management
- IPC/event bus
- persistence brokering
- audit and observability
- package verification
- failure recovery
- clock/time semantics

## User-space boundary

LLMs, AI agents, department applications, CRM, accounting, sales, marketing, workflows, customer-facing applications, industry packages, custom code, and third-party packages are user-space workloads.

> User space may request a privileged action. Only the kernel may authorize and mediate it.

## Principal model

Principal types:

```text
human
agent
service
process
package
system
external
```

Each principal receives identity, group membership, credentials, capabilities, namespace, and resource bounds.

## Permission model

CFHS combines:

1. discretionary permissions — read/write/execute/traverse;
2. fine-grained capabilities — e.g. `CAP_MAIL_SEND`, `CAP_REFUND_ISSUE`, `CAP_CODE_DEPLOY`;
3. contextual policy — amount, risk, time, geography, classification, approval requirements.

A capability indicates potential authority. Policy decides whether it can be exercised in context.

## Elevation

A sudo-like mechanism provides narrow, temporary, non-transferable, auditable elevation. A process may request an action beyond its current authority, but approval grants only the minimum additional scope and expires automatically.

## Resource control

Resource groups bound money, model tokens, API calls, messages, compute, storage, concurrency, browser sessions, and wall time. Child processes cannot exceed parent ceilings.

## Process lifecycle

```text
DECLARED → CREATING → READY → RUNNING → COMPLETED
                               ├→ WAITING
                               ├→ BLOCKED
                               └→ PAUSED
```

Failure states include `FAILED`, `CANCELLED`, `TERMINATED`, and `TIMED_OUT`.

## IPC primitives

```text
CALL
EVENT
QUEUE
SIGNAL
```

Derived events preserve correlation, causation, and trace identifiers.

## Side-effect classes

- S0 — read only
- S1 — reversible
- S2 — compensatable
- S3 — irreversible/consequential

Higher classes receive stronger policy, approval, checkpoint, and audit requirements.

## Secrets

Raw secrets do not appear in AI context or ordinary files. Workloads use opaque references and request short-lived, scope-limited secret leases through the secret broker.

## Observability

Every consequential operation should capture timestamp, actor, process, trace, operation, resource, device, authority, policy decision, result, duration, cost, and error.

## Boot sequence

```text
VERIFY → LOAD KERNEL → MOUNT ROOT → LOAD CONFIG → INITIALIZE IDENTITY
→ INITIALIZE POLICY → INITIALIZE SECRET BROKER → INITIALIZE RESOURCE CONTROLLERS
→ DISCOVER DEVICES → ATTACH MOUNTS → START IPC/EVENT BUS → RESTORE STATE
→ RECONCILE JOURNAL → START SERVICES → RUN HEALTH CHECKS → DECLARE READY
```

## Failure recovery

Supported semantics include retry, restart, checkpoint, resume, rollback, compensation, dead-letter, failover, degradation, isolation, termination, and rescue.

## Minimal syscall/API surface

- Filesystem: `open`, `read`, `write`, `list`, `stat`, `link`, `remove`
- Processes: `spawn`, `exec`, `signal`, `wait`, `checkpoint`
- IPC: `call`, `emit`, `subscribe`, `enqueue`, `dequeue`
- Devices: `describe`, `invoke`, `watch`
- Identity/authority: `authorize`, `elevate`, `delegate`
- Secrets: `lease`, `revoke`
- Scheduling: `schedule`, `cancel`
- Mounts: `mount`, `unmount`
- Observability: `log`, `metric`, `trace`

## Kernel non-goals

The kernel does not understand business nouns such as customer, sale, patient, invoice, grant, product, or campaign. Applications define those semantics.
