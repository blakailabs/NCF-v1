# Company Filesystem Hierarchy Standard (CFHS) v0.1

**Status:** Foundational Draft

## Purpose

CFHS defines a predictable logical namespace for an AI-native company. It separates configuration, software, external devices, mounts, runtime state, persistent state, queues, logs, archives, user workspaces, and system control surfaces.

The root is intentionally small and universal.

## Root hierarchy

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

## Constitutional rules

1. Root directories represent universal runtime primitives, not departments or industries.
2. AI runs in user space, never kernel space.
3. Default deny applies to identities, packages, services, and processes.
4. No AI process receives unrestricted root authority.
5. Policy constrains intelligence.
6. Child workloads may be more restricted than parents but may not self-escalate.
7. External side effects are kernel-mediated through device interfaces.
8. Consequential actions are attributable and auditable.

## Directory semantics

- `/boot` — minimum startup/recovery information, trust roots, versions, targets.
- `/bin` — essential commands available in minimal/recovery operation.
- `/sbin` — privileged system-management commands.
- `/etc` — company configuration, identity, groups, policy, capabilities, budgets, approvals, risk, classification, services, devices, mounts, models, routing, retention, schedules.
- `/lib` — essential shared runtime components.
- `/usr` — static user-space software, schemas, skills, templates.
- `/opt` — optional applications and industry/business packages.
- `/home` — persistent private workspaces for humans and agents.
- `/root` — break-glass administrative workspace.
- `/dev` — controlled external interfaces such as mail, payments, CRM, source control, cloud, phone, browser, and social systems.
- `/mnt` — mounted external information namespaces.
- `/proc` — virtual representation of currently executing Company Processes.
- `/run` — transient runtime state such as sockets, locks, leases, approvals, heartbeats, sessions, and IPC.
- `/sys` — virtual kernel/control-plane representation.
- `/srv` — content intentionally served outside the Company OS.
- `/tmp` — disposable scratch space; nothing canonical may depend on its survival.
- `/var` — persistent changing state including application data, logs, queues, cache, checkpoints, archives, and backups.

## Universal object envelope

Every persistent object should expose at least:

```yaml
id:
kind:
path:
owner:
group:
mode:
created_at:
updated_at:
version:
classification:
retention:
provenance:
labels: []
integrity_hash:
```

## Logical filesystem

CFHS paths are logical rather than implementation-constraining. Physical storage may use relational databases, graph databases, object storage, Git, event stores, vector stores, or external SaaS systems while preserving CFHS path semantics.

## North star

A hospital, funeral home, law firm, SaaS company, nonprofit, contractor, ecommerce company, and manufacturer should be able to run on the same CFHS and kernel while installing different applications and policies.
