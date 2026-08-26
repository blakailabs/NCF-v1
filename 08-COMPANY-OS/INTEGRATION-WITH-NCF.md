# Integrating Company OS with the Nexus Constitutional Framework

## Relationship

NCF remains the constitutional governance layer for autonomous workforces. Company OS adds a generalized runtime architecture beneath and around that governance model.

NCF emphasizes:

```text
Authority → Identity → Memory → Data → Governance → Agents → Workflows → Tools → Observability
```

Company OS reframes the runtime substrate as:

```text
CDM → CFHS → Kernel → Applications → Processes → Devices
```

The two models are complementary.

## Mapping

| NCF concept | Company OS equivalent |
|---|---|
| Constitution | `/etc/company`, `/etc/policy`, kernel policy engine |
| Constitutional Identity | kernel principal identity + `/etc/identity` |
| Authority Classes | capabilities, policy conditions, elevation |
| Memory Classes | `/home`, `/var/lib`, knowledge applications, archives |
| Registries | logical filesystem objects + application registries |
| Agent Registry | user-space principals and process manifests |
| Workflow Registry | process/service definitions |
| Tool Registry | `/dev` device contracts |
| Approval Registry | `/etc/approvals` + runtime elevation records |
| Event Registry | kernel IPC/event bus |
| Error Registry | `/var/log`, dead-letter queues, recovery records |
| Metrics Registry | observability subsystem |
| Certification | CDM certification gates + NCF governance certification |

## Architectural correction

> Agents are not organizational primitives at the kernel level.

Agents are user-space processes. Sales, Marketing, Finance, HR, and industry-specific functions are applications. This allows the same kernel to operate radically different organizations without changing the kernel.

## Recommended NCF evolution

Treat the Company OS extension as an experimental runtime profile until CFHS, CDM, and the kernel contracts mature enough to become formal NCF standards.
