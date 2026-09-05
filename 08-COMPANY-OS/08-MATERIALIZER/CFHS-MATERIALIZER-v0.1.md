# CFHS Materializer Specification v0.1

## Purpose

The CFHS Materializer consumes a validated `company.cdm.yaml` (or JSON equivalent) and produces a deterministic logical Company OS filesystem. It is an installer, not an AI agent and not a policy decision maker.

## Preconditions

The caller MUST provide:

- a parsed CDM document;
- target CFHS version;
- target directory or virtual namespace;
- a validation/certification result at or above the deployment profile requirement.

The materializer MUST refuse:

- unresolved P0 boot blockers;
- inline credential material;
- invalid root path traversal;
- mappings that target outside CFHS root;
- conflicting canonical writes without an explicit conflict policy.

## Materialization phases

```text
M0 PRECHECK
M1 STAGE ROOT
M2 WRITE BOOT METADATA
M3 MATERIALIZE CONFIG
M4 MATERIALIZE IDENTITIES
M5 MATERIALIZE DEVICES
M6 MATERIALIZE MOUNTS
M7 MATERIALIZE PACKAGES
M8 MATERIALIZE PERSISTENT STATE DESCRIPTORS
M9 BUILD VIRTUAL KERNEL VIEWS
M10 WRITE MANIFEST
M11 VERIFY
M12 COMMIT/ACTIVATE
```

## Root namespace

The materializer creates:

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

Required subdirectories include:

```text
/etc/company
/etc/identity
/etc/groups
/etc/policy
/etc/capabilities
/etc/approvals
/etc/budgets
/etc/devices
/etc/mounts
/etc/services
/etc/schedules
/home/humans
/home/agents
/usr/skills
/var/lib
/var/log/{kernel,process,device,security,audit,agent}
/var/spool/{jobs,approvals,dead-letter}
/var/checkpoint
/var/archive
/run/{pids,sockets,locks,leases,sessions,approvals,heartbeats,ipc}
/sys/{kernel,identity,capabilities,policy,resources,cgroups,models,scheduler,devices,health}
```

## Mapping rules

The reference materializer implements these conservative mappings when corresponding CDM sections exist:

| CDM | CFHS |
|---|---|
| `company` | `/etc/company/company.json` |
| `principals` | `/etc/identity/principals.json` |
| human principals | `/home/humans/<id>/.identity.json` |
| agent principals | `/home/agents/<id>/.identity.json` |
| `groups` / `organization.groups` | `/etc/groups/groups.json` |
| `authority` | `/etc/capabilities/authority.json` |
| `policies` | `/etc/policy/policies.json` |
| `resources` | `/etc/budgets/resources.json` and `/sys/resources/resources.json` |
| `systems` | `/etc/devices/systems.json` |
| systems with operational interfaces | `/dev/<category>/<system-id>.json` |
| `repositories` | `/etc/mounts/repositories.json` and `/mnt/<repo-id>/.mount.json` |
| `applications` | `/opt/<app-id>/manifest.json` |
| `capabilities` | `/usr/skills/<capability-id>/manifest.json` |
| `schedules` | `/etc/schedules/schedules.json` |
| `processes` | `/var/lib/process-catalog/processes.json` |
| `events` | `/var/lib/event-catalog/events.json` |
| `metrics` | `/var/lib/metrics/definitions.json` |
| `documents` | `/var/lib/document-catalog/documents.json` |
| `media` | `/var/lib/assets/media.json` |

Unknown CDM sections remain in the source manifest and are recorded as `unmapped_sections` rather than discarded.

## Secret rule

Any scalar value matching a secret-bearing field name such as `password`, `token`, `api_key`, `private_key`, `client_secret`, `access_key`, or `credential` MUST be one of:

- absent/null;
- an approved opaque reference beginning with `secret://`;
- an explicitly non-secret metadata descriptor.

The reference implementation rejects apparent inline secret values.

## Atomicity

A materialization SHOULD be created in a staging namespace. Activation occurs only after verification. Failed materialization must leave the prior active filesystem unchanged.

## Output manifest

The root contains `.cfhs-manifest.json` with:

- materializer version;
- source CDM identifier/version;
- CFHS version;
- generated timestamp;
- source digest;
- generated files/directories;
- unmapped sections;
- warnings;
- verification status.

