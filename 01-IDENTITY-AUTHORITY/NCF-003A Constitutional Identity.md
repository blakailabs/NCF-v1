# NCF-003A Constitutional Identity Standard v1.0

## Status

Approved / Ratified

## Purpose

The Constitutional Identity Standard establishes a universal identity system for all entities operating within an NCF-compliant organization.

Every significant object must be globally unique, human-readable, machine-readable, traceable, auditable, and self-describing.

## Core Principle

**Identity Must Convey Context.**

A valid NCF identifier should allow an operator to understand an object's origin, ownership, type, environment, time, and sequence without querying a database.

## Identity Pair

Every significant object receives both:

- CID: Constitutional ID
- UID: Universal UUID

The UID guarantees uniqueness. The CID guarantees meaning.

## Constitutional ID Format

```text
NCF-[ORG]-[TYPE]-[SUBTYPE]-[ENV]-[TIMESTAMP]-[SERIAL]
```

## Example Run CID

```text
NCF-INF-RUN-CONTENT-PROD-20260115T143022-00001
```

## Segment Definitions

| Segment | Meaning |
|---|---|
| NCF | Framework identifier |
| ORG | Organization namespace |
| TYPE | Object type |
| SUBTYPE | Object subtype |
| ENV | Environment |
| TIMESTAMP | Date/time context |
| SERIAL | Sequence number |

## Object Types

- ORG: Organization
- AGT: Agent
- WFL: Workflow
- RUN: Run
- AST: Asset
- MEM: Memory
- APR: Approval
- EVT: Event
- ERR: Error
- MTR: Metric

## Environment Codes

- DEV
- TEST
- STAGE
- PROD

## Lineage Fields

Every object should support:

```json
{
  "cid": "",
  "uid": "",
  "parent_cid": "",
  "lineage_root_cid": ""
}
```

## Prime Directive

Every significant object within an NCF-compliant system shall possess both a CID and UID.

Identity establishes ownership. Ownership establishes accountability. Accountability enables governance.
