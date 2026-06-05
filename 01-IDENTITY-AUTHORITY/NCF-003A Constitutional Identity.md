# NCF-003A Constitutional Identity Standard v1.1 Enterprise Edition

## Status

Approved / Ratified Foundation — Expanded Enterprise Draft

## Parent Authority

- NCF-001 Constitution
- NCF-002 Enterprise Architecture

---

# Executive Summary

The Constitutional Identity Standard defines the identity system used by NCF-compliant organizations to identify, trace, audit, relate, and govern every significant entity in an autonomous AI workforce.

NCF identity is inspired by systems such as VINs, DNS, ISBNs, MAC addresses, and registry codes.

A random database ID is not enough for constitutional governance.

NCF requires identity that is both machine-unique and human-meaningful.

This is why every significant object receives both:

- CID: Constitutional Identifier
- UID: Universal Identifier

The UID guarantees uniqueness.

The CID guarantees meaning.

---

# Article I — Core Principle

## Identity Must Convey Context

A valid NCF identifier should allow an operator, auditor, engineer, or governance authority to understand the object's origin, ownership, type, environment, time context, and sequence without querying a database.

Identity is not merely technical metadata.

Identity is constitutional infrastructure.

---

# Article II — Identity Pair

Every significant object receives:

## Constitutional Identifier — CID

A human-readable operational identifier that conveys context.

## Universal Identifier — UID

A globally unique machine identifier, usually implemented as a UUID.

## Rule

CID communicates meaning.

UID guarantees uniqueness.

Both are required.

---

# Article III — CID Grammar

Canonical format:

```text
NCF-[ORG]-[TYPE]-[SUBTYPE]-[ENV]-[TIMESTAMP]-[SERIAL]
```

Some long-lived objects may omit TIMESTAMP when sequence is sufficient.

Example Agent CID:

```text
NCF-INF-AGT-CONTENT-PROD-000001
```

Example Run CID:

```text
NCF-INF-RUN-CONTENT-PROD-20260115T143022-00001
```

---

# Article IV — Segment Definitions

| Segment | Meaning | Example |
|---|---|---|
| NCF | Framework identifier | NCF |
| ORG | Registered organization namespace | INF |
| TYPE | Primary object type | RUN |
| SUBTYPE | Object subtype | CONTENT |
| ENV | Environment | PROD |
| TIMESTAMP | ISO-derived timestamp | 20260115T143022 |
| SERIAL | Sequence number | 00001 |

---

# Article V — Organization Namespace

The ORG segment must reference a registered organization namespace governed by the Organization Registry.

Examples:

- INF
- ACM
- NXL
- BLAKAI

Unregistered organization codes may not be used in production CIDs.

---

# Article VI — Object Type Codes

| Code | Object Type |
|---|---|
| ORG | Organization |
| AGT | Agent |
| WFL | Workflow |
| RUN | Workflow Run |
| WRK | Workforce |
| OBJ | Business Object |
| AST | Asset |
| MEM | Memory |
| APR | Approval |
| EVT | Event |
| ERR | Error |
| MTR | Metric |
| TLS | Tool |
| CRT | Certification |
| GDR | Governance Decision Record |
| AMD | Amendment |
| REG | Registry Record |

---

# Article VII — Environment Codes

Allowed values:

- DEV
- TEST
- STAGE
- PROD

Production records must use PROD.

Test records must not be represented as production records.

---

# Article VIII — Timestamp Standard

Timestamp segment format:

```text
YYYYMMDDTHHMMSS
```

Example:

```text
20260115T143022
```

UTC is preferred for system-generated identities unless organizational policy requires local timezone context.

Date context must still be stored in the record body according to NCF-005 Data Standard.

---

# Article IX — Serial Standard

Serial numbers should be zero-padded.

Examples:

```text
00001
00002
00003
```

Serial uniqueness must be guaranteed within the CID namespace segment combination.

---

# Article X — Lineage Requirements

Every significant object should support:

```json
{
  "cid": "",
  "uid": "",
  "parent_cid": "",
  "lineage_root_cid": "",
  "created_by_agent_cid": "",
  "organization_code": "",
  "environment": ""
}
```

Lineage allows any object to be traced back to its parent, root, creator, organization, and environment.

---

# Article XI — Identity Examples

## Organization

```text
NCF-INF-ORG-PROD-000001
```

## Workforce

```text
NCF-INF-WRK-CONTENT-PROD-000001
```

## Agent

```text
NCF-INF-AGT-CONTENT-PROD-000001
```

## Workflow

```text
NCF-INF-WFL-PUBLISH-PROD-000001
```

## Run

```text
NCF-INF-RUN-CONTENT-PROD-20260115T143022-00001
```

## Asset

```text
NCF-INF-AST-VIDEO-PROD-20260115T143022-00001
```

## Memory Record

```text
NCF-INF-MEM-KNOWLEDGE-PROD-000001
```

## Governance Decision Record

```text
NCF-INF-GDR-GOVERNANCE-PROD-000001
```

---

# Article XII — Parent-Child Relationships

CIDs must support hierarchical lineage.

Example:

```text
Workforce
  → Workflow
    → Run
      → Asset
        → Metric
```

A video asset should be traceable back to the run, workflow, agent, workforce, and organization that produced it.

---

# Article XIII — Identity Governance

Identity creation must be governed.

Systems must prevent:

- Duplicate CIDs
- Invalid namespace usage
- Invalid type codes
- Invalid environment codes
- Orphaned records
- Conflicting lineage
- Production use of unregistered namespaces

---

# Article XIV — CID vs UID

## CID

Used for operations, auditing, reporting, lineage, and human interpretation.

## UID

Used for database uniqueness, system joins, storage, and machine operations.

Both are required because they solve different problems.

---

# Article XV — Infinity Loop Example

The Infinity Loop Content Workforce uses organization namespace:

```text
INF
```

Master workforce CID:

```text
NCF-INF-WRK-CONTENT-PROD-000001
```

Content Orchestrator CID:

```text
NCF-INF-AGT-CONTENT-PROD-000001
```

Master Content Workflow CID:

```text
NCF-INF-WFL-CONTENT-PROD-000001
```

Example Run CID:

```text
NCF-INF-RUN-CONTENT-PROD-20260115T143022-00001
```

---

# Article XVI — Compliance Requirements

An implementation is identity-compliant when:

- Significant objects have CIDs and UIDs
- Organization namespaces are registered
- Type codes are valid
- Environment codes are valid
- Lineage fields exist
- Registry records validate CIDs
- Duplicate IDs are prevented
- Production records use production namespaces

---

# Prime Directive

Identity establishes ownership.

Ownership establishes accountability.

Accountability enables governance.

Every significant object within an NCF-compliant system shall possess both a CID and UID.
