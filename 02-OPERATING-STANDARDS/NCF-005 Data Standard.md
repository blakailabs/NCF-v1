# NCF-005 Data Standard v1.1 Enterprise Edition

## Status

Approved / Ratified Foundation — Expanded Enterprise Draft

## Parent Authority

- NCF-001 Constitution
- NCF-002 Enterprise Architecture
- NCF-003 Identity & Authority Standards
- NCF-004 Memory Standard

---

# Executive Summary

The NCF Data Standard defines how information is structured, stored, related, governed, validated, exchanged, and audited across NCF-compliant systems.

Data is the constitutional record of organizational activity.

NCF requires data to be identifiable, traceable, auditable, governed, and portable across tools, vendors, models, and runtime environments.

The purpose of the Data Standard is to prevent autonomous systems from relying on hidden state, undocumented schemas, inconsistent field names, untraceable records, or vendor-specific data structures.

---

# Article I — Data Governance Principles

## Principle 1 — Single Source of Truth

Every business object must have one authoritative record.

A file may live in Google Drive, a post may live on YouTube, and a metric may live in an analytics platform, but the NCF registry record remains the authoritative constitutional record.

## Principle 2 — IDs Before Names

Relationships must be established using CID and UID values rather than names, titles, labels, or filenames.

## Principle 3 — Structured Before Stored

Significant outputs must be normalized into structured records before persistence.

## Principle 4 — Data Outlives Technology

Data structures must survive model changes, vendor changes, platform migrations, and workflow runtime changes.

## Principle 5 — Human + Machine Readable

NCF systems should store both human-readable and machine-readable forms where useful.

Example:

```json
{
  "day_of_week": "Thursday",
  "day_of_week_number": 4
}
```

## Principle 6 — Auditability Is Mandatory

Every significant mutation must be traceable.

## Principle 7 — Registries Are Authoritative

Hidden state is not constitutional state.

Registries define system truth.

---

# Article II — Standard Data Types

| Type | Description |
|---|---|
| CID | Constitutional Identifier |
| UID | Universal Identifier |
| STRING | Text |
| INTEGER | Whole number |
| DECIMAL | Numeric value with decimals |
| BOOLEAN | True / False |
| ENUM | Controlled value set |
| DATE | YYYY-MM-DD |
| TIMESTAMP | ISO-8601 date-time |
| JSON | Structured object |
| ARRAY | Ordered collection |
| URL | Resource location |
| EMAIL | Email address |
| PHONE | Telephone number |

---

# Article III — Universal Record Header

Every significant NCF record should include the following constitutional header:

```json
{
  "cid": "",
  "uid": "",
  "parent_cid": "",
  "lineage_root_cid": "",
  "organization_code": "",
  "environment": "",
  "created_at": "",
  "updated_at": "",
  "created_by_agent_cid": "",
  "schema_version": "1.0"
}
```

---

# Article IV — Date & Time Standard

All NCF systems must use ISO-8601 timestamps.

Required Date Context:

```json
{
  "date": "2026-01-15",
  "day_of_week": "Thursday",
  "day_of_week_number": 4,
  "week_of_year": 3,
  "month": 1,
  "month_name": "January",
  "quarter": 1,
  "year": 2026,
  "timezone": "America/New_York",
  "timezone_offset": "-05:00",
  "timestamp": "2026-01-15T14:30:00-05:00"
}
```

Never store only relative date terms such as today, tomorrow, yesterday, or Monday without the actual date context.

---

# Article V — Core Registries

NCF defines the following core registries:

- Organization Registry
- Agent Registry
- Workflow Registry
- Run Registry
- Object Registry
- Asset Registry
- Memory Registry
- Approval Registry
- Error Registry
- Event Registry
- Metrics Registry
- Tool Registry
- Certification Registry

Each registry is a governed source of truth for its object class.

---

# Article VI — Agent Registry

## Purpose

Stores agent definitions, ownership, authority, lifecycle status, and permissions.

## Required Fields

| Field | Type | Description |
|---|---|---|
| agent_cid | CID | Agent constitutional identifier |
| agent_uid | UID | Agent universal identifier |
| agent_name | STRING | Human-readable name |
| agent_type | ENUM | Executive, Department, Specialist, Workflow, Utility |
| authority_class | ENUM | A1-A5 |
| owner_cid | CID | Accountable owner |
| status | ENUM | Draft, Testing, Active, Suspended, Retired |
| version | STRING | Agent version |

---

# Article VII — Workflow Registry

## Purpose

Stores workflow definitions and workflow ownership.

## Required Fields

| Field | Type | Description |
|---|---|---|
| workflow_cid | CID | Workflow constitutional identifier |
| workflow_uid | UID | Workflow universal identifier |
| workflow_name | STRING | Human-readable name |
| owner_agent_cid | CID | Responsible agent |
| workflow_class | ENUM | Strategic, Operational, Transactional, Utility |
| status | ENUM | Draft, Approved, Active, Archived |
| version | STRING | Workflow version |

---

# Article VIII — Run Registry

## Purpose

Stores workflow execution records.

## Required Fields

| Field | Type | Description |
|---|---|---|
| run_cid | CID | Run constitutional identifier |
| run_uid | UID | Run universal identifier |
| workflow_cid | CID | Workflow executed |
| initiating_agent_cid | CID | Agent that initiated the run |
| status | ENUM | Runtime status |
| risk_level | ENUM | R0-R4 |
| started_at | TIMESTAMP | Run start |
| completed_at | TIMESTAMP | Run completion |
| duration_seconds | INTEGER | Runtime duration |

## Standard Run States

- queued
- initialized
- executing
- waiting
- processing
- review
- publishing
- completed
- failed
- cancelled

---

# Article IX — Object Registry

## Purpose

Stores primary business entities.

Examples:

- Content
- Campaigns
- Customers
- Leads
- Projects
- Tickets

## Required Fields

| Field | Type | Description |
|---|---|---|
| object_cid | CID | Object constitutional identifier |
| object_uid | UID | Object universal identifier |
| object_type | ENUM | Entity category |
| owner_cid | CID | Owner |
| status | ENUM | Lifecycle status |
| source_system | STRING | Origin system |
| source_record_id | STRING | External source identifier |

---

# Article X — Asset Registry

## Purpose

Stores digital asset records.

Examples:

- Videos
- Images
- Documents
- Captions
- Metadata
- Audio

## Required Fields

| Field | Type | Description |
|---|---|---|
| asset_cid | CID | Asset constitutional identifier |
| asset_uid | UID | Asset universal identifier |
| object_cid | CID | Related business object |
| run_cid | CID | Run that created the asset |
| asset_type | ENUM | Video, Image, Document, Metadata, Audio |
| storage_provider | STRING | Storage location |
| storage_url | URL | Resource URL |
| checksum | STRING | Integrity hash when available |
| status | ENUM | Created, Uploaded, Failed, Archived |

---

# Article XI — Event Registry

## Purpose

Stores meaningful events across the system.

## Required Fields

| Field | Type | Description |
|---|---|---|
| event_cid | CID | Event constitutional identifier |
| run_cid | CID | Related run |
| event_type | ENUM | Event classification |
| actor_cid | CID | Actor causing event |
| target_cid | CID | Object affected |
| timestamp | TIMESTAMP | Event time |
| message | STRING | Human-readable description |

---

# Article XII — Error Registry

## Purpose

Stores failures, retry state, and escalation information.

## Required Fields

| Field | Type | Description |
|---|---|---|
| error_cid | CID | Error constitutional identifier |
| run_cid | CID | Related run |
| agent_cid | CID | Agent associated with error |
| error_code | STRING | Standardized error code |
| severity | ENUM | E1-E5 |
| retryable | BOOLEAN | Retry status |
| retry_count | INTEGER | Number of retries |
| error_message | STRING | Description |
| timestamp | TIMESTAMP | Error time |

---

# Article XIII — Approval Registry

## Purpose

Stores governance approvals and review outcomes.

## Required Fields

| Field | Type | Description |
|---|---|---|
| approval_cid | CID | Approval constitutional identifier |
| object_cid | CID | Object requiring approval |
| requesting_agent_cid | CID | Agent requesting approval |
| reviewer_cid | CID | Human or agent reviewer |
| decision | ENUM | Approved, Denied, Needs Revision, Expired |
| reason | STRING | Review rationale |
| timestamp | TIMESTAMP | Decision time |

---

# Article XIV — Metrics Registry

## Purpose

Stores KPI and performance measurements.

## Required Fields

| Field | Type | Description |
|---|---|---|
| metric_cid | CID | Metric constitutional identifier |
| source_cid | CID | Source object |
| metric_name | STRING | Metric name |
| metric_value | DECIMAL | Numeric value |
| metric_unit | STRING | Unit of measurement |
| measurement_date | DATE | Measurement date |
| recorded_at | TIMESTAMP | Record timestamp |

---

# Article XV — Referential Integrity

Records may not reference missing, invalid, suspended, retired, or unauthorized CIDs.

All foreign CID references must resolve to valid registry records.

---

# Article XVI — Data Quality Framework

NCF data must be evaluated for:

- Accuracy
- Completeness
- Consistency
- Timeliness
- Uniqueness
- Traceability
- Validity
- Authority

---

# Article XVII — Data Retention Classes

| Class | Name | Retention |
|---|---|---|
| A | Constitutional | Never delete |
| B | Institutional | Retain indefinitely |
| C | Knowledge | Retain while active |
| D | Operational | Policy-based |
| E | Working | Temporary |

---

# Article XVIII — Data Contracts

Every inter-agent message, registry record, tool invocation, approval, error, and output should conform to a defined contract.

Contracts must include:

- Required fields
- Optional fields
- Validation rules
- Schema version
- Error handling
- Example payloads

---

# Article XIX — Infinity Loop Example

NCF-RI-001 uses this Data Standard to map:

- Content Objects
- Video Assets
- Thumbnail Assets
- Publishing Records
- Performance Metrics
- Agent Messages
- Runtime Events
- Error Records
- Approval Records

into governed registries.

---

# Prime Directive

Data is not merely information.

Data is the constitutional record of organizational activity.

Every object within an NCF-compliant system must possess identity, ownership, lineage, lifecycle, and traceability.
