# NCF-005 Data Standard v1.0

## Status

Approved / Ratified

## Purpose

Defines how information is structured, stored, related, governed, and audited across NCF-compliant systems.

## Core Principles

1. Single Source of Truth
2. IDs Before Names
3. Structured Before Stored
4. Data Outlives Technology
5. Human + Machine Readable

## Core Registries

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

## Standard Data Types

- CID
- UID
- STRING
- INTEGER
- DECIMAL
- BOOLEAN
- ENUM
- DATE
- TIMESTAMP
- JSON
- ARRAY
- URL
- EMAIL
- PHONE

## Date Standard

All dates use ISO-8601.

Required context:

- date
- day_of_week
- week_of_year
- month
- quarter
- year
- timezone
- timestamp

## Lineage Requirements

Every object should support:

- cid
- uid
- parent_cid
- lineage_root_cid

## Referential Integrity

Records may not reference missing or invalid CIDs.

## Data Quality Dimensions

- Accuracy
- Completeness
- Consistency
- Timeliness
- Uniqueness
- Traceability

## Prime Directive

Every object within an NCF-compliant system must possess identity, ownership, lineage, lifecycle, and traceability.
