# NCF-RI-001D Memory Architecture v1.0

## Status

Reference Implementation — Memory Architecture Draft

## Parent Authority

- NCF-004 Memory Standard
- NCF-005 Data Standard
- NCF-006 Governance Standard
- NCF-RI-001A Workforce Specification

---

# Purpose

This document defines the memory architecture for the Infinity Loop Content Workforce.

It fills the missing RI-001D slot and maps all seven NCF memory classes into the reference implementation.

---

# Memory Architecture Principle

The workforce must not rely only on model memory, chat history, or hidden context.

Authoritative operational context must be stored, classified, governed, retrievable, and auditable.

---

# Memory Classes

## Working Memory

Current run context.

Examples:

- active run package
- current content topic
- temporary video generation status
- intermediate metadata drafts

Retention: end of run or policy-based archive.

## Operational Memory

Active business state.

Examples:

- content calendar
- publishing queue
- campaign tracker
- asset queue

## Knowledge Memory

Approved reusable knowledge.

Examples:

- brand voice
- platform rules
- video prompt standards
- content SOPs
- metadata standards

## Decision Memory

Governance and strategy decisions.

Examples:

- publishing policy
- approval rules
- platform strategy
- campaign decisions

## Performance Memory

Historical performance data.

Examples:

- views
- CTR
- watch time
- shares
- comments
- saves
- conversions

## Institutional Memory

Long-term organizational context.

Examples:

- Infinity Loop mission
- content principles
- operating model
- stakeholder guidance

## Constitutional Memory

NCF standards governing RI-001.

Examples:

- NCF-001 Constitution
- NCF-004 Memory Standard
- NCF-006 Governance Standard
- NCF-RI-001 specifications

---

# Memory Retrieval Pattern

Before execution, agents should retrieve:

```text
Operational Memory
↓
Knowledge Memory
↓
Decision Memory
↓
Performance Memory
↓
Constitutional Memory when governance is relevant
```

---

# Memory Registry Requirements

Every governed memory object must include:

- memory_cid
- memory_uid
- memory_type
- memory_name
- owner_cid
- source_cid
- retention_class
- status
- version
- created_at
- updated_at

---

# Agent Memory Access Matrix

| Agent | Working | Operational | Knowledge | Decision | Performance | Constitutional |
|---|---|---|---|---|---|---|
| Content Orchestrator | RW | RW | R | R | RW | R |
| Schedule Discovery Agent | RW | R | R | R | - | - |
| Content Brief Agent | RW | R | R | R | R | - |
| Video Generation Agent | RW | R | R | - | R | - |
| Metadata Agent | RW | R | R | R | R | - |
| Publishing Agent | RW | R | R | R | - | R |
| Performance Agent | RW | R | - | - | RW | - |
| Validation Agent | RW | R | R | R | R | R |
| Logging Agent | RW | R | - | R | R | R |

Legend:

- R = Read
- W = Write
- RW = Read / Write
- - = No default access

---

# Memory Governance Rules

- Working Memory may be discarded after run completion.
- Operational Memory must be owned by the Content Orchestrator or assigned steward.
- Knowledge Memory must be versioned and source-attributed.
- Decision Memory requires governance context.
- Performance Memory must link to metrics records.
- Constitutional Memory is read-only for RI-001 agents.

---

# Storage Guidance

Acceptable early-stage storage:

- Google Drive
- Google Sheets
- Markdown files
- GitHub repository

Recommended production storage:

- relational registry database
- document store
- vector retrieval layer
- Git-backed constitutional memory

Vector retrieval is an access layer, not the authority layer.

---

# Prime Directive

The Infinity Loop workforce must remember through governed memory, not accidental context.
