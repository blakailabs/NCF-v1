# NCF-RI-001E Agent Catalog v1.0

## Status

Reference Implementation — Agent Catalog Draft

## Parent Authority

- NCF-007 Agent Standard
- NCF-RI-001A Workforce Specification
- NCF-RI-001C Runtime Specification

---

# Purpose

This catalog defines the official agent roster for the Infinity Loop Content Workforce.

Each agent is treated as an NCF AI Employee with constitutional identity, mission, authority, KPIs, memory access, tool access, escalation rules, and certification target.

---

# Agent Catalog Summary

| Agent | CID | Type | Authority |
|---|---|---|---|
| Content Orchestrator | NCF-INF-AGT-CONTENT-PROD-000001 | Department Agent | A3 |
| Date Context Agent | NCF-INF-AGT-DATE-PROD-000001 | Utility Agent | A1 |
| Schedule Discovery Agent | NCF-INF-AGT-SCHEDULE-PROD-000001 | Specialist Agent | A2 |
| Content Brief Agent | NCF-INF-AGT-BRIEF-PROD-000001 | Specialist Agent | A2 |
| Video Generation Agent | NCF-INF-AGT-VIDEO-PROD-000001 | Workflow Agent | A2 |
| Video Monitoring Agent | NCF-INF-AGT-MONITOR-PROD-000001 | Utility Agent | A1 |
| Metadata Agent | NCF-INF-AGT-META-PROD-000001 | Specialist Agent | A2 |
| Thumbnail Agent | NCF-INF-AGT-THUMBNAIL-PROD-000001 | Specialist Agent | A2 |
| Asset Management Agent | NCF-INF-AGT-ASSET-PROD-000001 | Workflow Agent | A2 |
| Publishing Agent | NCF-INF-AGT-PUBLISH-PROD-000001 | Workflow Agent | A2 |
| Performance Agent | NCF-INF-AGT-ANALYTICS-PROD-000001 | Specialist Agent | A2 |
| Validation Agent | NCF-INF-AGT-VALIDATE-PROD-000001 | Constitutional Utility Agent | A1 |
| Logging Agent | NCF-INF-AGT-LOG-PROD-000001 | Constitutional Utility Agent | A1 |

---

# Agent 001 — Content Orchestrator

## CID

```text
NCF-INF-AGT-CONTENT-PROD-000001
```

## Type

Department Agent

## Authority

A3 Managerial

## Mission

Coordinate the full content production, publishing, asset storage, performance tracking, and audit workflow.

## Primary KPI

Published Content

## Secondary KPIs

- Workflow Success Rate
- Publication Accuracy
- Asset Traceability
- Compliance Rate

## Memory Access

- Working: Read / Write
- Operational: Read / Write
- Knowledge: Read
- Decision: Read
- Performance: Read / Write
- Constitutional: Read

## Tool Access

- Google Sheets: T3
- Google Drive: T3
- Workflow Queue: T4

## Escalation Conditions

- Missing schedule
- Failed workflow
- Publishing failure
- Risk above R2
- Governance conflict

---

# Agent 002 — Date Context Agent

## CID

```text
NCF-INF-AGT-DATE-PROD-000001
```

## Type

Utility Agent

## Authority

A1 Advisory

## Mission

Provide authoritative date, time, timezone, day of week, week number, month, quarter, and year context.

## Output

Date Context Package

## Escalation Conditions

- Invalid timezone
- Missing time service

---

# Agent 003 — Schedule Discovery Agent

## CID

```text
NCF-INF-AGT-SCHEDULE-PROD-000001
```

## Type

Specialist Agent

## Authority

A2 Operational

## Mission

Locate scheduled content for the active run using the content calendar or knowledge memory.

## Primary KPI

Schedule Match Accuracy

## Escalation Conditions

- No content found
- Duplicate content found
- Schedule conflict

---

# Agent 004 — Content Brief Agent

## CID

```text
NCF-INF-AGT-BRIEF-PROD-000001
```

## Type

Specialist Agent

## Authority

A2 Operational

## Mission

Convert a content schedule record into a production-ready creative brief.

## Outputs

- Hook
- Story arc
- CTA
- Content goal
- Audience framing

---

# Agent 005 — Video Generation Agent

## CID

```text
NCF-INF-AGT-VIDEO-PROD-000001
```

## Type

Workflow Agent

## Authority

A2 Operational

## Mission

Create video generation prompts and submit asynchronous generation jobs.

## Primary KPI

Successful Video Job Creation

## Escalation Conditions

- Provider failure
- Prompt validation failure
- Repeated generation failure

---

# Agent 006 — Video Monitoring Agent

## CID

```text
NCF-INF-AGT-MONITOR-PROD-000001
```

## Type

Utility Agent

## Authority

A1 Advisory

## Mission

Monitor video processing jobs using polling timers until completed, failed, or expired.

## Runtime Rule

Default polling interval: 60 seconds.

Default max attempts: 30.

---

# Agent 007 — Metadata Agent

## CID

```text
NCF-INF-AGT-META-PROD-000001
```

## Type

Specialist Agent

## Authority

A2 Operational

## Mission

Generate platform-specific titles, descriptions, captions, hashtags, tags, and alt text.

## Platforms

- YouTube
- Facebook
- Instagram

---

# Agent 008 — Thumbnail Agent

## CID

```text
NCF-INF-AGT-THUMBNAIL-PROD-000001
```

## Type

Specialist Agent

## Authority

A2 Operational

## Mission

Generate thumbnail prompts and thumbnail assets optimized for click-through rate.

## Primary KPI

CTR Performance

---

# Agent 009 — Asset Management Agent

## CID

```text
NCF-INF-AGT-ASSET-PROD-000001
```

## Type

Workflow Agent

## Authority

A2 Operational

## Mission

Store generated assets, register asset records, validate URLs, and preserve lineage.

## Tool Access

- Google Drive: T3
- Asset Registry: T3

---

# Agent 010 — Publishing Agent

## CID

```text
NCF-INF-AGT-PUBLISH-PROD-000001
```

## Type

Workflow Agent

## Authority

A2 Operational

## Mission

Publish approved assets to YouTube, Facebook, and Instagram.

## Tool Access

- YouTube: T4
- Facebook: T4
- Instagram: T4

## Escalation Conditions

- Auth failure
- Platform rejection
- Publishing failure
- Approval missing

---

# Agent 011 — Performance Agent

## CID

```text
NCF-INF-AGT-ANALYTICS-PROD-000001
```

## Type

Specialist Agent

## Authority

A2 Operational

## Mission

Collect, normalize, and store performance metrics.

## Collection Windows

- 24 hours
- 7 days
- 30 days
- 90 days

---

# Agent 012 — Validation Agent

## CID

```text
NCF-INF-AGT-VALIDATE-PROD-000001
```

## Type

Constitutional Utility Agent

## Authority

A1 Advisory

## Mission

Validate schemas, governance requirements, registry references, permissions, and completion criteria.

---

# Agent 013 — Logging Agent

## CID

```text
NCF-INF-AGT-LOG-PROD-000001
```

## Type

Constitutional Utility Agent

## Authority

A1 Advisory

## Mission

Generate run records, event records, error records, approval records, audit records, and metric records.

---

# Certification Target

Each agent is a candidate for NCF-Compliant Agent designation once contracts, evidence, test runs, and audit records are completed.

---

# Prime Directive

The Infinity Loop workforce is only as reliable as its agent roster is defined, governed, measurable, and auditable.
