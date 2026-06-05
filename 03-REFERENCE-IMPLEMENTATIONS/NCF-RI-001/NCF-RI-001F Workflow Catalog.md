# NCF-RI-001F Workflow Catalog v1.0

## Status

Reference Implementation — Workflow Catalog Draft

## Parent Authority

- NCF-008 Workflow Standard
- NCF-RI-001A Workforce Specification
- NCF-RI-001C Runtime Specification

---

# Purpose

This catalog defines the official workflow roster for the Infinity Loop Content Workforce.

Each workflow is treated as an NCF-governed execution process with constitutional identity, purpose, inputs, outputs, agents, tools, registry updates, error handling, approvals, KPIs, and completion criteria.

---

# Workflow Catalog Summary

| Workflow | CID | Class | Primary Owner |
|---|---|---|---|
| Content Production Workflow | NCF-INF-WFL-CONTENT-PROD-000001 | Operational | Content Orchestrator |
| Date Context Workflow | NCF-INF-WFL-DATE-PROD-000001 | Utility | Date Context Agent |
| Schedule Discovery Workflow | NCF-INF-WFL-SCHEDULE-PROD-000001 | Operational | Schedule Discovery Agent |
| Brief Creation Workflow | NCF-INF-WFL-BRIEF-PROD-000001 | Operational | Content Brief Agent |
| Video Generation Workflow | NCF-INF-WFL-VIDEO-PROD-000001 | Operational | Video Generation Agent |
| Video Monitoring Workflow | NCF-INF-WFL-MONITOR-PROD-000001 | Utility | Video Monitoring Agent |
| Metadata Creation Workflow | NCF-INF-WFL-META-PROD-000001 | Operational | Metadata Agent |
| Thumbnail Creation Workflow | NCF-INF-WFL-THUMBNAIL-PROD-000001 | Operational | Thumbnail Agent |
| Asset Registration Workflow | NCF-INF-WFL-ASSET-PROD-000001 | Operational | Asset Management Agent |
| Publishing Workflow | NCF-INF-WFL-PUBLISH-PROD-000001 | Transactional | Publishing Agent |
| Performance Collection Workflow | NCF-INF-WFL-ANALYTICS-PROD-000001 | Operational | Performance Agent |
| Validation Workflow | NCF-INF-WFL-VALIDATE-PROD-000001 | Utility | Validation Agent |
| Logging Workflow | NCF-INF-WFL-LOG-PROD-000001 | Utility | Logging Agent |

---

# Workflow 001 — Content Production Workflow

## CID

```text
NCF-INF-WFL-CONTENT-PROD-000001
```

## Class

Operational Workflow

## Purpose

Coordinate the full content lifecycle from schedule discovery to performance logging.

## Inputs

- Date context
- Content schedule record
- Platform targets
- Brand memory
- Approval policy

## Outputs

- Video asset
- Thumbnail asset
- Platform metadata
- Publishing records
- Performance records
- Audit records

## Primary Agents

- Content Orchestrator
- Schedule Discovery Agent
- Content Brief Agent
- Video Generation Agent
- Metadata Agent
- Publishing Agent
- Performance Agent

## Runtime Sequence

```text
Date Context
→ Schedule Discovery
→ Brief Creation
→ Video Generation
→ Monitoring
→ Asset Registration
→ Metadata
→ Thumbnail
→ Approval if Required
→ Publishing
→ Performance Collection
→ Logging
```

## KPIs

- Workflow Success Rate
- Publication Accuracy
- Asset Traceability
- Audit Coverage

---

# Workflow 002 — Date Context Workflow

## CID

```text
NCF-INF-WFL-DATE-PROD-000001
```

## Class

Utility Workflow

## Purpose

Generate authoritative date and time context for the run.

## Outputs

- Date
- Day of week
- Week of year
- Month
- Quarter
- Year
- Timezone
- Timestamp

---

# Workflow 003 — Schedule Discovery Workflow

## CID

```text
NCF-INF-WFL-SCHEDULE-PROD-000001
```

## Class

Operational Workflow

## Purpose

Locate the scheduled content item for the current run.

## Inputs

- Date context
- Content calendar
- Knowledge memory if applicable

## Outputs

- Content object
- Schedule record
- Platform targets

## Errors

- Schedule not found
- Duplicate schedule record
- Invalid publish date

---

# Workflow 004 — Brief Creation Workflow

## CID

```text
NCF-INF-WFL-BRIEF-PROD-000001
```

## Class

Operational Workflow

## Purpose

Convert the content schedule record into a production-ready creative brief.

## Outputs

- Hook
- Story arc
- CTA
- Audience framing
- Creative direction

---

# Workflow 005 — Video Generation Workflow

## CID

```text
NCF-INF-WFL-VIDEO-PROD-000001
```

## Class

Operational Workflow

## Purpose

Generate a video prompt and submit the video generation job.

## Outputs

- Video prompt
- Video job ID
- Job status

## Tool Dependency

Video generation provider.

---

# Workflow 006 — Video Monitoring Workflow

## CID

```text
NCF-INF-WFL-MONITOR-PROD-000001
```

## Class

Utility Workflow

## Purpose

Monitor asynchronous video generation jobs until completion, failure, or timeout.

## Timer Policy

- Polling interval: 60 seconds
- Max attempts: 30

---

# Workflow 007 — Metadata Creation Workflow

## CID

```text
NCF-INF-WFL-META-PROD-000001
```

## Class

Operational Workflow

## Purpose

Create platform-specific titles, descriptions, captions, hashtags, tags, and alt text.

## Platforms

- YouTube
- Facebook
- Instagram

---

# Workflow 008 — Thumbnail Creation Workflow

## CID

```text
NCF-INF-WFL-THUMBNAIL-PROD-000001
```

## Class

Operational Workflow

## Purpose

Generate thumbnail prompts and thumbnail assets optimized for CTR.

## KPI

CTR Performance

---

# Workflow 009 — Asset Registration Workflow

## CID

```text
NCF-INF-WFL-ASSET-PROD-000001
```

## Class

Operational Workflow

## Purpose

Store, register, validate, and link all generated assets.

## Registry Updates

- Asset Registry
- Event Registry
- Run Registry

---

# Workflow 010 — Publishing Workflow

## CID

```text
NCF-INF-WFL-PUBLISH-PROD-000001
```

## Class

Transactional Workflow

## Purpose

Publish approved content to target platforms.

## Risk

R2 Customer Facing

## Approval

Required when policy indicates human review or campaign risk exceeds threshold.

## Platforms

- YouTube
- Facebook
- Instagram

---

# Workflow 011 — Performance Collection Workflow

## CID

```text
NCF-INF-WFL-ANALYTICS-PROD-000001
```

## Class

Operational Workflow

## Purpose

Collect, normalize, and store performance metrics.

## Collection Windows

- 24 hours
- 7 days
- 30 days
- 90 days

---

# Workflow 012 — Validation Workflow

## CID

```text
NCF-INF-WFL-VALIDATE-PROD-000001
```

## Class

Utility Workflow

## Purpose

Validate schemas, inputs, outputs, registry references, governance requirements, and completion criteria.

---

# Workflow 013 — Logging Workflow

## CID

```text
NCF-INF-WFL-LOG-PROD-000001
```

## Class

Utility Workflow

## Purpose

Create constitutional records for runs, events, errors, approvals, audits, and metrics.

---

# Compliance Requirements

The workflow catalog is compliant when:

- Every workflow has a CID
- Every workflow has an owner
- Every workflow has defined inputs and outputs
- Every workflow has completion criteria
- Every workflow has error handling
- Every workflow preserves lineage
- Every public-facing workflow has risk classification

---

# Prime Directive

Workflows convert agent capability into repeatable, governed, auditable execution.
