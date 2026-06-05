# NCF-RI-001C Runtime Specification v1.1 Enterprise Edition

## Status

Reference Implementation — Enterprise Expansion Draft

## Parent Authority

- NCF-002 Enterprise Architecture
- NCF-006 Governance Standard
- NCF-007 Agent Standard
- NCF-008 Workflow Standard
- NCF-009 Tool Standard

---

# Executive Summary

The Runtime Specification defines how the Infinity Loop Content Workforce executes work in production.

It converts the NCF workforce design into an event-driven runtime architecture using agents, queues, timers, memory retrieval, approval gates, tool routing, registry updates, and observability records.

This document is the execution engine for NCF-RI-001.

---

# Runtime Architecture

```text
Content Orchestrator
        ↓
Runtime Context Package
        ↓
Task Queue
        ↓
Specialist / Workflow Agents
        ↓
Tool Router
        ↓
Registries + Memory Stores
        ↓
Publishing Platforms
        ↓
Performance Collection
        ↓
Observability Layer
```

The orchestrator coordinates work. It does not perform every task directly.

---

# Core Runtime Services

The runtime requires:

- Agent Runtime
- Task Queue
- Event Bus
- Memory Retrieval Service
- Validation Service
- Approval Service
- Tool Router
- Timer Service
- Retry Service
- Logging Service
- Metrics Service

---

# Runtime States

Standard run states:

- queued
- initialized
- executing
- waiting
- waiting_for_approval
- waiting_for_processing
- processing
- review
- publishing
- completed
- failed
- retrying
- escalated
- resolved
- cancelled

State changes must generate event records.

---

# Runtime Context Package

Every run begins with a context package.

```json
{
  "run_cid": "",
  "workflow_cid": "",
  "content_cid": "",
  "organization_code": "INF",
  "environment": "PROD",
  "current_date": "",
  "day_of_week": "",
  "timezone": "",
  "platforms": [],
  "memory_context": [],
  "risk_level": "R2",
  "schema_version": "1.0"
}
```

The context package is the runtime source of execution context.

---

# Agent Communication Contract

Agents communicate through structured contracts.

```json
{
  "message_cid": "",
  "from_agent_cid": "",
  "to_agent_cid": "",
  "workflow_cid": "",
  "run_cid": "",
  "message_type": "",
  "payload": {},
  "timestamp": ""
}
```

Message types:

- TASK_REQUEST
- TASK_COMPLETE
- TASK_FAILED
- APPROVAL_REQUEST
- APPROVAL_GRANTED
- APPROVAL_DENIED
- RETRY_REQUEST
- STATUS_UPDATE
- ESCALATION_REQUEST

---

# Queue Management

Every executable task enters the task queue.

Queue item fields:

- queue_item_cid
- run_cid
- assigned_agent_cid
- priority
- status
- queued_at
- started_at
- completed_at

Priorities:

- P1 Critical
- P2 High
- P3 Normal
- P4 Low

---

# Memory Retrieval

Before execution, agents retrieve relevant memory:

- Operational Memory for content schedule and publishing queue
- Knowledge Memory for brand voice and SOPs
- Decision Memory for approval rules
- Performance Memory for optimization context
- Constitutional Memory for governing standards

Authoritative memory takes priority over model assumptions.

---

# Video Generation Runtime

Video generation is asynchronous.

Flow:

1. Video Agent creates generation prompt.
2. Video Agent submits job to video tool.
3. Job record is created.
4. Timer Service creates polling timer.
5. Monitoring Agent checks status.
6. On completion, Asset Agent stores video.
7. Asset Registry is updated.
8. Workflow resumes.

---

# Timer Contract

```json
{
  "timer_cid": "",
  "run_cid": "",
  "job_cid": "",
  "interval_seconds": 60,
  "max_attempts": 30,
  "attempt_count": 0,
  "status": "active"
}
```

Timer statuses:

- active
- paused
- completed
- expired

---

# Approval Interrupts

Approval gates pause runtime execution.

Flow:

```text
Agent Request
→ Approval Record
→ Human or Authorized Reviewer
→ Approved / Denied / Needs Revision
→ Resume or Stop
```

Approval decisions must be recorded in the Approval Registry.

---

# Tool Routing

Tool actions are routed through the Tool Router.

Before execution, the Tool Router validates:

- Agent permission
- Tool permission
- Risk level
- Approval requirement
- Input contract
- Credential availability

---

# Failure Recovery

All failures follow:

```text
Detect → Classify → Log → Retry → Escalate → Resolve
```

Retryable failures:

- API timeout
- Rate limit
- Temporary processing failure
- Upload retry

Non-retryable failures:

- Missing authority
- Governance violation
- Missing required source data
- Invalid credentials

---

# Observability Requirements

Every run generates:

- Run Record
- Event Records
- Error Records
- Approval Records
- Asset Records
- Publishing Records
- Metric Records
- Completion Report

---

# Runtime Dashboards

Required dashboard categories:

- Workforce Health
- Active Runs
- Failed Runs
- Queue Depth
- Publishing Status
- Agent Performance
- Error Rate
- Approval Latency
- Content Performance

---

# Runtime KPIs

| KPI | Target |
|---|---|
| Workflow Success Rate | >95% |
| Asset Traceability | 100% |
| Publication Accuracy | >99% |
| Approval Compliance | 100% |
| Audit Coverage | 100% |
| Error Capture Rate | 100% |

---

# Canonical Runtime Sequence

```text
Date Context
→ Schedule Discovery
→ Brief Creation
→ Video Prompt Creation
→ Video Generation
→ Video Monitoring
→ Asset Registration
→ Metadata Creation
→ Thumbnail Creation
→ Approval Gate if Required
→ Publishing
→ Performance Collection
→ Logging
→ Completion Report
```

---

# Compliance Requirements

The runtime is compliant when:

- All runs create run records
- All tasks enter queue or are otherwise traceable
- All agent messages use contracts
- All tool actions are routed and logged
- All async jobs use timers or equivalent monitoring
- All failures are captured
- All approvals are recorded
- All assets are registered
- All metrics link to source records

---

# Prime Directive

A runtime is NCF-compliant only when execution is observable, governed, traceable, recoverable, and auditable from start to finish.
