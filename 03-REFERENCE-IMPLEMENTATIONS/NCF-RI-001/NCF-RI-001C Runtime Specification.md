# NCF-RI-001C Runtime Specification v1.0

## Purpose

Defines how the Infinity Loop Content Workforce executes work in production.

## Runtime Architecture

The workforce executes as an event-driven orchestration system.

```text
Content Orchestrator
        ↓
Task Queue
        ↓
Specialist Agents
        ↓
Asset Storage
        ↓
Publishing
        ↓
Performance Tracking
```

## Runtime States

- queued
- initialized
- executing
- waiting
- processing
- review
- publishing
- completed
- failed
- retrying
- escalated
- resolved

## Runtime Context Package

```json
{
  "run_cid": "",
  "workflow_cid": "",
  "content_cid": "",
  "organization_code": "INF",
  "current_date": "",
  "day_of_week": "",
  "timezone": "",
  "platforms": [],
  "memory_context": [],
  "risk_level": "R2"
}
```

## Agent Communication Contract

Agents communicate through contracts, not loose chat messages.

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

## Message Types

- TASK_REQUEST
- TASK_COMPLETE
- TASK_FAILED
- APPROVAL_REQUEST
- APPROVAL_GRANTED
- APPROVAL_DENIED
- RETRY_REQUEST
- STATUS_UPDATE

## Video Generation Runtime

Video generation is asynchronous.

Flow:

1. Video Agent submits generation request.
2. Video job enters processing.
3. Timer is created.
4. Monitoring Agent polls status.
5. On completion, Asset Agent stores and registers the file.

## Timer Contract

```json
{
  "timer_cid": "",
  "job_cid": "",
  "interval_seconds": 60,
  "max_attempts": 30
}
```

## Failure Recovery

Detect → Classify → Log → Retry → Escalate → Resolve

## Runtime KPIs

- Workflow Success Rate > 95%
- Asset Traceability 100%
- Publication Accuracy > 99%
- Approval Compliance 100%
- Audit Coverage 100%
