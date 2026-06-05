# NCF-RI-001G Deployment Blueprint v1.0

## Status

Reference Implementation — Deployment Blueprint Draft

## Purpose

Defines how the Infinity Loop Content Workforce can be deployed as an NCF-compliant production system.

---

# Deployment Principle

NCF is vendor-neutral.

The deployment stack may change, but constitutional contracts, registries, identity, governance, and audit requirements must remain stable.

---

# Logical Deployment Architecture

```text
User / Human Approver
        ↓
Task Intake Layer
        ↓
Content Orchestrator Runtime
        ↓
Queue + Event Bus
        ↓
Agent Workers
        ↓
Tool Router
        ↓
External Platforms
        ↓
Registries + Logs + Metrics
```

---

# Core Infrastructure Components

- Agent Runtime
- Registry Database
- Memory Store
- Queue System
- Event Bus
- Scheduler
- Timer Service
- Tool Router
- Approval Service
- Logging Service
- Metrics Dashboard

---

# Suggested Storage Layer

Acceptable implementations include:

- PostgreSQL
- Supabase
- Airtable
- Google Sheets for early prototypes

Production systems should prefer relational storage for registries.

---

# Suggested Memory Layer

Acceptable implementations include:

- Document repository
- Vector database
- Knowledge base
- Git-backed standards repository

Vector memory is retrieval infrastructure, not constitutional authority.

---

# Suggested Runtime Layer

Acceptable implementations include:

- Custom Python runtime
- LangGraph
- CrewAI
- OpenClaw
- n8n
- Make
- Hybrid orchestration stack

---

# Suggested Tool Layer

- Google Sheets for content calendar
- Google Drive for asset storage
- Video generation provider
- CloudConvert or equivalent conversion service
- YouTube publishing API
- Facebook publishing API
- Instagram publishing API

---

# Security Requirements

- Store credentials outside prompts
- Use environment-level secrets
- Scope credentials by tool and action
- Rotate credentials according to policy
- Log tool invocations
- Require approval for high-risk actions

---

# Deployment Environments

- DEV
- TEST
- STAGE
- PROD

Production runs must use PROD CIDs and production registry records.

---

# Minimum Viable Deployment

A minimal deployment may include:

- Google Sheet content calendar
- Google Drive asset storage
- Orchestrator agent
- Content generation agents
- Manual approval step
- Manual or semi-automated publishing
- Registry tables in Sheets or Supabase

---

# Production Deployment

A production deployment should include:

- Dedicated registry database
- Agent runtime service
- Queue service
- Timer service
- Tool router
- Approval service
- Observability dashboard
- Automated backups
- Audit log retention

---

# Compliance Requirements

Deployment is NCF-compliant when:

- Registries are persistent
- Tool credentials are governed
- Runs are logged
- Assets are registered
- Approvals are recorded
- Errors are captured
- Metrics are stored
- Lineage is preserved
- Human override is available

---

# Prime Directive

Deployment technology is replaceable.

Constitutional governance is not.
