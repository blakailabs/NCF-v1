# NCF-007 Agent Standard v1.1 Enterprise Edition

## Status

Approved / Ratified Foundation — Expanded Enterprise Draft

## Parent Authority

- NCF-001 Constitution
- NCF-002 Enterprise Architecture
- NCF-003 Identity & Authority Standards
- NCF-004 Memory Standard
- NCF-005 Data Standard
- NCF-006 Governance Standard

---

# Executive Summary

The NCF Agent Standard defines what an agent is, how an agent is governed, how an agent is registered, what an agent may do, what an agent must report, and what makes an agent production-ready.

Most AI systems define an agent as a model with tools.

NCF rejects that definition.

Under NCF, an agent is a governed organizational entity operating under delegated authority for the purpose of achieving measurable outcomes.

A model may power an agent.

A prompt may instruct an agent.

A workflow may coordinate an agent.

A tool may extend an agent.

But none of these alone constitute an NCF Agent.

---

# Article I — Constitutional Definition

An NCF Agent is a governed organizational entity with identity, mission, authority, memory access, tool access, workflows, KPIs, and accountability.

An agent is not:

- A prompt
- A model
- A workflow
- A tool
- A script
- A chatbot

Those may be implementation components.

The agent itself is the accountable operational entity.

---

# Article II — Mandatory Agent Components

Every NCF Agent must have:

1. Agent CID
2. Agent UID
3. Agent name
4. Agent type
5. Mission
6. Business owner
7. Technical owner
8. Governance owner
9. Authority class
10. Risk classification
11. Primary KPI
12. Secondary KPIs
13. Memory access profile
14. Tool access profile
15. Workflow portfolio
16. Escalation rules
17. Reporting requirements
18. Lifecycle status
19. Version
20. Compliance status

---

# Article III — Agent Types

## Executive Agent

Coordinates departments and supports strategic execution.

Examples:

- Chief of Staff Agent
- COO Agent
- Strategic Planning Agent

## Department Agent

Manages a functional business area.

Examples:

- Marketing Agent
- Sales Agent
- Operations Agent
- Content Orchestrator

## Specialist Agent

Performs expert work within a defined domain.

Examples:

- Research Agent
- Metadata Agent
- Analytics Agent
- CRM Agent

## Workflow Agent

Executes a repeatable operational task.

Examples:

- Publishing Agent
- Thumbnail Agent
- Video Monitoring Agent

## Utility Agent

Provides reusable services.

Examples:

- Date Context Agent
- Validation Agent
- Logging Agent

## Constitutional Utility Agent

Supports governance, observability, identity, registry integrity, or runtime safety.

Examples:

- Audit Agent
- Registry Validation Agent
- Approval Agent
- Retry Agent

---

# Article IV — Agent Lifecycle

```text
Draft → Testing → Approved → Active → Suspended → Retired
```

## Draft

Agent is being designed.

## Testing

Agent is evaluated in non-production conditions.

## Approved

Agent has passed governance review.

## Active

Agent may operate in production.

## Suspended

Agent is temporarily disabled.

## Retired

Agent is permanently removed from active operation.

No agent may bypass lifecycle governance.

---

# Article V — Autonomy Levels

## Level 1 — Assistant

May research, draft, summarize, and recommend.

May not execute external actions.

## Level 2 — Operator

May execute approved low-risk operational actions.

## Level 3 — Specialist

May manage domain-specific workflows.

## Level 4 — Manager

May coordinate multiple agents and workflows.

## Level 5 — Executive

May coordinate departments and prioritize organizational execution under human-defined strategy.

Autonomy does not eliminate accountability.

---

# Article VI — Agent Ownership

Every agent must identify:

## Business Owner

Responsible for outcomes.

## Technical Owner

Responsible for implementation and reliability.

## Governance Owner

Responsible for compliance and risk.

No owner = no production deployment.

---

# Article VII — Agent Mission and KPI

Every agent must have a mission statement and measurable success criteria.

## Required Metrics

- Primary KPI
- Secondary KPI
- Operational KPI
- Failure KPI

Example:

```text
Agent: Publishing Agent
Primary KPI: Successful platform posts
Operational KPI: Publishing accuracy
Failure KPI: API publishing failures
```

---

# Article VIII — Agent Memory Access Profile

Each agent must declare access to memory classes:

- Working Memory
- Operational Memory
- Knowledge Memory
- Decision Memory
- Performance Memory
- Institutional Memory
- Constitutional Memory

Access must specify:

- Read
- Write
- Modify
- Approve
- Archive

Constitutional Memory access requires explicit governance approval.

---

# Article IX — Agent Tool Access Profile

Agents may only use approved tools.

Tool access must define:

- Tool name
- Tool CID
- Permission level
- Allowed actions
- Prohibited actions
- Risk classification
- Credential boundary

Agents do not own credentials.

Credentials belong to the organization.

---

# Article X — Agent Workflow Portfolio

Every agent must define which workflows it may participate in.

A workflow portfolio should include:

- Workflow CID
- Role in workflow
- Input contract
- Output contract
- Validation responsibilities
- Escalation responsibilities

---

# Article XI — Agent Communication

Agents must communicate through structured contracts rather than hidden context or informal messages.

Minimum message header:

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

---

# Article XII — Agent Validation Responsibilities

Agents must validate:

- Required inputs
- Memory freshness
- Data contracts
- Tool permissions
- Risk level
- Output completeness
- Governance requirements

Invalid inputs must not be silently processed.

---

# Article XIII — Agent Reporting Requirements

Agents must produce:

- Activity records
- Error records
- Completion reports
- KPI updates
- Audit events when applicable

Agents may not claim completion without verifiable output or tool confirmation.

---

# Article XIV — Agent Failure Handling

Agent failures must follow:

```text
Detect → Log → Retry → Escalate → Resolve
```

Failure categories include:

- Tool Failure
- Data Failure
- Memory Failure
- Governance Failure
- Workflow Failure
- Approval Failure
- Model Failure

---

# Article XV — Agent Compliance Checklist

An agent may be designated NCF-Compliant if it has:

- CID and UID
- Registered owner
- Mission
- KPI
- Authority class
- Risk classification
- Memory profile
- Tool profile
- Workflow portfolio
- Input/output contracts
- Escalation rules
- Reporting requirements
- Lifecycle status
- Auditability

---

# Article XVI — Infinity Loop Example

## Content Orchestrator

Type: Department Agent

Authority: A3 Managerial

Mission: Coordinate the full Infinity Loop content production and publishing lifecycle.

Primary KPI: Content Published

Memory Access:

- Operational Memory: Read/Write
- Knowledge Memory: Read
- Decision Memory: Read
- Performance Memory: Read/Write

Tool Access:

- Google Sheets
- Google Drive
- YouTube
- Facebook
- Instagram
- CloudConvert

Escalates when:

- Schedule is missing
- Publishing fails
- Risk exceeds R2
- Governance conflict exists

---

# Prime Directive

An Agent is not defined by the model it uses.

An Agent is defined by identity, mission, authority, accountability, and outcomes.

Models execute work.

Agents own responsibility.
