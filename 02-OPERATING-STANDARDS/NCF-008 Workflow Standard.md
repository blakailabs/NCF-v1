# NCF-008 Workflow Standard v1.1 Enterprise Edition

## Status

Approved / Ratified Foundation — Expanded Enterprise Draft

## Parent Authority

- NCF-001 Constitution
- NCF-002 Enterprise Architecture
- NCF-005 Data Standard
- NCF-006 Governance Standard
- NCF-007 Agent Standard

---

# Executive Summary

The NCF Workflow Standard defines how work is requested, planned, executed, validated, approved, delivered, logged, and improved inside NCF-compliant autonomous AI workforces.

Agents define responsibility.

Workflows define execution.

A workflow is the governed operational structure through which agents produce measurable outcomes.

Without workflow standards, agents improvise.

With workflow standards, agents execute repeatable, auditable, measurable processes.

---

# Article I — Constitutional Definition

A workflow is a governed sequence of activities performed by one or more agents to achieve a measurable outcome.

A workflow is not:

- An agent
- A prompt
- A tool
- A memory object
- A one-off task

A workflow is the operational process through which agents perform work.

---

# Article II — Mandatory Workflow Components

Every NCF workflow must define:

1. Workflow CID
2. Workflow UID
3. Workflow name
4. Workflow class
5. Business owner
6. Agent owner
7. Purpose
8. Inputs
9. Outputs
10. States
11. KPIs
12. Risk classification
13. Approval gates
14. Escalation rules
15. Error handling
16. Logging requirements
17. Completion criteria
18. Version
19. Lifecycle status

---

# Article III — Workflow Classes

## Strategic Workflow

Long-term planning or strategic decision workflows.

Examples:

- Annual planning
- Content strategy
- Product roadmap planning

## Operational Workflow

Repeatable business execution workflows.

Examples:

- Content production
- Customer onboarding
- Lead qualification

## Transactional Workflow

Single-outcome workflows.

Examples:

- Publish video
- Create invoice
- Send approved email

## Utility Workflow

Support workflows used by other workflows.

Examples:

- Date context generation
- Data validation
- Memory retrieval
- Logging

---

# Article IV — Workflow Lifecycle

```text
Draft → Approved → Active → Executing → Completed → Archived
```

Failure path:

```text
Executing → Failed → Retry → Escalate → Resolved
```

No workflow may bypass lifecycle governance.

---

# Article V — Runtime States

Standard runtime states:

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
- cancelled

Custom states require governance approval.

---

# Article VI — Workflow Inputs

Inputs must be:

- Structured
- Validated
- Traceable
- Versioned when necessary
- Linked to source records

Required input contract fields:

- workflow_cid
- run_cid
- requesting_agent_cid
- payload
- source_cid
- schema_version

---

# Article VII — Workflow Outputs

Outputs must be:

- Deliverable
- Verifiable
- Traceable
- Registered
- Linked to the run record

Outputs may include:

- Assets
- Records
- Messages
- Approvals
- Reports
- Metrics
- Tool results

---

# Article VIII — Workflow Ownership

Every workflow must identify:

## Business Owner

Responsible for business outcome.

## Agent Owner

Responsible for workflow execution.

## Governance Owner

Responsible for compliance.

No owner = no production workflow.

---

# Article IX — Workflow Validation

Before execution, workflows must validate:

- Inputs
- Required memory
- Agent permissions
- Tool permissions
- Risk level
- Required approvals
- Data contracts
- Dependencies

Invalid workflows must stop and return validation errors.

---

# Article X — Workflow Handoffs

Agent handoffs must use structured contracts.

Minimum handoff schema:

```json
{
  "handoff_cid": "",
  "from_agent_cid": "",
  "to_agent_cid": "",
  "workflow_cid": "",
  "run_cid": "",
  "handoff_type": "",
  "payload": {},
  "timestamp": ""
}
```

No workflow may rely on hidden context.

---

# Article XI — Approval Gates

Approval gates pause workflow execution until approval is granted or denied.

Approval gate examples:

- Content Review
- Legal Review
- Security Review
- Financial Review
- Executive Approval
- Constitutional Approval

Approval decisions must be recorded in the Approval Registry.

---

# Article XII — Error Handling

Workflow failures must follow:

```text
Detect → Classify → Log → Retry → Escalate → Resolve
```

Retryable failures include:

- Temporary API failures
- Rate limits
- Processing delays
- Upload failures

Non-retryable failures include:

- Missing authority
- Invalid credentials
- Governance violations
- Missing required source data
- Constitutional conflicts

---

# Article XIII — Workflow Observability

Every workflow must generate:

- Run Records
- Event Records
- Error Records
- Approval Records
- Asset Records when applicable
- Metric Records when applicable
- Completion Reports

---

# Article XIV — Workflow Lineage

Workflows must preserve lineage across:

- Parent workflows
- Child workflows
- Runs
- Assets
- Events
- Metrics
- Approvals

Lineage allows any output to be traced back to the workflow, run, agent, memory, and approval that produced it.

---

# Article XV — Workflow Composition

Workflows may be composed of sub-workflows.

Example:

```text
Content Production
    ├── Schedule Discovery
    ├── Brief Creation
    ├── Video Generation
    ├── Metadata Generation
    ├── Publishing
    └── Performance Tracking
```

Composed workflows must preserve parent-child lineage.

---

# Article XVI — Workflow Quality Framework

Workflows should be evaluated for:

- Accuracy
- Completeness
- Efficiency
- Reliability
- Compliance
- Outcome achievement
- Human intervention rate
- Error rate

---

# Article XVII — Infinity Loop Example

NCF-RI-001 uses the following master workflow:

```text
Date Context
→ Schedule Lookup
→ Brief Creation
→ Video Prompt Creation
→ Video Generation
→ Video Monitoring
→ Asset Registration
→ Metadata Creation
→ Thumbnail Creation
→ Publishing
→ Performance Collection
→ Logging
```

This workflow demonstrates:

- Multi-agent orchestration
- Asynchronous job monitoring
- Public publishing governance
- Asset lineage
- Metrics tracking
- Runtime observability

---

# Article XVIII — Workflow Compliance Checklist

A workflow may be considered NCF-compliant if it has:

- CID and UID
- Defined owner
- Defined purpose
- Structured inputs
- Structured outputs
- Lifecycle states
- Risk classification
- Approval gates
- Error handling
- Logging
- KPI tracking
- Lineage
- Completion criteria

---

# Prime Directive

Agents define responsibility.

Workflows define execution.

Organizations scale through repeatable workflows, not isolated actions.
