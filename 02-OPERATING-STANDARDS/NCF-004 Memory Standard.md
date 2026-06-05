# NCF-004 Memory Standard v1.1 Enterprise Edition

## Status

Approved / Ratified Foundation — Expanded Enterprise Draft

## Parent Authority

- NCF-001 Constitution
- NCF-002 Enterprise Architecture
- NCF-003 Identity & Authority Standards

---

# Executive Summary

The NCF Memory Standard governs how autonomous AI workforces remember, retrieve, preserve, validate, share, and evolve organizational intelligence.

NCF treats memory as a first-class constitutional asset.

Most AI systems treat memory as optional context, chat history, vector retrieval, or implementation detail.

NCF defines memory as governed organizational infrastructure.

A workforce without governed memory becomes stateless, inconsistent, repetitive, and difficult to audit.

A workforce with governed memory can preserve decisions, retrieve knowledge, compare performance, avoid duplicate work, and maintain institutional continuity across model changes, employee turnover, vendor changes, and system migrations.

---

# Constitutional Principle

## Organizational Memory Outlives Individuals

Humans leave.

Agents are upgraded.

Models change.

Vendors change.

Memory remains.

NCF memory exists to preserve institutional intelligence independent of any single person, model, platform, or tool.

---

# Article I — Purpose

The purpose of the Memory Standard is to define:

- Memory classes
- Memory ownership
- Memory lifecycle
- Memory retrieval rules
- Memory promotion rules
- Memory governance
- Memory retention
- Memory lineage
- Memory access controls
- Memory quality standards
- Constitutional memory protections

---

# Article II — Memory Classes

NCF recognizes seven memory classes:

1. Working Memory
2. Operational Memory
3. Knowledge Memory
4. Decision Memory
5. Performance Memory
6. Institutional Memory
7. Constitutional Memory

These memory classes are not interchangeable.

Each class has a distinct purpose, lifecycle, owner, retention requirement, and governance model.

---

# Article III — Working Memory

## Definition

Working Memory is temporary execution memory used during an active workflow run.

## Examples

- Current task
- Active run context
- Intermediate outputs
- Temporary calculations
- Transient validation results
- Agent-to-agent handoff context

## Retention

Default retention: End of Run.

Working Memory should be destroyed or archived according to policy once the workflow completes.

## Promotion

Working Memory may be promoted to Operational Memory if it becomes useful beyond the current run.

---

# Article IV — Operational Memory

## Definition

Operational Memory is persistent business memory used to continue active work across runs.

## Examples

- Content schedules
- Active projects
- Customer records
- Publishing queues
- Campaign trackers
- Open tasks
- Work-in-progress records

## Retention

Policy-based.

Operational Memory is retained while operationally relevant.

## Ownership

Usually owned by Department Agents, Department Owners, or Operational Stewards.

---

# Article V — Knowledge Memory

## Definition

Knowledge Memory contains approved reusable knowledge.

## Examples

- SOPs
- Brand voice guides
- Product documentation
- Approved claims
- Content standards
- Sales scripts
- Support policies
- Technical documentation

## Requirements

Knowledge Memory must be:

- Versioned
- Source-attributed
- Approved
- Retrievable
- Reviewable
- Supersedable

---

# Article VI — Decision Memory

## Definition

Decision Memory preserves important organizational decisions and their rationale.

## Examples

- Governance Decision Records
- Architecture decisions
- Strategy changes
- Approval outcomes
- Ratification records
- Policy exceptions

## Purpose

Decision Memory prevents institutional amnesia.

Organizations should not repeatedly solve the same problem without access to prior decisions.

---

# Article VII — Performance Memory

## Definition

Performance Memory stores results and KPI history.

## Examples

- Workflow success rate
- Agent error rate
- Content performance
- Conversion metrics
- Publishing accuracy
- Approval latency
- Retry frequency

## Purpose

Performance Memory enables continuous improvement.

Without Performance Memory, agents cannot learn which processes, assets, workflows, or decisions produced measurable results.

---

# Article VIII — Institutional Memory

## Definition

Institutional Memory preserves organizational identity, history, strategy, principles, and long-term knowledge.

## Examples

- Founding principles
- Organizational structure
- Long-term strategy
- Operating model
- Historical lessons
- Department charters

## Retention

Indefinite unless formally retired.

---

# Article IX — Constitutional Memory

## Definition

Constitutional Memory is the highest-protection subclass of Institutional Memory.

It contains ratified constitutional records.

## Examples

- NCF Constitution
- Ratified NCF Standards
- Governance Decision Records
- Namespace Authority Records
- Certification Records
- Amendment Records

## Retention

Never delete.

Constitutional Memory may be superseded by a newer version but must not be silently altered or removed.

---

# Article X — Memory Registry

Every governed memory object must be registered.

## Required Fields

| Field | Type | Description |
|---|---|---|
| memory_cid | CID | Constitutional memory identifier |
| memory_uid | UID | Universal unique identifier |
| memory_type | ENUM | Working, Operational, Knowledge, Decision, Performance, Institutional, Constitutional |
| memory_name | STRING | Human-readable name |
| owner_cid | CID | Owner or steward |
| source_cid | CID | Source object or authority |
| retention_class | ENUM | Retention classification |
| status | ENUM | Draft, Active, Superseded, Archived, Retired |
| created_at | TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP | Last update timestamp |
| version | STRING | Memory version |

---

# Article XI — Memory Promotion

Memory may be promoted upward when its value increases.

```text
Working → Operational → Knowledge → Institutional → Constitutional
```

## Promotion Examples

A temporary note becomes a task.

A task becomes an SOP.

An SOP becomes a standard.

A standard becomes constitutional memory.

## Promotion Requirements

Promotion requires:

- Owner review
- Source validation
- Governance approval when required
- Registry update
- Version record

---

# Article XII — Memory Retrieval Requirements

Before performing work, agents must retrieve relevant governed memory when available.

Required retrieval may include:

- Operational Memory for current business state
- Knowledge Memory for approved procedures
- Decision Memory for prior governance choices
- Performance Memory for optimization
- Institutional Memory for organizational context

## Rule

Agents should not act solely from model weights when authoritative memory exists.

---

# Article XIII — Memory Access Control

Memory access must follow:

- Least privilege
- Need-to-know
- Role-based access
- Auditability
- Retention policy

## Access Levels

- Read
- Write
- Modify
- Approve
- Archive
- Delete

Delete permissions for Constitutional Memory are prohibited except under formal constitutional retirement procedures.

---

# Article XIV — Memory Quality Framework

All governed memory should be evaluated for:

- Accuracy
- Relevance
- Completeness
- Timeliness
- Traceability
- Authority
- Version clarity

Low-quality memory should not be promoted.

Stale memory must be marked for review.

---

# Article XV — Memory Storage Architecture

NCF does not require a single storage technology.

Memory may be stored in:

- Document stores
- Vector databases
- Relational databases
- Knowledge bases
- File systems
- Git repositories
- CRMs
- Project management systems

However, storage technology does not define memory authority.

The Memory Registry defines authority.

---

# Article XVI — Vector Memory vs Constitutional Memory

Vector retrieval is an access method.

It is not governance.

Embeddings may help retrieve memory, but they do not replace:

- Source records
- Version control
- Ownership
- Approval
- Retention class
- Auditability

---

# Article XVII — Memory Lineage

Every memory object should support lineage.

Required lineage fields:

- memory_cid
- parent_cid
- source_cid
- lineage_root_cid
- created_by_agent_cid

Lineage allows an organization to determine where memory came from, why it exists, and which authority created it.

---

# Article XVIII — Infinity Loop Example

## Working Memory

Current content run context.

## Operational Memory

Content calendar, publishing queue, current campaign tracker.

## Knowledge Memory

Brand voice, video prompt standards, platform publishing SOPs.

## Decision Memory

Ratified content strategy choices and approval rules.

## Performance Memory

Views, CTR, watch time, saves, shares, comments, and conversions.

## Institutional Memory

Infinity Loop mission, content principles, and operating model.

## Constitutional Memory

NCF standards governing the Infinity Loop workforce.

---

# Prime Directive

Data stores facts.

Memory preserves meaning.

Organizations that fail to govern memory lose institutional intelligence.

Organizations that govern memory create durable, transferable, and scalable intelligence.
