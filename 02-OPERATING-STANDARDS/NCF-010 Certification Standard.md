# NCF-010 Certification Standard v1.1 Enterprise Edition

## Status

Approved / Ratified Foundation — Expanded Enterprise Draft

## Parent Authority

All ratified NCF standards.

---

# Executive Summary

The NCF Certification Standard defines how organizations, agents, workflows, tools, memory systems, data architectures, and reference implementations are evaluated for conformity with the Nexus Constitutional Framework.

Certification provides evidence of compliance.

Certification does not guarantee business success, model quality, revenue performance, or operational perfection.

Certification verifies that an implementation follows NCF governance, identity, memory, data, agent, workflow, tool, audit, and reporting requirements.

---

# Article I — Certification Principles

## Principle 1 — Evidence Over Claims

Certification requires documented evidence.

Unverified claims of compliance are insufficient.

## Principle 2 — Certification Is Auditable

Certification decisions must be traceable through records, reviewers, evidence, scores, and outcomes.

## Principle 3 — Certification May Be Revoked

Certification is not permanent if an implementation violates constitutional requirements.

## Principle 4 — Constitutional Compliance Supersedes Convenience

Implementation difficulty does not justify bypassing constitutional standards.

---

# Article II — Certification Levels

## Level 1 — NCF-Compatible

Uses NCF concepts or terminology but does not fully implement required standards.

## Level 2 — NCF-Compliant

Meets minimum constitutional requirements.

## Level 3 — NCF-Verified

Has been reviewed and evidence has been validated.

## Level 4 — NCF-Certified

Passed full certification review and is eligible for official designation.

---

# Article III — Certification Targets

Certification may apply to:

- Organizations
- Departments
- Agents
- Workflows
- Tool Integrations
- Memory Systems
- Data Architectures
- Runtime Systems
- Reference Implementations

---

# Article IV — Agent Certification Requirements

An agent must demonstrate:

- CID and UID
- Registered owner
- Mission statement
- KPI set
- Authority class
- Risk classification
- Memory access profile
- Tool access profile
- Workflow portfolio
- Input/output contracts
- Escalation rules
- Reporting rules
- Lifecycle status
- Auditability

---

# Article V — Workflow Certification Requirements

A workflow must demonstrate:

- Workflow CID and UID
- Defined purpose
- Defined owners
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

# Article VI — Tool Certification Requirements

A tool integration must demonstrate:

- Tool registration
- Owner
- Category
- Permission model
- Credential governance
- Audit logging
- Failure handling
- Approval rules
- Risk classification

---

# Article VII — Memory Certification Requirements

A memory system must demonstrate:

- Memory classification
- Retention class
- Ownership
- Access controls
- Versioning
- Lineage
- Retrieval rules
- Governance approvals where required

---

# Article VIII — Data Certification Requirements

A data architecture must demonstrate:

- Registry architecture
- Universal record headers
- Lineage
- Referential integrity
- Retention policies
- Data quality controls
- Schema versioning
- Auditability

---

# Article IX — Evidence Requirements

Certification evidence may include:

- Architecture diagrams
- Registry schemas
- Data dictionaries
- Workflow maps
- Agent profiles
- Tool permission profiles
- Audit logs
- Run records
- Error records
- Approval records
- KPI reports
- Governance Decision Records

---

# Article X — Compliance Scoring

| Score | Status |
|---|---|
| 90-100 | NCF-Certified |
| 75-89 | NCF-Verified |
| 60-74 | NCF-Compliant |
| Below 60 | NCF-Compatible |

Scores should be based on documented requirements, evidence review, and governance assessment.

---

# Article XI — Certification Registry

Every certification must be recorded.

## Required Fields

| Field | Type | Description |
|---|---|---|
| certification_cid | CID | Certification identifier |
| entity_cid | CID | Certified entity |
| certification_level | ENUM | Compatible, Compliant, Verified, Certified |
| issued_by | STRING | Issuing authority |
| issued_at | TIMESTAMP | Issue date |
| expires_at | TIMESTAMP | Expiration date when applicable |
| status | ENUM | Active, Suspended, Revoked, Expired |

---

# Article XII — Revocation

Certification may be revoked for:

- Constitutional violations
- Governance violations
- Security violations
- Fraudulent claims
- Registry tampering
- Memory tampering
- Persistent audit failure
- Unresolved critical risks

Revocation must be recorded in the Certification Registry.

---

# Article XIII — Reference Implementations

Reference Implementations are canonical examples demonstrating how NCF standards are applied in practice.

## NCF-RI-001

Infinity Loop Content Workforce

Status: Candidate Reference Implementation

Reference Implementations should include:

- Workforce specification
- Registry mapping
- Runtime specification
- Agent contracts
- Data contracts
- Deployment blueprint
- Governance model
- Compliance checklist

---

# Article XIV — Certification Lifecycle

```text
Candidate → Review → Evidence Submitted → Scored → Certified / Rejected → Monitored → Renewed / Revoked
```

---

# Article XV — Certification Limits

Certification does not certify:

- Business profitability
- Model reasoning quality
- Market success
- Legal sufficiency
- Regulatory compliance outside NCF
- Absence of all risk

Certification only verifies adherence to NCF requirements.

---

# Prime Directive

Certification is the mechanism through which trust is established.

An organization may claim compliance.

Certification provides evidence.

NCF requires evidence.
