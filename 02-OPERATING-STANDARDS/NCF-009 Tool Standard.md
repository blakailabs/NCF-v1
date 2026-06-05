# NCF-009 Tool Standard v1.1 Enterprise Edition

## Status

Approved / Ratified Foundation — Expanded Enterprise Draft

## Parent Authority

- NCF-001 Constitution
- NCF-002 Enterprise Architecture
- NCF-006 Governance Standard
- NCF-007 Agent Standard
- NCF-008 Workflow Standard

---

# Executive Summary

The NCF Tool Standard governs how agents and workflows safely interact with external systems, applications, APIs, services, platforms, databases, files, and infrastructure.

Tools give agents operational capability.

Because tools can create, modify, publish, deploy, delete, communicate, spend, or expose information, tool use must be governed with the same rigor as identity, memory, data, and workflows.

NCF defines tools as controlled resources. Agents do not own tools. Agents receive permissions to use tools under delegated authority.

---

# Article I — Constitutional Definition

A Tool is an external capability used by an agent or workflow to perform work.

Examples:

- Gmail
- Google Drive
- GitHub
- Vercel
- Stripe
- YouTube
- Instagram
- Facebook
- CRMs
- Databases
- APIs
- Cloud storage
- Schedulers
- Conversion services

A tool is not an agent.

A tool is not a workflow.

A tool is an external capability governed by access rules.

---

# Article II — Tool Governance Principles

## Principle 1 — Tools Are Resources

Tools are organizational resources that may be accessed by agents under permission.

## Principle 2 — Agents Receive Permissions

Agents receive tool access through approved tool profiles.

## Principle 3 — Every Tool Action Is Traceable

Tool actions must be attributable to an agent, workflow, run, authority, and timestamp.

## Principle 4 — Least Privilege Applies

Agents receive the minimum tool permissions required to perform their role.

## Principle 5 — Credentials Belong to Organizations

Agents do not own credentials. Credentials are organization-controlled secrets.

---

# Article III — Tool Categories

NCF recognizes the following tool categories:

## Communication

Email, messaging, chat, notifications.

Examples: Gmail, Slack, Teams, Discord, Telegram.

## Storage

Files, objects, folders, documents, and backups.

Examples: Google Drive, Dropbox, S3.

## Publishing

Public or external distribution platforms.

Examples: YouTube, Facebook, Instagram, LinkedIn.

## Development

Code, repositories, deployments, testing, and infrastructure.

Examples: GitHub, GitLab, Vercel.

## Finance

Payments, invoicing, accounting, billing.

Examples: Stripe, QuickBooks.

## Analytics

Dashboards, BI, performance tracking.

Examples: GA4, Looker, Power BI.

## Research

Search, internal knowledge bases, public information, document repositories.

## Operations

CRMs, helpdesks, project management, ticketing, workflow systems.

---

# Article IV — Tool Authority Levels

## T1 — Read Only

Query, search, view, retrieve.

## T2 — Create

Create new documents, records, drafts, files, or tasks.

## T3 — Modify

Update, edit, move, transform, convert, or annotate existing resources.

## T4 — Execute

Send, publish, deploy, trigger, upload, post, or run externally visible actions.

## T5 — Administrative

Manage credentials, delete resources, modify permissions, configure systems, or perform administrative operations.

T5 requires strict human governance.

---

# Article V — Tool Registry

Every governed tool must be registered.

## Required Fields

| Field | Type | Description |
|---|---|---|
| tool_cid | CID | Tool constitutional identifier |
| tool_uid | UID | Universal identifier |
| tool_name | STRING | Human-readable name |
| tool_category | ENUM | Tool category |
| owner_cid | CID | Accountable owner |
| status | ENUM | Draft, Active, Suspended, Retired |
| risk_level | ENUM | Default tool risk |
| credential_owner | STRING | Credential authority |
| audit_required | BOOLEAN | Whether audit logging is required |

---

# Article VI — Tool Access Profile

Every agent must define a Tool Access Profile.

Example:

```json
{
  "agent_cid": "NCF-INF-AGT-PUBLISH-PROD-000001",
  "tools": [
    {
      "tool_name": "YouTube",
      "tool_permission": "T4",
      "allowed_actions": ["upload_video", "publish_video"],
      "approval_required": true
    }
  ]
}
```

---

# Article VII — Tool Invocation Contract

Every tool action should create a Tool Invocation Record.

```json
{
  "tool_action_cid": "",
  "agent_cid": "",
  "workflow_cid": "",
  "run_cid": "",
  "tool_cid": "",
  "action": "",
  "risk_level": "",
  "status": "",
  "timestamp": ""
}
```

---

# Article VIII — Tool Risk Classification

## Low Risk

Read-only actions.

## Medium Risk

Create or modify internal records.

## High Risk

Public-facing execution such as publishing or customer messaging.

## Critical Risk

Financial, legal, security, credential, deletion, or production deployment actions.

---

# Article IX — Credential Governance

Credentials must be:

- Owned by the organization
- Stored securely
- Scoped to minimum necessary permissions
- Rotated according to policy
- Audited
- Revoked when no longer needed

Agents must never store raw credentials in memory, prompts, logs, outputs, or files.

---

# Article X — Tool Safety Validation

Before tool execution, systems must validate:

- Agent permission
- Tool status
- Workflow authority
- Risk level
- Approval requirements
- Input contract
- Credential availability
- Governance conflicts

---

# Article XI — Tool Failure Framework

Tool failures include:

- Authentication failure
- Permission failure
- API failure
- Rate limit failure
- Validation failure
- Dependency failure
- Timeout
- Partial completion

Failure handling:

```text
Detect → Log → Retry → Escalate → Resolve
```

---

# Article XII — Tool Audit Requirements

Every significant tool action must produce:

- Event Record
- Run Record
- Audit Record
- Error Record when applicable

Audit must answer:

- Which agent used the tool?
- Which workflow authorized it?
- Which run executed it?
- What changed?
- What was the result?

---

# Article XIII — Tool Bundles

Organizations may define tool bundles.

## Content Bundle

- Google Drive
- Google Sheets
- YouTube
- Facebook
- Instagram
- CloudConvert

## Sales Bundle

- CRM
- Gmail
- Calendar
- LinkedIn

## Development Bundle

- GitHub
- Vercel
- Monitoring

Bundles do not override permission rules.

---

# Article XIV — Infinity Loop Example

The Infinity Loop Content Workforce uses:

| Tool | Category | Permission |
|---|---|---|
| Google Sheets | Storage / Operations | T3 |
| Google Drive | Storage | T3 |
| Video Generator | Content | T4 |
| CloudConvert | Operations | T3 |
| YouTube | Publishing | T4 |
| Facebook | Publishing | T4 |
| Instagram | Publishing | T4 |

Publishing actions are R2 Customer Facing and may require approval depending on policy.

---

# Article XV — Tool Compliance Checklist

A tool integration may be NCF-compliant if it includes:

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

# Prime Directive

Agents perform work.

Workflows organize work.

Tools execute work.

Every tool interaction must be authorized, governed, auditable, and traceable.
