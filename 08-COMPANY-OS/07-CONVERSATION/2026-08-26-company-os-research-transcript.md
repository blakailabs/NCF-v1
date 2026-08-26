# Company OS / CFHS / CDM Development Conversation

**Date:** 2026-08-26
**Status:** Sanitized project transcript

## Sanitization note

This transcript preserves the project reasoning, decisions, and user direction necessary to continue the work. It intentionally excludes credentials, secret values, private account identifiers, unrelated personal knowledge, and tool-internal metadata. No API keys, tokens, passwords, or private keys are included.

---

## 1. Starting point — autonomous company platforms

**User:** Provided a summary of Polsia AI as an autonomous business platform, including its ability to plan, code, market, research competitors, build websites, perform outreach, and run businesses. The user highlighted mixed feedback, aggressive pricing, support concerns, inconsistent results, and suitability for experienced entrepreneurs.

**Assistant:** Confirmed the broad characterization and focused on a deeper opportunity: the architecture of an AI-native company operating system rather than simply whether one autonomous-company product is worthwhile.

---

## 2. Research an AI-native Company Operating System

**User:** “Let’s research an AI-native company operating system. That model is worth dissecting because there are several ways to build a substantially better version without necessarily taking 20% of a customer’s company revenue.”

**Assistant — resulting direction:** The category was reframed as a governed operating layer where humans set strategy, policy, budgets, and authority while AI workers execute continuously inside those boundaries.

Concepts proposed at this stage included a Company Constitution, Company Graph, machine-readable role contracts, Authority Engine, reversible autonomy levels, Company Action Ledger, Company Learning Loop, outcome scoreboards, human-board/AI-operations model, customer-owned infrastructure, and subscription/usage/marketplace economics.

The main conclusion was that the defensible opportunity is not “more agents” but the management system governing autonomous economic activity.

---

## 3. Hierarchy and inheritance discussion

**User:** Asked whether Google has an “OKP” framework for folders.

**Assistant:** Distinguished objectives/planning frameworks from Google Cloud-style resource hierarchy and policy inheritance. The useful insight was hierarchical policy inheritance: restrictions and authority should propagate downward while child scopes can become more restrictive.

---

## 4. Architectural correction — use an operating system as the north star

**User:** “I think we’re going about this the wrong way. I think we need to look at file structure of an operating system and let that be our guiding star.”

**Assistant:** Agreed and made the central correction: we had been designing an AI organization and calling it an operating system.

An actual operating system starts with primitives such as files, processes, users, permissions, memory/state, devices, services, scheduling, communication, execution, configuration, packages, and logs.

Departments became applications rather than system primitives.

The Company OS root was modeled after a Unix/Linux-style hierarchy and expanded to include virtual `/proc` and `/sys` plus a clear kernel/user-space boundary.

Key analogy decisions:

- `/etc` → company configuration / constitution / policy
- `/bin` → essential commands
- `/lib` → shared capabilities
- `/dev` → external system interfaces
- `/mnt` → mounted external knowledge/data systems
- `/home` → human and AI workspaces
- `/proc` → active company processes
- `/run` → transient runtime state
- `/var` → mutable persistent company state
- `/var/log` → action/audit logs
- `/var/spool` → queues
- `/tmp` → disposable AI scratch space
- `/opt` → installable business packages/apps

A sudo analogy was adopted for privileged business actions requiring temporary approval/elevation.

---

## 5. Goal defined — CFHS and Company Kernel

**User:** Defined the goal explicitly: create a Company Filesystem Hierarchy Standard and Company Kernel specification covering root directories, object types, permissions, process lifecycle, IPC/events, device abstraction, persistence, logs, packages, boot/shutdown, failure recovery, and the boundary between kernel space and business/user space.

**Assistant:** Produced CFHS + Company Kernel v0.1.

Constitutional principles established:

1. The root is universal.
2. AI is user space, not kernel space.
3. Default deny.
4. No omnipotent AI root account.
5. Policy constrains intelligence.
6. Child restrictions may tighten but not escape parent limits.
7. External side effects are kernel mediated.
8. Consequential actions are attributable.

Kernel scope established identity, authorization, capabilities, policy, processes, scheduling, resource control, device/secret brokering, namespace/mounts, IPC/events, persistence, audit, package verification, and recovery.

Golden rule:

> A user-space application may request an action. Only the kernel may authorize and mediate a privileged action.

---

## 6. What is required to populate the company filesystem?

**User:** Asked what information would be needed to map every file, photo, system, process, and datum so the Company OS could function completely.

**Assistant:** Defined the need for a Company Discovery Manifest rather than a folder questionnaire.

Required discovery domains included company identity, legal structure, humans/agents/roles/authority, systems, repositories, data classification, business objects, processes, events, state machines, policies, budgets/resources, applications, capabilities, schedules, communications, documents, media, vendors, compliance, continuity, sources of truth, provenance, decisions, metrics, and exceptions.

Three acquisition modes were established:

1. automatically discover;
2. infer and ask for validation;
3. explicit human declaration.

---

## 7. Company Discovery Manifest Specification v0.1

**User:** Requested a CDM specification defining every question, field, connector scan, artifact request, inference rule, completeness test, and mapping rule necessary to turn an existing company into CFHS automatically.

**Assistant:** Produced CDM v0.1.

Core discovery sequence:

```text
OBSERVE → CORROBORATE → INFER → ASK → CONFIRM
```

Lifecycle:

```text
D0 INIT → D1 DECLARE → D2 CONNECT → D3 DISCOVER → D4 INGEST
→ D5 NORMALIZE → D6 CORRELATE → D7 INFER → D8 RESOLVE
→ D9 CLASSIFY → D10 MAP → D11 VALIDATE → D12 MATERIALIZE
→ D13 BOOT-TEST → D14 CERTIFY
```

Evidence authority:

```text
A5 LEGALLY AUTHORITATIVE
A4 SYSTEM OF RECORD
A3 AUTHORIZED HUMAN DECLARATION
A2 OFFICIAL COMPANY DOCUMENT
A1 BEHAVIORAL OBSERVATION
A0 INFERENCE
```

Important rule: nothing inferred becomes canonical merely because AI is confident. High-impact legal, financial, authority, deletion/retention, source-of-truth, regulated-data, or secret-scope facts require authoritative evidence or explicit confirmation.

Certification levels:

```text
CDM-0 DISCOVERED
CDM-1 MAPPED
CDM-2 BOOTABLE
CDM-3 OPERABLE
CDM-4 GOVERNED
CDM-5 AUTONOMY-READY
```

---

## 8. Machine Contract Package

**User:** Requested actual JSON Schemas for all CDM object types, connector interface specification, inference-rule format, mapping-rule DSL, validation rules, certification test suite, and a sample `company.cdm.yaml`.

**Assistant:** Created and validated `cdm-machine-contract-v0.1` with schemas, specs, rules, question/artifact catalogs, examples, tests/fixtures, certification logic, and a validation script.

The package deliberately separates structural/schema validity from operational/certification validity.

---

## 9. Integrating with NCF

**User:** Requested connection to GitHub and a commit to a new branch of the NCF framework.

**User follow-up:** “include the conversation and knowledgebase. do not commit keys/sensitive data.”

Repository decision:

- use `blakailabs/NCF-v1`;
- preserve existing NCF constitutional structure;
- add Company OS as a new experimental extension namespace;
- include this sanitized conversation transcript;
- include a canonical project knowledge base;
- include the complete machine-contract source package;
- exclude keys, credentials, secret values, private account metadata, and unrelated personal information.

---

## Canonical decisions from this conversation

1. Company OS is an operating-system architecture, not an agent org chart.
2. CFHS uses universal filesystem/runtime primitives.
3. Departments and domain concepts are applications.
4. AI agents are user-space processes.
5. The kernel owns authorization and privileged mediation.
6. External systems are devices or mounts.
7. Raw credentials are never part of manifests or agent context.
8. CDM discovers reality before CFHS materializes it.
9. Inference is evidence-bearing and non-canonical until appropriately confirmed.
10. Completeness is scoped and certification-based.
11. NCF remains the constitutional framework; Company OS is an experimental runtime extension beneath/alongside it.
