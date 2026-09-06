# Company Operating System — Evidence & Structural Fidelity Doctrine

**Status:** constitutional engineering doctrine  
**Applies to:** Company OS architecture, kernel, CFHS, CDM, applications, workflows, AI agents, runtime adapters, and future design decisions

## Purpose

Company OS must be built from **real system structure, verified constraints, and observable organizational reality** rather than from AI metaphors, convenient folder trees, or anthropomorphic agent assumptions.

The operating-system analogy is useful only where it maps to tested computing primitives or real organizational mechanisms.

The rule is:

> **Reality first. Structure second. Automation third. AI last.**

AI is a user-space workload. It does not define truth, authority, organizational reality, or kernel semantics.

---

## 1. Evidence hierarchy

Architecture claims should be classified by evidence strength.

### E1 — Formal standards / specifications

Examples:

- filesystem hierarchy specifications;
- language/runtime specifications;
- networking standards;
- database consistency/isolation contracts;
- security and identity standards;
- accounting/regulatory specifications where applicable.

E1 claims may define canonical low-level primitives when the standard actually covers the behavior being modeled.

### E2 — Authoritative implementation documentation

Examples:

- operating-system kernel documentation;
- database vendor consistency and transaction documentation;
- cloud/provider API contracts;
- identity-provider protocol documentation;
- audited platform guarantees.

E2 evidence may define adapter behavior, but vendor behavior must not silently become universal kernel truth.

### E3 — Empirical research

Examples:

- peer-reviewed human-factors research;
- organizational-behavior research;
- software-engineering experiments;
- reliability/security studies;
- psychometric or human-computer-interaction research.

E3 evidence informs design tradeoffs and human-system behavior. It does not override stronger technical invariants.

### E4 — Proven production pattern

A pattern may be accepted when it is independently observable across mature systems and its assumptions are documented.

Examples:

- capability-based authorization;
- immutable audit records;
- idempotency keys;
- fencing tokens;
- leases with monotonic epochs;
- write-ahead/ordered journals;
- compensating transactions;
- event-driven integration.

### E5 — Design heuristic / analogy

Examples:

- “a company is an operating system”;
- “a workflow is a path through connected files”;
- “departments are applications.”

These can be extremely useful, but they are **not facts merely because they are intuitive**.

An E5 idea must be translated into E1–E4 primitives before becoming a kernel invariant.

---

## 2. Structural fidelity rule

Every modeled object must answer:

```text
What real thing does this represent?
Who/what owns it?
Who/what may mutate it?
What is its source of truth?
What evidence establishes it?
What state can it occupy?
What transitions are legal?
What authority is required for each transition?
What external side effect can occur?
How is that side effect reconciled?
What happens after failure/restart/takeover?
```

If these questions cannot be answered, the object is not ready to become canonical runtime state.

Unknown facts remain explicit unknowns. The system must never invent organizational authority, legal identity, financial limits, policy, ownership, or historical facts.

---

## 3. Workflow-as-connected-state heuristic

The useful insight behind “a workflow is a path through connected files” is preserved as a graph rule:

```text
NODE = durable state/object/document/interface
EDGE = explicit verb/action
ACTOR = principal/process/agent performing or requesting the action
AUTHORITY = capability/policy/approval required for the edge
EVIDENCE = provenance proving the input/state/authority
RESULT = new state + audit/event + optional side effect
```

An arrow without a verb is incomplete.

A verb without an actor is incomplete.

An actor without authority is denied.

A state transition without evidence/audit is not consequentially trustworthy.

A consequential external action without replay protection, reconciliation, and failure semantics is not production-ready.

### Example

```text
request.md
  --reads--> intake context
  --requires--> verified-information manifest
  --invokes--> gap-check capability
  --writes--> gaps.md
  --awaits--> owner review
```

Company OS should generalize this beyond Markdown files. A node may be a file, database object, API resource, queue event, approval, process, device, or mounted external namespace.

The filesystem is therefore a **namespace and coordination model**, not a claim that every real business object must physically be stored as a file.

---

## 4. Human factors are first-class system facts

Programming and organizational execution are human activities as well as technical activities.

Company OS must therefore model human-system realities explicitly:

- role ambiguity;
- authority boundaries;
- approval burden;
- handoffs;
- cognitive load;
- missing information;
- incentive conflicts;
- training/experience differences;
- communication paths;
- exceptions;
- recovery after mistakes;
- confidence and uncertainty.

The kernel should not attempt to “solve psychology.” It should create structures that make authority, state, provenance, work ownership, and failure visible enough for humans and agents to reason about safely.

---

## 5. No magical-agent architecture

Company OS must never depend on an AI agent being:

- always correct;
- continuously available;
- perfectly aligned;
- aware of unstated organizational facts;
- entitled to infer missing authority;
- able to self-grant capabilities;
- trusted to remember critical state only in model context;
- trusted to determine whether its own side effect occurred after an ambiguous failure.

Durable state belongs to the system.

Authority belongs to policy/kernel controls.

External truth comes from authoritative sources and reconciliation.

Agents request work through constrained interfaces.

---

## 6. Company OS mapping discipline

The OS-inspired architecture is valid only where mappings are explicit.

```text
Computing primitive        Company OS interpretation
------------------------   ----------------------------------------------
identity/principal         human, service, agent, workload identity
permissions/capabilities   delegated organizational authority
filesystem namespace      predictable company object/service namespace
process                    bounded executing work instance
scheduler                  policy-controlled allocation/timing of work
IPC/events                 explicit inter-process/business event exchange
device                     controlled external side-effect interface
mount                      connected external namespace/system
configuration              declared operating policy and runtime settings
logs/audit                 durable evidence of execution and decisions
resource limits            money, quota, capacity, rate, risk ceilings
lease/fence                temporary exclusive authority with stale-owner defense
recovery                    restart, retry, reconciliation, compensation
package/application        installable domain/business capability
```

Business nouns remain application semantics unless they truly represent universal kernel primitives.

---

## 7. Architecture decision evidence record

Any major new kernel/runtime primitive should record:

```text
Decision:
Problem being solved:
Real-world/system referent:
Evidence class: E1 / E2 / E3 / E4 / E5
Primary sources:
Assumptions:
Known counterexamples:
Failure modes:
Security implications:
Human-factor implications:
Why this belongs in kernel vs application space:
How it is tested:
What would falsify/revise this decision:
```

Designs sourced only from E5 analogy must be labeled provisional until supported by stronger evidence or bounded as application-level convention.

---

## 8. Current doctrine applied to Company OS

### Filesystem hierarchy

Use real filesystem hierarchy principles to create a predictable universal namespace. Do not copy directory names cosmetically; preserve their underlying separation of configuration, runtime state, devices/interfaces, mutable state, services, packages, temporary data, etc.

### Kernel authority

Use real authorization/process/resource/failure primitives. Do not encode department names or business-specific nouns in the kernel.

### CDM

Discover organizational reality before generating filesystem/runtime structure. Explicit unknown is preferable to invented certainty.

### AI agents

Agents remain user-space workloads whose actions are constrained by identity, capability, policy, resource limits, approvals, audit, fencing, idempotency and reconciliation.

### Workflows

Represent workflows as explicit state/action graphs with verbs, owners, authority, evidence and transitions. Files can be a highly useful interface where appropriate, but physical storage format is not the architecture.

---

## 9. Constitutional tests

A proposed feature fails architectural review if any answer is YES:

```text
Does it exist only because the AI metaphor sounds convenient?
Does it infer authority that was never established?
Does it store critical truth only in model context?
Does it confuse a folder convention with an execution model?
Does it treat an analogy as a technical standard?
Does it hide the actor or verb behind a workflow edge?
Does it allow consequential action without explicit authority?
Does it lack durable state or restart semantics?
Does it depend on caller clocks for distributed safety?
Does it call a reference implementation production-ready without evidence?
Does it erase uncertainty rather than recording it?
```

If YES, redesign before promotion.

---

## 10. Guiding principle

Company OS should feel obvious in hindsight because each abstraction maps cleanly to something real:

```text
real company
→ discovered facts and unknowns
→ predictable namespace
→ explicit authority
→ durable state
→ controlled execution
→ observable transitions
→ recoverable side effects
→ applications and agents operating inside those constraints
```

The objective is not to make a company *look like* an operating system.

The objective is to give a company the same kinds of **explicit structure, predictable interfaces, bounded authority, observable state, and recoverability** that make mature operating systems manageable.
