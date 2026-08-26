# AI-Native Company Operating System — Market and Architecture Research

## Research question

What should an AI-native Company Operating System be if it is designed as infrastructure rather than as a bundle of AI agents?

## Market observation

The market is moving through a sequence:

```text
AI assistant
→ AI agent
→ AI workforce
→ AI organization
→ AI-native company operating system
```

Current products largely cluster around autonomous task execution, agent workforces, department automation, or company-building automation. The opportunity is not merely to create more agents. It is to create the governed management layer above them.

## Key design conclusions

### Company OS is not an org chart

An operating system begins with primitives rather than departments. The relevant primitives are identity, permissions, processes, scheduling, state, devices/interfaces, configuration, packages, events/IPC, logs/audit, resources, persistence, and recovery.

Departments are applications.

### The kernel must be deterministic

LLMs and autonomous agents should never be the trusted kernel. They may propose and request actions, but deterministic policy enforcement decides whether those actions are authorized.

### Authority is a first-class resource

Every action must be attributable to a principal and governed by bounded capability, policy, resource limits, and approval rules.

### Customer-owned infrastructure is preferable

The operating layer should orchestrate customer-owned systems rather than becoming the owner of domains, data, payment accounts, code repositories, or advertising accounts.

### The moat is institutional state

The durable moat is not a particular model. It is the accumulated company graph, provenance, authority model, process history, decision history, operating playbooks, and measured outcomes.

## Economic model implication

A Company OS does not require a percentage of customer revenue. Better models include subscription platform fees, transparent compute/orchestration usage, marketplace revenue, department-as-a-service offerings, and enterprise governance/compliance tiers.

## Product wedge

The strongest initial wedge is not “create a company in five minutes.” It is:

> Install an AI operating layer into an existing company, discover how it works, formalize authority, and progressively move safe processes toward governed autonomy.

That requires CDM, CFHS, and the Company Kernel.
