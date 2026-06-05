# NCF-004 Memory Standard v1.0

## Status

Approved / Ratified

## Purpose

The NCF Memory Standard governs how autonomous AI workforces remember, retrieve, learn, archive, share knowledge, and preserve organizational intelligence.

Memory is a first-class organizational asset.

## Constitutional Principle

**Organizational Memory Outlives Individuals.**

Humans leave. Agents are upgraded. Models change. Vendors change. Memory remains.

## Memory Classes

1. Working Memory
2. Operational Memory
3. Knowledge Memory
4. Decision Memory
5. Performance Memory
6. Institutional Memory
7. Constitutional Memory

## Working Memory

Temporary execution memory for the current workflow run.

Retention: End of Run.

## Operational Memory

Persistent business memory supporting active operations.

Examples:

- Content schedules
- Active projects
- Customer records
- Publishing queues

## Knowledge Memory

Long-term organizational knowledge.

Examples:

- SOPs
- Brand voice
- Policies
- Product information
- Approved claims

## Decision Memory

Preserves organizational decisions, ratifications, and architecture choices.

## Performance Memory

Stores KPI history and performance intelligence.

## Institutional Memory

Preserves organizational identity, foundational principles, and long-term lessons.

## Constitutional Memory

A subclass of Institutional Memory containing ratified NCF standards, governance decisions, namespace authority records, and constitutional records.

## Memory Registry Required Fields

| Field | Type |
|---|---|
| cid | CID |
| uid | UID |
| memory_type | ENUM |
| owner | STRING |
| created_at | TIMESTAMP |
| updated_at | TIMESTAMP |
| status | ENUM |
| source | STRING |
| retention_class | ENUM |

## Memory Promotion

Working → Operational → Knowledge → Institutional → Constitutional

## Retrieval Rule

Agents should not act solely from model weights when authoritative memory exists.

## Retention Classes

- Class A: Constitutional — Never Delete
- Class B: Institutional — Retain Indefinitely
- Class C: Knowledge — Retain While Active
- Class D: Operational — Policy-Based
- Class E: Working — Temporary

## Prime Directive

Data stores facts. Memory preserves meaning. Organizations that govern memory create enduring intelligence.
