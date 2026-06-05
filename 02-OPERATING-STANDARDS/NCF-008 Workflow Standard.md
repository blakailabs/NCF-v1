# NCF-008 Workflow Standard v1.0

## Status

Approved / Ratified

## Constitutional Definition

A workflow is a governed sequence of activities performed by one or more agents to achieve a measurable outcome.

## Workflow Components

- Identity
- Owner
- Purpose
- Inputs
- Outputs
- States
- KPIs
- Governance Requirements

## Workflow Lifecycle

Draft → Approved → Active → Executing → Completed → Archived

Failure Path:

Executing → Failed → Retry → Escalate → Resolved

## Workflow Classes

- Strategic Workflow
- Operational Workflow
- Transactional Workflow
- Utility Workflow

## Workflow States

- queued
- started
- in_progress
- waiting
- waiting_for_approval
- waiting_for_processing
- completed
- failed
- cancelled

## Validation Requirements

Inputs, memory, permissions, and dependencies must be validated before execution.

## Prime Directive

Agents define responsibility. Workflows define execution.
