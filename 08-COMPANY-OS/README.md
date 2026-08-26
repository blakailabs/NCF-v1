# NCF Company OS Extension

**Status:** Experimental branch extension
**Version:** v0.1
**Parent:** Nexus Constitutional Framework (NCF)

This directory captures the Company Operating System work developed on 2026-08-26 and integrates it with NCF without modifying NCF's constitutional core.

## Core thesis

NCF governs autonomous AI workforces. The Company OS extension generalizes those principles into an operating-system model for an entire company.

The stack is:

```text
Real Company
    ↓
CDM — discover reality
    ↓
CFHS — represent reality
    ↓
Company Kernel — govern authority and execution
    ↓
Applications — implement business semantics
    ↓
Processes / AI Agents — perform authorized work
```

## Foundational rule

> AI is a user-space workload. Authority belongs to the kernel.

## Contents

- `01-RESEARCH/` — market/category research and design rationale
- `02-CFHS/` — Company Filesystem Hierarchy Standard
- `03-KERNEL/` — Company Kernel specification
- `04-CDM/` — Company Discovery Manifest specification
- `05-MACHINE-CONTRACT/` — executable/machine-readable CDM v0.1 package
- `06-KNOWLEDGE-BASE/` — canonical project knowledge base
- `07-CONVERSATION/` — sanitized development transcript
- `SECURITY.md` — repository safety rules for this extension
- `INTEGRATION-WITH-NCF.md` — relationship between NCF and Company OS

## Safety

No passwords, API keys, bearer tokens, private keys, raw credentials, or secret values should ever be committed. Machine contracts reference secrets only through opaque references such as `secret://payments/stripe`.
