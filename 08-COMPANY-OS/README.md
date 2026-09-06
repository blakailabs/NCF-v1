# Company Operating System

**Status:** Active architecture and reference-runtime project  
**Current kernel milestone:** Live-Adapter Safety v0.6  
**Constitutional layer:** Nexus Constitutional Framework (NCF)

The Company Operating System is a universal operating-system model for a company. It discovers an existing organization, represents that organization in a standard namespace, governs identity/authority/resources through a deterministic kernel, and runs business applications and AI agents as user-space workloads.

## Core thesis

```text
Real Company
    ↓
CDM — discover and verify reality
    ↓
CFHS — represent reality in a universal company namespace
    ↓
Company Kernel — govern identity, authority, resources and execution
    ↓
Applications — implement business/domain semantics
    ↓
Processes / AI Agents — perform authorized work
```

## Foundational rule

> **AI is a user-space workload. Authority belongs to the kernel.**

LLMs and agents may reason, plan, recommend and request actions. They do not bypass deterministic policy enforcement, resource controls, approval requirements, audit/replay boundaries or device/provider mediation.

## Current implementation state

Completed architecture/runtime milestones:

```text
NCF constitutional governance
CDM v0.1 discovery contract
CFHS v0.1 filesystem hierarchy
Company Kernel specification
Company Kernel runtime v0.1
Kernel Hardening v0.2
Kernel Trust Layer v0.3
Kernel Trust Hardening v0.4
Kernel Action Safety v0.5
Kernel Live-Adapter Safety v0.6
```

### v0.6 certification

Canonical runtime:

```text
kernel.server_v06_hardened
→ TrustKernelV06ReleaseGate
```

Canonical validator:

```bash
cd 11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v06.py
```

Current certified surface:

```text
102 targeted safety tests
11 modules
exact test-count enforcement
includes v0.5 regression coverage
GitHub Actions: PASS
```

v0.6 is certified as a **sandbox architecture milestone**. Production credentials/providers remain disabled while distributed/production safety work proceeds.

## Project areas

- `01-RESEARCH/` — market/category research and architecture rationale
- `02-CFHS/` — Company Filesystem Hierarchy Standard
- `03-KERNEL/` — Company Kernel specification
- `04-CDM/` — Company Discovery Manifest specification
- `05-MACHINE-CONTRACT/` — machine-readable CDM contract package
- `06-KNOWLEDGE-BASE/` — canonical project decisions and lessons
- `07-CONVERSATION/` — sanitized development record
- `08-REFERENCE-RUNTIME/` — early reference-runtime work where present
- `11-KERNEL-RUNTIME/` — current runnable/hardened Company Kernel reference implementation
- `RUNTIME-STATUS.md` — canonical current implementation/release status
- `SECURITY.md` — repository safety rules
- `INTEGRATION-WITH-NCF.md` — relationship between NCF and the broader Company OS

## Safety rules

- no passwords, API keys, bearer tokens, private keys or raw secret values in Git;
- secrets are referenced through opaque handles and resolved at runtime;
- default deny;
- technical permission does not equal legitimate business authority;
- consequential actions require attributable authority and audit evidence;
- provider writes are mediated through kernel-owned safety contracts;
- explicit unknown state is preferred over invented/corrupted certainty;
- production write providers remain disabled until the production release gates are satisfied.

## Next milestone

**Company Kernel Distributed / Production Safety v0.7**

Immediate priorities:

1. shared/fenced persistence for replay, resources, approvals, provider state and reconciliation;
2. operation-specific business-object identity/deduplication;
3. symmetric forward/compensation reconciliation;
4. exact-unit financial authority limits;
5. production external identity/MFA requirements;
6. production-grade remote audit anchoring and secret delivery;
7. one real provider adapter in test/sandbox mode only after the above controls are in place.

The project should continue moving upward and outward from the kernel: first production/distributed safety, then Company Discovery/installation, user-space applications/services/agents, provider pilots and eventually a controlled Company Operating System v1.0 release.
