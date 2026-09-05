# Company Operating System

**A governed operating system for AI-native companies.**

The Company Operating System project defines how a real company can be discovered, represented, booted, governed, operated, audited, and progressively automated using operating-system principles rather than a loose collection of AI agents.

## Core Principle

> **AI is user space. Authority belongs to the kernel.**

The project treats a company as a running system:

```text
Real Company
   ↓
CDM — Company Discovery Manifest
   ↓
CFHS — Company Filesystem Hierarchy Standard
   ↓
Materializer
   ↓
Company Filesystem
   ↓
Company Kernel
   ↓
Applications / Human + AI Processes
   ↓
Governed External Action
```

## NCF Relationship

The **Nexus Constitutional Framework (NCF)** remains the constitutional governance layer inside the Company Operating System. It defines durable principles for authority, identity, governance, workflows, tools, memory, approvals, auditability, and certification.

```text
NCF = Constitution
CFHS = Filesystem standard
CDM = Discovery/install manifest
Company Kernel = Privileged runtime authority
Applications/agents = User space
```

## Repository Structure

```text
00-FOUNDATION/               NCF constitutional foundation
01-IDENTITY-AUTHORITY/       identity and authority contracts
02-OPERATING-STANDARDS/      operating standards
03-REFERENCE-IMPLEMENTATIONS/
04-GOVERNANCE/
05-REFERENCE/
08-COMPANY-OS/               Company OS specifications and runtime
```

## Current Runtime Milestones

```text
CDM machine contract................ implemented
CFHS materializer................... implemented
Company Kernel API.................. implemented
Company Kernel runtime v0.1......... implemented
Kernel hardening v0.2............... implemented
Kernel trust layer v0.3............. in development
```

## Canonical Project Name

**Company Operating System**  
Recommended GitHub repository slug: `Company-Operating-System`

The repository may still appear under its historical `NCF-v1` GitHub slug until the administrative rename is completed. NCF remains a foundational component of the project after that rename.
