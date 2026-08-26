# Company Discovery Manifest (CDM) Specification v0.1

**Status:** Foundational Draft
**Parent:** CFHS

## Mission

CDM is the installer/discovery contract that turns an existing company's fragmented operational reality into a validated CFHS representation.

```text
Existing Company
      ↓
Discovery Engine
      ↓
Company Discovery Manifest
      ↓
Validation / Resolution
      ↓
CFHS Mapping
      ↓
Company Filesystem
      ↓
Kernel Boot Test
```

CDM is an inventory, evidence graph, ontology discovery system, identity audit, permission audit, process discovery engine, data catalog, provenance record, uncertainty register, mapping plan, installation manifest, and completeness test.

## Discovery order

```text
OBSERVE → CORROBORATE → INFER → ASK → CONFIRM
```

The goal is to ask humans only for information that cannot be discovered safely, is contradictory, is normative, or affects consequential authority.

## Lifecycle

```text
D0 INIT
D1 DECLARE
D2 CONNECT
D3 DISCOVER
D4 INGEST
D5 NORMALIZE
D6 CORRELATE
D7 INFER
D8 RESOLVE
D9 CLASSIFY
D10 MAP
D11 VALIDATE
D12 MATERIALIZE
D13 BOOT-TEST
D14 CERTIFY
```

## Evidence classes

```text
DECLARED
DOCUMENTED
OBSERVED
SYSTEM_REPORTED
DERIVED
INFERRED
CORROBORATED
CONFIRMED
```

## Evidence authority

```text
A5 LEGALLY_AUTHORITATIVE
A4 SYSTEM_OF_RECORD
A3 AUTHORIZED_HUMAN_DECLARATION
A2 OFFICIAL_COMPANY_DOCUMENT
A1 BEHAVIORAL_OBSERVATION
A0 INFERENCE
```

Confidence and authority are separate.

## High-impact fact rule

Legal identity, ownership, regulatory obligations, financial authority, contract-signing authority, deletion/retention policy, privileged credential scope, source-of-truth designation, regulated-data classification, and autonomous spending authority cannot become canonical solely through inference.

## Top-level domains

```text
company legal locations principals organization authority systems connectors
repositories data schemas processes events states policies resources applications
capabilities schedules communications documents media external_entities compliance
security continuity decisions exceptions metrics knowledge conflicts unknowns mappings certification
```

## Connector principle

Discovery uses read-only least privilege wherever technically possible. Discovery must not mutate, publish, send, delete, spend, transfer, or change permissions except during explicitly authorized installation tests.

## Source-of-truth states

```text
RESOLVED
FEDERATED
DERIVED
UNRESOLVED
```

The installer must never invent a source of truth to improve readiness.

## Process classification

```text
H0 HUMAN_ONLY
H1 AI_ASSISTED
H2 AI_RECOMMENDS
H3 AI_EXECUTES_WITH_APPROVAL
H4 AUTONOMOUS_MONITORED
H5 AUTONOMOUS_SELF_OPTIMIZING
```

This classification describes operating mode; it does not grant authority.

## Inference rule

Nothing inferred becomes canonical merely because AI is confident. Every inference carries evidence, provenance, confidence, authority level, risk, and confirmation requirement.

## Unknowns and contradictions

Contradictions and unknowns are first-class objects. They are never silently overwritten or replaced with invented defaults.

## Mapping modes

```text
COPY
MOVE
MOUNT
REFERENCE
GENERATE
VIRTUALIZE
IGNORE
ARCHIVE
```

## Certification

```text
CDM-0 DISCOVERED
CDM-1 MAPPED
CDM-2 BOOTABLE
CDM-3 OPERABLE
CDM-4 GOVERNED
CDM-5 AUTONOMY-READY
```

No P0 blocker may remain for normal company boot.

## Definition of complete

“100% complete” means 100% of required knowledge for the declared operating scope is either verified or explicitly accepted as unknown without blocking safe operation. It does not mean the system knows every possible fact about the company.

The executable contracts are packaged in `../05-MACHINE-CONTRACT/`.
