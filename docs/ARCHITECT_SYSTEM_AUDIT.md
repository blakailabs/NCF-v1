# Architect System Audit — NCF v1

Date: 2026-07-04
Repository: `blakailabs/NCF-v1`
Mode: Architect-first, execution-second

## Executive Summary

NCF v1 is a standards/governance framework. Recent work added a certification JSON schema, which means this project is moving toward formal validation and compliance-style certification records.

The highest-leverage use of the Architect System here is to make NCF the operating standard that other projects use to define identity, governance, certification, authority, approval, lineage, and auditability.

## Product Requirement Direction

### Problem

AI projects quickly become inconsistent: different agent definitions, missing authority boundaries, unclear certification status, weak audit trails, and no shared standard for what it means to be compliant, verified, or certified.

### Promise

NCF provides a canonical framework for registering, validating, certifying, and governing digital systems, agents, tools, workflows, and organizational standards.

### MVP Loop

1. Define entity or system being certified.
2. Assign canonical identifier.
3. Validate required schema fields.
4. Check governance requirements.
5. Issue certification level.
6. Store certification record.
7. Track status, issuer, evidence, and expiration/review date.
8. Use certification status in downstream project gates.

## Model Routing Plan

| Task | Tier | Notes |
|---|---:|---|
| Schema validation | deterministic | no LLM |
| Certification checklist generation | worker | from template |
| Standard interpretation | architect | when governance ambiguity exists |
| Compliance report drafting | mid | source-backed only |
| Final certification decision | human/authority | AI advisory only |

## Caching Strategy

Cache by:

```text
standard_version + target_cid + evidence_hash + checklist_version + task_type
```

Required caches:

- Schema validation result cache.
- Certification checklist cache.
- Evidence review cache.
- Compliance report cache.
- Standard interpretation cache.

Invalidate when schema, standard version, target artifact, evidence, or certification level changes.

## Cost Controls

- Do not use AI for schema validation.
- Use deterministic validators first.
- Use worker models only to summarize evidence packages.
- Escalate to architect model for standard conflicts or new certification categories.
- Batch low-risk certification reports.
- Track cost per certification record.

## Security and Governance

- Certification authority must be explicit.
- Certification records should include evidence, issuer, date, status, and review cadence.
- Do not allow AI to issue final certification without human/authorized authority.
- Use immutable audit events for issued/revoked certifications.
- Define revocation workflow.
- Define versioned standards.

## Premortem

Assume NCF failed. Why?

1. It became documentation without enforcement.
2. Certification levels were ambiguous.
3. AI issued certifications without authority.
4. Schemas drifted across projects.
5. Projects used NCF labels without validation.
6. Certification evidence was not stored.
7. No revocation/update process existed.

## Postmortem Metrics

- Standards defined.
- Schemas validated.
- Certifications issued.
- Certifications rejected.
- Revocations.
- Projects using NCF gates.
- Schema validation failures.
- Cost per review.
- Human overrides.

## Blind Spots and Mitigations

- **Rubber-stamp certification:** require evidence references and authorized issuer.
- **Version confusion:** pin every certification to standard/schema version.
- **No enforcement:** downstream projects must gate critical actions on certification status.
- **AI authority drift:** AI can recommend, not certify.
- **Schema sprawl:** central schema registry.

## Implementation Plan

1. Expand certification schema with evidence references, issuer authority, expires_at, review_due_at, and revocation fields.
2. Add deterministic schema validator.
3. Add certification registry.
4. Add audit log for issue/update/revoke.
5. Add model router for evidence summaries and standards interpretation.
6. Add project integration guide.
7. Add gold-standard certification examples.

## Definition of Done

NCF v1 is architecture-ready when certification records are versioned, evidence-backed, authority-bound, auditable, revocable, and enforceable across downstream projects.
