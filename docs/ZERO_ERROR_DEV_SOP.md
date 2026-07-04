# Zero-Error Developer SOP

## Purpose

Use this SOP before implementation so developers do not rely on chat history, guess at architecture, burn unnecessary credits, or create unsafe side effects.

## Required Read Order

1. `README.md`
2. `docs/ARCHITECT_SYSTEM_AUDIT.md`
3. This SOP
4. Existing PRD, architecture, schema, roadmap, and risk docs
5. Relevant source files and tests

## Work Packet Format

Every task must document: objective, user problem, files expected to change, data/schema impact, model/tool/API impact, cache impact, security impact, tests, rollback plan, and acceptance criteria.

## Engineering Gates

1. No direct model calls from feature code; use a model router.
2. Cache before compute; check source, artifact, and LLM cache before provider calls.
3. No hardcoded secrets, private URLs, tokens, org IDs, channel IDs, or credentials.
4. No unapproved external side effects: send, submit, publish, charge, delete, file, or message must pass approval gates.
5. Structured outputs are required for database writes.
6. Every generated claim needs provenance, confidence, source ID/hash, and timestamp.
7. Idempotency is mandatory for retries and scheduled jobs.
8. Every important run logs model, prompt version, input hash, output hash, cache status, cost estimate, and validation result.
9. Human review is required for high-risk or client-facing decisions.
10. Tests or fixtures must prove the critical path.

## Model Routing Standard

Every AI task must define task type, risk level, model tier, prompt version, schema version, cache policy, max cost, fallback model, and whether human review is required. Premium models are for architecture, ambiguity, synthesis, final review, and high-value judgment. Worker models and deterministic code handle parsing, extraction, formatting, classification, and repetitive tasks.

## Cache Standard

Cache keys should include:

```text
task_type + prompt_version + schema_version + normalized_input_hash + source_snapshot_hash
```

Invalidate on source change, prompt/schema change, scoring/rubric change, safety policy change, or human correction.

## Stop Conditions

Stop before merging if a retry can duplicate an external action, secrets or PII appear in code/logs, approval gates are missing, the feature cannot be dry-run or tested, or the model could create legal/compliance/safety/client-facing claims without review.

## Definition of Done

A change is done only when it is secure, testable, observable, idempotent, cache-aware, routed through the correct model/tool layer, and documented enough that another developer can continue without chat history.
