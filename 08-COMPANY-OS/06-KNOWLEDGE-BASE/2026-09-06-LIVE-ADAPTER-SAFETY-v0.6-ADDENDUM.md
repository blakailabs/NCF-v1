# Company Operating System Knowledge Base — Live-Adapter Safety v0.6

**Date:** 2026-09-06 UTC

## Milestone thesis

A real provider adapter cannot be treated as another tool call.

Once an external system can move money, message customers, change business records or reverse prior actions, the kernel must govern **economic intent, release authority, provider truth and retry semantics** as durable state.

v0.6 remains sandbox-only.

## Canonical safety formula

```text
provider action safety =
semantic business intent
+ replay identity
+ exact resource accounting
+ independent approval provenance
+ immutable authorization evidence
+ fail-closed audit anchoring
+ provider idempotency
+ provider result lookup
+ explicit reconciliation
+ separately governed compensation
```

## New architectural decisions

### Money/resource settlement uses integers

Financial resources must be represented as exact minor units, never rounded generic floating values.

### Provider truth is part of recovery

After a provider call begins, transport errors do not tell us whether the business action happened.

Therefore:

```text
transport uncertainty ≠ retry permission
```

The system asks the provider for the durable idempotency key and reconciles from provider truth.

### Two replay layers are intentional

Provider idempotency protects the external provider call.

Kernel replay protects the Company OS semantic action.

Both are required.

### Replay identity is reserved before intent persistence

The caller nonce is claimed before the durable provider intent exists. A crash after intent commit but before replay attachment is repaired on restart.

### Approval is evidence, not a name

A counted approval must identify the authenticated session that produced it. For sensitive future production actions, policy can further require externally verified identity/MFA classes.

### Release authority is an auditable object

The exact capability/policy constraints and approval-provenance digest that released the action are immutable and anchored before provider PREPARE.

### Audit anchoring is part of the transaction boundary

An anchor outage must stop a consequential action before the provider is called when the required PREPARE/release checkpoint cannot be confirmed.

### Rollback is another consequential action

Compensation cannot be a hidden callback with weaker controls than the forward action.

S3 compensation receives its own semantic intent, independent approvals, session provenance, authorization decision and anchor evidence.

## Important defects discovered during review

- economic float accounting;
- non-finite numeric inputs;
- missing provider idempotency persistence;
- timeout retry ambiguity;
- provider-success/local-failure ambiguity;
- approvals without session provenance;
- unanchored release authority;
- provider audit not independently anchored;
- caller nonce not independently bound at the kernel layer;
- S3 rollback authority bypass;
- compensation requester with no base execution authority;
- invalid inline SQLite partial-unique syntax;
- replay nonce bound after intent persistence, leaving a crash gap.

## Important unresolved production distinction

A caller replay nonce identifies an **attempt**, not necessarily the underlying business object.

A live adapter needs an operation-specific business identity such as charge ID, claim ID, customer/entity version, campaign/budget epoch or transfer reference.

That identity must be included in live provider safety before production credentials are accepted.

## Next milestone

**Distributed / Production Safety v0.7** should prioritize:

- shared/fenced state for replay/resource/reconciliation;
- business-object identity contracts;
- symmetric compensation reconciliation;
- production external identity/MFA enforcement;
- production remote anchor authentication/HA;
- exact-unit financial authority limits;
- one real provider's test-mode adapter and hard external ceilings;
- clean execution certification before production credentials.
