# Company Operating System — Kernel Threat Model v0.3

**Scope:** Company Kernel runtime, hardening, and trust layer  
**Security posture:** deny-by-default, least privilege, monotonic authority

## Protected assets

- principal identity and session authority;
- process capability bounds and delegation chains;
- signed policy packages;
- secrets and secret leases;
- audit history and audit anchors;
- durable event/queue state;
- company filesystem state;
- external provider access;
- financial/resource ceilings;
- approval/elevation state.

## Primary adversaries

### Compromised AI/user-space process

Assume an AI agent or application can be malicious, prompt-injected, hallucinating, or compromised. It may attempt to:

- call devices it was never granted;
- exceed amount/resource limits;
- impersonate a different process;
- spawn a more privileged child;
- reuse a revoked session;
- access another adapter's secret lease;
- rewrite history;
- send malformed events to trigger downstream work.

**Required defense:** the kernel must treat every user-space request as untrusted.

### Compromised provider input

External content returned from GitHub, web systems, CRM, email, or future connectors may contain hostile instructions or malformed data.

**Required defense:** provider content is data, never authority. No provider response can grant a capability or alter kernel policy by itself.

### Compromised policy artifact

An attacker may modify a policy file, substitute an old package, use an untrusted signing key, or alter package contents after signing.

**Required defense:** signature verification, package identity/versioning, restrictive-only semantics, atomic activation, and future rollback protection.

### Compromised runtime database

An attacker with database write access may try to change sessions, process metadata, approvals, events, or audit state.

**Required defense:** hash-linked audit trails, external anchors, narrow OS-level database permissions, and future signed state/checkpoints.

### Malicious or compromised human administrator

A privileged human may intentionally approve dangerous actions or attempt to erase evidence.

**Required defense:** separation of duties for high-risk actions, externally anchored audit, approval provenance, and configurable multi-party authorization.

## Threats and required controls

| Threat | Current v0.3 control | Remaining requirement |
|---|---|---|
| Principal spoofing | opaque authenticated sessions | external IdP/OIDC + MFA |
| Session replay | expiration, revocation, rotation | device/session binding and rotation policy |
| Bootstrap theft | secret outside repo; no printed owner token | durable one-time ceremony + hardware/IdP bootstrap |
| Child privilege escalation | capability bounding against parent and child principal | formal delegation algebra + recursive proof verification |
| Policy tampering | signed package verification | asymmetric signing/HSM + rollback/version policy |
| Policy bypass | trust policy cannot create ALLOW | policy compiler/formal decision tests |
| Secret leakage | audience-bound lease; adapter-only resolution | production vault + zeroization + adapter sandbox |
| Audit rewriting | hash-linked audit + independent anchor chain | remote immutable external anchoring |
| Queue theft | claim/ack ownership | lease expiry, dead-letter rules, distributed concurrency |
| SSRF | host-pinned/read-only adapter patterns | central egress proxy + DNS rebinding defense |
| Provider writes | GitHub adapter exposes GET only | per-provider scope verification |
| Resource runaway | hard ceilings in kernel | distributed reservations and quotas |
| Approval abuse | narrow time-limited elevation | multi-party approval for S3 actions |
| Prompt injection | AI has no direct authority | content isolation, tool-input validation, taint labels |
| Replay of consequential request | idempotency keys | durable nonce/replay registry across clusters |
| Audit suppression | kernel-side audit | fail-closed action commit when audit unavailable |

## Explicit adversarial tests

The v0.3/v0.4 security suite must attempt at least:

1. modified signed policy with original signature;
2. untrusted signing-key substitution;
3. same-version policy content replacement;
4. child process requesting a higher amount limit than parent;
5. child process requesting an action parent does not possess;
6. process ID belonging to another principal;
7. revoked session replay;
8. expired session replay;
9. wrong-audience secret lease;
10. expired secret lease;
11. queue acknowledgement by non-owner;
12. duplicate event delivery;
13. audit record modification;
14. audit record deletion/reordering;
15. anchor record modification;
16. restricted-data request through external read adapter;
17. URL/userinfo SSRF attempts;
18. private/loopback/link-local network access in production mode;
19. oversized provider response;
20. attempt to invoke a write method on read-only GitHub device;
21. action allowed by principal but denied by process capability bound;
22. action allowed by v0.1 capability but tightened by v0.2/v0.3 policy;
23. restart followed by bootstrap-secret replay;
24. failed audit write during consequential action;
25. concurrent claims for the same queue message.

## Side-effect release gate

No real S2/S3 provider may be enabled until the trust layer can demonstrate:

```text
identity verified
+ process authority bounded
+ policy authenticity verified
+ secret scope bounded
+ audit commit available
+ replay/idempotency protection available
+ resource reservation available
+ rollback/compensation defined
+ approval path defined when required
```

## Current security conclusion

v0.3 materially improves trustworthiness but is **not production security certification**. The architecture is intentionally stopping before live write-capable integrations so the trust boundary can be attacked while consequences remain simulated/read-only.
