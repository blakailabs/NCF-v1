# Company Kernel Live-Adapter Safety v0.6 — Pre-Mortem

**Branch:** `feature/company-kernel-live-adapter-safety-v0.6`  
**Scope:** Sandbox-only provider-shaped execution  
**Question:** Assume a future live-provider rollout failed badly. What most likely caused it, and what must be true before production credentials are accepted?

## Executive finding

v0.6 materially reduces accidental duplicate execution, under-accounting, unverifiable approvals and unsafe rollback. It does **not** make the system production-ready.

The remaining high-risk failures are primarily distributed-systems, identity/key-management and provider-specific semantic problems rather than missing basic transaction logic.

## Failure matrix

| Failure scenario | v0.6 mitigation | Remaining production requirement |
|---|---|---|
| Provider executes twice after timeout | provider idempotency + kernel replay + reconciliation blocks retry | real adapter must prove provider idempotency semantics and retention window |
| Kernel uses same nonce for two meanings | semantic replay nonce binding before intent persistence | distributed/global replay store for multi-kernel deployment |
| Crash after nonce claim | durable `RESERVED` state | HA-safe shared replay database |
| Crash after intent persistence but before replay attachment | startup semantic attachment recovery | distributed recovery ownership/leases |
| Floating point money drift | integer minor-unit settlement | currency-specific provider validation and exact policy limits |
| Agent understates spend/resource request | kernel derives exact units from operation profile | provider-specific fees/taxes/FX must also be represented explicitly |
| S3 action approved by wrong people | eligible approvers + session provenance | require production IdP/MFA authentication class for selected S3 classes |
| Approval row forged without session | every counted approval requires provenance | cryptographic external identity verifier and anti-session-theft controls |
| Authority changes after approval | immutable authorization evidence tied to intent/approval provenance | signed policy/HSM trust root and policy epoch/revocation semantics |
| Audit unavailable before action | fail-closed authorization/provider PREPARE anchor | highly available immutable anchor service; outage runbook |
| Provider succeeds then local commit fails | reconciliation from provider truth | provider-specific lookup contract and eventual-consistency rules |
| Provider says success but business object is wrong | device/provider/profile binding | operation-specific target/business-object binding |
| Same business action submitted with a new nonce | not universally preventable at generic kernel layer | operation-level business idempotency key/target identity and provider-side constraints |
| Compensation bypasses original governance | separate compensation intent + approvals + provenance + anchored authority | compensation provider uncertainty/reconciliation and provider-specific reversal rules |
| Compensation provider commits then response is lost | not fully modeled in sandbox compensation API | compensation lookup/idempotency reconciliation before live rollout |
| Two kernels reserve the same resource concurrently | single SQLite transaction protects one node | distributed serializable reservation service / fencing tokens |
| Two kernels reconcile same unknown outcome | single-node state machine | distributed reconciliation lease/ownership |
| Production credentials leak | provider registry contains sandbox only | workload identity/mTLS/HSM-backed secret delivery; no long-lived app secrets |
| Fake or stale OIDC identity accepted | optional verified identity evidence contract exists | production JWT signature/issuer/audience/nonce/MFA verification and key rotation |
| Anchor endpoint compromised | exact returned head hash is checked | independent trust domain, signed receipts, retention/monitoring, potentially multiple anchors |
| Policy threshold precision differs from settlement | exact settlement; legacy authorization constraints may still compare numeric values | exact-unit policy constraints for money/quantity authority |
| SQLite migration interrupted | reference migrations are local and fail closed | versioned migration framework, backup/restore, migration crash tests |
| Provider stores action longer/shorter than kernel expects | persistent sandbox reference model | adapter contract must define idempotency TTL, lookup retention and terminal statuses |
| API rate limiting causes reconciliation storm | no automatic execute retry | provider backoff/rate-limit budget, reconciliation scheduler and circuit breaker |
| External provider eventually changes a terminal status | sandbox statuses are simple | provider webhook/event reconciliation and terminality policy |

## Blind spot: semantic business identity

A replay nonce protects one caller-declared attempt. It cannot prove that a caller did not issue the same real-world business command again with a different nonce.

For a live provider, each consequential operation must define business identity fields such as:

```text
payment/refund → charge/payment/claim ID
email → message/campaign/customer + template/version
CRM mutation → entity ID + desired state/version
ad spend → campaign/account/budget epoch
bank transfer → source + destination + transfer business reference
```

A future live adapter must bind those fields into an operation-specific business idempotency key and/or enforce provider-side object constraints.

The current refund sandbox is therefore a transaction-semantics model, not a complete real payment domain model.

## Blind spot: compensation uncertainty

Original-provider execution supports an explicit unknown-outcome/reconciliation flow.

The current sandbox compensation call is idempotent and can fail before commit, but it does not yet model:

```text
provider compensation committed
        ↓
transport response lost
        ↓
compensation reconciliation
```

A live reversible operation is blocked until the compensation adapter supports lookup/reconciliation with the same rigor as the forward action.

## Blind spot: production approval identity class

v0.6 accepts a valid kernel session as approval evidence and can additionally bind verified external identity evidence.

For production S3 actions, policy should be able to require:

```text
authentication_class = verified_external_identity
MFA present
issuer in trusted allowlist
recent-authentication age ≤ threshold
possibly phishing-resistant authentication
```

That enforcement is not yet a production release guarantee.

## Blind spot: distributed authority and accounting

SQLite gives useful serializable single-node reference semantics but is not the future HA authority store.

Before multiple kernels can execute consequential actions, the system needs shared/fenced ownership for:

- replay nonces;
- exact resource reservations;
- approval state;
- provider action state;
- reconciliation cases;
- audit sequencing;
- compensation state.

A second kernel must never be able to act merely because it cannot see a first kernel's local lock.

## Required production gates

Production credentials remain prohibited until all of the following are true:

1. the committed v0.6 validator executes cleanly in an isolated environment;
2. GitHub/alternative CI executes the same validator from the repository commit being released;
3. a real provider adapter implements durable idempotency and lookup/reconciliation in test mode;
4. operation-specific business identity is defined and bound;
5. compensation uncertainty has provider lookup/reconciliation;
6. production S3 approvals require cryptographically verified external identity/MFA as policy demands;
7. policy packages use production asymmetric verification/HSM-backed trust roots;
8. audit anchoring is remote, immutable, highly available and independently monitored;
9. resource/replay/reconciliation state moves to a distributed serializable/fenced persistence design before HA;
10. secrets are delivered by workload identity/mTLS/HSM-backed mechanisms;
11. exact-unit authority thresholds replace legacy floating comparisons for financial limits;
12. provider sandbox/canary limits are enforced externally as well as inside the kernel;
13. incident and `UNKNOWN_SIDE_EFFECT` operator runbooks are exercised;
14. provider webhook/event reconciliation is modeled where the provider can change state asynchronously.

## Pre-mortem decision

v0.6 is a valid **sandbox architecture milestone** because the most dangerous unknown-outcome and governance paths fail closed or enter reconciliation.

It is intentionally not a production milestone. The next architecture stage should focus on **distributed production safety and one real provider's test-mode semantics**, not on adding more agent features.
