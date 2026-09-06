# Company Kernel Distributed / Production Safety v0.7

**Project:** Company Operating System  
**Branch:** `feature/company-kernel-distributed-safety-v0.7`  
**Status:** final PR #3 checkpoint; production credentials/providers remain disabled

## Canonical runtime

```text
kernel.server_v07
→ TrustKernelV07RecoverableAnchorFinalGate
→ TrustKernelV07ProductionIdentityFinalGate
→ TrustKernelV07ExactAuthorityFinalGate
→ TrustKernelV07ControlPlaneFinalGate
→ TrustKernelV07DistributedCompensationFinalGate
→ TrustKernelV07TransactionalProviderGate
→ RecoverableSQLiteFencedStateCoordinator
```

## Canonical consequential-action path

```text
BusinessObjectIdentity
→ semantic replay binding
→ session-proven approvals
→ production authentication-class checks when enabled
→ authorization decision
→ anchored authorization evidence
→ exact financial authority where applicable
→ distributed transaction PREPARE
    ├── exact resource capacity
    ├── current ownership fence
    └── versioned transaction journal
→ provider PREPARE using the same reservation
→ transaction/fence revalidation
→ provider/gateway stale-fence guard
→ provider execution
→ terminal state OR forward reconciliation
→ independently governed compensation where required
→ compensation identity + new fence epoch
→ provider-idempotent reversal
→ COMPENSATED OR compensation reconciliation
```

## Certified v0.7 controls

v0.7 implements and tests:

- versioned business-object identity independent of replay nonce;
- semantic replay protection;
- monotonic fencing and provider stale-token rejection;
- transaction-coordinated exact-capacity PREPARE;
- restart/takeover semantics under higher fencing epochs;
- forward unknown-outcome reconciliation;
- separately governed distributed compensation;
- compensation unknown-outcome reconciliation and retry history;
- shared-state CAS/fencing/journal contract;
- fenced/versioned approval mutation with atomic session provenance;
- exact minor-unit financial authority and exact-unit elevations;
- production external-identity/MFA policy contract;
- authenticated quorum audit-anchor reference contract;
- durable partial anchor receipts and replay-safe quorum reconciliation;
- same-head provider-action and authorization anchor recovery;
- fail-closed canonical server wiring.

## Production identity / MFA

The repository default remains:

```text
security.production_identity.mode = sandbox
```

Production-mode policy requires allowed external provider/issuer, MFA/AMR, acceptable ACR where configured, fresh authentication time and a live matching kernel session.

Weak or legacy approval/elevation provenance is rechecked at release and fails closed.

No live production IdP or production identity credentials are committed.

## Exact financial authority

Reference standing refund authority:

```text
USD $250.00 = 25,000 minor units
```

```text
$250.00   → ALLOW
$250.01   → ELEVATION_REQUIRED
$250.001  → REJECT
NaN/Inf   → REJECT
float-only elevation → cannot bypass exact authority
```

## Authenticated quorum audit anchoring

The hardened reference anchor contract uses deterministic request identity and N-of-M endpoint confirmation.

```text
local chain head H
→ canonical metadata digest
→ deterministic anchor request ID
→ authenticated request envelope
→ endpoint A signed receipt
→ endpoint B signed receipt
→ ...
→ quorum confirmation
```

Properties:

```text
single endpoint hardened mode........ REJECTED
partial runtime configuration........ FAIL CLOSED
wrong-head receipt................... NOT COUNTED
bad/untrusted signature.............. NOT COUNTED
tampered metadata.................... REJECTED
partial verified receipts............ DURABLE
retry................................ MISSING ENDPOINTS ONLY
same semantic request................ SAME REQUEST ID
same-head retry after outage......... REQUIRED
```

Runtime key values come only from named environment variables. The repository stores no anchor secrets.

The current HMAC implementation is deliberately **reference/test cryptography**. Production still requires asymmetric workload identity/mTLS/HSM/KMS-backed trust and appropriate key lifecycle controls.

## Same-head recovery

A failed external anchor no longer causes the consumer to append a fresh local event on retry.

```text
append semantic transition once
→ persist pending checkpoint {event_digest, audit_head_hash, metadata}
→ external anchor unavailable
→ action fails closed
→ restart/retry
→ reuse exact original audit_head_hash
→ reconcile anchor confirmation
```

This is implemented for both provider-action transitions and provider-authorization evidence.

## Shared persistence contract

A production cross-host backend must preserve:

```text
serializable transactions
compare-and-swap
monotonic fencing
durable ordered journal
multi-connection visibility
synchronous durability
authoritative shared time
distributed quorum
```

SQLite is the semantic reference and remains not production-certified.

## Runnable server

```bash
python -m kernel.server_v07 \
  --state-dir <state> \
  --config examples/kernel.config.json \
  --policy-dir examples/policies \
  --kernel-instance-id kernel-a
```

Default mode uses the local reference anchor.

Authenticated remote quorum reference mode requires repeated endpoint/key bindings plus a quorum and runtime request-key reference. Hardened remote mode requires at least two HTTPS endpoints.

## Final PR #3 certification

```bash
cd 08-COMPANY-OS/11-KERNEL-RUNTIME
PYTHONPATH=. python scripts/validate_v07.py
```

```text
Run ID: 34054241130
Commit: 4c091e7a35894e6c4b7d18c1690401ff1756a77c
Ran 264 tests in 6.411s
264 / 264 PASS
0 failures
0 errors
0 skipped
exact_test_count = true
successful = true
```

## Release posture

```text
Business-object identity................ IMPLEMENTED
Semantic replay safety.................. IMPLEMENTED
Distributed fencing..................... IMPLEMENTED
Transactional PREPARE................... IMPLEMENTED
Forward reconciliation.................. IMPLEMENTED
Distributed compensation................ IMPLEMENTED
Compensation reconciliation............. IMPLEMENTED
Shared persistence contract............. IMPLEMENTED / REFERENCE ONLY
Fenced approval control plane........... IMPLEMENTED
Exact financial authority............... IMPLEMENTED
Production identity/MFA policy.......... IMPLEMENTED / SANDBOX CONFIG
Authenticated quorum anchor contract..... IMPLEMENTED / REFERENCE CRYPTO
Same-head anchor recovery................ IMPLEMENTED
Canonical v0.7 certification............ 264 / 264 PASS
Production HA backend................... PENDING
Production asymmetric/HSM anchor trust.. PENDING
Live production IdP..................... NOT ENABLED
Provider webhook/event reconciliation... PENDING
Real provider test mode................. NOT YET ENABLED
Production credentials.................. DENIED
Production write providers.............. DISABLED
```

## Next clean PR

After PR #3 merges, continue from the merged checkpoint in a new branch/PR. The next PR should focus on one remaining production boundary—preferably the production shared/HA persistence backend—rather than expanding PR #3 further.
