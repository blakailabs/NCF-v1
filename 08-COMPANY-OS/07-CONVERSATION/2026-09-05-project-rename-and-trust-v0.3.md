# Company Operating System — Project Rename and Trust Layer v0.3 Continuation

**Date:** 2026-09-05  
**Status:** Sanitized project continuation

## User direction

**User:** “Let’s update the name of the repositories so they align with what the actual project is. Then proceed with next steps.”

## Repository inventory decision

The connected BlakAi Labs repository inventory was reviewed. Only the historical `NCF-v1` repository was found to contain the Company Operating System architecture and runtime work. Other repositories were separate products/projects and were intentionally left unchanged.

The canonical project name was set to:

```text
Company Operating System
```

Recommended repository slug:

```text
Company-Operating-System
```

NCF remains the constitutional governance layer inside the broader Company Operating System project.

## Administrative rename limitation

The connected GitHub tooling allows branch, file, commit, pull-request, and workflow operations but does not expose repository-name mutation. The local GitHub CLI was not authenticated. A fallback tracking-issue attempt was also rejected by GitHub due to account email-verification requirements.

The repository was therefore aligned internally through the root README and `ADMIN-RENAME.md`, while the actual GitHub slug rename remains an explicit administrative task.

## Trust Layer v0.3 work

A new child branch was created:

```text
feature/company-kernel-trust-v0.3
```

v0.3 added:

- signed restrictive policy package semantics;
- atomic policy activation;
- session rotation with old-token revocation;
- parent/child capability bounding;
- durable delegation proofs;
- provider-neutral vault secret leases;
- durable event/queue claim, acknowledge, release, and retry semantics;
- independent audit anchoring;
- a strict GitHub read-only provider adapter;
- a one-time bootstrap endpoint that does not print privileged sessions;
- a threat model and adversarial test catalog;
- TrustKernel runtime integration tests.

## Validation

An independent reference harness passed 11/11 trust primitive checks covering policy signing/tampering, audit-anchor tampering, vault audience binding, session replay after rotation, child privilege escalation, durable queue ownership/retry, and GitHub read-only behavior.

GitHub Actions on the v0.3 branch is currently producing `startup_failure` placeholders with zero jobs. These records occur before checkout, compilation, or tests and are therefore recorded as CI infrastructure/startup failures rather than software test failures.

The v0.3 acceptance state is:

```text
REFERENCE PASS / RELEASE BLOCKED
```

No write-capable production provider was enabled.

## Next trust milestone

The next child milestone is **Company Kernel Trust Hardening v0.4**, beginning with durable bootstrap completion so a restart cannot reopen the initial privileged bootstrap ceremony.
