# Company Kernel Trust Layer v0.3 — Review Package

**Intended base:** `feature/company-kernel-hardening-v0.2`  
**Head:** `feature/company-kernel-trust-v0.3`  
**Stack status:** 19 commits ahead, 0 behind at review preparation

## Intended PR title

`Add Company Kernel Trust Layer v0.3`

## Review summary

This change advances the **Company Operating System** from Kernel Hardening v0.2 into Kernel Trust Layer v0.3.

### Project identity

The repository is internally identified as **Company Operating System**. NCF remains the constitutional governance layer inside the broader project. The recommended GitHub slug is `Company-Operating-System`; the actual repository rename remains an administrative task because repository-name mutation is not exposed by the connected GitHub tooling.

### Trust features

- signed restrictive policy package semantics and atomic activation;
- trusted signing-key abstraction;
- session rotation with old-token revocation;
- parent/child capability bounding;
- process-level capability bounds;
- durable delegation proofs with proof digests;
- provider-neutral vault contract and audience-bound leases;
- durable event/queue publish, claim, acknowledge, release, and retry;
- independent audit-anchor abstraction;
- strict GitHub read-only provider adapter with no write API surface;
- one-time bootstrap endpoint that does not print an owner token at startup;
- explicit threat model and adversarial test catalog;
- TrustKernel unit/integration tests.

### Validation

Independent reference validation passed **11/11** trust primitive checks.

### Release caveat

GitHub Actions is currently generating `startup_failure` placeholders with zero jobs on the v0.3 branch. These occur before checkout or tests. The last real GitHub Actions execution remains v0.2 run `33998002023`, which passed 16 tests and the committed-secret scan.

v0.3 remains `REFERENCE PASS / RELEASE BLOCKED` until a clean-environment full integration run succeeds.

### Safety boundary

No write-capable production email, payment, banking, CRM, deployment, advertising, accounting, or legal-signature provider is enabled.

## GitHub PR creation status

Automated PR creation was attempted and GitHub returned:

```text
403 — At least one email address must be verified to do that.
```

The intended PR should remain **draft** until the release caveats above are closed.
