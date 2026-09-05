# Company Kernel v0.1 Acceptance Report

**Date:** 2026-09-05

## Automated tests

```text
test_allow_mail_and_idempotency ... ok
test_approver_required .......... ok
test_checkpoint_survives_restart  ok
test_default_deny ............... ok
test_elevation_flow ............. ok
test_resource_ceiling ........... ok

Ran 6 tests
OK
```

## Runtime demo

```text
HEALTH................ READY
Allowed S2 mail....... SUCCEEDED
Refund > normal limit. ELEVATION_REQUIRED
Elevation request..... PENDING
Human approval........ APPROVED
Elevated refund....... SUCCEEDED
Unsafe/unavailable op. rejected
Checkpoint............ CREATED
Restart restoration... PASS
Audit chain........... 10 records in demo
```

## HTTP smoke test

The standard-library daemon was started on localhost and returned:

```text
GET /v1/health → READY
POST /v1/authorize mail.send → ALLOW
POST /v1/authorize payments.refund amount=5000 → ELEVATION_REQUIRED
```

## Safety

No live external providers were contacted. Device adapters are mocks, and no passwords, API keys, access tokens, or private keys are required by the runtime.
