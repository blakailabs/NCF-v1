# Company OS Runtime Status

**Updated:** 2026-09-05  
**Branch:** `feature/company-os-cfhs-cdm-v0.1`

## Implemented and validated

- CDM machine contract v0.1
- deterministic CFHS materializer v0.1
- staged/atomic materialization behavior for new targets
- inline-secret rejection and opaque `secret://` references
- Company Kernel API contract v0.1
- OpenAPI 3.1 contract
- minimal CDM → CFHS reference materialization
- contract/materializer tests

## Not yet implemented

- production kernel daemon
- production identity/session authentication
- executable policy/capability engine
- live device adapters
- secret-vault broker
- process scheduler/table
- event bus and durable queues
- resource reservation/cgroup-equivalent runtime
- checkpoints/resume
- rollback/compensation engine
- rescue/recovery target

## Next engineering milestone

Implement a minimal Company Kernel daemon behind the OpenAPI contract using a local durable state store. Demonstrate one end-to-end controlled workflow where:

1. an authorized low-risk action succeeds;
2. an unauthorized action is denied;
3. a consequential action returns `ELEVATION_REQUIRED`;
4. human approval creates narrow temporary authority;
5. the device action executes through the broker;
6. every decision/action is traceable in audit logs;
7. a process checkpoint survives restart and resumes safely.
