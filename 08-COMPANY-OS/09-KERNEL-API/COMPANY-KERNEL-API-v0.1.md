# Company Kernel API Contract v0.1

## Purpose

The Company Kernel API is the privileged boundary between user-space workloads and Company OS authority. AI agents, applications, workflows, and services call this API; they do not directly operate privileged devices or secret stores.

## Design principles

1. **Default deny.** Missing authority is denial.
2. **Actor + process required.** Every request is attributable.
3. **Policy before execution.** Device writes require authorization before invocation.
4. **Idempotency for consequential writes.** S1–S3 operations should supply idempotency keys.
5. **Side-effect classification.** Device operations expose S0/S1/S2/S3.
6. **No inline credentials.** Secrets use opaque `secret://` references and leased handles.
7. **Trace causality.** Requests carry `trace_id`, `correlation_id`, and optional `causation_id`.
8. **No business semantics in kernel.** Kernel operates on paths, principals, processes, capabilities, devices, resources, events, schedules, and mounts.

## Kernel request context

Every privileged request includes headers or equivalent context:

```text
X-CFHS-Actor-ID
X-CFHS-Process-ID
X-CFHS-Trace-ID
X-CFHS-Correlation-ID
Idempotency-Key        # required by applicable device policy
```

## API groups

### Health

- `GET /v1/health`

### Authorization

- `POST /v1/authorize`
- `POST /v1/elevations`
- `POST /v1/delegations`

### Filesystem

- `POST /v1/fs/stat`
- `POST /v1/fs/list`
- `POST /v1/fs/read`
- `POST /v1/fs/write`

### Processes

- `POST /v1/processes`
- `GET /v1/processes/{process_id}`
- `POST /v1/processes/{process_id}/signals`
- `POST /v1/processes/{process_id}/checkpoints`

### IPC/events

- `POST /v1/events`
- `POST /v1/queues/{queue}/messages`

### Devices

- `GET /v1/devices`
- `GET /v1/devices/{device_id}`
- `POST /v1/devices/{device_id}/invoke`

### Secrets

- `POST /v1/secrets/leases`
- `DELETE /v1/secrets/leases/{lease_id}`

### Scheduling

- `POST /v1/schedules`
- `DELETE /v1/schedules/{schedule_id}`

### Mounts

- `POST /v1/mounts`
- `DELETE /v1/mounts/{mount_id}`

### Observability

- `POST /v1/logs`
- `POST /v1/metrics`
- `POST /v1/traces`

## Authorization response

The kernel returns an explicit decision object:

```json
{
  "decision": "ALLOW",
  "decision_id": "dec_...",
  "principal_id": "agent:sdr",
  "action": "mail.send",
  "resource": "/dev/mail/gmail",
  "matched_policies": ["policy:outbound-v4"],
  "constraints": {"remaining_today": 42},
  "expires_at": "2026-09-05T23:59:59Z"
}
```

Valid decisions are `ALLOW`, `DENY`, and `ELEVATION_REQUIRED`.

## Device invocation

Invocation is a two-phase conceptual operation:

```text
REQUEST
  ↓
AUTHORIZE
  ↓
RESERVE RESOURCE BUDGET
  ↓
LEASE REQUIRED SECRET
  ↓
INVOKE DEVICE ADAPTER
  ↓
RECORD RESULT
  ↓
EMIT EVENT/AUDIT
  ↓
RELEASE/COMMIT RESERVATION
```

The response records `side_effect_class`, `reversibility`, `result`, and audit identifiers.

## Error model

All errors use:

```json
{
  "error": {
    "code": "CFHS_POLICY_DENIED",
    "message": "Requested action is not authorized",
    "request_id": "req_...",
    "trace_id": "trace_...",
    "retryable": false,
    "details": {}
  }
}
```

Kernel errors are stable contract identifiers, not LLM prose.

## Minimum stable error codes

```text
CFHS_INVALID_REQUEST
CFHS_UNAUTHENTICATED
CFHS_POLICY_DENIED
CFHS_ELEVATION_REQUIRED
CFHS_RESOURCE_EXHAUSTED
CFHS_NOT_FOUND
CFHS_CONFLICT
CFHS_DEVICE_UNAVAILABLE
CFHS_DEVICE_FAILED
CFHS_SECRET_DENIED
CFHS_MOUNT_FAILED
CFHS_PROCESS_INVALID_STATE
CFHS_IDEMPOTENCY_CONFLICT
CFHS_INTERNAL
```

