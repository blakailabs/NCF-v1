# NCF-003B Organization Registry & Namespace Standard v1.0

## Status

Approved / Ratified

## Purpose

Defines how organizations reserve, register, govern, and validate official NCF organization codes.

An organization code is a constitutional namespace, not merely an abbreviation.

## Core Rule

All organization codes used in Constitutional IDs must be registered before production use.

## Organization Record

```json
{
  "organization_cid": "NCF-INF-ORG-PROD-000001",
  "organization_uid": "uuid",
  "organization_code": "INF",
  "legal_name": "Infinity Loop",
  "display_name": "Infinity Loop",
  "registered_domain": "160years.com",
  "status": "active",
  "registered_at": "2026-01-01T00:00:00Z",
  "ratified_by": "Nexus Registry Authority"
}
```

## Organization Code Rules

- 3-6 uppercase alphanumeric characters
- Globally unique
- Registered in the Organization Registry
- Traceable to an organization record

## Registration Lifecycle

```text
requested → reserved → verified → ratified → active → suspended / retired
```

## Reserved Codes

The following codes are reserved and may not be claimed by organizations:

- NCF
- SYS
- ROOT
- ADMIN
- NRA
- TEST
- DEV
- NULL

## Conflict Resolution

If two organizations request the same code:

1. Verified legal or trademark owner receives priority.
2. If ambiguous, first verified registration receives priority.
3. Other organizations must choose alternate codes.
4. Retired codes may not be reused without governance approval.

## Prime Directive

Organization codes create namespace authority. Namespace authority must be unique, traceable, and governed.
