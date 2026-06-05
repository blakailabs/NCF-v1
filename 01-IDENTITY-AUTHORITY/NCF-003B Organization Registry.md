# NCF-003B Organization Registry & Namespace Standard v1.1 Enterprise Edition

## Status

Approved / Ratified Foundation — Expanded Enterprise Draft

## Parent Authority

- NCF-001 Constitution
- NCF-003A Constitutional Identity Standard

---

# Executive Summary

The Organization Registry & Namespace Standard defines how organizations reserve, register, govern, validate, transfer, suspend, and retire official NCF organization codes.

An organization code is not merely an abbreviation.

It is a constitutional namespace.

The organization namespace is the second segment of the NCF Constitutional Identifier and establishes ownership context for every agent, workflow, run, memory object, asset, tool action, approval, event, and certification created under that organization.

Without namespace governance, CIDs lose authority.

---

# Article I — Purpose

This standard governs:

- Organization registration
- Namespace reservation
- Organization code validation
- Namespace ownership
- Namespace lifecycle
- Reserved codes
- Conflict resolution
- Namespace retirement
- Federation readiness

---

# Article II — Core Rule

All organization codes used in production Constitutional IDs must be registered in the NCF Organization Registry.

Unregistered organization codes may be used in experimental or internal contexts only if clearly marked as non-production and non-certified.

---

# Article III — Organization Code Definition

An organization code is a unique namespace assigned to a registered organization.

Example:

```text
NCF-INF-RUN-CONTENT-PROD-20260115T143022-00001
```

In this CID, `INF` identifies the organization namespace.

---

# Article IV — Organization Code Rules

Organization codes must be:

- 3-6 characters unless exception is approved
- Uppercase
- Alphanumeric
- Globally unique within the NCF registry
- Traceable to an organization record
- Registered before production use

Recommended examples:

- INF
- ACM
- NXL
- BLAKAI

---

# Article V — Organization Registry Record

Every organization must have a registry record.

```json
{
  "organization_cid": "NCF-INF-ORG-PROD-000001",
  "organization_uid": "uuid",
  "organization_code": "INF",
  "legal_name": "Infinity Loop",
  "display_name": "Infinity Loop",
  "registered_domain": "160years.com",
  "primary_contact": "",
  "status": "active",
  "registered_at": "2026-01-01T00:00:00Z",
  "ratified_by": "Nexus Registry Authority",
  "schema_version": "1.0"
}
```

---

# Article VI — Registration Lifecycle

```text
requested → reserved → verified → ratified → active → suspended → retired
```

## Requested

Organization has requested a namespace.

## Reserved

Namespace is temporarily held pending verification.

## Verified

Organization identity has been reviewed.

## Ratified

Namespace has been formally approved.

## Active

Namespace may be used in production CIDs.

## Suspended

Namespace is temporarily disabled.

## Retired

Namespace is no longer active.

---

# Article VII — Reserved Codes

The following codes are reserved and may not be claimed by organizations:

- NCF
- SYS
- ROOT
- ADMIN
- NRA
- TEST
- DEV
- NULL
- TEMP
- DEMO
- GLOBAL

Reserved codes may be used only by approved constitutional, system, testing, or registry authority functions.

---

# Article VIII — Namespace Ownership

Namespace ownership establishes constitutional authority over records created under that namespace.

Organizations are responsible for:

- Preventing unauthorized use
- Maintaining accurate registration data
- Protecting namespace credentials
- Reporting misuse
- Maintaining governance compliance

---

# Article IX — Conflict Resolution

If two organizations request the same code:

1. Verified legal or trademark owner receives priority.
2. If legal ownership is unclear, first verified registration receives priority.
3. If both claims are unresolved, the Nexus Registry Authority mediates.
4. Non-prevailing organizations must choose alternate codes.
5. Disputed namespaces may be reserved until resolution.

---

# Article X — Namespace Transfer

Namespace transfer may occur during:

- Acquisition
- Merger
- Rebrand
- Organizational restructuring
- Governance transfer

Transfers require:

- Written request
- Verification
- Approval
- Audit record
- Registry update

---

# Article XI — Namespace Suspension

A namespace may be suspended for:

- Fraudulent registration
- Security breach
- Governance violation
- Certification fraud
- Registry tampering
- Persistent misuse

Suspension must be recorded and reviewed.

---

# Article XII — Namespace Retirement

Retired namespaces should not be reused without governance approval.

Retirement preserves historical integrity.

Historical records under retired namespaces remain valid unless revoked.

---

# Article XIII — Federation Readiness

The namespace model should support future federation across multiple registry authorities, jurisdictions, industries, or enterprise deployments.

Federated namespace systems must preserve:

- Uniqueness
- Traceability
- Authority
- Auditability
- Conflict resolution

---

# Article XIV — Infinity Loop Example

The Infinity Loop reference implementation uses:

```text
Organization Code: INF
Organization CID: NCF-INF-ORG-PROD-000001
```

This namespace governs all Infinity Loop reference implementation records.

---

# Article XV — Compliance Requirements

An organization namespace is compliant when:

- Code is registered
- Code is unique
- Organization record exists
- Ownership is documented
- Status is active
- Namespace is not reserved or prohibited
- Registry authority is recorded
- Namespace changes are auditable

---

# Prime Directive

Organization codes create namespace authority.

Namespace authority must be unique, traceable, governed, and auditable.
