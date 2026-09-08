# NCF-005A Evidence & Data Integrity Standard v1.0

## Status

Approved implementation draft — pending validation and merge.

## Parent Authority

- NCF-001 Constitution
- NCF-002 Enterprise Architecture
- NCF-005 Data Standard
- NCF-006 Governance Standard
- NCF-007 Agent Standard
- NCF-009 Tool Standard
- NCF-011 Security Standard

---

# Executive Summary

NCF-compliant systems must distinguish what is known, what is observed, what is derived, what is inferred, and what remains unknown.

The governing principle is:

> When the system does not know, it searches, defers, or returns unknown. It does not guess.

An autonomous system may reason, infer, predict, rank, and recommend. It may not silently convert uncertainty into fact.

This standard applies to data extraction, scraping, enrichment, verification, scoring, memory, agent actions, tool results, generated records, business intelligence, lead intelligence, opportunity intelligence, and any other NCF-governed workflow that creates or mutates factual data.

---

# Article I — Epistemic States

Every material claim or field should be capable of resolving to one of the following states:

| State | Meaning |
|---|---|
| VERIFIED | Evidence directly supports the claim and required verification passed |
| OBSERVED | An identified source explicitly states the claim; independent verification was not required or completed |
| DERIVED | Deterministically calculated from supported facts |
| INFERRED | A reasoned conclusion supported by evidence but not established as fact |
| UNKNOWN | Insufficient evidence |
| CONFLICTING | Credible sources disagree |
| STALE | Previously supported but outside the applicable freshness policy |
| ERROR | Research, extraction, or verification failed technically |

The following inequalities are constitutional invariants:

```text
UNKNOWN != VERIFIED
ERROR != VERIFIED
INFERRED != OBSERVED
OBSERVED != VERIFIED
```

A lower-certainty state may be promoted only when the applicable evidence and verification requirements are satisfied.

---

# Article II — No-Guess Rule

NCF systems MUST NOT invent, autocomplete, synthesize, estimate, or guess a factual value merely because:

- a schema requires a field;
- a UI expects a value;
- a model can produce a plausible answer;
- an upstream source is incomplete;
- a provider is unavailable;
- a verification request timed out;
- a workflow needs to continue;
- a database row would otherwise be incomplete.

Null, empty, unknown, unavailable, or deferred are valid outcomes.

Inference remains permitted when clearly labeled and separated from factual fields.

---

# Article III — Evidence Envelope

Material facts SHOULD progressively adopt a standard evidence envelope:

```json
{
  "value": "2026-10-15",
  "state": "OBSERVED",
  "confidence": 0.95,
  "source": {
    "provider": "official_source",
    "url": "https://example.org/program",
    "record_id": null
  },
  "evidence": "Applications must be submitted by October 15, 2026.",
  "observed_at": "2026-09-08T16:00:00-05:00",
  "verified_at": null,
  "expires_at": null,
  "schema_version": "1.0"
}
```

Legacy flat fields MAY remain temporarily for compatibility, but their values must not be treated as verified without provenance.

---

# Article IV — Source and Provenance Rules

1. Search results are candidate sources, not proof.
2. A healed or redirected URL is a candidate source until the content is validated.
3. LLM output alone is not evidence for a factual claim.
4. Provider metadata must preserve source identity where legally and operationally appropriate.
5. Material claims should retain source URL, provider record ID, timestamp, or equivalent provenance when available.
6. Conflicting credible evidence must be preserved as CONFLICTING rather than silently resolved.
7. Provenance must not be fabricated retroactively for legacy data.

---

# Article V — Verification Rules

Verification must fail closed.

If a verifier is unavailable, missing credentials, times out, returns malformed data, or produces an ambiguous response, the result MUST be one of:

- UNKNOWN
- UNVERIFIED
- ERROR
- STALE

It MUST NOT become VERIFIED, CLEAN, ACTIVE, ELIGIBLE, SAFE, or equivalent solely because verification could not run.

A provider outage is operational state, not evidence.

---

# Article VI — Extraction and Generative AI Rules

Factual extraction prompts MUST include equivalent constraints to:

> Extract factual values only when supported by supplied evidence. Do not estimate, predict, guess, invent, synthesize, or complete missing factual fields. Return null, empty, or UNKNOWN when evidence is insufficient. If the evidence supports only an inference, return it separately as INFERRED.

Schemas SHOULD permit missing or nullable factual values where technically possible.

Creative generation may occur in clearly creative fields, but creative text must not introduce unsupported factual claims.

Examples:

- A cold-email opener may rephrase observed business facts, but may not invent a recent expansion.
- A proposal draft may persuasively describe an applicant's documented qualifications, but may not invent certifications.
- A grant summary may simplify supported criteria, but may not invent a deadline or award amount.

---

# Article VII — Discovery, Healing, and Prediction

Discovery, source resolution, and verification are separate responsibilities.

```text
DISCOVER
  ↓
CANDIDATE
  ↓
SOURCE RESOLUTION
  ↓
EVIDENCE EXTRACTION
  ↓
VERIFICATION
  ↓
VERIFIED / INFERRED / UNKNOWN / CONFLICTING / ERROR
```

A source resolver or "healer" may locate a candidate authoritative page. It does not certify the claims on that page.

Predictive systems may identify probable future opportunities, relationships, or events. Their outputs MUST remain INFERRED or CANDIDATE until evidence supports promotion.

Historical recurrence is not proof of a current cycle.

---

# Article VIII — Agent and Tool Truthfulness

Agents MUST NOT claim an action succeeded without tool or system confirmation.

Recommended action states:

```text
REQUESTED
ATTEMPTED
CONFIRMED
FAILED
UNKNOWN
```

Examples:

- "Committed successfully" requires repository confirmation.
- "Email is valid" requires an applicable verification result.
- "Grant is open" requires evidence of current active status.
- "Payment completed" requires payment-system confirmation.

Agent confidence does not substitute for tool confirmation.

---

# Article IX — Confidence Is Not Permission

Systems that score records must separate factual confidence from operational eligibility.

For example, lead systems should distinguish:

- identity confidence;
- relationship/ownership/employment confidence;
- contact validity;
- compliance or suppression status;
- ICP/commercial fit;
- freshness.

A valid phone number is not automatically contactable.
A deliverable email is not automatically an ICP match.
A strong ICP match is not automatically a verified identity.

---

# Article X — Freshness and Reverification

Evidence-backed facts may expire.

Systems SHOULD define freshness policies by field or object type and SHOULD reverify high-volatility facts before high-impact activation such as outreach, submission, payment, or publication.

A stale previously verified value becomes STALE; it does not remain perpetually verified.

---

# Article XI — Legacy Data

Existing records without evidence metadata must be treated conservatively.

They MAY retain their legacy value for compatibility, but SHOULD be marked LEGACY or UNVERIFIED until refreshed.

NCF systems MUST NOT manufacture source history, timestamps, or verification events for old records.

---

# Article XII — Testing and Certification

NCF certification SHOULD include negative hallucination tests.

A system must be tested with source documents in which important values are intentionally absent.

Example input:

```text
XYZ Foundation supports community programs.
Applications are currently accepted.
```

Expected behavior:

```text
amount: UNKNOWN
deadline: UNKNOWN
contact_email: UNKNOWN
```

Any fabricated value is a certification failure.

Required test classes should include:

- missing factual field;
- provider outage;
- timeout;
- malformed provider response;
- conflicting sources;
- stale data;
- historical-vs-current ambiguity;
- model attempt to fill a required but unsupported field;
- tool action without confirmation.

---

# Article XIII — Minimum Compliance Requirements

An NCF-compliant implementation of this standard must demonstrate that:

1. Unknown factual fields can remain unknown.
2. Verification failures do not fail open.
3. Inferences are labeled.
4. Material facts can retain provenance.
5. Agents distinguish attempted from confirmed actions.
6. Synthetic/demo data cannot silently enter production factual records.
7. Regression tests protect the no-guess invariant.

---

# Constitutional Rule

**When we do not know, we search, defer, or say UNKNOWN. We do not guess.**