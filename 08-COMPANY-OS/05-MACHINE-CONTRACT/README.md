# CDM Machine Contract Package v0.1

This package is the executable contract layer for the Company Discovery Manifest (CDM) and Company Filesystem Hierarchy Standard (CFHS).

It is intended to be consumed by:
- discovery installers,
- connector implementations,
- policy engines,
- schema validators,
- mapping engines,
- certification runners,
- Company Kernel bootstrap tooling.

## Contract layers

1. **JSON Schema** — structural validity of CDM objects and manifests.
2. **Connector Interface** — safe, read-only-by-default discovery contract.
3. **Inference Rule Format** — machine-readable candidate inference with confidence, authority, risk, and confirmation gates.
4. **Mapping Rule DSL** — deterministic conversion from normalized CDM objects to CFHS paths.
5. **Operational Validation Rules** — safety/completeness rules beyond JSON shape.
6. **Certification Profile** — CDM-0 through CDM-5 gates.
7. **Certification Test Suite** — positive and negative fixtures.
8. **Sample Manifest** — implementation-ready example.

## Source archive

The complete validated v0.1 source package is committed alongside this README as:

```text
cdm-machine-contract-v0.1.tar.xz
```

SHA-256:

```text
46812fdb37d46dc4e47704b7f716170b5b004bbca2e03b11089efc5512c904c3
```

Extract with:

```bash
tar -xJf cdm-machine-contract-v0.1.tar.xz
```

The archive contains the full source tree: schemas, specs, rules, examples, tests, fixtures, validation script, package manifest, and validation report.

## Safety rules

The package encodes these constitutional invariants:

- discovery is read-only by default;
- AI/inference cannot self-canonicalize consequential facts;
- no P0 unknown may remain for boot certification;
- technical permissions are distinct from business authority;
- consequential authority must be bounded;
- agent authority is non-delegable by default;
- raw secrets are not allowed in the manifest;
- privileged CFHS paths require confirmed A3+ sources;
- `/tmp` cannot contain canonical state;
- critical systems require ownership and recovery semantics;
- CDM-5 requires explicit autonomy evaluation evidence.

## Validation result

```text
CDM v0.1 machine-contract validation
Rule/schema files: PASS
Certification tests: PASS
Sample manifest schema: PASS
Sample computed certification: CDM-4
Sample failed operational rules: VR-021
```

The ordinary sample intentionally stops at CDM-4 because autonomy evaluation is incomplete. A separate `valid-cdm5.cdm.yaml` fixture in the source archive demonstrates CDM-5.

## Important semantic rule

A complete-looking manifest is not equivalent to a complete company.

The system must never increase its readiness or certification score by converting uncertainty into invented certainty.

> An explicit unknown is more correct than an invented fact.
