# Spanner Certification Environment

This directory defines the first real shared-state certification target for Company Kernel.

## Fixed naming standard

```text
project:       cfhs-kernel-cert
instance:      kernel-ha-cert-01
database:      cfhs-cert
deployment:    company-kernel-cert-spanner-01
region config: regional-us-central1
environment:   cert
production:    false
```

## Security boundary

Do not commit service-account keys, JSON credentials, access tokens, refresh tokens, private keys, or provider secrets.

GitHub deployment must use Google Cloud Workload Identity Federation/OIDC. The GitHub workflow identity should be restricted to this repository and the certification environment. Production credentials and production provider writes remain disabled.

## Bootstrap prerequisite

The GCP project must exist before Terraform can create project-scoped Spanner resources. Project creation/billing attachment is intentionally outside this module because it requires organization/billing authority that must not be inferred by the kernel.

Required external facts:

```text
GCP project ID: cfhs-kernel-cert
billing: enabled by authorized GCP administrator
GitHub WIF pool/provider: created by authorized GCP administrator
```

## Terraform

From this directory:

```text
terraform init
terraform plan
terraform apply
```

The module enables the Spanner API, creates the certification instance and database, and installs the three kernel shared-state tables.

## Tables

```text
cfhs_shared_objects
cfhs_shared_fences
cfhs_shared_journal
```

## After apply

Do not declare the deployment certified. Record the exact deployed identity and run the 14-stage Spanner live certification orchestrator. The live driver must collect observed evidence for identity, schema, multi-client visibility, serializability, CAS, fencing, journal ordering, atomic fenced mutation, commit timestamp ordering, durability, topology/fault behavior, external attestation, and the neutral v0.9 gate.

A blocked or failed phase remains BLOCKED/FAIL.
