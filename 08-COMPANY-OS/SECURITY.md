# Company OS Extension — Security and Sensitive Data Rules

This branch must remain safe to clone, fork, inspect, and audit.

## Never commit

- passwords
- API keys
- OAuth access or refresh tokens
- bearer tokens
- private keys
- seed phrases
- database passwords
- cloud credentials
- banking or payment credentials
- session cookies
- authentication headers
- unredacted secrets copied from `.env` files
- production customer data unless explicitly sanitized and approved
- regulated personal data used only as test fixtures

## Secret representation

Use opaque references only:

```text
secret://mail/google
secret://payments/stripe
secret://cloud/production
```

The Company Kernel's secret broker resolves these references at runtime.

## Discovery safety

CDM discovery is read-only by default. A connector uses minimum privileges and must not create, modify, publish, delete, spend, transfer, or send during discovery unless an explicitly authorized test requires it.

## Example data

All example companies, people, accounts, IDs, amounts, and operational data in this extension are synthetic unless stated otherwise. Do not substitute live credentials into examples.
