# Runtime Reference Validation

**Version:** 0.1  
**Validated:** 2026-09-05

## Results

- CFHS materializer tests: **PASS**
- Company Kernel API contract tests: **PASS**
- Common real-secret pattern scan: **PASS**
- Minimal example CDM materialization: **PASS**
- Materialization warnings: **0**
- Unmapped sections in minimal fixture: **0**

## Archive integrity

`company-os-runtime-v0.1.tar.xz`

SHA-256:

```text
2fa3770fc10049238bd9e57f5fb8a8ac9bdc78a28b83ee0265d52554408a33c3
```

## Expected generated example files

```text
.cfhs-manifest.json
boot/materialization.json
dev/mail/mail-primary.json
etc/budgets/resources.json
etc/company/company.json
etc/devices/systems.json
etc/identity/principals.json
etc/mounts/repositories.json
home/agents/research-agent/.identity.json
home/humans/founder/.identity.json
mnt/company-files/.mount.json
opt/crm/manifest.json
sys/resources/resources.json
usr/skills/research/manifest.json
var/archive/cdm-source.json
```

## Scope

This is a **reference contract/materializer**, not a production Company Kernel. It does not yet execute live device adapters, a production policy engine, a secret broker, process scheduling, checkpoints, or recovery.
