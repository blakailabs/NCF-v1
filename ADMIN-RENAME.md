# Repository Administrative Rename

## Canonical project name

**Company Operating System**

## Required GitHub slug rename

```text
blakailabs/NCF-v1
        ↓
blakailabs/Company-Operating-System
```

## Status

**Pending one administrative GitHub repository rename.**

The connected GitHub tooling can modify branches, files, commits, pull requests, issues, tests, and workflows, but it does **not** expose the repository-name mutation endpoint. The prior account-email blocker is resolved; the remaining limitation is specifically the connector's lack of repository-admin rename support.

## Why the rename is correct

NCF is still a foundational component, but it is now one layer within the broader project:

```text
Company Operating System
├── NCF — constitutional governance
├── CDM — company discovery/install manifest
├── CFHS — filesystem hierarchy standard
├── Materializer — CDM → CFHS installation
├── Company Kernel API
├── Company Kernel Runtime
├── Kernel Hardening
└── Kernel Trust / Safety Layers
```

## GitHub Settings action

In the GitHub repository UI:

```text
Settings
→ General
→ Repository name
→ Company-Operating-System
→ Rename
```

## After the GitHub rename

1. Confirm the old GitHub URL redirects to the new repository.
2. Update local remotes or automation references that do not follow GitHub redirects.
3. Update the repository description to: `A governed operating system for AI-native companies.`
4. Preserve NCF terminology for the constitutional layer.
5. Re-run Company Kernel CI after the rename.
6. Update `RUNTIME-STATUS.md` to remove the historical-slug rename-pending note.
