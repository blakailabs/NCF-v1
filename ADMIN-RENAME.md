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

**Pending administrative GitHub rename.**

The connected GitHub tooling can modify branches, files, commits, pull requests, tests, and workflows, but does not expose repository-name mutation. A fallback attempt to create a GitHub tracking issue was rejected by GitHub because the connected account currently requires at least one verified email address for issue creation.

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
└── Kernel Trust Layer
```

## After the GitHub rename

1. Confirm the old GitHub URL redirects to the new repository.
2. Update local remotes or automation references that do not follow GitHub redirects.
3. Update the repository description to: `A governed operating system for AI-native companies.`
4. Preserve NCF terminology for the constitutional layer.
5. Re-run Company Kernel CI after the rename.
