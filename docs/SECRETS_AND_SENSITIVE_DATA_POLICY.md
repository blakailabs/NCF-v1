# Secrets and Sensitive Data Policy

## Absolute Rule

No API keys, access tokens, private keys, passwords, credentials, service-account JSON, webhook secrets, session cookies, private URLs, customer data, protected health/financial data, or sensitive personal information may be committed to Git or hardcoded in source code.

This applies to code, docs, tests, screenshots, examples, logs, fixtures, prompts, issue text, comments, and generated files.

## Allowed

- `.env.example` with variable names only.
- Placeholder values such as `REPLACE_ME`, `your_key_here`, or empty strings.
- Public documentation URLs.
- Non-sensitive configuration that is explicitly safe to publish.

## Not Allowed

- Real `.env` files.
- Provider keys: OpenAI, Anthropic, Gemini, HeyGen, Buffer, Firebase Admin, Supabase, Stripe, Twilio, SendGrid, Gmail, GitHub, Netlify, Vercel, Apify, PeopleDataLabs, LegiScan, Open States, etc.
- Service account private keys.
- OAuth client secrets.
- Webhook signing secrets.
- Bearer tokens.
- Private customer URLs or document links.
- Raw logs containing credentials, PII, or provider payloads.
- Hardcoded org IDs, channel IDs, avatar IDs, voice IDs, project IDs, or private spreadsheet/export URLs when they are deployment-specific.

## Required Pattern

All sensitive values must be loaded from environment variables, managed secret stores, deployment provider secret settings, or runtime configuration records with access controls. Feature code must never contain secret literals.

## Required Pre-Commit Checklist

- Run secret scan if available.
- Search changed files for `key`, `secret`, `token`, `password`, `private_key`, `bearer`, `.env`, `credential`, `client_secret`.
- Confirm examples use placeholders only.
- Confirm logs and screenshots do not expose dashboards, keys, tokens, IDs, emails, private URLs, or customer data.

## If a Secret Is Committed

Stop work, do not paste the value anywhere, rotate/revoke it in the provider dashboard, remove it from code, rewrite Git history if required, audit usage, and document the incident without exposing the secret.

## Definition of Done

A change is not complete until secrets and sensitive data are absent from Git, loaded only through approved runtime configuration, and protected by scans or review gates where possible.
