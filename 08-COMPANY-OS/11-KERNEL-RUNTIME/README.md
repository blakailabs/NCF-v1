# Minimal Company Kernel Runtime v0.1

This is the first runnable reference implementation of the Company Kernel behind the CFHS/NCF Company OS architecture.

## What it proves

- durable principal registry
- deterministic default-deny authorization
- fine-grained capability matching
- contextual limits (`max_amount`, resource ceilings)
- `ALLOW`, `DENY`, and `ELEVATION_REQUIRED`
- human approval → narrow time-limited elevation
- mock device broker with S0–S3 side-effect metadata
- idempotency handling
- process table and lifecycle state
- durable checkpoints
- restart/recovery from SQLite state
- complete append-oriented audit trail
- HTTP daemon using Python standard library only

## Safety

The reference devices are mocks. They do not send real email, move money, or call external providers. No credentials or secret values are required.

## Run tests

```bash
PYTHONPATH=. python -m unittest discover -s tests -v
```

## Run acceptance demo

```bash
PYTHONPATH=. python examples/demo.py
```

## Run daemon

```bash
PYTHONPATH=. python -m kernel.server --state-dir ./state --config examples/kernel.config.json --port 8042
```

Then:

```bash
curl http://127.0.0.1:8042/v1/health
```

## Boundary

This is a **working reference kernel MVP**, not a production-ready financial/security kernel. Productionization still requires hardened authentication, policy compilation, secure secret-vault integration, sandboxed live device adapters, cryptographically tamper-evident audit storage, concurrency controls, distributed queues, HA/failover, and formal security review.
