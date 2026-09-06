#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from http.server import ThreadingHTTPServer

from .provider_execution_gate import TrustKernelV06ExecutionGate
from .remote_anchor import HTTPSAuditAnchorProvider
from .runtime import CompanyKernel
from .server_v02 import HardenedKernel
from .server_v06 import Handler, _load_policy_keys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--policy-dir", required=True)
    ap.add_argument("--policy-key-env", action="append", default=[])
    ap.add_argument("--bootstrap-env", default="CFHS_BOOTSTRAP_SECRET")
    ap.add_argument("--bootstrap-principal", default="human:owner")
    ap.add_argument("--remote-anchor-endpoint")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8047)
    args = ap.parse_args()

    core = CompanyKernel.from_file(args.state_dir, args.config)
    hardened = HardenedKernel(core, args.policy_dir, set(), False)
    anchor = HTTPSAuditAnchorProvider(args.remote_anchor_endpoint) if args.remote_anchor_endpoint else None
    Handler.kernel = TrustKernelV06ExecutionGate(hardened, _load_policy_keys(args.policy_key_env), anchor)
    Handler.bootstrap_principal = args.bootstrap_principal

    state = Handler.kernel.bootstrap.status()
    if not state["initialized"]:
        secret = os.environ.get(args.bootstrap_env)
        if not secret:
            raise SystemExit(
                f"Bootstrap environment variable is required only for first initialization: {args.bootstrap_env}"
            )
        state = Handler.kernel.bootstrap.initialize(secret)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Company Kernel Live-Adapter Safety v0.6 hardened listening on http://{args.host}:{args.port}", flush=True)
    print("Execution gate: SEMANTIC REPLAY + ANCHORED AUTHORITY + ANCHORED PROVIDER AUDIT", flush=True)
    print("Provider registry: SANDBOX ONLY. Production credentials/providers are rejected.", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
