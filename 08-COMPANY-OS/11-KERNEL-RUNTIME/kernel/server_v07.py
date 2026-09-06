#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from http.server import ThreadingHTTPServer
from urllib.parse import urlparse

from .distributed_provider_gate import TrustKernelV07DistributedProviderGate
from .remote_anchor import HTTPSAuditAnchorProvider
from .runtime import CompanyKernel
from .server_v02 import HardenedKernel
from .server_v06 import _load_policy_keys
from .server_v06_hardened import HardenedHandler


class V07Handler(HardenedHandler):
    kernel: TrustKernelV07DistributedProviderGate = None  # type: ignore

    def _translate_v7_path(self) -> str:
        original = self.path
        parsed = urlparse(original)
        if parsed.path.startswith("/v7/"):
            suffix = parsed.path[len("/v7/") :]
            replacement = "/v6/" + suffix
            if parsed.query:
                replacement += "?" + parsed.query
            self.path = replacement
        return original

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/v7/health":
            health = self.kernel.core.health()
            health.update(
                {
                    "distributed_safety_version": "0.7",
                    "kernel_instance_id": self.kernel.kernel_instance_id,
                    "production_credentials_allowed": False,
                    "provider_registry": sorted(self.kernel.providers),
                    "distributed_controls": [
                        "business-object identity",
                        "monotonic fencing",
                        "provider stale-fence rejection",
                        "fenced provider execution",
                        "fenced reconciliation ownership",
                    ],
                    "compensation_status": "BLOCKED_PENDING_DISTRIBUTED_INTEGRATION",
                    "audit_chain": self.kernel.hardened.audit_chain.verify(),
                    "anchor_chain": self.kernel.anchors.verify(),
                    "bootstrap": self.kernel.bootstrap.status(),
                }
            )
            return self._send(200, health)
        original = self._translate_v7_path()
        try:
            return super().do_GET()
        finally:
            self.path = original

    def do_POST(self):
        original = self._translate_v7_path()
        try:
            return super().do_POST()
        finally:
            self.path = original


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--policy-dir", required=True)
    ap.add_argument("--kernel-instance-id", required=True)
    ap.add_argument("--policy-key-env", action="append", default=[])
    ap.add_argument("--bootstrap-env", default="CFHS_BOOTSTRAP_SECRET")
    ap.add_argument("--bootstrap-principal", default="human:owner")
    ap.add_argument("--remote-anchor-endpoint")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8048)
    args = ap.parse_args()

    core = CompanyKernel.from_file(args.state_dir, args.config)
    hardened = HardenedKernel(core, args.policy_dir, set(), False)
    anchor = HTTPSAuditAnchorProvider(args.remote_anchor_endpoint) if args.remote_anchor_endpoint else None
    V07Handler.kernel = TrustKernelV07DistributedProviderGate(
        hardened,
        _load_policy_keys(args.policy_key_env),
        anchor,
        kernel_instance_id=args.kernel_instance_id,
    )
    V07Handler.bootstrap_principal = args.bootstrap_principal

    state = V07Handler.kernel.bootstrap.status()
    if not state["initialized"]:
        secret = os.environ.get(args.bootstrap_env)
        if not secret:
            raise SystemExit(
                f"Bootstrap environment variable is required only for first initialization: {args.bootstrap_env}"
            )
        V07Handler.kernel.bootstrap.initialize(secret)

    server = ThreadingHTTPServer((args.host, args.port), V07Handler)
    print(f"Company Kernel Distributed Safety v0.7 listening on http://{args.host}:{args.port}", flush=True)
    print(f"Kernel instance: {args.kernel_instance_id}", flush=True)
    print("Execution: BUSINESS IDENTITY + CURRENT FENCE REQUIRED BEFORE PROVIDER INVOCATION", flush=True)
    print("Reconciliation: SEPARATELY FENCED WITH A HIGHER OWNERSHIP EPOCH", flush=True)
    print("Compensation: BLOCKED UNTIL DISTRIBUTED COMPENSATION SAFETY IS INTEGRATED", flush=True)
    print("Provider registry: SANDBOX ONLY. Production credentials/providers are rejected.", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
