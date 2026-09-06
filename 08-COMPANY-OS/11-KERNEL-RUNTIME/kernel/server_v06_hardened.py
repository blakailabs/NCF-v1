#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from http.server import ThreadingHTTPServer
from urllib.parse import urlparse

from .hardening import HardeningError
from .provider_release_gate import TrustKernelV06ReleaseGate
from .remote_anchor import HTTPSAuditAnchorProvider
from .runtime import CompanyKernel, KernelError
from .server_v02 import HardenedKernel
from .server_v06 import Handler, _load_policy_keys


class HardenedHandler(Handler):
    kernel: TrustKernelV06ReleaseGate = None  # type: ignore

    def do_POST(self):
        path = urlparse(self.path).path
        special = {
            "/v6/provider/compensation/approvals/request",
            "/v6/provider/compensate",
        }
        if path not in special:
            return super().do_POST()
        try:
            body = self._json()
            ctx, _bearer = self._ctx_and_bearer()
            if path == "/v6/provider/compensation/approvals/request":
                return self._send(
                    201,
                    self.kernel.request_provider_compensation_approval(
                        ctx,
                        body["intent_id"],
                        body.get("arguments", {}),
                        body.get("eligible_approvers", []),
                        body.get("required_count"),
                        int(body.get("ttl_seconds", 900)),
                    ),
                )
            return self._send(
                200,
                self.kernel.compensate_provider_action(
                    ctx,
                    body["intent_id"],
                    body.get("arguments", {}),
                    body.get("sandbox_mode", "success"),
                    body.get("compensation_intent_id"),
                    body.get("compensation_approval_request_id"),
                ),
            )
        except (HardeningError, KernelError) as exc:
            self._error(exc)
        except Exception as exc:
            self._send(500, {"error": {"code": "CFHS_INTERNAL", "message": str(exc)}})


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
    HardenedHandler.kernel = TrustKernelV06ReleaseGate(hardened, _load_policy_keys(args.policy_key_env), anchor)
    HardenedHandler.bootstrap_principal = args.bootstrap_principal

    state = HardenedHandler.kernel.bootstrap.status()
    if not state["initialized"]:
        secret = os.environ.get(args.bootstrap_env)
        if not secret:
            raise SystemExit(
                f"Bootstrap environment variable is required only for first initialization: {args.bootstrap_env}"
            )
        state = HardenedHandler.kernel.bootstrap.initialize(secret)

    server = ThreadingHTTPServer((args.host, args.port), HardenedHandler)
    print(f"Company Kernel Live-Adapter Safety v0.6 hardened listening on http://{args.host}:{args.port}", flush=True)
    print("Release gate: REPLAY PRE-RESERVATION + ANCHORED AUTHORITY + ANCHORED PROVIDER AUDIT", flush=True)
    print("Compensation gate: SEPARATE S3 INTENT + MULTI-PARTY PROVENANCE + ANCHORED AUTHORITY", flush=True)
    print("Provider registry: SANDBOX ONLY. Production credentials/providers are rejected.", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
