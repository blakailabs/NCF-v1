#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from http.server import ThreadingHTTPServer
from urllib.parse import urlparse

from .exact_authority import TrustKernelV07ExactAuthorityFinalGate
from .hardening import HardeningError
from .remote_anchor import HTTPSAuditAnchorProvider
from .runtime import CompanyKernel, KernelError
from .server_v02 import HardenedKernel
from .server_v06 import _load_policy_keys
from .server_v06_hardened import HardenedHandler


class V07Handler(HardenedHandler):
    kernel: TrustKernelV07ExactAuthorityFinalGate = None  # type: ignore

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
                    "canonical_provider_gate": "TrustKernelV07ExactAuthorityFinalGate",
                    "production_credentials_allowed": False,
                    "provider_registry": sorted(self.kernel.providers),
                    "distributed_controls": [
                        "business-object identity",
                        "monotonic fencing",
                        "provider stale-fence rejection",
                        "fenced provider execution",
                        "fenced reconciliation ownership",
                        "atomic fenced exact-resource prepare",
                        "versioned distributed transaction journal",
                        "retryable safe abort",
                        "pre-execution takeover after fence expiry",
                        "transaction-coordinated provider lifecycle",
                        "distributed compensation ownership epoch",
                        "compensation provider idempotency",
                        "compensation unknown-outcome reconciliation",
                        "compensation reconciliation attempt history",
                        "fenced approval mutation",
                        "atomic approval plus session provenance",
                        "versioned approval control-plane journal",
                        "exact minor-unit financial authority",
                        "exact-unit elevation scope",
                    ],
                    "compensation_status": "DISTRIBUTED_FENCED_AND_RECONCILABLE",
                    "approval_control_status": "FENCED_SESSION_PROVEN_AND_VERSIONED",
                    "financial_authority_status": "EXACT_MINOR_UNITS_WITH_EXACT_ELEVATION",
                    "reference_backend_production_ready": False,
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
        path = urlparse(self.path).path
        if path == "/v7/provider/compensation/reconcile":
            try:
                body = self._json()
                ctx, _bearer = self._ctx_and_bearer()
                return self._send(
                    200,
                    self.kernel.reconcile_provider_compensation(
                        ctx,
                        body["intent_id"],
                        body["compensation_intent_id"],
                    ),
                )
            except (HardeningError, KernelError) as exc:
                return self._error(exc)
            except Exception as exc:
                return self._send(500, {"error": {"code": "CFHS_INTERNAL", "message": str(exc)}})
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
    V07Handler.kernel = TrustKernelV07ExactAuthorityFinalGate(
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
    print("Canonical gate: TrustKernelV07ExactAuthorityFinalGate", flush=True)
    print("Financial authority: EXACT MINOR UNITS + EXACT-UNIT ELEVATIONS", flush=True)
    print("Approvals: FENCED + SESSION-PROVEN + ATOMICALLY VERSIONED", flush=True)
    print("PREPARE: AUTHORITY ANCHORED + EXACT CAPACITY + OWNERSHIP FENCE COORDINATED", flush=True)
    print("Execution: CURRENT TRANSACTION EPOCH + PROVIDER STALE-FENCE ACCEPTANCE REQUIRED", flush=True)
    print("Reconciliation: SAME TRANSACTION ID + HIGHER FENCING EPOCH", flush=True)
    print("Compensation: INDEPENDENT AUTHORITY + NEW FENCING EPOCH + PROVIDER IDEMPOTENCY + RECONCILIATION", flush=True)
    print("Shared backend reference: NOT PRODUCTION CERTIFIED (NO QUORUM / AUTHORITATIVE TIME)", flush=True)
    print("Provider registry: SANDBOX ONLY. Production credentials/providers are rejected.", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
