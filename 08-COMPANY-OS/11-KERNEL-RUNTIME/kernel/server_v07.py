#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from http.server import ThreadingHTTPServer
from urllib.parse import urlparse

from .hardening import HardeningError
from .recoverable_anchor_consumers import TrustKernelV07RecoverableAnchorFinalGate
from .remote_anchor_config import build_reference_quorum_anchor, reference_quorum_anchor_status
from .runtime import CompanyKernel, KernelError
from .server_v02 import HardenedKernel
from .server_v06 import _load_policy_keys
from .server_v06_hardened import HardenedHandler


class V07Handler(HardenedHandler):
    kernel: TrustKernelV07RecoverableAnchorFinalGate = None  # type: ignore
    remote_anchor_provider = None

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
                    "canonical_provider_gate": "TrustKernelV07RecoverableAnchorFinalGate",
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
                        "trusted external identity policy",
                        "MFA and ACR enforcement",
                        "authentication freshness enforcement",
                        "MFA-bound elevation approval",
                        "S3 strong-provenance release",
                        "authenticated audit-anchor request binding",
                        "signed endpoint anchor receipts",
                        "N-of-M anchor quorum",
                        "durable partial anchor receipts",
                        "same-head anchor recovery",
                    ],
                    "compensation_status": "DISTRIBUTED_FENCED_AND_RECONCILABLE",
                    "approval_control_status": "FENCED_SESSION_PROVEN_AND_VERSIONED",
                    "financial_authority_status": "EXACT_MINOR_UNITS_WITH_EXACT_ELEVATION",
                    "identity_policy": self.kernel.identity_policy_status(),
                    "remote_anchor": reference_quorum_anchor_status(self.remote_anchor_provider),
                    "anchor_recovery": self.kernel.anchor_recovery_status(),
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
        special = {
            "/v7/provider/compensation/reconcile",
            "/v7/provider/compensation/approvals/request",
            "/v7/provider/compensate",
            "/v7/elevations/approve",
        }
        if path in special:
            try:
                body = self._json()
                ctx, bearer = self._ctx_and_bearer()
                if path == "/v7/provider/compensation/reconcile":
                    return self._send(
                        200,
                        self.kernel.reconcile_provider_compensation(
                            ctx,
                            body["intent_id"],
                            body["compensation_intent_id"],
                        ),
                    )
                if path == "/v7/provider/compensation/approvals/request":
                    return self._send(
                        201,
                        self.kernel.request_provider_compensation_approval_with_session(
                            ctx,
                            bearer,
                            body["intent_id"],
                            body.get("arguments", {}),
                            body.get("eligible_approvers", []),
                            body.get("required_count"),
                            int(body.get("ttl_seconds", 900)),
                        ),
                    )
                if path == "/v7/provider/compensate":
                    return self._send(
                        200,
                        self.kernel.compensate_provider_action_with_session(
                            ctx,
                            bearer,
                            body["intent_id"],
                            body.get("arguments", {}),
                            body.get("sandbox_mode", "success"),
                            body.get("compensation_intent_id"),
                            body.get("compensation_approval_request_id"),
                        ),
                    )
                return self._send(
                    200,
                    self.kernel.approve_elevation_with_session(
                        ctx,
                        bearer,
                        body["elevation_id"],
                        int(body.get("ttl_seconds", 600)),
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


def _build_remote_anchor(args, conn):
    endpoint_specs = list(args.remote_anchor_endpoint or [])
    receipt_specs = list(args.remote_anchor_receipt_key_env or [])
    extra_config = bool(
        receipt_specs
        or args.remote_anchor_quorum
        or args.remote_anchor_request_key_env
        or args.remote_anchor_request_key_id
    )
    if not endpoint_specs:
        if extra_config:
            raise HardeningError(
                "CFHS_INVALID_POLICY",
                "Remote anchor quorum/key options require at least two --remote-anchor-endpoint values",
            )
        return None
    return build_reference_quorum_anchor(
        conn,
        endpoint_specs=endpoint_specs,
        receipt_key_specs=receipt_specs,
        quorum=int(args.remote_anchor_quorum),
        request_key_id=str(args.remote_anchor_request_key_id or ""),
        request_key_env=str(args.remote_anchor_request_key_env or ""),
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--policy-dir", required=True)
    ap.add_argument("--kernel-instance-id", required=True)
    ap.add_argument("--policy-key-env", action="append", default=[])
    ap.add_argument("--bootstrap-env", default="CFHS_BOOTSTRAP_SECRET")
    ap.add_argument("--bootstrap-principal", default="human:owner")
    ap.add_argument(
        "--remote-anchor-endpoint",
        action="append",
        default=[],
        help="Repeat as ENDPOINT_ID=https://host/path. Hardened remote mode requires at least two.",
    )
    ap.add_argument(
        "--remote-anchor-receipt-key-env",
        action="append",
        default=[],
        help="Repeat as ENDPOINT_ID:KEY_ID:ENV_VAR; key bytes are loaded only at runtime.",
    )
    ap.add_argument("--remote-anchor-quorum", type=int, default=0)
    ap.add_argument("--remote-anchor-request-key-id")
    ap.add_argument("--remote-anchor-request-key-env")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8048)
    args = ap.parse_args()

    core = CompanyKernel.from_file(args.state_dir, args.config)
    hardened = HardenedKernel(core, args.policy_dir, set(), False)
    try:
        anchor = _build_remote_anchor(args, core.store.conn)
    except HardeningError as exc:
        raise SystemExit(f"Remote anchor configuration rejected: {exc.code}: {exc}") from exc

    V07Handler.remote_anchor_provider = anchor
    V07Handler.kernel = TrustKernelV07RecoverableAnchorFinalGate(
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

    anchor_status = reference_quorum_anchor_status(anchor)
    server = ThreadingHTTPServer((args.host, args.port), V07Handler)
    print(f"Company Kernel Distributed Safety v0.7 listening on http://{args.host}:{args.port}", flush=True)
    print(f"Kernel instance: {args.kernel_instance_id}", flush=True)
    print("Canonical gate: TrustKernelV07RecoverableAnchorFinalGate", flush=True)
    print(f"Identity policy mode: {V07Handler.kernel.production_identity_policy.mode.upper()}", flush=True)
    print(f"Remote anchor mode: {anchor_status['mode']}", flush=True)
    if anchor_status["authenticated_quorum_configured"]:
        print(
            "Remote anchor quorum: "
            f"{anchor_status['required_quorum']} of {len(anchor_status['endpoint_ids'])} endpoints",
            flush=True,
        )
    print("Anchor retry: SAME LOCAL CHAIN HEAD + DURABLE PENDING CHECKPOINT", flush=True)
    print("Reference anchor crypto: NOT PRODUCTION CERTIFIED (HMAC reference/test mechanism)", flush=True)
    print("Production identity: TRUSTED PROVIDER/ISSUER + MFA/ACR + AUTH FRESHNESS WHEN PRODUCTION MODE IS ENABLED", flush=True)
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
