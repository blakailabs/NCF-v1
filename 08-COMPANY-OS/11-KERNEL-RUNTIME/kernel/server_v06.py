#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .action_safety import ActionIntent
from .anchored_provider_audit import AnchoredProviderActionAudit
from .approval_provenance import (
    ApprovalProvenanceLedger,
    ApprovalSessionResolver,
    SessionIdentityProvenanceLedger,
)
from .exact_units import ExactResourceLedger, ExactUnitPolicy
from .hardening import HardeningError
from .live_adapter_safety import (
    ProviderBoundCompensationRegistry,
    ProviderReconciliationLedger,
    SQLiteSandboxProvider,
)
from .provider_action_hardening import ResilientProviderActionCoordinator
from .remote_anchor import HTTPSAuditAnchorProvider
from .runtime import CompanyKernel, KernelError, RequestContext
from .server_v02 import HardenedKernel
from .server_v05 import TrustKernelV05


class TrustKernelV06(TrustKernelV05):
    """Sandbox-only provider-shaped kernel with exact accounting and reconciliation."""

    def __init__(self, hardened: HardenedKernel, trusted_policy_keys: dict[str, bytes] | None = None, provider_anchor=None):
        super().__init__(hardened, trusted_policy_keys or {})
        conn = self.core.store.conn
        self.exact_resources = ExactResourceLedger(conn)
        self.session_identity_provenance = SessionIdentityProvenanceLedger(conn)
        self.approval_session_resolver = ApprovalSessionResolver(conn, self.session_identity_provenance)
        self.approval_provenance = ApprovalProvenanceLedger(conn)
        self.provider_reconciliation = ProviderReconciliationLedger(conn)
        self.provider_compensation_bindings = ProviderBoundCompensationRegistry(conn)
        self.provider_audit = AnchoredProviderActionAudit(
            conn,
            self.hardened.audit_chain,
            provider_anchor or self.anchors,
        )
        self.provider_actions = ResilientProviderActionCoordinator(
            conn,
            self.exact_resources,
            self.provider_reconciliation,
            self.provider_compensation_bindings,
            self.provider_audit,
        )
        self.providers = {
            "sandbox-payments": SQLiteSandboxProvider(conn, "sandbox-payments"),
        }
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_intent_bindings_v06(
                intent_id TEXT PRIMARY KEY,
                intent_digest TEXT NOT NULL UNIQUE,
                device_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                resource TEXT NOT NULL,
                side_effect_class TEXT NOT NULL,
                live_profile_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()

    def _provider(self, provider_id: str) -> SQLiteSandboxProvider:
        provider = self.providers.get(provider_id)
        if not provider:
            raise HardeningError(
                "CFHS_DEVICE_DENIED",
                "v0.6 accepts only explicitly registered sandbox providers",
                {"provider_id": provider_id},
            )
        return provider

    def _live_profile(self, device: dict[str, Any], operation: dict[str, Any], require_exact: bool = True) -> dict[str, Any]:
        profile = dict(operation.get("live_adapter_safety") or {})
        if not profile or profile.get("sandbox_only") is not True:
            raise HardeningError("CFHS_INVALID_POLICY", "v0.6 provider operation must be explicitly sandbox-only")
        provider_id = str(profile.get("provider_id", ""))
        if not provider_id or provider_id != str(device.get("provider", "")):
            raise HardeningError("CFHS_INVALID_POLICY", "Provider safety profile does not match device provider")
        self._provider(provider_id)
        if require_exact:
            exact = profile.get("exact_resource")
            if not isinstance(exact, dict):
                raise HardeningError("CFHS_INVALID_POLICY", "Provider operation lacks exact-resource policy")
            for key in ("pool_id", "argument", "unit_kind"):
                if not exact.get(key):
                    raise HardeningError("CFHS_INVALID_POLICY", f"Exact-resource profile is missing: {key}")
        return profile

    def _provider_binding(self, intent_id: str) -> dict[str, Any]:
        row = self.core.store.one("SELECT * FROM provider_intent_bindings_v06 WHERE intent_id=?", (intent_id,))
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Provider intent binding not found")
        return dict(row)

    def _bound_provider_context(self, intent_id: str) -> tuple[ActionIntent, dict[str, Any], dict[str, Any], dict[str, Any]]:
        intent = self._load_intent(intent_id)
        binding = self._provider_binding(intent_id)
        if binding["intent_digest"] != intent.intent_digest():
            raise HardeningError("CFHS_CONFLICT", "Provider intent digest no longer matches its durable binding")
        device, operation = self._device_operation(binding["device_id"], binding["operation"])
        profile = self._live_profile(device, operation)
        frozen = json.dumps(profile, sort_keys=True, separators=(",", ":"))
        if (
            binding["provider_id"] != profile["provider_id"]
            or binding["resource"] != device.get("resource", f"/dev/{binding['device_id']}")
            or binding["side_effect_class"] != operation.get("side_effect_class", "S0")
            or binding["live_profile_json"] != frozen
            or intent.resource != binding["resource"]
            or intent.action != binding["operation"]
            or intent.side_effect_class != binding["side_effect_class"]
        ):
            raise HardeningError("CFHS_CONFLICT", "Provider/device/safety profile changed after intent creation")
        return intent, binding, operation, profile

    @staticmethod
    def _exact_policy(profile: dict[str, Any]) -> ExactUnitPolicy:
        exact = profile["exact_resource"]
        return ExactUnitPolicy(
            pool_id=str(exact["pool_id"]),
            argument=str(exact["argument"]),
            unit_kind=str(exact["unit_kind"]),
            minor_exponent=int(exact.get("minor_exponent", 0)),
            currency=exact.get("currency"),
        )

    def configure_exact_resource_pool(
        self,
        ctx: RequestContext,
        pool_id: str,
        hard_limit_units: int,
        unit_kind: str,
        unit_metadata: dict[str, Any] | None = None,
        used_units: int | None = None,
    ) -> dict[str, Any]:
        decision = self.authorize(ctx, "kernel.provider.resource.configure", f"/run/provider-actions/resources/{pool_id}", {})
        if decision["decision"] != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Exact provider resource configuration denied", decision)
        result = self.exact_resources.configure_pool(pool_id, hard_limit_units, unit_kind, unit_metadata, used_units)
        self.hardened._chain(ctx, "provider.resource.configured.v06", result)
        return result

    def create_provider_intent(
        self,
        ctx: RequestContext,
        device_id: str,
        operation_name: str,
        arguments: dict[str, Any],
        replay_nonce: str,
        purpose: str,
        evidence_refs: list[str] | None = None,
        required_approvals: int | None = None,
    ) -> dict[str, Any]:
        decision = self.authorize(ctx, "kernel.action.intent.create", "/run/actions/intents", {})
        if decision["decision"] != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Provider-intent creation denied", decision)
        device, operation = self._device_operation(device_id, operation_name)
        profile = self._live_profile(device, operation)
        side = operation.get("side_effect_class", "S0")
        action_safety = operation.get("action_safety") or {}
        policy_minimum = int(action_safety.get("minimum_approvals", 2 if side == "S3" else 0))
        requested = int(required_approvals or 0)
        effective_approvals = max(policy_minimum, requested)
        # Validate exact conversion at intent creation without storing floating
        # resource amounts in the semantic envelope.
        exact_policy = self._exact_policy(profile)
        exact_units = exact_policy.to_units(arguments)
        intent = ActionIntent.create(
            actor_id=ctx.actor_id,
            process_id=ctx.process_id,
            action=operation_name,
            resource=device.get("resource", f"/dev/{device_id}"),
            side_effect_class=side,
            purpose=purpose,
            arguments=arguments,
            replay_nonce=replay_nonce,
            required_approvals=effective_approvals,
            evidence_refs=evidence_refs,
            resource_requests=[],
        )
        frozen = json.dumps(profile, sort_keys=True, separators=(",", ":"))
        now = intent.created_at
        try:
            self.core.store.conn.execute("BEGIN IMMEDIATE")
            self.core.store.conn.execute(
                """
                INSERT INTO action_intent_index(
                    intent_id,intent_digest,replay_nonce,side_effect_class,envelope_json,status,created_at,updated_at
                ) VALUES(?,?,?,?,?,'PENDING',?,?)
                """,
                (
                    intent.intent_id,
                    intent.intent_digest(),
                    intent.replay_nonce,
                    intent.side_effect_class,
                    json.dumps(intent.envelope(), sort_keys=True),
                    now,
                    now,
                ),
            )
            self.core.store.conn.execute(
                "INSERT INTO provider_intent_bindings_v06(intent_id,intent_digest,device_id,provider_id,operation,resource,side_effect_class,live_profile_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    intent.intent_id,
                    intent.intent_digest(),
                    device_id,
                    profile["provider_id"],
                    operation_name,
                    intent.resource,
                    side,
                    frozen,
                    now,
                ),
            )
            self.core.store.conn.commit()
        except Exception:
            self.core.store.conn.rollback()
            raise

        compensation = profile.get("compensation")
        if isinstance(compensation, dict):
            self.provider_compensation_bindings.bind(
                intent.intent_digest(),
                profile["provider_id"],
                device_id,
                operation_name,
                str(compensation["device_id"]),
                str(compensation["operation"]),
                str(compensation["authorization_action"]),
            )

        result = {
            "intent": intent.envelope(),
            "intent_digest": intent.intent_digest(),
            "device_id": device_id,
            "provider_id": profile["provider_id"],
            "exact_resource": {
                "pool_id": exact_policy.pool_id,
                "units": exact_units,
                "unit_kind": exact_policy.unit_kind,
                "currency": exact_policy.currency,
                "minor_exponent": exact_policy.minor_exponent,
            },
            "required_approvals": effective_approvals,
            "sandbox_only": True,
        }
        self.hardened._chain(ctx, "provider.intent.created.v06", result)
        return result

    def approve_action_with_session(self, ctx: RequestContext, bearer_token: str, request_id: str) -> dict[str, Any]:
        decision = self.authorize(ctx, "kernel.action.approval.approve", f"/run/actions/approvals/{request_id}", {})
        if decision["decision"] != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Action approval denied", decision)
        evidence = self.approval_session_resolver.resolve(bearer_token, ctx.actor_id)
        result = self.action_approvals.approve(request_id, ctx.actor_id)
        provenance = self.approval_provenance.record(request_id, ctx.actor_id, evidence)
        safe = {
            **result,
            "session_id": provenance["session_id"],
            "authentication_class": provenance["authentication_class"],
            "session_evidence_digest": provenance["session_evidence_digest"],
        }
        self.hardened._chain(ctx, "action.approval.provenance.v06", safe)
        return safe

    def _approval_bound_intent(self, intent: ActionIntent, approval_request_id: str | None) -> ActionIntent:
        if intent.required_approvals <= 0:
            return intent
        if not approval_request_id:
            raise HardeningError("CFHS_ELEVATION_REQUIRED", "Provider action requires an approval request")
        bound = intent.with_approval(approval_request_id)
        self.action_approvals.require_satisfied(approval_request_id, bound.intent_digest(), bound.required_approvals)
        provenance = self.approval_provenance.require_complete(approval_request_id)
        if provenance["approval_count"] < bound.required_approvals:
            raise HardeningError("CFHS_ELEVATION_REQUIRED", "Provider action lacks enough proven approvals")
        return bound

    def prepare_provider_action(
        self,
        ctx: RequestContext,
        intent_id: str,
        arguments: dict[str, Any],
        approval_request_id: str | None = None,
    ) -> dict[str, Any]:
        intent, binding, _operation, profile = self._bound_provider_context(intent_id)
        if ctx.actor_id != intent.actor_id or ctx.process_id != intent.process_id:
            raise HardeningError("CFHS_POLICY_DENIED", "Provider intent is bound to another principal/process")
        bound = self._approval_bound_intent(intent, approval_request_id)
        provider = self._provider(binding["provider_id"])
        exact_policy = self._exact_policy(profile)
        result = self.provider_actions.prepare(
            bound,
            binding["device_id"],
            provider,
            arguments,
            exact_policy,
            lambda i, a: self.authorize(ctx, i.action, i.resource, a),
        )
        self.hardened._chain(
            ctx,
            "provider.action.prepared.v06",
            {
                "intent_id": intent_id,
                "intent_digest": intent.intent_digest(),
                "provider_id": binding["provider_id"],
                "status": result["status"],
                "audit_id": result["audit_id"],
                "exact_units": result["exact_units"],
                "sandbox_only": True,
            },
        )
        return result

    def execute_provider_action(
        self,
        ctx: RequestContext,
        intent_id: str,
        arguments: dict[str, Any],
        approval_request_id: str | None = None,
        sandbox_mode: str = "success",
    ) -> dict[str, Any]:
        intent, binding, _operation, _profile = self._bound_provider_context(intent_id)
        if ctx.actor_id != intent.actor_id or ctx.process_id != intent.process_id:
            raise HardeningError("CFHS_POLICY_DENIED", "Provider intent is bound to another principal/process")
        bound = self._approval_bound_intent(intent, approval_request_id)
        provider = self._provider(binding["provider_id"])
        result = self.provider_actions.execute_prepared(bound, provider, arguments, sandbox_mode)
        safe = {
            "intent_id": intent_id,
            "intent_digest": result.intent_digest,
            "provider_id": result.provider_id,
            "provider_action_id": result.provider_action_id,
            "provider_idempotency_key": result.provider_idempotency_key,
            "status": result.status,
            "reconciliation_case_id": result.reconciliation_case_id,
            "exact_units": result.exact_units,
            "sandbox_only": True,
        }
        if result.status == "RECONCILIATION_REQUIRED":
            self.events_v04.publish("company.provider.reconciliation_required", safe)
        self.hardened._chain(ctx, "provider.action.executed.v06", safe)
        return {**safe, "result": result.result}

    def reconcile_provider_action(self, ctx: RequestContext, intent_id: str) -> dict[str, Any]:
        intent, binding, _operation, _profile = self._bound_provider_context(intent_id)
        decision = self.authorize(ctx, "kernel.provider.reconcile", f"/run/provider-actions/{intent.intent_digest()}", {})
        if decision["decision"] != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Provider reconciliation denied", decision)
        provider = self._provider(binding["provider_id"])
        result = self.provider_actions.reconcile(intent.intent_digest(), provider)
        safe = {
            "intent_id": intent_id,
            "intent_digest": result.intent_digest,
            "provider_id": result.provider_id,
            "provider_action_id": result.provider_action_id,
            "status": result.status,
            "reconciliation_case_id": result.reconciliation_case_id,
            "exact_units": result.exact_units,
            "sandbox_only": True,
        }
        self.hardened._chain(ctx, "provider.action.reconciled.v06", safe)
        return {**safe, "result": result.result}

    def compensate_provider_action(self, ctx: RequestContext, intent_id: str, arguments: dict[str, Any], sandbox_mode: str = "success") -> dict[str, Any]:
        intent, binding, _operation, _profile = self._bound_provider_context(intent_id)
        provider = self._provider(binding["provider_id"])

        def authorize_compensation(compensation_binding: dict[str, Any], comp_arguments: dict[str, Any]):
            device, operation = self._device_operation(
                compensation_binding["compensation_device_id"],
                compensation_binding["compensation_operation"],
            )
            if device.get("provider") != provider.provider_id:
                return {"decision": "DENY", "reason": "compensation_provider_mismatch"}
            return self.authorize(
                ctx,
                compensation_binding["authorization_action"],
                device.get("resource", f"/dev/{compensation_binding['compensation_device_id']}"),
                comp_arguments,
            )

        result = self.provider_actions.compensate(intent, provider, arguments, authorize_compensation, sandbox_mode)
        safe = {
            "intent_id": intent_id,
            "intent_digest": result.intent_digest,
            "provider_id": result.provider_id,
            "provider_action_id": result.provider_action_id,
            "status": result.status,
            "exact_units": result.exact_units,
            "sandbox_only": True,
        }
        self.hardened._chain(ctx, "provider.action.compensated.v06", safe)
        return {**safe, "result": result.result}

    def provider_action_status(self, ctx: RequestContext, intent_id: str) -> dict[str, Any]:
        intent, _binding, _operation, _profile = self._bound_provider_context(intent_id)
        decision = self.authorize(ctx, "kernel.provider.status", f"/run/provider-actions/{intent.intent_digest()}", {})
        if decision["decision"] != "ALLOW" and ctx.actor_id != intent.actor_id:
            raise HardeningError("CFHS_POLICY_DENIED", "Provider action status denied", decision)
        result = self.provider_actions.state(intent.intent_digest())
        result["sandbox_only"] = True
        return result


class Handler(BaseHTTPRequestHandler):
    kernel: TrustKernelV06 = None  # type: ignore
    bootstrap_principal = "human:owner"

    def log_message(self, *_args):
        pass

    def _json(self):
        n = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(n) if n else b"{}")

    def _send(self, code: int, obj: Any):
        data = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _bearer(self) -> str:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise HardeningError("CFHS_UNAUTHENTICATED", "Bearer kernel session required")
        return auth[7:]

    def _ctx_and_bearer(self) -> tuple[RequestContext, str]:
        bearer = self._bearer()
        process_id = self.headers.get("X-CFHS-Process-ID")
        trace_id = self.headers.get("X-CFHS-Trace-ID")
        if not process_id or not trace_id:
            raise HardeningError("CFHS_INVALID_REQUEST", "Process and trace headers required")
        ctx = self.kernel.hardened.authenticated_context(
            bearer,
            process_id,
            trace_id,
            self.headers.get("X-CFHS-Correlation-ID"),
        )
        return ctx, bearer

    def _error(self, exc: Exception):
        code = getattr(exc, "code", "CFHS_INTERNAL")
        status = 401 if code == "CFHS_UNAUTHENTICATED" else 403 if code in {"CFHS_POLICY_DENIED", "CFHS_ELEVATION_REQUIRED", "CFHS_DEVICE_DENIED"} else 409 if code in {"CFHS_CONFLICT", "CFHS_IDEMPOTENCY_CONFLICT", "CFHS_UNKNOWN_SIDE_EFFECT"} else 400
        self._send(status, {"error": {"code": code, "message": str(exc), "details": getattr(exc, "details", {})}})

    def do_GET(self):
        try:
            path = urlparse(self.path).path
            if path == "/v6/health":
                health = self.kernel.core.health()
                health.update(
                    {
                        "live_adapter_safety_version": "0.6",
                        "sandbox_only": True,
                        "registered_providers": sorted(self.kernel.providers),
                        "audit_chain": self.kernel.hardened.audit_chain.verify(),
                        "anchor_chain": self.kernel.anchors.verify(),
                        "bootstrap": self.kernel.bootstrap.status(),
                    }
                )
                return self._send(200, health)
            ctx, _bearer = self._ctx_and_bearer()
            prefix = "/v6/provider/actions/"
            if path.startswith(prefix):
                return self._send(200, self.kernel.provider_action_status(ctx, path[len(prefix):]))
            raise HardeningError("CFHS_NOT_FOUND", "Endpoint not found")
        except (HardeningError, KernelError) as exc:
            self._error(exc)
        except Exception as exc:
            self._send(500, {"error": {"code": "CFHS_INTERNAL", "message": str(exc)}})

    def do_POST(self):
        try:
            path = urlparse(self.path).path
            body = self._json()
            if path == "/v6/bootstrap":
                return self._send(
                    201,
                    self.kernel.bootstrap.complete(
                        self.kernel.hardened.sessions,
                        str(body.get("bootstrap_secret", "")),
                        self.bootstrap_principal,
                        int(body.get("ttl_seconds", 900)),
                    ),
                )

            ctx, bearer = self._ctx_and_bearer()
            if path == "/v6/provider/resources/configure":
                return self._send(
                    200,
                    self.kernel.configure_exact_resource_pool(
                        ctx,
                        body["pool_id"],
                        int(body["hard_limit_units"]),
                        body["unit_kind"],
                        body.get("unit_metadata"),
                        int(body["used_units"]) if body.get("used_units") is not None else None,
                    ),
                )
            if path == "/v6/provider/intents":
                return self._send(
                    201,
                    self.kernel.create_provider_intent(
                        ctx,
                        body["device_id"],
                        body["operation"],
                        body.get("arguments", {}),
                        body["replay_nonce"],
                        body.get("purpose", ""),
                        body.get("evidence_refs"),
                        body.get("required_approvals"),
                    ),
                )
            if path == "/v6/action/approvals/request":
                return self._send(
                    201,
                    self.kernel.request_action_approval(
                        ctx,
                        body["intent_id"],
                        body.get("eligible_approvers", []),
                        body.get("required_count"),
                        int(body.get("ttl_seconds", 900)),
                    ),
                )
            if path == "/v6/action/approvals/approve":
                return self._send(200, self.kernel.approve_action_with_session(ctx, bearer, body["request_id"]))
            if path == "/v6/provider/prepare":
                return self._send(
                    200,
                    self.kernel.prepare_provider_action(
                        ctx,
                        body["intent_id"],
                        body.get("arguments", {}),
                        body.get("approval_request_id"),
                    ),
                )
            if path == "/v6/provider/execute":
                return self._send(
                    200,
                    self.kernel.execute_provider_action(
                        ctx,
                        body["intent_id"],
                        body.get("arguments", {}),
                        body.get("approval_request_id"),
                        body.get("sandbox_mode", "success"),
                    ),
                )
            if path == "/v6/provider/reconcile":
                return self._send(200, self.kernel.reconcile_provider_action(ctx, body["intent_id"]))
            if path == "/v6/provider/compensate":
                return self._send(
                    200,
                    self.kernel.compensate_provider_action(
                        ctx,
                        body["intent_id"],
                        body.get("arguments", {}),
                        body.get("sandbox_mode", "success"),
                    ),
                )
            raise HardeningError("CFHS_NOT_FOUND", "Endpoint not found")
        except (HardeningError, KernelError) as exc:
            self._error(exc)
        except Exception as exc:
            self._send(500, {"error": {"code": "CFHS_INTERNAL", "message": str(exc)}})


def _load_policy_keys(specs: list[str]) -> dict[str, bytes]:
    keys: dict[str, bytes] = {}
    for spec in specs:
        if "=" not in spec:
            raise SystemExit("--policy-key-env must be KEY_ID=ENV_VAR")
        key_id, env_name = spec.split("=", 1)
        value = os.environ.get(env_name)
        if value is None:
            raise SystemExit(f"Policy key environment variable missing: {env_name}")
        keys[key_id] = value.encode("utf-8")
    return keys


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
    remote_anchor = HTTPSAuditAnchorProvider(args.remote_anchor_endpoint) if args.remote_anchor_endpoint else None
    Handler.kernel = TrustKernelV06(hardened, _load_policy_keys(args.policy_key_env), remote_anchor)
    Handler.bootstrap_principal = args.bootstrap_principal

    state = Handler.kernel.bootstrap.status()
    if not state["initialized"]:
        secret = os.environ.get(args.bootstrap_env)
        if not secret:
            raise SystemExit(f"Bootstrap environment variable is required only for first initialization: {args.bootstrap_env}")
        state = Handler.kernel.bootstrap.initialize(secret)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Company Kernel Live-Adapter Safety v0.6 listening on http://{args.host}:{args.port}", flush=True)
    print("Provider registry: SANDBOX ONLY. Production credentials and providers are rejected.", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
