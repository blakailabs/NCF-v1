#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .action_safety import (
    ActionIntent,
    CompensationRegistry,
    MultiPartyApprovalLedger,
    ReplayNonceRegistry,
    ResourceRequest,
    ResourceReservationLedger,
    SQLiteActionAuditSink,
)
from .action_safety_runtime import CrashSafeConsequentialActionCoordinator
from .hardening import HardeningError
from .runtime import CompanyKernel, KernelError, RequestContext
from .server_v02 import HardenedKernel
from .server_v04 import TrustKernelV04


class SimulatedConsequentialAdapter:
    """Non-production provider used to exercise the real action-safety path."""

    def invoke(self, device_id: str, operation: str, arguments: dict[str, Any], mode: str = "success") -> dict[str, Any]:
        if mode == "provider_failure":
            raise RuntimeError("simulated provider failure after invocation began")
        return {
            "simulation": True,
            "device_id": device_id,
            "operation": operation,
            "status": "SUCCEEDED",
            "accepted_arguments_digest_only": True,
        }

    def compensate(self, device_id: str, operation: str, arguments: dict[str, Any], cause: Exception | None, mode: str = "success") -> dict[str, Any]:
        if mode == "compensation_failure":
            raise RuntimeError("simulated compensation failure")
        return {
            "simulation": True,
            "device_id": device_id,
            "operation": operation,
            "status": "COMPENSATED",
            "cause": type(cause).__name__ if cause else None,
        }


class TrustKernelV05(TrustKernelV04):
    def __init__(self, hardened: HardenedKernel, trusted_policy_keys: dict[str, bytes] | None = None):
        super().__init__(hardened, trusted_policy_keys or {})
        conn = self.core.store.conn
        self.action_replay = ReplayNonceRegistry(conn)
        self.action_resources = ResourceReservationLedger(conn)
        self.action_approvals = MultiPartyApprovalLedger(conn)
        self.action_compensation = CompensationRegistry(conn)
        self.action_audit = SQLiteActionAuditSink(conn)
        self.action_coordinator = CrashSafeConsequentialActionCoordinator(
            conn,
            self.action_replay,
            self.action_resources,
            self.action_approvals,
            self.action_compensation,
            self.action_audit,
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS action_device_bindings(
                intent_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                resource TEXT NOT NULL,
                side_effect_class TEXT NOT NULL,
                provider TEXT NOT NULL,
                safety_profile_json TEXT NOT NULL
            )
            """
        )
        conn.commit()
        self.simulated_adapter = SimulatedConsequentialAdapter()
        self.startup_recovery = self.action_coordinator.recovery.reconcile_all()

    def _device_operation(self, device_id: str, operation: str) -> tuple[dict[str, Any], dict[str, Any]]:
        device = next((d for d in self.core.config.get("devices", []) if d.get("id") == device_id), None)
        if not device:
            raise HardeningError("CFHS_NOT_FOUND", "Device not found")
        op = next((o for o in device.get("operations", []) if o.get("name") == operation), None)
        if not op:
            raise HardeningError("CFHS_NOT_FOUND", "Device operation not found")
        return device, op

    @staticmethod
    def _request_signature(requests: list[ResourceRequest]) -> list[tuple[str, float]]:
        return sorted((r.pool_id, float(r.amount)) for r in requests)

    def _derive_action_safety(
        self,
        op: dict[str, Any],
        arguments: dict[str, Any],
        caller_resource_requests: list[dict[str, Any]] | None,
        caller_required_approvals: int | None,
    ) -> tuple[list[ResourceRequest], int, dict[str, Any]]:
        side = op.get("side_effect_class", "S0")
        profile = dict(op.get("action_safety") or {})
        minimum = int(profile.get("minimum_approvals", 2 if side == "S3" else 0))
        requested = int(caller_required_approvals or 0)
        effective_approvals = max(minimum, requested)

        derived: list[ResourceRequest] = []
        pool_id = profile.get("resource_pool_id")
        amount_argument = profile.get("resource_amount_argument")
        if pool_id or amount_argument:
            if not pool_id or not amount_argument:
                raise HardeningError("CFHS_INVALID_POLICY", "Action safety resource policy is incomplete")
            if amount_argument not in arguments:
                raise HardeningError("CFHS_INVALID_REQUEST", f"Action requires resource amount argument: {amount_argument}")
            try:
                amount = float(arguments[amount_argument])
            except (TypeError, ValueError):
                raise HardeningError("CFHS_INVALID_REQUEST", f"Resource amount argument is not numeric: {amount_argument}")
            if amount <= 0:
                raise HardeningError("CFHS_INVALID_REQUEST", "Resource amount must be positive")
            derived = [ResourceRequest(str(pool_id), amount)]
        elif side in {"S2", "S3"}:
            raise HardeningError("CFHS_INVALID_POLICY", "Consequential operation lacks kernel-owned resource reservation policy")

        if caller_resource_requests:
            supplied = [ResourceRequest(str(r["pool_id"]), float(r["amount"])) for r in caller_resource_requests]
            if self._request_signature(supplied) != self._request_signature(derived):
                raise HardeningError("CFHS_POLICY_DENIED", "Caller cannot alter operation resource reservations")

        return derived, effective_approvals, profile

    def _binding(self, intent_id: str):
        row = self.core.store.one("SELECT * FROM action_device_bindings WHERE intent_id=?", (intent_id,))
        if not row:
            raise HardeningError("CFHS_CONFLICT", "Action intent is missing its device binding")
        return row

    def configure_action_resource_pool(self, ctx: RequestContext, pool_id: str, hard_limit: float, used: float | None = None) -> dict[str, Any]:
        decision = self.authorize(ctx, "kernel.action.resource.configure", f"/run/actions/resources/{pool_id}", {})
        if decision["decision"] != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Action resource-pool configuration denied", decision)
        self.action_resources.configure_pool(pool_id, hard_limit, used)
        state = self.action_resources.pool_state(pool_id)
        self.hardened._chain(ctx, "action.resource.configured", state)
        return state

    def create_action_intent(
        self,
        ctx: RequestContext,
        device_id: str,
        operation: str,
        arguments: dict[str, Any],
        replay_nonce: str,
        purpose: str,
        evidence_refs: list[str] | None = None,
        resource_requests: list[dict[str, Any]] | None = None,
        required_approvals: int | None = None,
    ) -> dict[str, Any]:
        decision = self.authorize(ctx, "kernel.action.intent.create", "/run/actions/intents", {})
        if decision["decision"] != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Action-intent creation denied", decision)
        device, op = self._device_operation(device_id, operation)
        requests, effective_approvals, safety_profile = self._derive_action_safety(
            op, arguments, resource_requests, required_approvals
        )
        intent = ActionIntent.create(
            actor_id=ctx.actor_id,
            process_id=ctx.process_id,
            action=operation,
            resource=device.get("resource", f"/dev/{device_id}"),
            side_effect_class=op.get("side_effect_class", "S0"),
            purpose=purpose,
            arguments=arguments,
            replay_nonce=replay_nonce,
            required_approvals=effective_approvals,
            evidence_refs=evidence_refs,
            resource_requests=requests,
        )
        self.core.store.execute(
            "INSERT INTO action_device_bindings(intent_id,device_id,operation,resource,side_effect_class,provider,safety_profile_json) VALUES(?,?,?,?,?,?,?)",
            (
                intent.intent_id,
                device_id,
                operation,
                intent.resource,
                intent.side_effect_class,
                str(device.get("provider", "unknown")),
                json.dumps(safety_profile, sort_keys=True),
            ),
        )
        self.action_coordinator.intents.register(intent)
        result = {
            "intent": intent.envelope(),
            "intent_digest": intent.intent_digest(),
            "device_id": device_id,
            "operation": operation,
            "simulation_only": True,
        }
        self.hardened._chain(
            ctx,
            "action.intent.created",
            {
                "intent_id": intent.intent_id,
                "intent_digest": intent.intent_digest(),
                "side_effect_class": intent.side_effect_class,
                "device_id": device_id,
                "required_approvals": intent.required_approvals,
                "resource_requests": [r.__dict__ for r in intent.resource_requests],
            },
        )
        return result

    def _load_intent(self, intent_id: str) -> ActionIntent:
        row = self.core.store.one("SELECT envelope_json FROM action_intent_index WHERE intent_id=?", (intent_id,))
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Action intent not found")
        e = json.loads(row["envelope_json"])
        return ActionIntent(
            intent_id=e["intent_id"],
            actor_id=e["actor_id"],
            process_id=e["process_id"],
            action=e["action"],
            resource=e["resource"],
            side_effect_class=e["side_effect_class"],
            purpose=e["purpose"],
            arguments_digest=e["arguments_digest"],
            replay_nonce=e["replay_nonce"],
            required_approvals=int(e.get("required_approvals", 0)),
            evidence_refs=tuple(e.get("evidence_refs", [])),
            resource_requests=tuple(ResourceRequest(str(r["pool_id"]), float(r["amount"])) for r in e.get("resource_requests", [])),
            approval_request_id=e.get("approval_request_id"),
            created_at=e["created_at"],
        )

    def request_action_approval(self, ctx: RequestContext, intent_id: str, eligible_approvers: list[str], required_count: int | None = None, ttl_seconds: int = 900) -> dict[str, Any]:
        intent = self._load_intent(intent_id)
        if ctx.actor_id != intent.actor_id or ctx.process_id != intent.process_id:
            raise HardeningError("CFHS_POLICY_DENIED", "Only the originating principal/process may request approval")
        decision = self.authorize(ctx, "kernel.action.approval.request", f"/run/actions/{intent_id}", {})
        if decision["decision"] != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Action approval request denied", decision)
        count = max(intent.required_approvals, int(required_count or intent.required_approvals or 1))
        eligible = sorted(set(eligible_approvers))
        if count > 0 and len([p for p in eligible if p != ctx.actor_id]) < count:
            raise HardeningError("CFHS_INVALID_REQUEST", "Not enough explicit eligible approvers for required approval count")
        for principal_id in eligible:
            self.core._principal(principal_id)
        result = self.action_approvals.create(intent.intent_digest(), ctx.actor_id, count, ttl_seconds, eligible)
        self.hardened._chain(ctx, "action.approval.requested", {"intent_id": intent_id, **result})
        return result

    def approve_action(self, ctx: RequestContext, request_id: str) -> dict[str, Any]:
        decision = self.authorize(ctx, "kernel.action.approval.approve", f"/run/actions/approvals/{request_id}", {})
        if decision["decision"] != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Action approval denied", decision)
        result = self.action_approvals.approve(request_id, ctx.actor_id)
        self.hardened._chain(ctx, "action.approval.recorded", result)
        return result

    def declare_compensation(self, ctx: RequestContext, intent_id: str, compensation_action: str, compensation_resource: str) -> dict[str, Any]:
        intent = self._load_intent(intent_id)
        if ctx.actor_id != intent.actor_id or ctx.process_id != intent.process_id:
            raise HardeningError("CFHS_POLICY_DENIED", "Only the originating principal/process may declare compensation")
        decision = self.authorize(ctx, "kernel.action.compensation.declare", f"/run/actions/{intent_id}", {})
        if decision["decision"] != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Compensation declaration denied", decision)
        result = self.action_compensation.declare(intent.intent_digest(), compensation_action, compensation_resource)
        self.hardened._chain(ctx, "action.compensation.declared", {"intent_id": intent_id, **result})
        return result

    def execute_simulated_action(
        self,
        ctx: RequestContext,
        intent_id: str,
        device_id: str,
        arguments: dict[str, Any],
        approval_request_id: str | None = None,
        simulation_mode: str = "success",
        compensation_mode: str = "success",
    ) -> dict[str, Any]:
        intent = self._load_intent(intent_id)
        if ctx.actor_id != intent.actor_id or ctx.process_id != intent.process_id:
            raise HardeningError("CFHS_POLICY_DENIED", "Action intent is bound to a different principal/process")
        binding = self._binding(intent_id)
        if binding["device_id"] != device_id or binding["operation"] != intent.action:
            raise HardeningError("CFHS_CONFLICT", "Caller cannot substitute a different device or operation")
        device, op = self._device_operation(device_id, intent.action)
        expected_resource = device.get("resource", f"/dev/{device_id}")
        if (
            expected_resource != binding["resource"]
            or expected_resource != intent.resource
            or op.get("side_effect_class", "S0") != binding["side_effect_class"]
            or op.get("side_effect_class", "S0") != intent.side_effect_class
            or str(device.get("provider", "unknown")) != binding["provider"]
        ):
            raise HardeningError("CFHS_CONFLICT", "Current device configuration differs from the bound action intent")
        current_profile = json.dumps(op.get("action_safety") or {}, sort_keys=True)
        if current_profile != binding["safety_profile_json"]:
            raise HardeningError("CFHS_CONFLICT", "Action safety policy changed after intent creation; create a new intent")
        if approval_request_id:
            intent = intent.with_approval(approval_request_id)

        def authorize(bound_intent: ActionIntent, bound_arguments: dict[str, Any]):
            return self.authorize(ctx, bound_intent.action, bound_intent.resource, bound_arguments)

        def invoke(bound_arguments: dict[str, Any]):
            return self.simulated_adapter.invoke(device_id, intent.action, bound_arguments, simulation_mode)

        compensate = None
        if intent.side_effect_class in {"S1", "S2"}:
            compensate = lambda bound_arguments, cause: self.simulated_adapter.compensate(
                device_id, intent.action, bound_arguments, cause, compensation_mode
            )

        result = self.action_coordinator.execute(intent, arguments, authorize, invoke, compensate)
        self.hardened._chain(
            ctx,
            "action.executed.simulated",
            {"intent_id": intent_id, "status": result["status"], "simulation_only": True, "device_id": device_id},
        )
        return result


class Handler(BaseHTTPRequestHandler):
    kernel: TrustKernelV05 = None  # type: ignore
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

    def _ctx(self) -> RequestContext:
        process_id = self.headers.get("X-CFHS-Process-ID")
        trace_id = self.headers.get("X-CFHS-Trace-ID")
        if not process_id or not trace_id:
            raise HardeningError("CFHS_INVALID_REQUEST", "Process and trace headers required")
        return self.kernel.hardened.authenticated_context(
            self._bearer(), process_id, trace_id, self.headers.get("X-CFHS-Correlation-ID")
        )

    def _error(self, exc: Exception):
        code_name = getattr(exc, "code", "CFHS_INTERNAL")
        status = 401 if code_name == "CFHS_UNAUTHENTICATED" else 403 if code_name in {"CFHS_POLICY_DENIED", "CFHS_ELEVATION_REQUIRED"} else 409 if code_name in {"CFHS_IDEMPOTENCY_CONFLICT", "CFHS_UNKNOWN_SIDE_EFFECT"} else 400
        self._send(status, {"error": {"code": code_name, "message": str(exc), "details": getattr(exc, "details", {})}})

    def do_GET(self):
        try:
            path = urlparse(self.path).path
            if path == "/v5/health":
                health = self.kernel.core.health()
                health.update(
                    {
                        "action_safety_version": "0.5",
                        "simulation_only": True,
                        "startup_recovery": self.kernel.startup_recovery,
                        "bootstrap": self.kernel.bootstrap.status(),
                    }
                )
                return self._send(200, health)
            raise HardeningError("CFHS_NOT_FOUND", "Endpoint not found")
        except (HardeningError, KernelError) as exc:
            self._error(exc)
        except Exception as exc:
            self._send(500, {"error": {"code": "CFHS_INTERNAL", "message": str(exc)}})

    def do_POST(self):
        try:
            path = urlparse(self.path).path
            body = self._json()
            if path == "/v5/bootstrap":
                return self._send(201, self.kernel.bootstrap.complete(
                    self.kernel.hardened.sessions,
                    str(body.get("bootstrap_secret", "")),
                    self.bootstrap_principal,
                    int(body.get("ttl_seconds", 900)),
                ))

            ctx = self._ctx()
            if path == "/v5/action/resources/configure":
                return self._send(200, self.kernel.configure_action_resource_pool(ctx, body["pool_id"], float(body["hard_limit"]), body.get("used")))
            if path == "/v5/action/intents":
                return self._send(201, self.kernel.create_action_intent(
                    ctx, body["device_id"], body["operation"], body.get("arguments", {}), body["replay_nonce"], body.get("purpose", ""),
                    body.get("evidence_refs"), body.get("resource_requests"), body.get("required_approvals")
                ))
            if path == "/v5/action/approvals/request":
                return self._send(201, self.kernel.request_action_approval(ctx, body["intent_id"], body.get("eligible_approvers", []), body.get("required_count"), int(body.get("ttl_seconds", 900))))
            if path == "/v5/action/approvals/approve":
                return self._send(200, self.kernel.approve_action(ctx, body["request_id"]))
            if path == "/v5/action/compensation":
                return self._send(201, self.kernel.declare_compensation(ctx, body["intent_id"], body["compensation_action"], body["compensation_resource"]))
            if path == "/v5/action/execute-simulated":
                return self._send(200, self.kernel.execute_simulated_action(
                    ctx, body["intent_id"], body["device_id"], body.get("arguments", {}), body.get("approval_request_id"),
                    body.get("simulation_mode", "success"), body.get("compensation_mode", "success")
                ))
            if path == "/v5/action/recovery":
                decision = self.kernel.authorize(ctx, "kernel.action.recovery", "/run/actions/recovery", {})
                if decision["decision"] != "ALLOW":
                    raise HardeningError("CFHS_POLICY_DENIED", "Action recovery denied", decision)
                return self._send(200, self.kernel.action_coordinator.recovery.reconcile_all())
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
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8046)
    args = ap.parse_args()

    core = CompanyKernel.from_file(args.state_dir, args.config)
    hardened = HardenedKernel(core, args.policy_dir, set(), False)
    Handler.kernel = TrustKernelV05(hardened, _load_policy_keys(args.policy_key_env))
    Handler.bootstrap_principal = args.bootstrap_principal

    state = Handler.kernel.bootstrap.status()
    if not state["initialized"]:
        bootstrap_secret = os.environ.get(args.bootstrap_env)
        if not bootstrap_secret:
            raise SystemExit(f"Bootstrap environment variable is required only for first initialization: {args.bootstrap_env}")
        state = Handler.kernel.bootstrap.initialize(bootstrap_secret)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Company Kernel Action Safety v0.5 listening on http://{args.host}:{args.port}", flush=True)
    print("Provider mode: SIMULATION ONLY. No live business writes are enabled.", flush=True)
    print(f"Startup recovery: {Handler.kernel.startup_recovery}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
