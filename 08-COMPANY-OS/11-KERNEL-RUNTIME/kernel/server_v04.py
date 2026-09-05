#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .delegation_hardening import RecursiveDelegationVerifier
from .hardening import HardeningError
from .policy_hardening import PersistentRollbackProtectedPolicyStore
from .runtime import CompanyKernel, KernelError, RequestContext
from .server_v02 import HardenedKernel
from .server_v03 import TrustKernel
from .trust_hardening import DurableBootstrapCeremony, LeasedDeadLetterEventBus


class TrustKernelV04(TrustKernel):
    def __init__(self, hardened: HardenedKernel, trusted_policy_keys: dict[str, bytes] | None = None):
        # Build the v0.3 composition, then replace restart-sensitive components.
        super().__init__(hardened, trusted_policy_keys or {})
        self.signed_policies_v04 = PersistentRollbackProtectedPolicyStore(self.core.store.conn, trusted_policy_keys or {})
        self.events_v04 = LeasedDeadLetterEventBus(self.core.store.conn, max_attempts=5, claim_ttl_seconds=30)
        self.bootstrap = DurableBootstrapCeremony(self.core.store.conn)
        self.delegations = RecursiveDelegationVerifier(self.core.store.conn)

    def _evaluate_signed_policies(self, principal: str, action: str, resource: str, context: dict[str, Any]) -> tuple[str | None, list[str]]:
        matches = []
        for policy in self.signed_policies_v04.active_policies():
            if not self._match(principal, str(policy.get("principal", "*"))):
                continue
            if not self._match(action, str(policy.get("action", "*"))):
                continue
            if not self._match(resource, str(policy.get("resource", "*"))):
                continue
            cond = policy.get("conditions") or {}
            if "amount_gt" in cond and not float(context.get("amount", 0)) > float(cond["amount_gt"]):
                continue
            if "classification_in" in cond and context.get("classification") not in cond["classification_in"]:
                continue
            if "external" in cond and bool(context.get("external", False)) != bool(cond["external"]):
                continue
            matches.append(policy)
        if not matches:
            return None, []
        effect = "DENY" if any(p["effect"] == "DENY" for p in matches) else "ELEVATION_REQUIRED"
        ids = [f"{p['package_id']}@{p['package_version']}:{p.get('id','policy')}" for p in matches]
        return effect, ids

    def _verify_process_provenance_if_delegated(self, process_id: str) -> None:
        row = self.core.store.one("SELECT parent_id FROM processes WHERE id=?", (process_id,))
        if row and row["parent_id"] is not None:
            self.delegations.verify_chain(process_id)

    def authorize(self, ctx: RequestContext, action: str, resource: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        self._verify_process_provenance_if_delegated(ctx.process_id)
        return super().authorize(ctx, action, resource, context)

    def install_signed_policy_packages(self, ctx: RequestContext, envelopes: list[dict[str, Any]]) -> dict[str, Any]:
        decision = self.authorize(ctx, "kernel.policy.install", "/etc/policy/signed", {})
        if decision["decision"] != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Signed policy installation not authorized", decision)
        result = self.signed_policies_v04.install_atomic(envelopes)
        self.hardened._chain(ctx, "policy.packages.installed.v04", result)
        return result

    def publish_event(self, ctx: RequestContext, topic: str, payload: dict[str, Any], delay_seconds: int = 0) -> dict[str, Any]:
        decision = self.authorize(ctx, "event.publish", "/run/ipc/" + topic, {})
        if decision["decision"] != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Event publish denied", decision)
        result = self.events_v04.publish(topic, payload, delay_seconds)
        self.hardened._chain(ctx, "event.published.v04", result)
        return result

    def poll_event(self, ctx: RequestContext, topics: list[str]):
        for topic in topics:
            decision = self.authorize(ctx, "event.consume", "/run/ipc/" + topic, {})
            if decision["decision"] != "ALLOW":
                raise HardeningError("CFHS_POLICY_DENIED", "Event consume denied", decision)
        return self.events_v04.poll(ctx.process_id, topics)

    def ack_event(self, ctx: RequestContext, event_id: str) -> None:
        self.events_v04.ack(ctx.process_id, event_id)
        self.hardened._chain(ctx, "event.acked.v04", {"event_id": event_id})

    def release_event(self, ctx: RequestContext, event_id: str, delay_seconds: int = 0, reason: str = "retry") -> None:
        self.events_v04.release(ctx.process_id, event_id, delay_seconds, reason)
        self.hardened._chain(ctx, "event.released.v04", {"event_id": event_id, "delay_seconds": delay_seconds, "reason": reason})


class Handler(BaseHTTPRequestHandler):
    trust: TrustKernelV04 = None  # type: ignore
    bootstrap_secret: str = ""
    bootstrap_principal: str = "human:owner"

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
        return self.trust.hardened.authenticated_context(
            self._bearer(), process_id, trace_id, self.headers.get("X-CFHS-Correlation-ID")
        )

    def _error(self, exc: Exception):
        code_name = getattr(exc, "code", "CFHS_INTERNAL")
        status = 401 if code_name == "CFHS_UNAUTHENTICATED" else 403 if code_name in {"CFHS_POLICY_DENIED", "CFHS_ELEVATION_REQUIRED"} else 400
        self._send(status, {"error": {"code": code_name, "message": str(exc), "details": getattr(exc, "details", {})}})

    def do_GET(self):
        try:
            path = urlparse(self.path).path
            if path == "/v4/health":
                health = self.trust.core.health()
                health.update(
                    {
                        "trust_hardening_version": "0.4",
                        "bootstrap": self.trust.bootstrap.status(),
                        "policy_state": self.trust.signed_policies_v04.state(),
                        "dead_letter_count": len(self.trust.events_v04.dead_letters()),
                        "audit_chain": self.trust.hardened.audit_chain.verify(),
                        "anchor_chain": self.trust.anchors.verify(),
                    }
                )
                return self._send(200, health)
            self._ctx()
            if path == "/v4/events/dead-letter":
                return self._send(200, {"messages": self.trust.events_v04.dead_letters()})
            raise HardeningError("CFHS_NOT_FOUND", "Endpoint not found")
        except (HardeningError, KernelError) as exc:
            self._error(exc)
        except Exception as exc:
            self._send(500, {"error": {"code": "CFHS_INTERNAL", "message": str(exc)}})

    def do_POST(self):
        try:
            path = urlparse(self.path).path
            body = self._json()
            if path == "/v4/bootstrap":
                result = self.trust.bootstrap.complete(
                    self.trust.hardened.sessions,
                    str(body.get("bootstrap_secret", "")),
                    self.bootstrap_principal,
                    int(body.get("ttl_seconds", 900)),
                )
                return self._send(201, result)

            ctx = self._ctx()
            if path == "/v4/authorize":
                return self._send(200, self.trust.authorize(ctx, body["action"], body["resource"], body.get("context")))
            if path == "/v4/policies/install":
                return self._send(200, self.trust.install_signed_policy_packages(ctx, body.get("envelopes", [])))
            if path == "/v4/processes/bounded":
                return self._send(201, self.trust.spawn_bounded_process(ctx, body["name"], body["owner"], body.get("capabilities", []), body.get("metadata")))
            if path == "/v4/processes/delegation/verify":
                return self._send(200, self.trust.delegations.verify_chain(body["process_id"]))
            if path == "/v4/events":
                return self._send(202, self.trust.publish_event(ctx, body["topic"], body.get("payload", {}), int(body.get("delay_seconds", 0))))
            if path == "/v4/events/poll":
                message = self.trust.poll_event(ctx, body.get("topics", []))
                return self._send(200, None if message is None else message.__dict__)
            if path.startswith("/v4/events/") and path.endswith("/ack"):
                event_id = path.split("/")[-2]
                self.trust.ack_event(ctx, event_id)
                return self._send(202, {"event_id": event_id, "status": "ACKED"})
            if path.startswith("/v4/events/") and path.endswith("/release"):
                event_id = path.split("/")[-2]
                self.trust.release_event(ctx, event_id, int(body.get("delay_seconds", 0)), str(body.get("reason", "retry")))
                return self._send(202, {"event_id": event_id, "status": "RELEASED"})
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
    ap.add_argument("--port", type=int, default=8045)
    args = ap.parse_args()

    bootstrap_secret = os.environ.get(args.bootstrap_env)
    if not bootstrap_secret:
        raise SystemExit(f"Bootstrap environment variable is required: {args.bootstrap_env}")

    core = CompanyKernel.from_file(args.state_dir, args.config)
    hardened = HardenedKernel(core, args.policy_dir, set(), False)
    Handler.trust = TrustKernelV04(hardened, _load_policy_keys(args.policy_key_env))
    Handler.bootstrap_secret = bootstrap_secret
    Handler.bootstrap_principal = args.bootstrap_principal
    Handler.trust.bootstrap.initialize(bootstrap_secret)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Company Kernel Trust Hardening v0.4 listening on http://{args.host}:{args.port}", flush=True)
    print(f"Bootstrap state: {Handler.trust.bootstrap.status()['status']}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
