#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from typing import Any

from .hardening import HardeningError
from .providers.github_readonly import GitHubReadOnlyAdapter
from .runtime import CompanyKernel, KernelError, RequestContext
from .server_v02 import HardenedKernel
from .trust import (
    CapabilityBoundingEngine,
    DurableEventBus,
    FileAuditAnchorProvider,
    MemoryVaultProvider,
    RotatingSessionManager,
    SignedPolicyStore,
    VaultSecretBroker,
    canonical_json,
    sha256_hex,
)


class TrustKernel:
    def __init__(
        self,
        hardened: HardenedKernel,
        trusted_policy_keys: dict[str, bytes] | None = None,
        anchor_path: str | Path | None = None,
        vault_values: dict[str, bytes] | None = None,
    ):
        self.hardened = hardened
        self.core = hardened.core
        self.signed_policies = SignedPolicyStore(trusted_policy_keys or {})
        self.rotating_sessions = RotatingSessionManager(hardened.sessions)
        self.events = DurableEventBus(self.core.store.conn)
        self.anchors = FileAuditAnchorProvider(anchor_path or (self.core.state_dir / "audit-anchors.jsonl"))
        self.vault = VaultSecretBroker(MemoryVaultProvider(vault_values or {}))
        self.github = GitHubReadOnlyAdapter(self.vault)
        self._init_delegation_table()

    def _init_delegation_table(self):
        self.core.store.execute(
            """
            CREATE TABLE IF NOT EXISTS delegation_proofs(
                id TEXT PRIMARY KEY,
                parent_process_id TEXT NOT NULL,
                child_process_id TEXT NOT NULL,
                delegator_id TEXT NOT NULL,
                delegate_id TEXT NOT NULL,
                capabilities_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                proof_digest TEXT NOT NULL
            )
            """
        )

    @staticmethod
    def _match(value: str, pattern: str) -> bool:
        return pattern == "*" or value == pattern or (pattern.endswith("*") and value.startswith(pattern[:-1]))

    def _evaluate_signed_policies(self, principal: str, action: str, resource: str, context: dict[str, Any]) -> tuple[str | None, list[str]]:
        matches = []
        for policy in self.signed_policies.policies():
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

    @staticmethod
    def _request_within_bound(bound: dict[str, Any], action: str, resource: str, context: dict[str, Any]) -> bool:
        if not TrustKernel._match(action, str(bound.get("action", ""))):
            return False
        if not TrustKernel._match(resource, str(bound.get("resource", ""))):
            return False
        cond = bound.get("conditions") or {}
        if "max_amount" in cond and float(context.get("amount", 0)) > float(cond["max_amount"]):
            return False
        if "max_bytes" in cond and float(context.get("bytes", 0)) > float(cond["max_bytes"]):
            return False
        if "max_duration_seconds" in cond and float(context.get("duration_seconds", 0)) > float(cond["max_duration_seconds"]):
            return False
        return True

    def _process_bounds(self, process_id: str) -> list[dict[str, Any]] | None:
        row = self.core.store.one("SELECT metadata_json FROM processes WHERE id=?", (process_id,))
        if not row:
            return None
        metadata = json.loads(row["metadata_json"])
        bounds = metadata.get("capability_bounds")
        return bounds if isinstance(bounds, list) else None

    def authorize(self, ctx: RequestContext, action: str, resource: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        context = context or {}
        result = self.hardened.authorize(ctx, action, resource, context)
        if result["decision"] == "ALLOW":
            signed_effect, signed_ids = self._evaluate_signed_policies(ctx.actor_id, action, resource, context)
            if signed_effect:
                result = dict(result)
                result["decision"] = signed_effect
                result["matched_policies"] = list(result.get("matched_policies", [])) + signed_ids
        if result["decision"] == "ALLOW":
            bounds = self._process_bounds(ctx.process_id)
            if bounds is not None and not any(self._request_within_bound(b, action, resource, context) for b in bounds):
                result = dict(result)
                result["decision"] = "DENY"
                result["matched_policies"] = list(result.get("matched_policies", [])) + ["process-capability-bound"]
        self.hardened._chain(ctx, "trust.authorization", result)
        return result

    def install_signed_policy_packages(self, ctx: RequestContext, envelopes: list[dict[str, Any]]) -> dict[str, Any]:
        decision = self.authorize(ctx, "kernel.policy.install", "/etc/policy/signed", {})
        if decision["decision"] != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Signed policy installation not authorized", decision)
        result = self.signed_policies.install_atomic(envelopes)
        self.hardened._chain(ctx, "policy.packages.installed", result)
        return result

    def rotate_session(self, ctx: RequestContext, current_token: str, ttl_seconds: int = 3600) -> dict[str, Any]:
        result = self.rotating_sessions.rotate(current_token, ttl_seconds)
        safe = {k: v for k, v in result.items() if k != "bearer_token"}
        self.hardened._chain(ctx, "session.rotated", safe)
        return result

    def spawn_bounded_process(
        self,
        ctx: RequestContext,
        name: str,
        child_owner: str,
        requested_capabilities: list[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.hardened._validate_process_binding(ctx.actor_id, ctx.process_id)
        parent_bounds = self._process_bounds(ctx.process_id)
        if parent_bounds is None:
            parent_principal = self.core._principal(ctx.actor_id)
            parent_bounds = json.loads(parent_principal["capabilities_json"])
        child_principal = self.core._principal(child_owner)
        child_base_caps = json.loads(child_principal["capabilities_json"])
        CapabilityBoundingEngine.assert_bounded(parent_bounds, requested_capabilities)
        CapabilityBoundingEngine.assert_bounded(child_base_caps, requested_capabilities)

        proof_base = {
            "parent_process_id": ctx.process_id,
            "delegator_id": ctx.actor_id,
            "delegate_id": child_owner,
            "capabilities": requested_capabilities,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        proof_digest = sha256_hex(proof_base)
        child_metadata = dict(metadata or {})
        child_metadata.update({
            "capability_bounds": requested_capabilities,
            "delegation_parent": ctx.process_id,
            "delegation_digest": proof_digest,
        })
        child = self.core.spawn_process(ctx, name, child_owner, child_metadata, ctx.process_id)
        proof_id = "deleg_" + secrets.token_hex(10)
        self.core.store.execute(
            "INSERT INTO delegation_proofs(id,parent_process_id,child_process_id,delegator_id,delegate_id,capabilities_json,created_at,proof_digest) VALUES(?,?,?,?,?,?,?,?)",
            (
                proof_id,
                ctx.process_id,
                child["process_id"],
                ctx.actor_id,
                child_owner,
                json.dumps(requested_capabilities, sort_keys=True),
                proof_base["created_at"],
                proof_digest,
            ),
        )
        child["delegation_proof_id"] = proof_id
        child["delegation_digest"] = proof_digest
        self.hardened._chain(ctx, "process.delegated", {"child_process_id": child["process_id"], "proof_id": proof_id, "proof_digest": proof_digest})
        return child

    def publish_event(self, ctx: RequestContext, topic: str, payload: dict[str, Any], delay_seconds: int = 0) -> dict[str, Any]:
        resource = "/run/ipc/" + topic
        decision = self.authorize(ctx, "event.publish", resource, {})
        if decision["decision"] != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Event publish denied", decision)
        result = self.events.publish(topic, payload, delay_seconds)
        self.hardened._chain(ctx, "event.published", result)
        return result

    def poll_event(self, ctx: RequestContext, topics: list[str]):
        for topic in topics:
            decision = self.authorize(ctx, "event.consume", "/run/ipc/" + topic, {})
            if decision["decision"] != "ALLOW":
                raise HardeningError("CFHS_POLICY_DENIED", "Event consume denied", decision)
        return self.events.poll(ctx.process_id, topics)

    def ack_event(self, ctx: RequestContext, event_id: str) -> None:
        self.events.ack(ctx.process_id, event_id)
        self.hardened._chain(ctx, "event.acked", {"event_id": event_id})

    def anchor_audit(self, ctx: RequestContext, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        decision = self.authorize(ctx, "kernel.audit.anchor", "/var/log/audit", {})
        if decision["decision"] != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Audit anchoring denied", decision)
        verification = self.hardened.audit_chain.verify()
        if not verification.get("valid"):
            raise HardeningError("CFHS_CONFLICT", "Cannot anchor an invalid audit chain", verification)
        result = self.anchors.anchor(verification["head_hash"], metadata)
        self.hardened._chain(ctx, "audit.anchored", {"anchor_id": result["anchor_id"], "audit_head_hash": result["audit_head_hash"]})
        return result

    def github_repository(self, ctx: RequestContext, owner: str, repo: str, lease_id: str | None = None) -> dict[str, Any]:
        decision = self.authorize(ctx, "github.repo.read", "/dev/github/readonly", {"external": True, "classification": "PUBLIC"})
        if decision["decision"] != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "GitHub repository read denied", decision)
        result = self.github.get_repository(owner, repo, lease_id)
        safe = {"owner": owner, "repo": repo, "side_effect_class": "S0", "result_keys": sorted(result.keys())}
        self.core.audit(ctx, "device.invoke", "github.repo.read", "/dev/github/readonly", "ALLOW", safe)
        self.hardened._chain(ctx, "device.invoke", safe)
        return result


class Handler(BaseHTTPRequestHandler):
    trust: TrustKernel = None  # type: ignore
    bootstrap_secret: str = ""
    bootstrap_principal: str = "human:owner"
    bootstrap_used: bool = False

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
        return self.trust.hardened.authenticated_context(self._bearer(), process_id, trace_id, self.headers.get("X-CFHS-Correlation-ID"))

    def _error(self, exc: Exception):
        code_name = getattr(exc, "code", "CFHS_INTERNAL")
        status = 401 if code_name == "CFHS_UNAUTHENTICATED" else 403 if code_name in {"CFHS_POLICY_DENIED", "CFHS_ELEVATION_REQUIRED"} else 400
        self._send(status, {"error": {"code": code_name, "message": str(exc), "details": getattr(exc, "details", {})}})

    def do_GET(self):
        try:
            p = urlparse(self.path).path
            if p == "/v3/health":
                health = self.trust.core.health()
                health.update({
                    "hardening_version": "0.2",
                    "trust_version": "0.3",
                    "audit_chain": self.trust.hardened.audit_chain.verify(),
                    "anchor_chain": self.trust.anchors.verify(),
                })
                return self._send(200, health)
            self._ctx()
            if p == "/v3/audit/anchors/verify":
                return self._send(200, self.trust.anchors.verify())
            raise HardeningError("CFHS_NOT_FOUND", "Endpoint not found")
        except (HardeningError, KernelError) as exc:
            self._error(exc)
        except Exception as exc:
            self._send(500, {"error": {"code": "CFHS_INTERNAL", "message": str(exc)}})

    def do_POST(self):
        try:
            p = urlparse(self.path).path
            body = self._json()
            if p == "/v3/bootstrap":
                if self.bootstrap_used:
                    raise HardeningError("CFHS_POLICY_DENIED", "Bootstrap ceremony already completed")
                supplied = str(body.get("bootstrap_secret", ""))
                if not self.bootstrap_secret or not hmac.compare_digest(supplied, self.bootstrap_secret):
                    raise HardeningError("CFHS_UNAUTHENTICATED", "Bootstrap secret invalid")
                self.bootstrap_used = True
                return self._send(201, self.trust.hardened.sessions.issue(self.bootstrap_principal, int(body.get("ttl_seconds", 900))))

            token = self._bearer()
            ctx = self._ctx()
            if p == "/v3/authorize":
                return self._send(200, self.trust.authorize(ctx, body["action"], body["resource"], body.get("context")))
            if p == "/v3/sessions/rotate":
                return self._send(201, self.trust.rotate_session(ctx, token, int(body.get("ttl_seconds", 3600))))
            if p == "/v3/policies/install":
                return self._send(200, self.trust.install_signed_policy_packages(ctx, body.get("envelopes", [])))
            if p == "/v3/processes/bounded":
                return self._send(201, self.trust.spawn_bounded_process(ctx, body["name"], body["owner"], body.get("capabilities", []), body.get("metadata")))
            if p == "/v3/events":
                return self._send(202, self.trust.publish_event(ctx, body["topic"], body.get("payload", {}), int(body.get("delay_seconds", 0))))
            if p == "/v3/events/poll":
                msg = self.trust.poll_event(ctx, body.get("topics", []))
                return self._send(200, None if msg is None else msg.__dict__)
            if p.startswith("/v3/events/") and p.endswith("/ack"):
                event_id = p.split("/")[-2]
                self.trust.ack_event(ctx, event_id)
                return self._send(202, {"event_id": event_id, "status": "ACKED"})
            if p == "/v3/audit/anchors":
                return self._send(201, self.trust.anchor_audit(ctx, body.get("metadata")))
            if p == "/v3/providers/github/repository":
                return self._send(200, self.trust.github_repository(ctx, body["owner"], body["repo"], body.get("lease_id")))
            raise HardeningError("CFHS_NOT_FOUND", "Endpoint not found")
        except (HardeningError, KernelError) as exc:
            self._error(exc)
        except Exception as exc:
            self._send(500, {"error": {"code": "CFHS_INTERNAL", "message": str(exc)}})


def _load_policy_keys(specs: list[str]) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for spec in specs:
        if "=" not in spec:
            raise SystemExit("--policy-key-env must be KEY_ID=ENV_VAR")
        key_id, env_name = spec.split("=", 1)
        value = os.environ.get(env_name)
        if value is None:
            raise SystemExit(f"Policy key environment variable is missing: {env_name}")
        out[key_id] = value.encode("utf-8")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--policy-dir", required=True)
    ap.add_argument("--policy-key-env", action="append", default=[])
    ap.add_argument("--bootstrap-env", default="CFHS_BOOTSTRAP_SECRET")
    ap.add_argument("--bootstrap-principal", default="human:owner")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8044)
    ap.add_argument("--readonly-host", action="append", default=[])
    args = ap.parse_args()

    bootstrap_secret = os.environ.get(args.bootstrap_env)
    if not bootstrap_secret:
        raise SystemExit(f"Bootstrap environment variable is required: {args.bootstrap_env}")

    core = CompanyKernel.from_file(args.state_dir, args.config)
    hardened = HardenedKernel(core, args.policy_dir, set(args.readonly_host), False)
    Handler.trust = TrustKernel(hardened, _load_policy_keys(args.policy_key_env))
    Handler.bootstrap_secret = bootstrap_secret
    Handler.bootstrap_principal = args.bootstrap_principal
    Handler.bootstrap_used = False

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Company Kernel Trust Layer v0.3 listening on http://{args.host}:{args.port}", flush=True)
    print("Bootstrap session is NOT printed. Complete the one-time /v3/bootstrap ceremony.", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
