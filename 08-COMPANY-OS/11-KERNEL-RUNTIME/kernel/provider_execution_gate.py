from __future__ import annotations

from typing import Any

from .action_safety import ActionIntent
from .anchored_provider_authorization import AnchoredProviderAuthorizationEvidenceLedger
from .hardening import HardeningError
from .provider_replay import ProviderReplayLedger
from .runtime import RequestContext
from .server_v06 import TrustKernelV06


class TrustKernelV06ExecutionGate(TrustKernelV06):
    """Final v0.6 gate: semantic replay + proven authority + anchored release evidence."""

    def __init__(self, hardened, trusted_policy_keys=None, provider_anchor=None):
        super().__init__(hardened, trusted_policy_keys or {}, provider_anchor)
        conn = self.core.store.conn
        self.provider_replay = ProviderReplayLedger(conn)
        self.provider_authorizations = AnchoredProviderAuthorizationEvidenceLedger(
            conn,
            self.hardened.audit_chain,
            self.provider_audit.anchor_provider,
        )

    def _probe_provider_intent(
        self,
        ctx: RequestContext,
        device_id: str,
        operation_name: str,
        arguments: dict[str, Any],
        replay_nonce: str,
        purpose: str,
        evidence_refs: list[str] | None,
        required_approvals: int | None,
    ) -> tuple[ActionIntent, dict[str, Any], Any, int]:
        device, operation = self._device_operation(device_id, operation_name)
        profile = self._live_profile(device, operation)
        side = operation.get("side_effect_class", "S0")
        action_safety = operation.get("action_safety") or {}
        policy_minimum = int(action_safety.get("minimum_approvals", 2 if side == "S3" else 0))
        effective_approvals = max(policy_minimum, int(required_approvals or 0))
        exact_policy = self._exact_policy(profile)
        exact_units = exact_policy.to_units(arguments)
        probe = ActionIntent.create(
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
        return probe, profile, exact_policy, exact_units

    def _existing_intent_response(self, intent_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
        intent, binding, _operation, profile = self._bound_provider_context(intent_id)
        exact_policy = self._exact_policy(profile)
        exact_units = exact_policy.to_units(arguments)
        return {
            "intent": intent.envelope(),
            "intent_digest": intent.intent_digest(),
            "device_id": binding["device_id"],
            "provider_id": binding["provider_id"],
            "exact_resource": {
                "pool_id": exact_policy.pool_id,
                "units": exact_units,
                "unit_kind": exact_policy.unit_kind,
                "currency": exact_policy.currency,
                "minor_exponent": exact_policy.minor_exponent,
            },
            "required_approvals": intent.required_approvals,
            "sandbox_only": True,
            "replayed_intent": True,
        }

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
        probe, _profile, _exact_policy, _exact_units = self._probe_provider_intent(
            ctx,
            device_id,
            operation_name,
            arguments,
            replay_nonce,
            purpose,
            evidence_refs,
            required_approvals,
        )
        semantic_digest = probe.intent_digest()
        existing = self.provider_replay.get(replay_nonce)
        if existing:
            if existing["intent_digest"] != semantic_digest:
                raise HardeningError(
                    "CFHS_IDEMPOTENCY_CONFLICT",
                    "Provider replay nonce is already bound to a different semantic action",
                )
            return self._existing_intent_response(existing["intent_id"], arguments)

        created = super().create_provider_intent(
            ctx,
            device_id,
            operation_name,
            arguments,
            replay_nonce,
            purpose,
            evidence_refs,
            required_approvals,
        )
        if created["intent_digest"] != semantic_digest:
            raise HardeningError("CFHS_CONFLICT", "Provider intent semantic digest changed during creation")
        self.provider_replay.bind(replay_nonce, semantic_digest, created["intent"]["intent_id"])
        created["replayed_intent"] = False
        return created

    def _approval_evidence(self, intent: ActionIntent, approval_request_id: str | None) -> tuple[ActionIntent, dict[str, Any] | None]:
        bound = self._approval_bound_intent(intent, approval_request_id)
        if bound.required_approvals <= 0:
            return bound, None
        if not approval_request_id:
            raise HardeningError("CFHS_ELEVATION_REQUIRED", "Approval request is required")
        evidence = self.approval_provenance.require_complete(approval_request_id)
        return bound, evidence

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
        replay = self.provider_replay.require_intent(intent.replay_nonce, intent.intent_digest())
        if replay["status"] == "COMMITTED":
            return self.provider_actions.state(intent.intent_digest())
        if replay["status"] == "RECONCILIATION_REQUIRED":
            raise HardeningError(
                "CFHS_UNKNOWN_SIDE_EFFECT",
                "Provider action must be reconciled before further execution",
                {"reconciliation_case_id": replay["reconciliation_case_id"]},
            )
        if replay["status"] not in {"PENDING", "PREPARED"}:
            raise HardeningError("CFHS_CONFLICT", f"Provider replay state is not preparable: {replay['status']}")

        bound, approval_evidence = self._approval_evidence(intent, approval_request_id)
        decision = self.authorize(ctx, bound.action, bound.resource, arguments)
        if decision.get("decision") != "ALLOW":
            code = "CFHS_ELEVATION_REQUIRED" if decision.get("decision") == "ELEVATION_REQUIRED" else "CFHS_POLICY_DENIED"
            raise HardeningError(code, "Provider authorization did not allow preparation", decision)

        release_evidence = self.provider_authorizations.bind_and_anchor(
            intent.intent_digest(),
            ctx.actor_id,
            ctx.process_id,
            decision,
            approval_evidence,
        )
        provider = self._provider(binding["provider_id"])
        exact_policy = self._exact_policy(profile)
        prepared = self.provider_actions.prepare(
            bound,
            binding["device_id"],
            provider,
            arguments,
            exact_policy,
            lambda _i, _a: decision,
        )
        self.provider_replay.transition(intent.replay_nonce, intent.intent_digest(), "PREPARED")
        self.hardened._chain(
            ctx,
            "provider.execution.gate.prepared.v06",
            {
                "intent_id": intent_id,
                "intent_digest": intent.intent_digest(),
                "authorization_evidence_digest": release_evidence["evidence"]["evidence_digest"],
                "authorization_anchor_head": release_evidence["anchor"]["audit_head_hash"],
                "approval_provenance_digest": approval_evidence.get("provenance_digest") if approval_evidence else None,
                "provider_audit_id": prepared["audit_id"],
                "exact_units": prepared["exact_units"],
                "sandbox_only": True,
            },
        )
        return prepared

    def execute_provider_action(
        self,
        ctx: RequestContext,
        intent_id: str,
        arguments: dict[str, Any],
        approval_request_id: str | None = None,
        sandbox_mode: str = "success",
    ) -> dict[str, Any]:
        intent, _binding, _operation, _profile = self._bound_provider_context(intent_id)
        replay = self.provider_replay.require_intent(intent.replay_nonce, intent.intent_digest())
        if replay["status"] == "RECONCILIATION_REQUIRED":
            raise HardeningError(
                "CFHS_UNKNOWN_SIDE_EFFECT",
                "Provider action requires reconciliation; execute retry is blocked",
                {"reconciliation_case_id": replay["reconciliation_case_id"]},
            )
        if replay["status"] not in {"PREPARED", "COMMITTED"}:
            raise HardeningError("CFHS_CONFLICT", f"Provider action cannot execute from replay state {replay['status']}")

        result = super().execute_provider_action(ctx, intent_id, arguments, approval_request_id, sandbox_mode)
        status = result["status"]
        if status in {"COMMITTED", "REPLAYED"}:
            self.provider_replay.transition(
                intent.replay_nonce,
                intent.intent_digest(),
                "COMMITTED",
                result.get("provider_action_id"),
            )
        elif status == "FAILED_NOT_EXECUTED":
            self.provider_replay.transition(intent.replay_nonce, intent.intent_digest(), "FAILED_NOT_EXECUTED")
        elif status == "RECONCILIATION_REQUIRED":
            self.provider_replay.transition(
                intent.replay_nonce,
                intent.intent_digest(),
                "RECONCILIATION_REQUIRED",
                result.get("provider_action_id"),
                result.get("reconciliation_case_id"),
            )
        return result

    def reconcile_provider_action(self, ctx: RequestContext, intent_id: str) -> dict[str, Any]:
        intent, _binding, _operation, _profile = self._bound_provider_context(intent_id)
        replay = self.provider_replay.require_intent(intent.replay_nonce, intent.intent_digest())
        if replay["status"] != "RECONCILIATION_REQUIRED":
            raise HardeningError("CFHS_CONFLICT", "Provider replay state does not require reconciliation")
        result = super().reconcile_provider_action(ctx, intent_id)
        if result["status"] == "COMMITTED_RECONCILED":
            target = "COMMITTED"
        elif result["status"] == "FAILED_NOT_EXECUTED_RECONCILED":
            target = "FAILED_NOT_EXECUTED"
        elif result["status"] == "COMPENSATED_RECONCILED":
            target = "COMPENSATED"
        else:
            return result
        self.provider_replay.transition(
            intent.replay_nonce,
            intent.intent_digest(),
            target,
            result.get("provider_action_id"),
            result.get("reconciliation_case_id"),
        )
        return result

    def compensate_provider_action(
        self,
        ctx: RequestContext,
        intent_id: str,
        arguments: dict[str, Any],
        sandbox_mode: str = "success",
    ) -> dict[str, Any]:
        intent, _binding, _operation, _profile = self._bound_provider_context(intent_id)
        replay = self.provider_replay.require_intent(intent.replay_nonce, intent.intent_digest())
        if replay["status"] == "COMPENSATED":
            return {"intent_id": intent_id, "intent_digest": intent.intent_digest(), "status": "COMPENSATED", "sandbox_only": True}
        if replay["status"] != "COMMITTED":
            raise HardeningError("CFHS_CONFLICT", "Only a committed provider action can enter compensation")
        result = super().compensate_provider_action(ctx, intent_id, arguments, sandbox_mode)
        if result["status"] == "COMPENSATED":
            self.provider_replay.transition(
                intent.replay_nonce,
                intent.intent_digest(),
                "COMPENSATED",
                result.get("provider_action_id"),
            )
        return result

    def provider_action_status(self, ctx: RequestContext, intent_id: str) -> dict[str, Any]:
        result = super().provider_action_status(ctx, intent_id)
        intent = self._load_intent(intent_id)
        result["kernel_replay"] = self.provider_replay.require_intent(intent.replay_nonce, intent.intent_digest())
        try:
            result["authorization_evidence"] = self.provider_authorizations.get(intent.intent_digest())
            result["authorization_anchor"] = self.provider_authorizations.receipt(intent.intent_digest())
        except HardeningError:
            result["authorization_evidence"] = None
            result["authorization_anchor"] = None
        return result
