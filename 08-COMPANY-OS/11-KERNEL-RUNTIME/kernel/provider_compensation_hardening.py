from __future__ import annotations

from typing import Any

from .hardening import HardeningError
from .provider_compensation_gate import ProviderCompensationIntentLedger
from .provider_execution_gate import TrustKernelV06ExecutionGate
from .runtime import RequestContext


class TrustKernelV06FinalGate(TrustKernelV06ExecutionGate):
    """Final sandbox v0.6 gate including separately governed S3 compensation."""

    def __init__(self, hardened, trusted_policy_keys=None, provider_anchor=None):
        super().__init__(hardened, trusted_policy_keys or {}, provider_anchor)
        self.compensation_intents = ProviderCompensationIntentLedger(self.core.store.conn)

    def request_provider_compensation_approval(
        self,
        ctx: RequestContext,
        intent_id: str,
        arguments: dict[str, Any],
        eligible_approvers: list[str],
        required_count: int | None = None,
        ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        original, binding, _operation, _profile = self._bound_provider_context(intent_id)
        replay = self.provider_replay.require_intent(original.replay_nonce, original.intent_digest())
        if replay["status"] != "COMMITTED":
            raise HardeningError("CFHS_CONFLICT", "Only a committed provider action can request compensation")
        state = self.provider_actions.state(original.intent_digest())
        provider_action_id = state.get("provider_action_id")
        if not provider_action_id:
            raise HardeningError("CFHS_CONFLICT", "Committed provider action lacks provider action id")

        compensation = self.provider_compensation_bindings.get(original.intent_digest())
        if compensation["provider_id"] != binding["provider_id"]:
            raise HardeningError("CFHS_CONFLICT", "Compensation provider differs from the original provider binding")
        comp_device, comp_operation = self._device_operation(
            compensation["compensation_device_id"],
            compensation["compensation_operation"],
        )
        self._live_profile(comp_device, comp_operation, require_exact=False)
        side = str(comp_operation.get("side_effect_class", "S0"))
        safety = comp_operation.get("action_safety") or {}
        policy_minimum = int(safety.get("minimum_approvals", 2 if side == "S3" else 1))
        requested = int(required_count or 0)
        effective_required = max(policy_minimum, requested)
        if effective_required < 1:
            raise HardeningError("CFHS_INVALID_POLICY", "Provider compensation must require independent approval")

        decision = self.authorize(
            ctx,
            "kernel.action.approval.request",
            f"/run/actions/provider-compensation/{original.intent_digest()}",
            {},
        )
        if decision["decision"] != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Compensation approval request denied", decision)
        eligible = sorted(set(eligible_approvers))
        if len([p for p in eligible if p != ctx.actor_id]) < effective_required:
            raise HardeningError("CFHS_INVALID_REQUEST", "Not enough independent eligible compensation approvers")
        for principal_id in eligible:
            self.core._principal(principal_id)

        comp_intent = self.compensation_intents.create(
            original.intent_digest(),
            ctx.actor_id,
            ctx.process_id,
            binding["provider_id"],
            provider_action_id,
            compensation["compensation_device_id"],
            compensation["compensation_operation"],
            comp_device.get("resource", f"/dev/{compensation['compensation_device_id']}"),
            side,
            arguments,
            effective_required,
        )
        if comp_intent.get("approval_request_id"):
            request = self.core.store.one(
                "SELECT * FROM action_approval_requests WHERE request_id=?",
                (comp_intent["approval_request_id"],),
            )
            if not request:
                raise HardeningError("CFHS_CONFLICT", "Compensation approval request binding is missing")
            return {
                "compensation_intent": comp_intent,
                "approval_request": dict(request),
                "replayed_request": True,
            }

        request = self.action_approvals.create(
            comp_intent["compensation_intent_digest"],
            ctx.actor_id,
            effective_required,
            ttl_seconds,
            eligible,
        )
        comp_intent = self.compensation_intents.attach_approval(
            comp_intent["compensation_intent_id"],
            request["request_id"],
        )
        self.hardened._chain(
            ctx,
            "provider.compensation.approval.requested.v06",
            {
                "intent_id": intent_id,
                "original_intent_digest": original.intent_digest(),
                "compensation_intent_id": comp_intent["compensation_intent_id"],
                "compensation_intent_digest": comp_intent["compensation_intent_digest"],
                "approval_request_id": request["request_id"],
                "required_count": effective_required,
                "sandbox_only": True,
            },
        )
        return {
            "compensation_intent": comp_intent,
            "approval_request": request,
            "replayed_request": False,
        }

    def compensate_provider_action(
        self,
        ctx: RequestContext,
        intent_id: str,
        arguments: dict[str, Any],
        sandbox_mode: str = "success",
        compensation_intent_id: str | None = None,
        compensation_approval_request_id: str | None = None,
    ) -> dict[str, Any]:
        if not compensation_intent_id or not compensation_approval_request_id:
            raise HardeningError(
                "CFHS_ELEVATION_REQUIRED",
                "S3 provider compensation requires a separately approved compensation intent",
            )
        original, compensation_binding, _operation, _profile = self._bound_provider_context(intent_id)
        replay = self.provider_replay.require_intent(original.replay_nonce, original.intent_digest())
        if replay["status"] == "COMPENSATED":
            return {
                "intent_id": intent_id,
                "intent_digest": original.intent_digest(),
                "status": "COMPENSATED",
                "sandbox_only": True,
            }
        if replay["status"] != "COMMITTED":
            raise HardeningError("CFHS_CONFLICT", "Only a committed provider action can be compensated")

        comp_intent = self.compensation_intents.require_arguments(compensation_intent_id, arguments)
        if comp_intent["original_intent_digest"] != original.intent_digest():
            raise HardeningError("CFHS_CONFLICT", "Compensation intent belongs to another provider action")
        if comp_intent["requester_id"] != ctx.actor_id or comp_intent["requester_process_id"] != ctx.process_id:
            raise HardeningError("CFHS_POLICY_DENIED", "Compensation execution is bound to its requesting principal/process")
        if comp_intent["approval_request_id"] != compensation_approval_request_id:
            raise HardeningError("CFHS_ELEVATION_REQUIRED", "Compensation approval request does not match compensation intent")
        if comp_intent["status"] not in {"PENDING", "APPROVED"}:
            raise HardeningError("CFHS_CONFLICT", f"Compensation intent is not executable from {comp_intent['status']}")

        self.action_approvals.require_satisfied(
            compensation_approval_request_id,
            comp_intent["compensation_intent_digest"],
            int(comp_intent["required_approvals"]),
        )
        approval_evidence = self.approval_provenance.require_complete(compensation_approval_request_id)

        provider_binding = self.provider_compensation_bindings.get(original.intent_digest())
        comp_device, _comp_operation = self._device_operation(
            provider_binding["compensation_device_id"],
            provider_binding["compensation_operation"],
        )
        decision = self.authorize(
            ctx,
            provider_binding["authorization_action"],
            comp_device.get("resource", f"/dev/{provider_binding['compensation_device_id']}"),
            arguments,
        )
        if decision.get("decision") != "ALLOW":
            code = "CFHS_ELEVATION_REQUIRED" if decision.get("decision") == "ELEVATION_REQUIRED" else "CFHS_POLICY_DENIED"
            raise HardeningError(code, "Compensating provider operation was not authorized", decision)

        release = self.provider_authorizations.bind_and_anchor(
            comp_intent["compensation_intent_digest"],
            ctx.actor_id,
            ctx.process_id,
            decision,
            approval_evidence,
        )
        self.compensation_intents.mark(compensation_intent_id, "APPROVED")
        result = super().compensate_provider_action(ctx, intent_id, arguments, sandbox_mode)
        if result["status"] == "COMPENSATED":
            self.compensation_intents.mark(compensation_intent_id, "COMPENSATED")
        result["compensation_intent_id"] = compensation_intent_id
        result["compensation_approval_request_id"] = compensation_approval_request_id
        result["compensation_authorization_evidence_digest"] = release["evidence"]["evidence_digest"]
        result["compensation_authorization_anchor_head"] = release["anchor"]["audit_head_hash"]
        return result
