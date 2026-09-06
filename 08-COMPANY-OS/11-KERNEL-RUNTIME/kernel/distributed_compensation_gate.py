from __future__ import annotations

from typing import Any

from .distributed_compensation import (
    CompensationTransactionCoordinator,
    DistributedCompensationBinding,
    DistributedCompensationLedger,
    lookup_compensation,
)
from .hardening import HardeningError
from .live_adapter_safety import (
    ProviderDefiniteFailure,
    ProviderOutcomeUnknown,
    compensation_idempotency_key,
)
from .provider_compensation_hardening import TrustKernelV06FinalGate
from .runtime import RequestContext
from .transactional_provider_gate import TrustKernelV07TransactionalProviderGate


class TrustKernelV07DistributedCompensationGate(TrustKernelV07TransactionalProviderGate):
    """v0.7 gate extending transaction/fencing safety through provider reversal."""

    def __init__(self, hardened, trusted_policy_keys=None, provider_anchor=None, kernel_instance_id="kernel:reference-v07"):
        super().__init__(hardened, trusted_policy_keys or {}, provider_anchor, kernel_instance_id)
        self.distributed_compensations = DistributedCompensationLedger(self.core.store.conn)
        self.compensation_transactions = CompensationTransactionCoordinator(self.distributed_state)

    def request_provider_compensation_approval(
        self,
        ctx: RequestContext,
        intent_id: str,
        arguments: dict[str, Any],
        eligible_approvers: list[str],
        required_count: int | None = None,
        ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        result = TrustKernelV06FinalGate.request_provider_compensation_approval(
            self,
            ctx,
            intent_id,
            arguments,
            eligible_approvers,
            required_count,
            ttl_seconds,
        )
        comp = result["compensation_intent"]
        self.hardened._chain(
            ctx,
            "provider.distributed.compensation.approval.requested.v07",
            {
                "intent_id": intent_id,
                "compensation_intent_id": comp["compensation_intent_id"],
                "compensation_intent_digest": comp["compensation_intent_digest"],
                "approval_request_id": result["approval_request"]["request_id"],
                "sandbox_only": True,
            },
        )
        return result

    def _validated_compensation_context(
        self,
        ctx: RequestContext,
        intent_id: str,
        arguments: dict[str, Any],
        compensation_intent_id: str,
        compensation_approval_request_id: str,
    ) -> tuple[Any, dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
        original, binding, _operation, profile = self._bound_provider_context(intent_id)
        replay = self.provider_replay.require_intent(original.replay_nonce, original.intent_digest())
        if replay["status"] != "COMMITTED":
            raise HardeningError("CFHS_CONFLICT", "Only a committed provider action can enter distributed compensation")
        tx = self.distributed_state.find_for_intent(original.intent_digest())
        if not tx or tx.status != "COMMITTED":
            raise HardeningError("CFHS_CONFLICT", "Original distributed transaction is not committed")

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
        if provider_binding["provider_id"] != binding["provider_id"]:
            raise HardeningError("CFHS_CONFLICT", "Compensation provider differs from original provider")
        comp_device, comp_operation = self._device_operation(
            provider_binding["compensation_device_id"],
            provider_binding["compensation_operation"],
        )
        self._live_profile(comp_device, comp_operation, require_exact=False)
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
        state = self.provider_actions.state(original.intent_digest())
        provider_action_id = state.get("provider_action_id")
        if not provider_action_id:
            raise HardeningError("CFHS_CONFLICT", "Committed provider action lacks provider action id")
        return original, binding, profile, comp_intent, provider_binding, {"state": state, "release": release, "tx": tx}

    def _bind_distributed_compensation(
        self,
        original,
        binding: dict[str, Any],
        comp_intent: dict[str, Any],
        provider_binding: dict[str, Any],
        state: dict[str, Any],
        arguments: dict[str, Any],
        tx,
    ) -> DistributedCompensationBinding:
        provider_action_id = state["provider_action_id"]
        comp_key = compensation_idempotency_key(
            original.intent_digest(),
            provider_action_id,
            provider_binding["compensation_operation"],
        )
        business = self._business_row(original.intent_id)
        return self.distributed_compensations.bind(
            compensation_intent_id=comp_intent["compensation_intent_id"],
            compensation_intent_digest=comp_intent["compensation_intent_digest"],
            original_transaction_id=tx.transaction_id,
            original_intent_digest=original.intent_digest(),
            original_identity_digest=business["identity_digest"],
            provider_id=binding["provider_id"],
            original_provider_action_id=provider_action_id,
            compensation_operation=provider_binding["compensation_operation"],
            arguments=arguments,
            idempotency_key=comp_key,
        )

    def _finalize_compensated(
        self,
        original,
        comp_intent: dict[str, Any],
        binding: DistributedCompensationBinding,
        receipt,
    ) -> None:
        state = self.provider_actions.state(original.intent_digest())
        reservation = self.exact_resources.reservation(state["exact_reservation_id"])
        if reservation["status"] == "COMMITTED":
            self.exact_resources.transition(
                state["exact_reservation_id"],
                "COMPENSATED",
                receipt.provider_action_id,
            )
        elif reservation["status"] != "COMPENSATED":
            raise HardeningError("CFHS_CONFLICT", f"Exact reservation cannot finalize compensation from {reservation['status']}")
        receipt_json = self.provider_actions._receipt_json(receipt)
        self.provider_actions.audit.set_status(
            state["audit_id"],
            "COMPENSATED",
            receipt.provider_action_id,
            receipt_json,
            {"compensation_operation": binding.compensation_operation, "distributed": True},
        )
        self.provider_actions._set_state(
            original.intent_digest(),
            "COMPENSATED",
            receipt.provider_action_id,
            provider_result=receipt_json,
        )
        self.provider_replay.transition(
            original.replay_nonce,
            original.intent_digest(),
            "COMPENSATED",
            receipt.provider_action_id,
        )
        self.compensation_intents.mark(comp_intent["compensation_intent_id"], "COMPENSATED")
        self.distributed_compensations.mark(
            comp_intent["compensation_intent_id"],
            "COMPENSATED",
            compensation_action_id=receipt.provider_action_id,
        )

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
                "Distributed S3 compensation requires a separately approved compensation intent",
            )
        original = self._load_intent(intent_id)
        replay = self.provider_replay.require_intent(original.replay_nonce, original.intent_digest())
        if replay["status"] == "COMPENSATED":
            existing = self.distributed_compensations.find_for_original(original.intent_digest())
            tx = self.distributed_state.find_for_intent(original.intent_digest())
            return {
                "intent_id": intent_id,
                "intent_digest": original.intent_digest(),
                "status": "COMPENSATED",
                "distributed_compensation": existing.envelope() if existing else None,
                "distributed_transaction": tx.envelope() if tx else None,
                "sandbox_only": True,
            }

        original, binding, profile, comp_intent, provider_binding, validated = self._validated_compensation_context(
            ctx,
            intent_id,
            arguments,
            compensation_intent_id,
            compensation_approval_request_id,
        )
        state = validated["state"]
        release = validated["release"]
        original_tx = validated["tx"]
        distributed = self._bind_distributed_compensation(
            original,
            binding,
            comp_intent,
            provider_binding,
            state,
            arguments,
            original_tx,
        )
        _contract, ttl = self._distributed_profile(profile, original.action)
        tx = self.compensation_transactions.begin_compensation(
            original_tx.transaction_id,
            f"{self.kernel_instance_id}:compensate",
            ttl,
            distributed.compensation_identity_digest,
            distributed.compensation_intent_digest,
        )
        provider = self._provider(binding["provider_id"])
        self.provider_fence_guard.accept(tx.provider_id, tx.resource_key, tx.fence_token)
        self.distributed_compensations.mark(compensation_intent_id, "COMPENSATING")
        self.hardened._chain(
            ctx,
            "provider.distributed.compensation.executing.v07",
            {
                "intent_id": intent_id,
                "transaction_id": tx.transaction_id,
                "transaction_version": tx.version,
                "compensation_intent_id": compensation_intent_id,
                "compensation_identity_digest": distributed.compensation_identity_digest,
                "fence_token": tx.fence_token,
                "authorization_evidence_digest": release["evidence"]["evidence_digest"],
            },
        )

        try:
            provider_mode = "success" if sandbox_mode == "commit_then_timeout" else sandbox_mode
            receipt = provider.compensate(
                distributed.original_provider_action_id,
                distributed.compensation_operation,
                arguments,
                distributed.idempotency_key,
                provider_mode,
            )
            if sandbox_mode == "commit_then_timeout":
                raise ProviderOutcomeUnknown(
                    "Provider persisted compensation but transport result was lost",
                    distributed.provider_id,
                    distributed.idempotency_key,
                )
        except ProviderDefiniteFailure as exc:
            current = self.compensation_transactions.transition(
                tx.transaction_id,
                tx.fence_token,
                tx.owner_id,
                "COMMITTED",
                {"provider_outcome": "definite_not_executed", "error": str(exc)},
            )
            self.distributed_compensations.mark(compensation_intent_id, "FAILED_NOT_EXECUTED")
            self.compensation_transactions.release(current)
            return {
                "intent_id": intent_id,
                "intent_digest": original.intent_digest(),
                "status": "COMPENSATION_FAILED_NOT_EXECUTED",
                "distributed_compensation": self.distributed_compensations.get(compensation_intent_id).envelope(),
                "distributed_transaction": current.envelope(),
                "sandbox_only": True,
            }
        except ProviderOutcomeUnknown as exc:
            case = self.distributed_compensations.open_reconciliation(
                distributed,
                {"reason": str(exc), "transaction_id": tx.transaction_id, "fence_token": tx.fence_token},
            )
            current = self.compensation_transactions.transition(
                tx.transaction_id,
                tx.fence_token,
                tx.owner_id,
                "COMPENSATION_RECONCILIATION_REQUIRED",
                {"reconciliation_case_id": case["case_id"]},
            )
            self.compensation_transactions.release(current)
            return {
                "intent_id": intent_id,
                "intent_digest": original.intent_digest(),
                "status": "COMPENSATION_RECONCILIATION_REQUIRED",
                "compensation_reconciliation_case_id": case["case_id"],
                "distributed_compensation": self.distributed_compensations.get(compensation_intent_id).envelope(),
                "distributed_transaction": current.envelope(),
                "sandbox_only": True,
            }
        except HardeningError:
            current = self.compensation_transactions.transition(
                tx.transaction_id,
                tx.fence_token,
                tx.owner_id,
                "COMMITTED",
                {"provider_outcome": "deterministic_kernel_or_provider_rejection"},
            )
            self.compensation_transactions.release(current)
            raise
        except Exception as exc:
            case = self.distributed_compensations.open_reconciliation(
                distributed,
                {"reason": type(exc).__name__, "transaction_id": tx.transaction_id, "fence_token": tx.fence_token},
            )
            current = self.compensation_transactions.transition(
                tx.transaction_id,
                tx.fence_token,
                tx.owner_id,
                "COMPENSATION_RECONCILIATION_REQUIRED",
                {"reconciliation_case_id": case["case_id"], "exception": type(exc).__name__},
            )
            self.compensation_transactions.release(current)
            raise HardeningError(
                "CFHS_UNKNOWN_SIDE_EFFECT",
                "Unexpected compensation failure requires reconciliation",
                {"reconciliation_case_id": case["case_id"]},
            ) from exc

        self._finalize_compensated(original, comp_intent, distributed, receipt)
        current = self.compensation_transactions.transition(
            tx.transaction_id,
            tx.fence_token,
            tx.owner_id,
            "COMPENSATED",
            {"compensation_action_id": receipt.provider_action_id},
        )
        self.compensation_transactions.release(current)
        result = {
            "intent_id": intent_id,
            "intent_digest": original.intent_digest(),
            "provider_id": binding["provider_id"],
            "provider_action_id": receipt.provider_action_id,
            "status": "COMPENSATED",
            "exact_units": int(state["exact_units"]),
            "compensation_intent_id": compensation_intent_id,
            "compensation_approval_request_id": compensation_approval_request_id,
            "compensation_authorization_evidence_digest": release["evidence"]["evidence_digest"],
            "distributed_compensation": self.distributed_compensations.get(compensation_intent_id).envelope(),
            "distributed_transaction": current.envelope(),
            "sandbox_only": True,
            "result": receipt.result,
        }
        self.hardened._chain(ctx, "provider.distributed.compensation.completed.v07", result)
        return result

    def reconcile_provider_compensation(
        self,
        ctx: RequestContext,
        intent_id: str,
        compensation_intent_id: str,
    ) -> dict[str, Any]:
        original, binding, _operation, profile = self._bound_provider_context(intent_id)
        decision = self.authorize(
            ctx,
            "kernel.provider.reconcile",
            f"/run/provider-actions/{original.intent_digest()}/compensation",
            {},
        )
        if decision.get("decision") != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Provider compensation reconciliation denied", decision)
        distributed = self.distributed_compensations.get(compensation_intent_id)
        if distributed.original_intent_digest != original.intent_digest():
            raise HardeningError("CFHS_CONFLICT", "Distributed compensation belongs to another provider action")
        if distributed.status != "RECONCILIATION_REQUIRED" or not distributed.reconciliation_case_id:
            raise HardeningError("CFHS_CONFLICT", "Distributed compensation does not require reconciliation")
        existing = self.distributed_state.find_for_intent(original.intent_digest())
        if not existing or existing.status != "COMPENSATION_RECONCILIATION_REQUIRED":
            raise HardeningError("CFHS_CONFLICT", "Original transaction does not require compensation reconciliation")
        _contract, ttl = self._distributed_profile(profile, original.action)
        tx = self.compensation_transactions.begin_reconciliation(
            existing.transaction_id,
            f"{self.kernel_instance_id}:compensation-reconcile",
            ttl,
            distributed.reconciliation_case_id,
        )
        self.provider_fence_guard.accept(tx.provider_id, tx.resource_key, tx.fence_token)
        self.distributed_compensations.mark(compensation_intent_id, "RECONCILING")
        provider = self._provider(binding["provider_id"])
        self.hardened._chain(
            ctx,
            "provider.distributed.compensation.reconciling.v07",
            {
                "intent_id": intent_id,
                "transaction_id": tx.transaction_id,
                "transaction_version": tx.version,
                "compensation_intent_id": compensation_intent_id,
                "reconciliation_case_id": distributed.reconciliation_case_id,
                "fence_token": tx.fence_token,
            },
        )
        try:
            receipt = lookup_compensation(provider, distributed.idempotency_key)
            if receipt is None:
                resolved = self.distributed_compensations.resolve_reconciliation(
                    distributed.reconciliation_case_id,
                    "CONFIRMED_NOT_EXECUTED",
                )
                self.distributed_compensations.mark(compensation_intent_id, "FAILED_NOT_EXECUTED")
                terminal = self.compensation_transactions.transition(
                    tx.transaction_id,
                    tx.fence_token,
                    tx.owner_id,
                    "COMMITTED",
                    {"compensation_reconciliation": resolved["status"]},
                )
                return {
                    "intent_id": intent_id,
                    "intent_digest": original.intent_digest(),
                    "status": "COMPENSATION_FAILED_NOT_EXECUTED_RECONCILED",
                    "compensation_reconciliation_case_id": distributed.reconciliation_case_id,
                    "distributed_compensation": self.distributed_compensations.get(compensation_intent_id).envelope(),
                    "distributed_transaction": terminal.envelope(),
                    "sandbox_only": True,
                }
            if receipt.status != "COMPENSATED":
                raise HardeningError("CFHS_UNKNOWN_SIDE_EFFECT", "Provider compensation reconciliation remains nonterminal")
            comp_intent = self.compensation_intents.get(compensation_intent_id)
            self._finalize_compensated(original, comp_intent, distributed, receipt)
            resolved = self.distributed_compensations.resolve_reconciliation(
                distributed.reconciliation_case_id,
                "CONFIRMED_COMPENSATED",
                receipt.provider_action_id,
            )
            terminal = self.compensation_transactions.transition(
                tx.transaction_id,
                tx.fence_token,
                tx.owner_id,
                "COMPENSATED",
                {
                    "compensation_reconciliation": resolved["status"],
                    "compensation_action_id": receipt.provider_action_id,
                },
            )
            return {
                "intent_id": intent_id,
                "intent_digest": original.intent_digest(),
                "provider_id": receipt.provider_id,
                "provider_action_id": receipt.provider_action_id,
                "status": "COMPENSATED_RECONCILED",
                "compensation_reconciliation_case_id": distributed.reconciliation_case_id,
                "distributed_compensation": self.distributed_compensations.get(compensation_intent_id).envelope(),
                "distributed_transaction": terminal.envelope(),
                "sandbox_only": True,
                "result": receipt.result,
            }
        finally:
            current = self.distributed_state.get(tx.transaction_id)
            try:
                self.compensation_transactions.release(current)
            except HardeningError as exc:
                if exc.code != "CFHS_STALE_FENCE":
                    raise

    def provider_action_status(self, ctx: RequestContext, intent_id: str) -> dict[str, Any]:
        result = super().provider_action_status(ctx, intent_id)
        original = self._load_intent(intent_id)
        distributed = self.distributed_compensations.find_for_original(original.intent_digest())
        result["distributed_compensation"] = distributed.envelope() if distributed else None
        result["distributed_compensation_reconciliation"] = (
            self.distributed_compensations.reconciliation(distributed.reconciliation_case_id)
            if distributed and distributed.reconciliation_case_id
            else None
        )
        return result
