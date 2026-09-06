from __future__ import annotations

from typing import Any

from .distributed_provider_gate import TrustKernelV07DistributedProviderGate
from .distributed_safety import BusinessObjectIdentity, DistributedActionPermit, FenceLease
from .distributed_state import DistributedStateTransaction
from .distributed_state_hardening import RecoverableSQLiteFencedStateCoordinator
from .hardening import HardeningError
from .provider_release_gate import TrustKernelV06ReleaseGate
from .runtime import RequestContext


class TrustKernelV07TransactionalProviderGate(TrustKernelV07DistributedProviderGate):
    """Canonical v0.7 gate with one fenced transaction epoch for provider work.

    The coordinator verifies immutable business/replay prerequisites and acquires
    exact resource capacity + the ownership fence atomically. The inherited v0.6
    provider coordinator must then consume that exact reservation idempotently.
    """

    def __init__(self, hardened, trusted_policy_keys=None, provider_anchor=None, kernel_instance_id="kernel:reference-v07"):
        super().__init__(hardened, trusted_policy_keys or {}, provider_anchor, kernel_instance_id)
        self.distributed_state = RecoverableSQLiteFencedStateCoordinator(self.core.store.conn)

    def _tx_permit(self, tx: DistributedStateTransaction, intent_id: str) -> DistributedActionPermit:
        business = self._business_row(intent_id)
        if business["identity_digest"] != tx.identity_digest or business["provider_id"] != tx.provider_id:
            raise HardeningError("CFHS_BUSINESS_IDENTITY_CONFLICT", "Transaction no longer matches provider business identity")
        identity = BusinessObjectIdentity(
            contract_id=business["contract_id"],
            contract_version=int(business["contract_version"]),
            operation=business["operation"],
            identity_digest=business["identity_digest"],
            component_digest=business["component_digest"],
        )
        lease = FenceLease(
            resource_key=tx.resource_key,
            owner_id=tx.owner_id,
            lease_id=tx.lease_id,
            fence_token=tx.fence_token,
            expires_at=tx.fence_expires_at,
        )
        return DistributedActionPermit(identity, tx.semantic_intent_digest, tx.provider_id, lease)

    def _prepare_transaction(
        self,
        intent_id: str,
        arguments: dict[str, Any],
    ) -> DistributedStateTransaction:
        intent, binding, _operation, profile = self._bound_provider_context(intent_id)
        business, _identity, ttl = self._ensure_business_binding(intent_id, arguments)
        exact_policy = self._exact_policy(profile)
        units = exact_policy.to_units(arguments)
        existing = self.distributed_state.find_for_intent(intent.intent_digest())
        if existing and existing.status == "PREPARED":
            try:
                self.distributed_state.assert_current(
                    existing.transaction_id,
                    existing.fence_token,
                    existing.owner_id,
                )
            except HardeningError as exc:
                if exc.code != "CFHS_STALE_FENCE":
                    raise
                return self.distributed_state.takeover_prepared(
                    existing.transaction_id,
                    self.kernel_instance_id,
                    ttl,
                )
            if existing.owner_id != self.kernel_instance_id:
                raise HardeningError(
                    "CFHS_FENCE_BUSY",
                    "Prepared distributed transaction belongs to another active kernel",
                    {"owner_id": existing.owner_id, "kernel_instance_id": self.kernel_instance_id},
                )
            return existing
        return self.distributed_state.prepare(
            semantic_intent_digest=intent.intent_digest(),
            replay_nonce=intent.replay_nonce,
            identity_digest=business["identity_digest"],
            provider_id=binding["provider_id"],
            resource_key=business["resource_key"],
            owner_id=self.kernel_instance_id,
            fence_ttl_seconds=ttl,
            exact_pool_id=exact_policy.pool_id,
            exact_units=units,
        )

    def prepare_provider_action(
        self,
        ctx: RequestContext,
        intent_id: str,
        arguments: dict[str, Any],
        approval_request_id: str | None = None,
    ) -> dict[str, Any]:
        intent, _binding, _operation, _profile = self._bound_provider_context(intent_id)
        if ctx.actor_id != intent.actor_id or ctx.process_id != intent.process_id:
            raise HardeningError("CFHS_POLICY_DENIED", "Provider intent is bound to another principal/process")
        replay = self.provider_replay.require_intent(intent.replay_nonce, intent.intent_digest())
        if replay["status"] == "COMMITTED":
            result = TrustKernelV06ReleaseGate.prepare_provider_action(self, ctx, intent_id, arguments, approval_request_id)
            tx = self.distributed_state.find_for_intent(intent.intent_digest())
            if tx:
                result["distributed_transaction"] = tx.envelope()
            return result
        if replay["status"] == "RECONCILIATION_REQUIRED":
            raise HardeningError("CFHS_UNKNOWN_SIDE_EFFECT", "Reconciliation is required before provider preparation")

        bound, approval_evidence = self._approval_evidence(intent, approval_request_id)
        decision = self.authorize(ctx, bound.action, bound.resource, arguments)
        if decision.get("decision") != "ALLOW":
            code = "CFHS_ELEVATION_REQUIRED" if decision.get("decision") == "ELEVATION_REQUIRED" else "CFHS_POLICY_DENIED"
            raise HardeningError(code, "Provider authorization did not allow distributed preparation", decision)
        release = self.provider_authorizations.bind_and_anchor(
            intent.intent_digest(),
            ctx.actor_id,
            ctx.process_id,
            decision,
            approval_evidence,
        )

        tx = self._prepare_transaction(intent_id, arguments)
        permit = self._tx_permit(tx, intent_id)
        self.distributed_permits.record(permit, "EXECUTE")
        try:
            prepared = TrustKernelV06ReleaseGate.prepare_provider_action(
                self,
                ctx,
                intent_id,
                arguments,
                approval_request_id,
            )
            if prepared["exact_reservation_id"] != tx.exact_reservation_id or int(prepared["exact_units"]) != tx.exact_units:
                raise HardeningError(
                    "CFHS_CONFLICT",
                    "v0.6 provider PREPARE did not consume the coordinator-owned exact reservation",
                    {
                        "transaction_reservation_id": tx.exact_reservation_id,
                        "provider_reservation_id": prepared.get("exact_reservation_id"),
                    },
                )
        except Exception:
            try:
                current = self.distributed_state.get(tx.transaction_id)
                if current.status == "PREPARED":
                    self.distributed_state.abort_pre_execute(
                        current.transaction_id,
                        current.fence_token,
                        current.owner_id,
                        "provider_prepare_failed",
                    )
                self.distributed_permits.mark(intent.intent_digest(), tx.fence_token, "RELEASED")
            except Exception:
                pass
            raise

        self.hardened._chain(
            ctx,
            "provider.distributed.transaction.prepared.v07",
            {
                "intent_id": intent_id,
                "intent_digest": intent.intent_digest(),
                "transaction_id": tx.transaction_id,
                "transaction_version": tx.version,
                "identity_digest": tx.identity_digest,
                "kernel_instance_id": tx.owner_id,
                "fence_token": tx.fence_token,
                "exact_reservation_id": tx.exact_reservation_id,
                "exact_units": tx.exact_units,
                "authorization_evidence_digest": release["evidence"]["evidence_digest"],
            },
        )
        result = dict(prepared)
        result["distributed_permit"] = permit.envelope()
        result["distributed_transaction"] = tx.envelope()
        return result

    def _current_execution_transaction(self, intent_id: str, arguments: dict[str, Any]) -> tuple[DistributedStateTransaction, DistributedActionPermit]:
        intent = self._load_intent(intent_id)
        self._ensure_business_binding(intent_id, arguments)
        tx = self.distributed_state.find_for_intent(intent.intent_digest())
        if not tx:
            raise HardeningError("CFHS_DISTRIBUTED_PERMIT_REQUIRED", "No distributed transaction exists for provider execution")
        if tx.status != "PREPARED":
            raise HardeningError("CFHS_CONFLICT", f"Distributed transaction cannot execute from {tx.status}")
        if tx.owner_id != self.kernel_instance_id:
            raise HardeningError(
                "CFHS_STALE_FENCE",
                "Distributed transaction belongs to another kernel instance",
                {"owner_id": tx.owner_id, "kernel_instance_id": self.kernel_instance_id},
            )
        self.distributed_state.assert_current(tx.transaction_id, tx.fence_token, tx.owner_id)
        return tx, self._tx_permit(tx, intent_id)

    def execute_provider_action(
        self,
        ctx: RequestContext,
        intent_id: str,
        arguments: dict[str, Any],
        approval_request_id: str | None = None,
        sandbox_mode: str = "success",
    ) -> dict[str, Any]:
        intent = self._load_intent(intent_id)
        replay = self.provider_replay.require_intent(intent.replay_nonce, intent.intent_digest())
        if replay["status"] == "COMMITTED":
            result = TrustKernelV06ReleaseGate.execute_provider_action(
                self, ctx, intent_id, arguments, approval_request_id, sandbox_mode
            )
            tx = self.distributed_state.find_for_intent(intent.intent_digest())
            result["distributed_transaction"] = tx.envelope() if tx else None
            result["distributed_replay"] = True
            return result
        if replay["status"] != "PREPARED":
            raise HardeningError("CFHS_CONFLICT", f"Provider action cannot execute from replay state {replay['status']}")
        authorization = self.provider_authorizations.get(intent.intent_digest())
        if authorization.get("approval_request_id") != approval_request_id:
            raise HardeningError("CFHS_ELEVATION_REQUIRED", "Execution approval request differs from prepared release evidence")

        tx, permit = self._current_execution_transaction(intent_id, arguments)
        self.provider_fence_guard.accept(tx.provider_id, tx.resource_key, tx.fence_token)
        running = self.distributed_state.transition(
            tx.transaction_id,
            tx.fence_token,
            tx.owner_id,
            "EXECUTING",
            {"provider_fence_accepted": True},
        )
        self.hardened._chain(
            ctx,
            "provider.distributed.transaction.executing.v07",
            {
                "intent_id": intent_id,
                "transaction_id": running.transaction_id,
                "transaction_version": running.version,
                "identity_digest": running.identity_digest,
                "fence_token": running.fence_token,
            },
        )

        try:
            result = TrustKernelV06ReleaseGate.execute_provider_action(
                self,
                ctx,
                intent_id,
                arguments,
                approval_request_id,
                sandbox_mode,
            )
        except Exception as exc:
            # Once the transactional state is EXECUTING, an unexpected exception
            # is treated conservatively as an uncertain side effect. The v0.6
            # provider layer is expected to classify ordinary provider failures.
            try:
                current = self.distributed_state.get(tx.transaction_id)
                if current.status == "EXECUTING":
                    self.distributed_state.transition(
                        current.transaction_id,
                        current.fence_token,
                        current.owner_id,
                        "RECONCILIATION_REQUIRED",
                        {"exception": type(exc).__name__},
                    )
                    self.distributed_state.release_epoch(current.transaction_id, current.fence_token, current.owner_id)
                    self.distributed_permits.mark(intent.intent_digest(), current.fence_token, "RELEASED")
            except Exception:
                pass
            raise

        status = result["status"]
        current = self.distributed_state.get(tx.transaction_id)
        if status in {"COMMITTED", "REPLAYED"}:
            terminal = self.distributed_state.transition(
                current.transaction_id, current.fence_token, current.owner_id, "COMMITTED"
            )
        elif status == "FAILED_NOT_EXECUTED":
            terminal = self.distributed_state.transition(
                current.transaction_id, current.fence_token, current.owner_id, "FAILED_NOT_EXECUTED"
            )
        elif status == "RECONCILIATION_REQUIRED":
            terminal = self.distributed_state.transition(
                current.transaction_id,
                current.fence_token,
                current.owner_id,
                "RECONCILIATION_REQUIRED",
                {"reconciliation_case_id": result.get("reconciliation_case_id")},
            )
        else:
            raise HardeningError("CFHS_CONFLICT", f"Unsupported provider result for distributed transaction: {status}")
        self.distributed_state.release_epoch(terminal.transaction_id, terminal.fence_token, terminal.owner_id)
        self.distributed_permits.mark(intent.intent_digest(), terminal.fence_token, "RELEASED")
        result["distributed_permit"] = permit.envelope()
        result["distributed_transaction"] = terminal.envelope()
        return result

    def reconcile_provider_action(self, ctx: RequestContext, intent_id: str) -> dict[str, Any]:
        intent = self._load_intent(intent_id)
        replay = self.provider_replay.require_intent(intent.replay_nonce, intent.intent_digest())
        if replay["status"] != "RECONCILIATION_REQUIRED":
            raise HardeningError("CFHS_CONFLICT", "Provider replay state does not require reconciliation")
        existing = self.distributed_state.find_for_intent(intent.intent_digest())
        if not existing or existing.status != "RECONCILIATION_REQUIRED":
            raise HardeningError("CFHS_CONFLICT", "Distributed transaction does not require reconciliation")
        _contract, ttl = self._distributed_profile(self._bound_provider_context(intent_id)[3], intent.action)
        tx = self.distributed_state.takeover_for_reconciliation(
            existing.transaction_id,
            f"{self.kernel_instance_id}:reconcile",
            ttl,
        )
        permit = self._tx_permit(tx, intent_id)
        self.distributed_permits.record(permit, "RECONCILE")
        try:
            self.provider_fence_guard.accept(tx.provider_id, tx.resource_key, tx.fence_token)
            self.hardened._chain(
                ctx,
                "provider.distributed.transaction.reconciling.v07",
                {
                    "intent_id": intent_id,
                    "transaction_id": tx.transaction_id,
                    "transaction_version": tx.version,
                    "identity_digest": tx.identity_digest,
                    "fence_token": tx.fence_token,
                },
            )
            result = TrustKernelV06ReleaseGate.reconcile_provider_action(self, ctx, intent_id)
            current = self.distributed_state.get(tx.transaction_id)
            if result["status"] == "COMMITTED_RECONCILED":
                terminal = self.distributed_state.transition(
                    current.transaction_id, current.fence_token, current.owner_id, "COMMITTED"
                )
            elif result["status"] == "FAILED_NOT_EXECUTED_RECONCILED":
                terminal = self.distributed_state.transition(
                    current.transaction_id, current.fence_token, current.owner_id, "FAILED_NOT_EXECUTED"
                )
            elif result["status"] == "COMPENSATED_RECONCILED":
                terminal = self.distributed_state.transition(
                    current.transaction_id,
                    current.fence_token,
                    current.owner_id,
                    "COMPENSATED",
                    {"provider_compensation": True},
                )
            else:
                raise HardeningError("CFHS_CONFLICT", f"Unsupported reconciliation result: {result['status']}")
            result["distributed_reconciliation_permit"] = permit.envelope()
            result["distributed_transaction"] = terminal.envelope()
            return result
        finally:
            current = self.distributed_state.get(tx.transaction_id)
            try:
                self.distributed_state.release_epoch(current.transaction_id, current.fence_token, current.owner_id)
            finally:
                try:
                    self.distributed_permits.mark(intent.intent_digest(), current.fence_token, "RELEASED")
                except Exception:
                    pass

    def provider_action_status(self, ctx: RequestContext, intent_id: str) -> dict[str, Any]:
        result = super().provider_action_status(ctx, intent_id)
        intent = self._load_intent(intent_id)
        tx = self.distributed_state.find_for_intent(intent.intent_digest())
        result["distributed_transaction"] = tx.envelope() if tx else None
        result["distributed_transaction_journal"] = self.distributed_state.journal(tx.transaction_id) if tx else []
        return result
