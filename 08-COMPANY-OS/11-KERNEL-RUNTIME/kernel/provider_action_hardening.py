from __future__ import annotations

import json
from typing import Any

from .action_safety import ActionIntent, digest as action_digest
from .hardening import HardeningError
from .live_adapter_safety import (
    ProviderDefiniteFailure,
    ProviderOutcomeUnknown,
    ProviderReceipt,
    ReconcilableProvider,
)
from .provider_action_runtime import ProviderActionCoordinator, ProviderActionResult


class ResilientProviderActionCoordinator(ProviderActionCoordinator):
    """Fail-closed provider coordinator with mandatory reconciliation after uncertainty.

    Any exception after the provider call begins is treated as potentially
    consequential unless the provider explicitly raises ProviderDefiniteFailure.
    The coordinator never issues a second provider execute call while a
    reconciliation case is open.
    """

    def _open_reconciliation(
        self,
        intent_digest: str,
        state: dict[str, Any],
        provider: ReconcilableProvider,
        reason: str,
        receipt: ProviderReceipt | None = None,
        error: Exception | None = None,
    ) -> ProviderActionResult:
        evidence = {
            "reason": reason,
            "audit_id": state["audit_id"],
            "device_id": state["device_id"],
            "operation": state["operation"],
        }
        if error is not None:
            evidence["error"] = f"{type(error).__name__}: {error}"
        if receipt is not None:
            evidence["provider_action_id"] = receipt.provider_action_id
            evidence["provider_receipt"] = self._receipt_json(receipt)
        case = self.reconciliation.open_case(
            intent_digest,
            provider.provider_id,
            state["idempotency_key"],
            evidence,
        )
        try:
            self.audit.set_status(
                state["audit_id"],
                "OUTCOME_UNKNOWN",
                receipt.provider_action_id if receipt else None,
                self._receipt_json(receipt) if receipt else None,
                {"reconciliation_case_id": case["case_id"], **evidence},
            )
        except Exception:
            pass
        try:
            self._set_state(
                intent_digest,
                "RECONCILIATION_REQUIRED",
                receipt.provider_action_id if receipt else None,
                case["case_id"],
                self._receipt_json(receipt) if receipt else None,
            )
        except Exception as exc:
            raise HardeningError(
                "CFHS_UNKNOWN_SIDE_EFFECT",
                "Provider outcome is uncertain and reconciliation state could not be fully persisted",
                {
                    "provider_id": provider.provider_id,
                    "provider_idempotency_key": state["idempotency_key"],
                    "reconciliation_case_id": case["case_id"],
                    "persistence_error": str(exc),
                },
            ) from exc
        return ProviderActionResult(
            "RECONCILIATION_REQUIRED",
            intent_digest,
            provider.provider_id,
            receipt.provider_action_id if receipt else None,
            state["idempotency_key"],
            case["case_id"],
            state["exact_reservation_id"],
            int(state["exact_units"]),
            receipt.result if receipt else None,
        )

    def execute_prepared(
        self,
        intent: ActionIntent,
        provider: ReconcilableProvider,
        arguments: dict[str, Any],
        mode: str = "success",
    ) -> ProviderActionResult:
        intent_digest = intent.intent_digest()
        state = self.state(intent_digest)
        if action_digest(arguments) != intent.arguments_digest:
            raise HardeningError("CFHS_CONFLICT", "Provider action arguments differ from prepared semantic intent")
        if provider.provider_id != state["provider_id"]:
            raise HardeningError("CFHS_CONFLICT", "Prepared action is bound to another provider")
        if state["status"] == "COMMITTED":
            receipt = provider.lookup(state["idempotency_key"])
            stored = json.loads(state["provider_result_json"] or "{}")
            return ProviderActionResult(
                "REPLAYED",
                intent_digest,
                provider.provider_id,
                state["provider_action_id"],
                state["idempotency_key"],
                exact_reservation_id=state["exact_reservation_id"],
                exact_units=int(state["exact_units"]),
                result=receipt.result if receipt else stored.get("result", stored),
            )
        if state["status"] == "COMPENSATED":
            raise HardeningError("CFHS_CONFLICT", "Compensated provider action cannot be executed again")
        if state["status"] in {"RECONCILIATION_REQUIRED", "UNKNOWN_SIDE_EFFECT"}:
            raise HardeningError(
                "CFHS_UNKNOWN_SIDE_EFFECT",
                "Provider outcome requires reconciliation before any retry",
                {"reconciliation_case_id": state["reconciliation_case_id"]},
            )
        if state["status"] != "PREPARED":
            raise HardeningError("CFHS_CONFLICT", f"Provider action is not executable from state {state['status']}")

        receipt: ProviderReceipt | None = None
        try:
            receipt = provider.execute(intent.action, arguments, state["idempotency_key"], mode)
        except ProviderDefiniteFailure as exc:
            try:
                reservation = self.exact_resources.reservation(state["exact_reservation_id"])
                if reservation["status"] == "RESERVED":
                    self.exact_resources.transition(state["exact_reservation_id"], "RELEASED")
                self.audit.set_status(state["audit_id"], "FAILED_NOT_EXECUTED", details={"error": str(exc)})
                self._set_state(intent_digest, "FAILED_NOT_EXECUTED")
            except Exception as local_exc:
                # Provider guarantees no side effect. Persist a reconciliation case
                # anyway so leaked local state can be repaired deterministically.
                return self._open_reconciliation(
                    intent_digest,
                    state,
                    provider,
                    "definite_provider_failure_but_local_cleanup_failed",
                    error=local_exc,
                )
            return ProviderActionResult(
                "FAILED_NOT_EXECUTED",
                intent_digest,
                provider.provider_id,
                provider_idempotency_key=state["idempotency_key"],
                exact_reservation_id=state["exact_reservation_id"],
                exact_units=int(state["exact_units"]),
            )
        except ProviderOutcomeUnknown as exc:
            return self._open_reconciliation(
                intent_digest,
                state,
                provider,
                "provider_reported_unknown_transport_outcome",
                error=exc,
            )
        except Exception as exc:
            return self._open_reconciliation(
                intent_digest,
                state,
                provider,
                "unexpected_provider_exception_after_execute_call_started",
                error=exc,
            )

        # The provider returned a success receipt. From this point onward any local
        # failure must reconcile from provider truth rather than re-execute.
        receipt_json = self._receipt_json(receipt)
        try:
            self.audit.set_status(
                state["audit_id"],
                "PROVIDER_CONFIRMED",
                receipt.provider_action_id,
                receipt_json,
            )
            reservation = self.exact_resources.reservation(state["exact_reservation_id"])
            if reservation["status"] == "RESERVED":
                self.exact_resources.transition(state["exact_reservation_id"], "COMMITTED")
            self.audit.set_status(
                state["audit_id"],
                "COMMITTED",
                receipt.provider_action_id,
                receipt_json,
            )
            self._set_state(
                intent_digest,
                "COMMITTED",
                receipt.provider_action_id,
                provider_result=receipt_json,
            )
        except Exception as exc:
            return self._open_reconciliation(
                intent_digest,
                state,
                provider,
                "provider_success_local_commit_interrupted",
                receipt=receipt,
                error=exc,
            )

        return ProviderActionResult(
            "COMMITTED",
            intent_digest,
            provider.provider_id,
            receipt.provider_action_id,
            state["idempotency_key"],
            exact_reservation_id=state["exact_reservation_id"],
            exact_units=int(state["exact_units"]),
            result=receipt.result,
        )
