from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .action_safety import ActionIntent, digest as action_digest
from .exact_units import ExactResourceLedger, ExactUnitPolicy
from .hardening import HardeningError
from .live_adapter_safety import (
    ProviderBoundCompensationRegistry,
    ProviderDefiniteFailure,
    ProviderOutcomeUnknown,
    ProviderReceipt,
    ProviderReconciliationLedger,
    ReconcilableProvider,
    compensation_idempotency_key,
    provider_idempotency_key,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ProviderActionResult:
    status: str
    intent_digest: str
    provider_id: str
    provider_action_id: str | None = None
    provider_idempotency_key: str | None = None
    reconciliation_case_id: str | None = None
    exact_reservation_id: str | None = None
    exact_units: int | None = None
    result: dict[str, Any] | None = None


class ProviderActionAudit:
    """Local v0.6 provider-action journal. External anchoring is layered above this."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_action_audit_v06(
                audit_id TEXT PRIMARY KEY,
                intent_digest TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                status TEXT NOT NULL,
                provider_action_id TEXT,
                result_digest TEXT,
                details_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(provider_id,idempotency_key)
            )
            """
        )
        self.conn.commit()

    def prepare(self, intent_digest: str, provider_id: str, idempotency_key: str, details: dict[str, Any]) -> dict[str, Any]:
        now = utcnow().isoformat()
        audit_id = "paudit_" + intent_digest[:20]
        try:
            self.conn.execute(
                "INSERT INTO provider_action_audit_v06(audit_id,intent_digest,provider_id,idempotency_key,status,details_json,created_at,updated_at) VALUES(?,?,?,?, 'PREPARED', ?, ?, ?)",
                (audit_id, intent_digest, provider_id, idempotency_key, json.dumps(details, sort_keys=True), now, now),
            )
            self.conn.commit()
        except sqlite3.IntegrityError:
            row = self.conn.execute(
                "SELECT * FROM provider_action_audit_v06 WHERE provider_id=? AND idempotency_key=?",
                (provider_id, idempotency_key),
            ).fetchone()
            if not row or row["intent_digest"] != intent_digest:
                raise HardeningError("CFHS_IDEMPOTENCY_CONFLICT", "Provider audit idempotency key belongs to another intent")
            return dict(row)
        return self.get(audit_id)

    def set_status(
        self,
        audit_id: str,
        status: str,
        provider_action_id: str | None = None,
        result: Any | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        row = self.get(audit_id)
        merged = json.loads(row["details_json"] or "{}")
        if details:
            merged.update(details)
        result_digest = action_digest(result) if result is not None else row["result_digest"]
        self.conn.execute(
            "UPDATE provider_action_audit_v06 SET status=?,provider_action_id=COALESCE(?,provider_action_id),result_digest=?,details_json=?,updated_at=? WHERE audit_id=?",
            (status, provider_action_id, result_digest, json.dumps(merged, sort_keys=True), utcnow().isoformat(), audit_id),
        )
        self.conn.commit()
        return self.get(audit_id)

    def get(self, audit_id: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM provider_action_audit_v06 WHERE audit_id=?", (audit_id,)).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Provider action audit record not found")
        return dict(row)


class ProviderActionCoordinator:
    """Sandbox-safe coordinator for a real-provider-shaped action lifecycle.

    The provider is required to support durable idempotency lookup. Unknown
    transport outcomes never cause an automatic second provider invocation.
    """

    TERMINAL = {"COMMITTED", "FAILED_NOT_EXECUTED", "COMPENSATED"}

    def __init__(
        self,
        conn: sqlite3.Connection,
        exact_resources: ExactResourceLedger,
        reconciliation: ProviderReconciliationLedger,
        compensation_bindings: ProviderBoundCompensationRegistry,
        audit: ProviderActionAudit | None = None,
    ):
        self.conn = conn
        self.exact_resources = exact_resources
        self.reconciliation = reconciliation
        self.compensation_bindings = compensation_bindings
        self.audit = audit or ProviderActionAudit(conn)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_action_state_v06(
                intent_digest TEXT PRIMARY KEY,
                intent_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                exact_pool_id TEXT NOT NULL,
                exact_units INTEGER NOT NULL,
                exact_reservation_id TEXT NOT NULL,
                status TEXT NOT NULL,
                provider_action_id TEXT,
                reconciliation_case_id TEXT,
                provider_result_json TEXT,
                audit_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(provider_id,idempotency_key)
            )
            """
        )
        self.conn.commit()

    def _state(self, intent_digest: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM provider_action_state_v06 WHERE intent_digest=?", (intent_digest,)).fetchone()
        return dict(row) if row else None

    def state(self, intent_digest: str) -> dict[str, Any]:
        row = self._state(intent_digest)
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Provider action state not found")
        if row.get("provider_result_json"):
            row["provider_result"] = json.loads(row["provider_result_json"])
        return row

    @staticmethod
    def _receipt_json(receipt: ProviderReceipt) -> dict[str, Any]:
        return {
            "provider_id": receipt.provider_id,
            "provider_action_id": receipt.provider_action_id,
            "operation": receipt.operation,
            "idempotency_key": receipt.idempotency_key,
            "request_digest": receipt.request_digest,
            "status": receipt.status,
            "result": receipt.result,
        }

    def _set_state(
        self,
        intent_digest: str,
        status: str,
        provider_action_id: str | None = None,
        reconciliation_case_id: str | None = None,
        provider_result: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.conn.execute(
            """
            UPDATE provider_action_state_v06
               SET status=?,
                   provider_action_id=COALESCE(?,provider_action_id),
                   reconciliation_case_id=COALESCE(?,reconciliation_case_id),
                   provider_result_json=COALESCE(?,provider_result_json),
                   updated_at=?
             WHERE intent_digest=?
            """,
            (
                status,
                provider_action_id,
                reconciliation_case_id,
                json.dumps(provider_result, sort_keys=True) if provider_result is not None else None,
                utcnow().isoformat(),
                intent_digest,
            ),
        )
        self.conn.commit()
        return self.state(intent_digest)

    def prepare(
        self,
        intent: ActionIntent,
        device_id: str,
        provider: ReconcilableProvider,
        arguments: dict[str, Any],
        exact_policy: ExactUnitPolicy,
        authorize: Callable[[ActionIntent, dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        if action_digest(arguments) != intent.arguments_digest:
            raise HardeningError("CFHS_CONFLICT", "Provider action arguments differ from the bound semantic intent")
        decision = authorize(intent, arguments)
        if decision.get("decision") != "ALLOW":
            code = "CFHS_ELEVATION_REQUIRED" if decision.get("decision") == "ELEVATION_REQUIRED" else "CFHS_POLICY_DENIED"
            raise HardeningError(code, "Provider action authorization did not allow execution", decision)

        intent_digest = intent.intent_digest()
        existing = self._state(intent_digest)
        if existing:
            expected_key = provider_idempotency_key(intent_digest, provider.provider_id, intent.action)
            if (
                existing["provider_id"] != provider.provider_id
                or existing["device_id"] != device_id
                or existing["operation"] != intent.action
                or existing["idempotency_key"] != expected_key
            ):
                raise HardeningError("CFHS_CONFLICT", "Existing provider action state differs from current binding")
            return self.state(intent_digest)

        units = exact_policy.to_units(arguments)
        reservation = self.exact_resources.reserve(intent_digest, exact_policy.pool_id, units)
        provider_key = provider_idempotency_key(intent_digest, provider.provider_id, intent.action)
        request_digest = action_digest({"operation": intent.action, "arguments": arguments})
        try:
            audit = self.audit.prepare(
                intent_digest,
                provider.provider_id,
                provider_key,
                {
                    "device_id": device_id,
                    "operation": intent.action,
                    "resource": intent.resource,
                    "side_effect_class": intent.side_effect_class,
                    "exact_pool_id": exact_policy.pool_id,
                    "exact_units": units,
                    "request_digest": request_digest,
                },
            )
            now = utcnow().isoformat()
            self.conn.execute(
                """
                INSERT INTO provider_action_state_v06(
                    intent_digest,intent_id,provider_id,device_id,operation,idempotency_key,request_digest,
                    exact_pool_id,exact_units,exact_reservation_id,status,audit_id,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,'PREPARED',?,?,?)
                """,
                (
                    intent_digest,
                    intent.intent_id,
                    provider.provider_id,
                    device_id,
                    intent.action,
                    provider_key,
                    request_digest,
                    exact_policy.pool_id,
                    units,
                    reservation["reservation_id"],
                    audit["audit_id"],
                    now,
                    now,
                ),
            )
            self.conn.commit()
        except Exception:
            try:
                if self.exact_resources.reservation(reservation["reservation_id"])["status"] == "RESERVED":
                    self.exact_resources.transition(reservation["reservation_id"], "RELEASED")
            except Exception:
                pass
            raise
        return self.state(intent_digest)

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
            return ProviderActionResult(
                "REPLAYED",
                intent_digest,
                provider.provider_id,
                state["provider_action_id"],
                state["idempotency_key"],
                exact_reservation_id=state["exact_reservation_id"],
                exact_units=int(state["exact_units"]),
                result=receipt.result if receipt else json.loads(state["provider_result_json"] or "{}"),
            )
        if state["status"] in {"RECONCILIATION_REQUIRED", "UNKNOWN_SIDE_EFFECT"}:
            raise HardeningError(
                "CFHS_UNKNOWN_SIDE_EFFECT",
                "Provider outcome requires reconciliation before any retry",
                {"reconciliation_case_id": state["reconciliation_case_id"]},
            )
        if state["status"] != "PREPARED":
            raise HardeningError("CFHS_CONFLICT", f"Provider action is not executable from state {state['status']}")

        try:
            receipt = provider.execute(intent.action, arguments, state["idempotency_key"], mode)
        except ProviderDefiniteFailure as exc:
            self.exact_resources.transition(state["exact_reservation_id"], "RELEASED")
            self.audit.set_status(state["audit_id"], "FAILED_NOT_EXECUTED", details={"error": str(exc)})
            self._set_state(intent_digest, "FAILED_NOT_EXECUTED")
            return ProviderActionResult(
                "FAILED_NOT_EXECUTED",
                intent_digest,
                provider.provider_id,
                provider_idempotency_key=state["idempotency_key"],
                exact_reservation_id=state["exact_reservation_id"],
                exact_units=int(state["exact_units"]),
            )
        except ProviderOutcomeUnknown as exc:
            case = self.reconciliation.open_case(
                intent_digest,
                provider.provider_id,
                state["idempotency_key"],
                {"reason": str(exc), "audit_id": state["audit_id"], "device_id": state["device_id"]},
            )
            self.audit.set_status(
                state["audit_id"],
                "OUTCOME_UNKNOWN",
                details={"reconciliation_case_id": case["case_id"], "error": str(exc)},
            )
            self._set_state(intent_digest, "RECONCILIATION_REQUIRED", reconciliation_case_id=case["case_id"])
            return ProviderActionResult(
                "RECONCILIATION_REQUIRED",
                intent_digest,
                provider.provider_id,
                provider_idempotency_key=state["idempotency_key"],
                reconciliation_case_id=case["case_id"],
                exact_reservation_id=state["exact_reservation_id"],
                exact_units=int(state["exact_units"]),
            )

        receipt_json = self._receipt_json(receipt)
        self.audit.set_status(
            state["audit_id"],
            "PROVIDER_CONFIRMED",
            receipt.provider_action_id,
            receipt_json,
        )
        self.exact_resources.transition(state["exact_reservation_id"], "COMMITTED")
        self.audit.set_status(
            state["audit_id"],
            "COMMITTED",
            receipt.provider_action_id,
            receipt_json,
        )
        self._set_state(intent_digest, "COMMITTED", receipt.provider_action_id, provider_result=receipt_json)
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

    def reconcile(self, intent_digest: str, provider: ReconcilableProvider) -> ProviderActionResult:
        state = self.state(intent_digest)
        if provider.provider_id != state["provider_id"]:
            raise HardeningError("CFHS_CONFLICT", "Provider action reconciliation supplied wrong provider")
        case_id = state["reconciliation_case_id"]
        if not case_id:
            raise HardeningError("CFHS_CONFLICT", "Provider action has no reconciliation case")
        resolved = self.reconciliation.reconcile(case_id, provider)
        reservation = self.exact_resources.reservation(state["exact_reservation_id"])

        if resolved["status"] == "CONFIRMED_COMMITTED":
            if reservation["status"] == "RESERVED":
                self.exact_resources.transition(state["exact_reservation_id"], "COMMITTED")
            receipt = provider.lookup(state["idempotency_key"])
            receipt_json = self._receipt_json(receipt) if receipt else {}
            self.audit.set_status(
                state["audit_id"],
                "COMMITTED_RECONCILED",
                resolved["provider_action_id"],
                receipt_json,
                {"reconciliation_case_id": case_id},
            )
            self._set_state(
                intent_digest,
                "COMMITTED",
                resolved["provider_action_id"],
                case_id,
                receipt_json,
            )
            return ProviderActionResult(
                "COMMITTED_RECONCILED",
                intent_digest,
                provider.provider_id,
                resolved["provider_action_id"],
                state["idempotency_key"],
                case_id,
                state["exact_reservation_id"],
                int(state["exact_units"]),
                receipt.result if receipt else None,
            )

        if resolved["status"] == "CONFIRMED_NOT_EXECUTED":
            if reservation["status"] == "RESERVED":
                self.exact_resources.transition(state["exact_reservation_id"], "RELEASED")
            self.audit.set_status(
                state["audit_id"],
                "FAILED_NOT_EXECUTED_RECONCILED",
                details={"reconciliation_case_id": case_id},
            )
            self._set_state(intent_digest, "FAILED_NOT_EXECUTED", reconciliation_case_id=case_id)
            return ProviderActionResult(
                "FAILED_NOT_EXECUTED_RECONCILED",
                intent_digest,
                provider.provider_id,
                provider_idempotency_key=state["idempotency_key"],
                reconciliation_case_id=case_id,
                exact_reservation_id=state["exact_reservation_id"],
                exact_units=int(state["exact_units"]),
            )

        if resolved["status"] == "COMPENSATED":
            if reservation["status"] == "RESERVED":
                self.exact_resources.transition(state["exact_reservation_id"], "RELEASED")
            elif reservation["status"] == "COMMITTED":
                self.exact_resources.transition(
                    state["exact_reservation_id"],
                    "COMPENSATED",
                    resolved.get("provider_action_id") or "provider-confirmed-compensation",
                )
            self.audit.set_status(
                state["audit_id"],
                "COMPENSATED_RECONCILED",
                resolved.get("provider_action_id"),
                details={"reconciliation_case_id": case_id},
            )
            self._set_state(intent_digest, "COMPENSATED", resolved.get("provider_action_id"), case_id)
            return ProviderActionResult(
                "COMPENSATED_RECONCILED",
                intent_digest,
                provider.provider_id,
                resolved.get("provider_action_id"),
                state["idempotency_key"],
                case_id,
                state["exact_reservation_id"],
                int(state["exact_units"]),
            )

        return ProviderActionResult(
            "RECONCILIATION_PENDING",
            intent_digest,
            provider.provider_id,
            resolved.get("provider_action_id"),
            state["idempotency_key"],
            case_id,
            state["exact_reservation_id"],
            int(state["exact_units"]),
        )

    def compensate(
        self,
        intent: ActionIntent,
        provider: ReconcilableProvider,
        arguments: dict[str, Any],
        authorize_compensation: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
        mode: str = "success",
    ) -> ProviderActionResult:
        intent_digest = intent.intent_digest()
        state = self.state(intent_digest)
        if state["status"] != "COMMITTED":
            if state["status"] == "COMPENSATED":
                return ProviderActionResult(
                    "COMPENSATED",
                    intent_digest,
                    state["provider_id"],
                    state["provider_action_id"],
                    state["idempotency_key"],
                    exact_reservation_id=state["exact_reservation_id"],
                    exact_units=int(state["exact_units"]),
                )
            raise HardeningError("CFHS_CONFLICT", "Only a committed provider action can be compensated")
        if provider.provider_id != state["provider_id"]:
            raise HardeningError("CFHS_CONFLICT", "Compensation provider differs from original provider")
        binding = self.compensation_bindings.get(intent_digest)
        if (
            binding["provider_id"] != provider.provider_id
            or binding["original_device_id"] != state["device_id"]
            or binding["original_operation"] != state["operation"]
        ):
            raise HardeningError("CFHS_CONFLICT", "Compensation binding does not match original provider action")
        decision = authorize_compensation(binding, arguments)
        if decision.get("decision") != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Compensating operation is not separately authorized", decision)
        provider_action_id = state["provider_action_id"]
        if not provider_action_id:
            raise HardeningError("CFHS_CONFLICT", "Committed provider action lacks provider action id")
        comp_key = compensation_idempotency_key(intent_digest, provider_action_id, binding["compensation_operation"])
        receipt = provider.compensate(
            provider_action_id,
            binding["compensation_operation"],
            arguments,
            comp_key,
            mode,
        )
        self.exact_resources.transition(
            state["exact_reservation_id"],
            "COMPENSATED",
            receipt.provider_action_id,
        )
        receipt_json = self._receipt_json(receipt)
        self.audit.set_status(
            state["audit_id"],
            "COMPENSATED",
            receipt.provider_action_id,
            receipt_json,
            {"compensation_operation": binding["compensation_operation"]},
        )
        self._set_state(intent_digest, "COMPENSATED", receipt.provider_action_id, provider_result=receipt_json)
        return ProviderActionResult(
            "COMPENSATED",
            intent_digest,
            provider.provider_id,
            receipt.provider_action_id,
            comp_key,
            exact_reservation_id=state["exact_reservation_id"],
            exact_units=int(state["exact_units"]),
            result=receipt.result,
        )
