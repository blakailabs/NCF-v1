from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol

from .hardening import HardeningError
from .trust import canonical_json, sha256_hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class ExactUnitPolicy:
    pool_id: str
    argument: str
    unit_kind: str
    minor_exponent: int = 0
    currency: str | None = None

    def to_units(self, arguments: dict[str, Any]) -> int:
        if self.argument not in arguments:
            raise HardeningError("CFHS_INVALID_REQUEST", f"Required resource argument missing: {self.argument}")
        raw = arguments[self.argument]
        if self.unit_kind == "count":
            if isinstance(raw, bool):
                raise HardeningError("CFHS_INVALID_REQUEST", "Boolean is not a valid resource count")
            try:
                value = Decimal(str(raw))
            except InvalidOperation as exc:
                raise HardeningError("CFHS_INVALID_REQUEST", "Resource count is not numeric") from exc
            if value != value.to_integral_value():
                raise HardeningError("CFHS_INVALID_REQUEST", "Count resources must be whole units")
            units = int(value)
        elif self.unit_kind == "currency_minor":
            if self.minor_exponent < 0 or self.minor_exponent > 9:
                raise HardeningError("CFHS_INVALID_POLICY", "Currency minor exponent is outside supported range")
            try:
                value = Decimal(str(raw))
            except InvalidOperation as exc:
                raise HardeningError("CFHS_INVALID_REQUEST", "Currency amount is not numeric") from exc
            scaled = value * (Decimal(10) ** self.minor_exponent)
            if scaled != scaled.to_integral_value():
                raise HardeningError(
                    "CFHS_INVALID_REQUEST",
                    "Currency amount contains precision smaller than configured minor unit",
                    {"currency": self.currency, "minor_exponent": self.minor_exponent},
                )
            units = int(scaled)
        else:
            raise HardeningError("CFHS_INVALID_POLICY", f"Unsupported exact unit kind: {self.unit_kind}")
        if units <= 0:
            raise HardeningError("CFHS_INVALID_REQUEST", "Resource units must be positive")
        return units


class ExactResourceLedger:
    """Integer-only resource reservation ledger suitable for money minor units/counts."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS exact_resource_pools(
                pool_id TEXT PRIMARY KEY,
                hard_limit_units INTEGER NOT NULL,
                used_units INTEGER NOT NULL DEFAULT 0,
                reserved_units INTEGER NOT NULL DEFAULT 0,
                unit_kind TEXT NOT NULL,
                unit_metadata_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS exact_resource_reservations(
                reservation_id TEXT PRIMARY KEY,
                intent_digest TEXT NOT NULL,
                pool_id TEXT NOT NULL,
                units INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def configure_pool(
        self,
        pool_id: str,
        hard_limit_units: int,
        unit_kind: str,
        unit_metadata: dict[str, Any] | None = None,
        used_units: int | None = None,
    ) -> dict[str, Any]:
        if isinstance(hard_limit_units, bool) or not isinstance(hard_limit_units, int) or hard_limit_units < 0:
            raise HardeningError("CFHS_INVALID_REQUEST", "Exact resource hard limit must be a non-negative integer")
        if used_units is not None and (isinstance(used_units, bool) or not isinstance(used_units, int) or used_units < 0):
            raise HardeningError("CFHS_INVALID_REQUEST", "Exact resource used amount must be a non-negative integer")
        metadata = json.dumps(unit_metadata or {}, sort_keys=True)
        now = utcnow().isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            current = self.conn.execute("SELECT * FROM exact_resource_pools WHERE pool_id=?", (pool_id,)).fetchone()
            if current:
                if current["unit_kind"] != unit_kind or current["unit_metadata_json"] != metadata:
                    raise HardeningError("CFHS_CONFLICT", "Resource unit definition cannot be changed in place")
                used = int(current["used_units"] if used_units is None else used_units)
                reserved = int(current["reserved_units"])
                if used + reserved > hard_limit_units:
                    raise HardeningError("CFHS_CONFLICT", "Hard limit cannot fall below used plus reserved exact units")
                self.conn.execute(
                    "UPDATE exact_resource_pools SET hard_limit_units=?,used_units=?,updated_at=? WHERE pool_id=?",
                    (hard_limit_units, used, now, pool_id),
                )
            else:
                used = int(used_units or 0)
                if used > hard_limit_units:
                    raise HardeningError("CFHS_INVALID_REQUEST", "Used exact units exceed hard limit")
                self.conn.execute(
                    "INSERT INTO exact_resource_pools(pool_id,hard_limit_units,used_units,reserved_units,unit_kind,unit_metadata_json,updated_at) VALUES(?,?,?,0,?,?,?)",
                    (pool_id, hard_limit_units, used, unit_kind, metadata, now),
                )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self.pool_state(pool_id)

    def reserve(self, intent_digest: str, pool_id: str, units: int) -> dict[str, Any]:
        if isinstance(units, bool) or not isinstance(units, int) or units <= 0:
            raise HardeningError("CFHS_INVALID_REQUEST", "Reservation units must be a positive integer")
        reservation_id = "xresv_" + secrets.token_hex(10)
        now = utcnow().isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            pool = self.conn.execute("SELECT * FROM exact_resource_pools WHERE pool_id=?", (pool_id,)).fetchone()
            if not pool:
                raise HardeningError("CFHS_NOT_FOUND", "Exact resource pool not found")
            available = int(pool["hard_limit_units"]) - int(pool["used_units"]) - int(pool["reserved_units"])
            if units > available:
                raise HardeningError(
                    "CFHS_RESOURCE_EXHAUSTED",
                    "Exact resource reservation exceeds available units",
                    {"pool_id": pool_id, "requested_units": units, "available_units": available},
                )
            self.conn.execute(
                "UPDATE exact_resource_pools SET reserved_units=reserved_units+?,updated_at=? WHERE pool_id=?",
                (units, now, pool_id),
            )
            self.conn.execute(
                "INSERT INTO exact_resource_reservations(reservation_id,intent_digest,pool_id,units,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                (reservation_id, intent_digest, pool_id, units, "RESERVED", now, now),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return {"reservation_id": reservation_id, "pool_id": pool_id, "units": units, "status": "RESERVED"}

    def transition(self, reservation_id: str, target: str) -> None:
        if target not in {"COMMITTED", "RELEASED"}:
            raise HardeningError("CFHS_INVALID_REQUEST", "Unsupported exact-resource transition")
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute("SELECT * FROM exact_resource_reservations WHERE reservation_id=?", (reservation_id,)).fetchone()
            if not row or row["status"] != "RESERVED":
                raise HardeningError("CFHS_CONFLICT", "Exact reservation is not transition-ready")
            now = utcnow().isoformat()
            if target == "COMMITTED":
                self.conn.execute(
                    "UPDATE exact_resource_pools SET reserved_units=reserved_units-?,used_units=used_units+?,updated_at=? WHERE pool_id=?",
                    (row["units"], row["units"], now, row["pool_id"]),
                )
            else:
                self.conn.execute(
                    "UPDATE exact_resource_pools SET reserved_units=reserved_units-?,updated_at=? WHERE pool_id=?",
                    (row["units"], now, row["pool_id"]),
                )
            self.conn.execute(
                "UPDATE exact_resource_reservations SET status=?,updated_at=? WHERE reservation_id=?",
                (target, now, reservation_id),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def pool_state(self, pool_id: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM exact_resource_pools WHERE pool_id=?", (pool_id,)).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Exact resource pool not found")
        result = dict(row)
        result["unit_metadata"] = json.loads(result.pop("unit_metadata_json"))
        return result


@dataclass(frozen=True)
class ProviderReceipt:
    provider_id: str
    provider_action_id: str
    operation: str
    idempotency_key: str
    request_digest: str
    status: str
    result: dict[str, Any]


class ProviderDefiniteFailure(Exception):
    pass


class ProviderOutcomeUnknown(Exception):
    def __init__(self, message: str, provider_id: str, idempotency_key: str):
        super().__init__(message)
        self.provider_id = provider_id
        self.idempotency_key = idempotency_key


class ReconcilableProvider(Protocol):
    provider_id: str

    def execute(self, operation: str, arguments: dict[str, Any], idempotency_key: str, mode: str = "success") -> ProviderReceipt: ...
    def lookup(self, idempotency_key: str) -> ProviderReceipt | None: ...
    def compensate(self, provider_action_id: str, operation: str, arguments: dict[str, Any], idempotency_key: str, mode: str = "success") -> ProviderReceipt: ...


class SQLiteSandboxProvider:
    """Persistent sandbox provider that models provider-side idempotency/reconciliation."""

    def __init__(self, conn: sqlite3.Connection, provider_id: str = "sandbox-provider"):
        self.conn = conn
        self.provider_id = provider_id
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS sandbox_provider_actions(
                provider_id TEXT NOT NULL,
                provider_action_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(provider_id,idempotency_key),
                UNIQUE(provider_id,provider_action_id)
            );
            CREATE TABLE IF NOT EXISTS sandbox_provider_compensations(
                provider_id TEXT NOT NULL,
                provider_action_id TEXT NOT NULL,
                compensation_action_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(provider_id,idempotency_key),
                UNIQUE(provider_id,compensation_action_id)
            );
            """
        )
        self.conn.commit()

    def _row_receipt(self, row) -> ProviderReceipt:
        return ProviderReceipt(
            provider_id=row["provider_id"],
            provider_action_id=row["provider_action_id"],
            operation=row["operation"],
            idempotency_key=row["idempotency_key"],
            request_digest=row["request_digest"],
            status=row["status"],
            result=json.loads(row["result_json"]),
        )

    def execute(self, operation: str, arguments: dict[str, Any], idempotency_key: str, mode: str = "success") -> ProviderReceipt:
        request_digest = digest({"operation": operation, "arguments": arguments})
        existing = self.conn.execute(
            "SELECT * FROM sandbox_provider_actions WHERE provider_id=? AND idempotency_key=?",
            (self.provider_id, idempotency_key),
        ).fetchone()
        if existing:
            if existing["request_digest"] != request_digest or existing["operation"] != operation:
                raise HardeningError("CFHS_IDEMPOTENCY_CONFLICT", "Provider idempotency key is bound to a different request")
            return self._row_receipt(existing)
        if mode == "fail_before_commit":
            raise ProviderDefiniteFailure("Sandbox provider rejected operation before persistence")

        provider_action_id = "pact_" + secrets.token_hex(10)
        now = utcnow().isoformat()
        result = {"sandbox": True, "operation": operation, "provider_action_id": provider_action_id}
        self.conn.execute(
            "INSERT INTO sandbox_provider_actions(provider_id,provider_action_id,operation,idempotency_key,request_digest,status,result_json,created_at,updated_at) VALUES(?,?,?,?,?,'SUCCEEDED',?,?,?)",
            (self.provider_id, provider_action_id, operation, idempotency_key, request_digest, json.dumps(result, sort_keys=True), now, now),
        )
        self.conn.commit()
        receipt = ProviderReceipt(self.provider_id, provider_action_id, operation, idempotency_key, request_digest, "SUCCEEDED", result)
        if mode == "commit_then_timeout":
            raise ProviderOutcomeUnknown("Provider persisted action but transport result was lost", self.provider_id, idempotency_key)
        return receipt

    def lookup(self, idempotency_key: str) -> ProviderReceipt | None:
        row = self.conn.execute(
            "SELECT * FROM sandbox_provider_actions WHERE provider_id=? AND idempotency_key=?",
            (self.provider_id, idempotency_key),
        ).fetchone()
        return self._row_receipt(row) if row else None

    def compensate(self, provider_action_id: str, operation: str, arguments: dict[str, Any], idempotency_key: str, mode: str = "success") -> ProviderReceipt:
        original = self.conn.execute(
            "SELECT * FROM sandbox_provider_actions WHERE provider_id=? AND provider_action_id=?",
            (self.provider_id, provider_action_id),
        ).fetchone()
        if not original:
            raise ProviderDefiniteFailure("Original provider action does not exist")
        request_digest = digest({"provider_action_id": provider_action_id, "operation": operation, "arguments": arguments})
        existing = self.conn.execute(
            "SELECT * FROM sandbox_provider_compensations WHERE provider_id=? AND idempotency_key=?",
            (self.provider_id, idempotency_key),
        ).fetchone()
        if existing:
            if existing["request_digest"] != request_digest:
                raise HardeningError("CFHS_IDEMPOTENCY_CONFLICT", "Compensation idempotency key is bound to another request")
            return ProviderReceipt(
                provider_id=existing["provider_id"],
                provider_action_id=existing["compensation_action_id"],
                operation=existing["operation"],
                idempotency_key=existing["idempotency_key"],
                request_digest=existing["request_digest"],
                status=existing["status"],
                result=json.loads(existing["result_json"]),
            )
        if mode == "fail_before_commit":
            raise ProviderDefiniteFailure("Sandbox compensation failed before persistence")
        compensation_action_id = "pcomp_" + secrets.token_hex(10)
        result = {"sandbox": True, "compensated_provider_action_id": provider_action_id, "compensation_action_id": compensation_action_id}
        now = utcnow().isoformat()
        self.conn.execute(
            "INSERT INTO sandbox_provider_compensations(provider_id,provider_action_id,compensation_action_id,operation,idempotency_key,request_digest,status,result_json,created_at) VALUES(?,?,?,?,?,?,'COMPENSATED',?,?)",
            (self.provider_id, provider_action_id, compensation_action_id, operation, idempotency_key, request_digest, json.dumps(result, sort_keys=True), now),
        )
        self.conn.execute(
            "UPDATE sandbox_provider_actions SET status='COMPENSATED',updated_at=? WHERE provider_id=? AND provider_action_id=?",
            (now, self.provider_id, provider_action_id),
        )
        self.conn.commit()
        return ProviderReceipt(self.provider_id, compensation_action_id, operation, idempotency_key, request_digest, "COMPENSATED", result)


class ProviderBoundCompensationRegistry:
    """Binds a compensating operation to the original semantic intent and provider."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_compensation_bindings(
                intent_digest TEXT PRIMARY KEY,
                provider_id TEXT NOT NULL,
                original_device_id TEXT NOT NULL,
                original_operation TEXT NOT NULL,
                compensation_device_id TEXT NOT NULL,
                compensation_operation TEXT NOT NULL,
                authorization_action TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def bind(
        self,
        intent_digest: str,
        provider_id: str,
        original_device_id: str,
        original_operation: str,
        compensation_device_id: str,
        compensation_operation: str,
        authorization_action: str,
    ) -> dict[str, Any]:
        if self.conn.execute("SELECT 1 FROM provider_compensation_bindings WHERE intent_digest=?", (intent_digest,)).fetchone():
            raise HardeningError("CFHS_CONFLICT", "Provider compensation is already bound for this intent")
        self.conn.execute(
            "INSERT INTO provider_compensation_bindings VALUES(?,?,?,?,?,?,?,?)",
            (
                intent_digest,
                provider_id,
                original_device_id,
                original_operation,
                compensation_device_id,
                compensation_operation,
                authorization_action,
                utcnow().isoformat(),
            ),
        )
        self.conn.commit()
        return self.get(intent_digest)

    def get(self, intent_digest: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM provider_compensation_bindings WHERE intent_digest=?", (intent_digest,)).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "No provider-bound compensation exists for this intent")
        return dict(row)


class ProviderReconciliationLedger:
    """Durable workflow for UNKNOWN_SIDE_EFFECT provider reconciliation."""

    TERMINAL = {"CONFIRMED_COMMITTED", "CONFIRMED_NOT_EXECUTED", "COMPENSATED"}

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_reconciliation_cases(
                case_id TEXT PRIMARY KEY,
                intent_digest TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                status TEXT NOT NULL,
                provider_status TEXT,
                provider_action_id TEXT,
                resolution TEXT,
                evidence_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                resolved_at TEXT,
                UNIQUE(provider_id,idempotency_key)
            )
            """
        )
        self.conn.commit()

    def open_case(self, intent_digest: str, provider_id: str, idempotency_key: str, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
        existing = self.conn.execute(
            "SELECT * FROM provider_reconciliation_cases WHERE provider_id=? AND idempotency_key=?",
            (provider_id, idempotency_key),
        ).fetchone()
        if existing:
            if existing["intent_digest"] != intent_digest:
                raise HardeningError("CFHS_IDEMPOTENCY_CONFLICT", "Reconciliation key belongs to another intent")
            return dict(existing)
        case_id = "recon_" + secrets.token_hex(10)
        self.conn.execute(
            "INSERT INTO provider_reconciliation_cases(case_id,intent_digest,provider_id,idempotency_key,status,evidence_json,created_at) VALUES(?,?,?,?, 'OPEN', ?, ?)",
            (case_id, intent_digest, provider_id, idempotency_key, json.dumps(evidence or {}, sort_keys=True), utcnow().isoformat()),
        )
        self.conn.commit()
        return self.get(case_id)

    def get(self, case_id: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM provider_reconciliation_cases WHERE case_id=?", (case_id,)).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Reconciliation case not found")
        result = dict(row)
        result["evidence"] = json.loads(result.pop("evidence_json"))
        return result

    def reconcile(self, case_id: str, provider: ReconcilableProvider) -> dict[str, Any]:
        case = self.get(case_id)
        if case["status"] in self.TERMINAL:
            return case
        if provider.provider_id != case["provider_id"]:
            raise HardeningError("CFHS_CONFLICT", "Wrong provider supplied for reconciliation")
        receipt = provider.lookup(case["idempotency_key"])
        if receipt is None:
            status = "CONFIRMED_NOT_EXECUTED"
            provider_status = "NOT_FOUND"
            provider_action_id = None
            resolution = "PROVIDER_HAS_NO_ACTION_FOR_IDEMPOTENCY_KEY"
        elif receipt.status == "SUCCEEDED":
            status = "CONFIRMED_COMMITTED"
            provider_status = receipt.status
            provider_action_id = receipt.provider_action_id
            resolution = "PROVIDER_CONFIRMED_SUCCESS"
        elif receipt.status == "COMPENSATED":
            status = "COMPENSATED"
            provider_status = receipt.status
            provider_action_id = receipt.provider_action_id
            resolution = "PROVIDER_CONFIRMED_COMPENSATION"
        else:
            self.conn.execute(
                "UPDATE provider_reconciliation_cases SET provider_status=?,provider_action_id=? WHERE case_id=?",
                (receipt.status, receipt.provider_action_id, case_id),
            )
            self.conn.commit()
            return self.get(case_id)
        now = utcnow().isoformat()
        self.conn.execute(
            "UPDATE provider_reconciliation_cases SET status=?,provider_status=?,provider_action_id=?,resolution=?,resolved_at=? WHERE case_id=?",
            (status, provider_status, provider_action_id, resolution, now, case_id),
        )
        self.conn.commit()
        return self.get(case_id)


def provider_idempotency_key(intent_digest: str, provider_id: str, operation: str) -> str:
    return "cfhs_" + sha256_hex({"intent_digest": intent_digest, "provider_id": provider_id, "operation": operation})[:48]


def compensation_idempotency_key(intent_digest: str, provider_action_id: str, compensation_operation: str) -> str:
    return "cfhs_comp_" + sha256_hex(
        {
            "intent_digest": intent_digest,
            "provider_action_id": provider_action_id,
            "compensation_operation": compensation_operation,
        }
    )[:43]
