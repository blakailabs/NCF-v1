from __future__ import annotations

import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from .hardening import HardeningError


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ExactUnitPolicy:
    """Converts business values into exact integer resource units without rounding."""

    pool_id: str
    argument: str
    unit_kind: str
    minor_exponent: int = 0
    currency: str | None = None

    def _decimal(self, raw: Any, label: str) -> Decimal:
        if isinstance(raw, bool):
            raise HardeningError("CFHS_INVALID_REQUEST", f"Boolean is not a valid {label}")
        try:
            value = Decimal(str(raw))
        except (InvalidOperation, ValueError) as exc:
            raise HardeningError("CFHS_INVALID_REQUEST", f"{label.capitalize()} is not numeric") from exc
        if not value.is_finite():
            raise HardeningError("CFHS_INVALID_REQUEST", f"{label.capitalize()} must be finite")
        return value

    def to_units(self, arguments: dict[str, Any]) -> int:
        if self.argument not in arguments:
            raise HardeningError("CFHS_INVALID_REQUEST", f"Required resource argument missing: {self.argument}")
        raw = arguments[self.argument]
        if self.unit_kind == "count":
            value = self._decimal(raw, "resource count")
            if value != value.to_integral_value():
                raise HardeningError("CFHS_INVALID_REQUEST", "Count resources must be whole units")
            units = int(value)
        elif self.unit_kind == "currency_minor":
            if self.minor_exponent < 0 or self.minor_exponent > 9:
                raise HardeningError("CFHS_INVALID_POLICY", "Currency minor exponent is outside supported range")
            if not self.currency or len(self.currency) != 3 or not self.currency.isalpha():
                raise HardeningError("CFHS_INVALID_POLICY", "Currency policy requires a three-letter currency code")
            value = self._decimal(raw, "currency amount")
            scaled = value * (Decimal(10) ** self.minor_exponent)
            if scaled != scaled.to_integral_value():
                raise HardeningError(
                    "CFHS_INVALID_REQUEST",
                    "Currency amount contains precision smaller than configured minor unit",
                    {"currency": self.currency.upper(), "minor_exponent": self.minor_exponent},
                )
            units = int(scaled)
        else:
            raise HardeningError("CFHS_INVALID_POLICY", f"Unsupported exact unit kind: {self.unit_kind}")
        if units <= 0:
            raise HardeningError("CFHS_INVALID_REQUEST", "Resource units must be positive")
        if units > 9_223_372_036_854_775_807:
            raise HardeningError("CFHS_RESOURCE_EXHAUSTED", "Exact resource units exceed signed 64-bit storage range")
        return units

    def metadata(self) -> dict[str, Any]:
        result = {"argument": self.argument, "unit_kind": self.unit_kind}
        if self.unit_kind == "currency_minor":
            result.update({"currency": self.currency.upper() if self.currency else None, "minor_exponent": self.minor_exponent})
        return result


class ExactResourceLedger:
    """Integer-only reservation/settlement ledger with compensation reversal."""

    VALID_KINDS = {"count", "currency_minor"}

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS exact_resource_pools_v06(
                pool_id TEXT PRIMARY KEY,
                hard_limit_units INTEGER NOT NULL,
                used_units INTEGER NOT NULL DEFAULT 0,
                reserved_units INTEGER NOT NULL DEFAULT 0,
                unit_kind TEXT NOT NULL,
                unit_metadata_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS exact_resource_reservations_v06(
                reservation_id TEXT PRIMARY KEY,
                intent_digest TEXT NOT NULL,
                pool_id TEXT NOT NULL,
                units INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                compensation_ref TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_exact_resource_one_active_intent_pool_v06
              ON exact_resource_reservations_v06(intent_digest,pool_id)
              WHERE status IN ('RESERVED','COMMITTED');
            """
        )
        self.conn.commit()

    @staticmethod
    def _integer(value: Any, label: str, allow_zero: bool = True) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise HardeningError("CFHS_INVALID_REQUEST", f"{label} must be an integer")
        if value < 0 or (not allow_zero and value == 0):
            raise HardeningError("CFHS_INVALID_REQUEST", f"{label} is outside the allowed range")
        return value

    def configure_pool(
        self,
        pool_id: str,
        hard_limit_units: int,
        unit_kind: str,
        unit_metadata: dict[str, Any] | None = None,
        used_units: int | None = None,
    ) -> dict[str, Any]:
        hard_limit = self._integer(hard_limit_units, "Hard limit")
        if unit_kind not in self.VALID_KINDS:
            raise HardeningError("CFHS_INVALID_POLICY", "Unsupported exact resource unit kind")
        used_requested = None if used_units is None else self._integer(used_units, "Used units")
        metadata = json.dumps(unit_metadata or {}, sort_keys=True, separators=(",", ":"))
        now = utcnow().isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            current = self.conn.execute("SELECT * FROM exact_resource_pools_v06 WHERE pool_id=?", (pool_id,)).fetchone()
            if current:
                if current["unit_kind"] != unit_kind or current["unit_metadata_json"] != metadata:
                    raise HardeningError("CFHS_CONFLICT", "Resource unit definition cannot be changed in place")
                used = int(current["used_units"] if used_requested is None else used_requested)
                reserved = int(current["reserved_units"])
                if used + reserved > hard_limit:
                    raise HardeningError("CFHS_CONFLICT", "Hard limit cannot fall below used plus reserved exact units")
                self.conn.execute(
                    "UPDATE exact_resource_pools_v06 SET hard_limit_units=?,used_units=?,updated_at=? WHERE pool_id=?",
                    (hard_limit, used, now, pool_id),
                )
            else:
                used = int(used_requested or 0)
                if used > hard_limit:
                    raise HardeningError("CFHS_INVALID_REQUEST", "Used exact units exceed hard limit")
                self.conn.execute(
                    "INSERT INTO exact_resource_pools_v06(pool_id,hard_limit_units,used_units,reserved_units,unit_kind,unit_metadata_json,updated_at) VALUES(?,?,?,0,?,?,?)",
                    (pool_id, hard_limit, used, unit_kind, metadata, now),
                )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self.pool_state(pool_id)

    def reserve(self, intent_digest: str, pool_id: str, units: int) -> dict[str, Any]:
        amount = self._integer(units, "Reservation units", allow_zero=False)
        reservation_id = "xresv_" + secrets.token_hex(10)
        now = utcnow().isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            existing = self.conn.execute(
                "SELECT * FROM exact_resource_reservations_v06 WHERE intent_digest=? AND pool_id=? AND status IN ('RESERVED','COMMITTED')",
                (intent_digest, pool_id),
            ).fetchone()
            if existing:
                if int(existing["units"]) != amount:
                    raise HardeningError("CFHS_IDEMPOTENCY_CONFLICT", "Intent already holds a different exact reservation")
                self.conn.commit()
                return dict(existing)
            pool = self.conn.execute("SELECT * FROM exact_resource_pools_v06 WHERE pool_id=?", (pool_id,)).fetchone()
            if not pool:
                raise HardeningError("CFHS_NOT_FOUND", "Exact resource pool not found")
            available = int(pool["hard_limit_units"]) - int(pool["used_units"]) - int(pool["reserved_units"])
            if amount > available:
                raise HardeningError(
                    "CFHS_RESOURCE_EXHAUSTED",
                    "Exact resource reservation exceeds available units",
                    {"pool_id": pool_id, "requested_units": amount, "available_units": available},
                )
            self.conn.execute(
                "UPDATE exact_resource_pools_v06 SET reserved_units=reserved_units+?,updated_at=? WHERE pool_id=?",
                (amount, now, pool_id),
            )
            self.conn.execute(
                "INSERT INTO exact_resource_reservations_v06(reservation_id,intent_digest,pool_id,units,status,created_at,updated_at) VALUES(?,?,?,?, 'RESERVED', ?, ?)",
                (reservation_id, intent_digest, pool_id, amount, now, now),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self.reservation(reservation_id)

    def transition(self, reservation_id: str, target: str, compensation_ref: str | None = None) -> dict[str, Any]:
        if target not in {"COMMITTED", "RELEASED", "COMPENSATED"}:
            raise HardeningError("CFHS_INVALID_REQUEST", "Unsupported exact-resource transition")
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute("SELECT * FROM exact_resource_reservations_v06 WHERE reservation_id=?", (reservation_id,)).fetchone()
            if not row:
                raise HardeningError("CFHS_NOT_FOUND", "Exact resource reservation not found")
            current = row["status"]
            if current == target:
                self.conn.commit()
                return dict(row)
            now = utcnow().isoformat()
            if target in {"COMMITTED", "RELEASED"}:
                if current != "RESERVED":
                    raise HardeningError("CFHS_CONFLICT", f"Cannot transition exact reservation {current} → {target}")
                if target == "COMMITTED":
                    self.conn.execute(
                        "UPDATE exact_resource_pools_v06 SET reserved_units=reserved_units-?,used_units=used_units+?,updated_at=? WHERE pool_id=?",
                        (row["units"], row["units"], now, row["pool_id"]),
                    )
                else:
                    self.conn.execute(
                        "UPDATE exact_resource_pools_v06 SET reserved_units=reserved_units-?,updated_at=? WHERE pool_id=?",
                        (row["units"], now, row["pool_id"]),
                    )
            else:
                if current != "COMMITTED":
                    raise HardeningError("CFHS_CONFLICT", f"Cannot compensate exact reservation in state {current}")
                if not compensation_ref:
                    raise HardeningError("CFHS_INVALID_REQUEST", "Compensation transition requires provider compensation evidence")
                pool = self.conn.execute("SELECT used_units FROM exact_resource_pools_v06 WHERE pool_id=?", (row["pool_id"],)).fetchone()
                if not pool or int(pool["used_units"]) < int(row["units"]):
                    raise HardeningError("CFHS_CONFLICT", "Exact resource pool cannot reverse committed units safely")
                self.conn.execute(
                    "UPDATE exact_resource_pools_v06 SET used_units=used_units-?,updated_at=? WHERE pool_id=?",
                    (row["units"], now, row["pool_id"]),
                )
            self.conn.execute(
                "UPDATE exact_resource_reservations_v06 SET status=?,updated_at=?,compensation_ref=COALESCE(?,compensation_ref) WHERE reservation_id=?",
                (target, now, compensation_ref, reservation_id),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self.reservation(reservation_id)

    def reservation(self, reservation_id: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM exact_resource_reservations_v06 WHERE reservation_id=?", (reservation_id,)).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Exact resource reservation not found")
        return dict(row)

    def find_for_intent(self, intent_digest: str, pool_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM exact_resource_reservations_v06 WHERE intent_digest=? AND pool_id=? ORDER BY created_at DESC LIMIT 1",
            (intent_digest, pool_id),
        ).fetchone()
        return dict(row) if row else None

    def pool_state(self, pool_id: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM exact_resource_pools_v06 WHERE pool_id=?", (pool_id,)).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Exact resource pool not found")
        result = dict(row)
        result["unit_metadata"] = json.loads(result.pop("unit_metadata_json"))
        return result
