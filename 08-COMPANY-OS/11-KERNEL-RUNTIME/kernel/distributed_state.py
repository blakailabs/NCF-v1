from __future__ import annotations

import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from .hardening import HardeningError
from .trust import sha256_hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FencedStateStore(Protocol):
    """Contract required from a future shared/HA persistence backend."""

    def prepare(
        self,
        *,
        semantic_intent_digest: str,
        replay_nonce: str,
        identity_digest: str,
        provider_id: str,
        resource_key: str,
        owner_id: str,
        fence_ttl_seconds: int,
        exact_pool_id: str,
        exact_units: int,
    ) -> "DistributedStateTransaction": ...

    def assert_current(self, transaction_id: str, fence_token: int, owner_id: str) -> "DistributedStateTransaction": ...
    def transition(self, transaction_id: str, fence_token: int, owner_id: str, target: str, details: dict[str, Any] | None = None) -> "DistributedStateTransaction": ...


@dataclass(frozen=True)
class DistributedStateTransaction:
    transaction_id: str
    semantic_intent_digest: str
    replay_nonce: str
    identity_digest: str
    provider_id: str
    resource_key: str
    owner_id: str
    lease_id: str
    fence_token: int
    fence_expires_at: str
    exact_pool_id: str
    exact_units: int
    exact_reservation_id: str
    purpose: str
    status: str
    version: int

    def envelope(self) -> dict[str, Any]:
        return {
            "transaction_id": self.transaction_id,
            "semantic_intent_digest": self.semantic_intent_digest,
            "replay_nonce": self.replay_nonce,
            "identity_digest": self.identity_digest,
            "provider_id": self.provider_id,
            "resource_key": self.resource_key,
            "owner_id": self.owner_id,
            "lease_id": self.lease_id,
            "fence_token": self.fence_token,
            "fence_expires_at": self.fence_expires_at,
            "exact_pool_id": self.exact_pool_id,
            "exact_units": self.exact_units,
            "exact_reservation_id": self.exact_reservation_id,
            "purpose": self.purpose,
            "status": self.status,
            "version": self.version,
        }


class SQLiteFencedStateCoordinator:
    """Reference atomic coordinator for a distributed provider action epoch.

    It deliberately operates on the existing v0.6/v0.7 tables in one SQLite
    transaction. A production shared backend must preserve the same semantics:

    - business identity and replay identity are immutable prerequisites;
    - exact capacity and ownership epoch are acquired atomically;
    - every mutation requires the exact current owner + fencing token;
    - transaction version increases monotonically;
    - stale epochs can never mutate terminal/shared state.
    """

    ACTIVE = {"PREPARED", "EXECUTING", "RECONCILING"}
    TERMINAL = {"COMMITTED", "FAILED_NOT_EXECUTED", "COMPENSATED", "ABORTED"}
    TRANSITIONS = {
        "PREPARED": {"PREPARED", "EXECUTING", "ABORTED"},
        "EXECUTING": {"EXECUTING", "COMMITTED", "FAILED_NOT_EXECUTED", "RECONCILIATION_REQUIRED"},
        "RECONCILIATION_REQUIRED": {"RECONCILING"},
        "RECONCILING": {"RECONCILING", "COMMITTED", "FAILED_NOT_EXECUTED", "COMPENSATED", "RECONCILIATION_REQUIRED"},
        "COMMITTED": {"COMMITTED", "COMPENSATED"},
        "FAILED_NOT_EXECUTED": {"FAILED_NOT_EXECUTED"},
        "COMPENSATED": {"COMPENSATED"},
        "ABORTED": {"ABORTED"},
    }

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS distributed_state_transactions_v07(
                transaction_id TEXT PRIMARY KEY,
                semantic_intent_digest TEXT NOT NULL UNIQUE,
                replay_nonce TEXT NOT NULL,
                identity_digest TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                resource_key TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                lease_id TEXT NOT NULL,
                fence_token INTEGER NOT NULL,
                fence_expires_at TEXT NOT NULL,
                exact_pool_id TEXT NOT NULL,
                exact_units INTEGER NOT NULL,
                exact_reservation_id TEXT NOT NULL,
                purpose TEXT NOT NULL,
                status TEXT NOT NULL,
                version INTEGER NOT NULL,
                details_digest TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS distributed_state_journal_v07(
                journal_id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                fence_token INTEGER NOT NULL,
                owner_id TEXT NOT NULL,
                from_status TEXT,
                to_status TEXT NOT NULL,
                event_digest TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(transaction_id,version)
            );
            """
        )
        self.conn.commit()

    @staticmethod
    def _positive_int(value: Any, label: str, maximum: int | None = None) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise HardeningError("CFHS_INVALID_REQUEST", f"{label} must be a positive integer")
        if maximum is not None and value > maximum:
            raise HardeningError("CFHS_INVALID_REQUEST", f"{label} exceeds supported range")
        return value

    @staticmethod
    def _expired(expires_at: str | None, now: datetime) -> bool:
        return not expires_at or datetime.fromisoformat(expires_at) <= now

    @staticmethod
    def _row_to_tx(row: sqlite3.Row) -> DistributedStateTransaction:
        return DistributedStateTransaction(
            transaction_id=row["transaction_id"],
            semantic_intent_digest=row["semantic_intent_digest"],
            replay_nonce=row["replay_nonce"],
            identity_digest=row["identity_digest"],
            provider_id=row["provider_id"],
            resource_key=row["resource_key"],
            owner_id=row["owner_id"],
            lease_id=row["lease_id"],
            fence_token=int(row["fence_token"]),
            fence_expires_at=row["fence_expires_at"],
            exact_pool_id=row["exact_pool_id"],
            exact_units=int(row["exact_units"]),
            exact_reservation_id=row["exact_reservation_id"],
            purpose=row["purpose"],
            status=row["status"],
            version=int(row["version"]),
        )

    def _journal(
        self,
        tx_id: str,
        version: int,
        fence_token: int,
        owner_id: str,
        from_status: str | None,
        to_status: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        event = {
            "transaction_id": tx_id,
            "version": version,
            "fence_token": fence_token,
            "owner_id": owner_id,
            "from_status": from_status,
            "to_status": to_status,
            "details": details or {},
        }
        self.conn.execute(
            """
            INSERT INTO distributed_state_journal_v07(
                transaction_id,version,fence_token,owner_id,from_status,to_status,event_digest,created_at
            ) VALUES(?,?,?,?,?,?,?,?)
            """,
            (tx_id, version, fence_token, owner_id, from_status, to_status, sha256_hex(event), utcnow().isoformat()),
        )

    def get(self, transaction_id: str) -> DistributedStateTransaction:
        row = self.conn.execute(
            "SELECT * FROM distributed_state_transactions_v07 WHERE transaction_id=?",
            (transaction_id,),
        ).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Distributed state transaction not found")
        return self._row_to_tx(row)

    def find_for_intent(self, semantic_intent_digest: str) -> DistributedStateTransaction | None:
        row = self.conn.execute(
            "SELECT * FROM distributed_state_transactions_v07 WHERE semantic_intent_digest=?",
            (semantic_intent_digest,),
        ).fetchone()
        return self._row_to_tx(row) if row else None

    def journal(self, transaction_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM distributed_state_journal_v07 WHERE transaction_id=? ORDER BY version",
            (transaction_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def prepare(
        self,
        *,
        semantic_intent_digest: str,
        replay_nonce: str,
        identity_digest: str,
        provider_id: str,
        resource_key: str,
        owner_id: str,
        fence_ttl_seconds: int,
        exact_pool_id: str,
        exact_units: int,
        now: datetime | None = None,
    ) -> DistributedStateTransaction:
        ttl = self._positive_int(fence_ttl_seconds, "Fence TTL", 86400)
        units = self._positive_int(exact_units, "Exact units", 9_223_372_036_854_775_807)
        if not all([semantic_intent_digest, replay_nonce, identity_digest, provider_id, resource_key, owner_id, exact_pool_id]):
            raise HardeningError("CFHS_INVALID_REQUEST", "Distributed transaction binding fields are required")
        current_time = now or utcnow()
        now_text = current_time.isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")

            existing_tx = self.conn.execute(
                "SELECT * FROM distributed_state_transactions_v07 WHERE semantic_intent_digest=?",
                (semantic_intent_digest,),
            ).fetchone()
            if existing_tx:
                immutable = {
                    "replay_nonce": replay_nonce,
                    "identity_digest": identity_digest,
                    "provider_id": provider_id,
                    "resource_key": resource_key,
                    "exact_pool_id": exact_pool_id,
                    "exact_units": units,
                }
                for key, value in immutable.items():
                    if existing_tx[key] != value:
                        raise HardeningError("CFHS_CONFLICT", f"Distributed transaction binding changed: {key}")
                if existing_tx["status"] in self.TERMINAL:
                    self.conn.commit()
                    return self._row_to_tx(existing_tx)
                if (
                    existing_tx["owner_id"] == owner_id
                    and not self._expired(existing_tx["fence_expires_at"], current_time)
                    and existing_tx["status"] in self.ACTIVE
                ):
                    self.conn.commit()
                    return self._row_to_tx(existing_tx)
                raise HardeningError(
                    "CFHS_FENCE_BUSY",
                    "Distributed transaction already has a nonterminal ownership epoch",
                    {
                        "transaction_id": existing_tx["transaction_id"],
                        "owner_id": existing_tx["owner_id"],
                        "status": existing_tx["status"],
                    },
                )

            business = self.conn.execute(
                "SELECT * FROM business_identity_bindings_v07 WHERE identity_digest=?",
                (identity_digest,),
            ).fetchone()
            if not business:
                raise HardeningError("CFHS_NOT_FOUND", "Business identity must exist before distributed transaction prepare")
            if business["semantic_intent_digest"] != semantic_intent_digest or business["provider_id"] != provider_id:
                raise HardeningError("CFHS_BUSINESS_IDENTITY_CONFLICT", "Business identity does not match distributed transaction")
            if business["status"] != "BOUND":
                raise HardeningError("CFHS_CONFLICT", f"Business identity is not transaction-preparable from {business['status']}")

            replay = self.conn.execute(
                "SELECT * FROM provider_replay_v06 WHERE replay_nonce=?",
                (replay_nonce,),
            ).fetchone()
            if not replay or replay["intent_digest"] != semantic_intent_digest or not replay["intent_id"]:
                raise HardeningError("CFHS_IDEMPOTENCY_CONFLICT", "Attached semantic replay binding is required before distributed prepare")
            if replay["status"] not in {"PENDING", "PREPARED"}:
                raise HardeningError("CFHS_CONFLICT", f"Replay state is not transaction-preparable from {replay['status']}")

            fence = self.conn.execute(
                "SELECT * FROM fence_resources_v07 WHERE resource_key=?",
                (resource_key,),
            ).fetchone()
            if fence and fence["current_token"] is not None and not self._expired(fence["expires_at"], current_time):
                raise HardeningError(
                    "CFHS_FENCE_BUSY",
                    "Business resource already has an active owner",
                    {"resource_key": resource_key, "owner_id": fence["owner_id"], "expires_at": fence["expires_at"]},
                )
            next_token = int(fence["last_token"] if fence else 0) + 1
            lease_id = "flease_" + secrets.token_hex(12)
            expires_at = (current_time + timedelta(seconds=ttl)).isoformat()
            if fence:
                self.conn.execute(
                    """
                    UPDATE fence_resources_v07
                       SET last_token=?,current_token=?,owner_id=?,lease_id=?,acquired_at=?,expires_at=?,updated_at=?
                     WHERE resource_key=?
                    """,
                    (next_token, next_token, owner_id, lease_id, now_text, expires_at, now_text, resource_key),
                )
            else:
                self.conn.execute(
                    """
                    INSERT INTO fence_resources_v07(
                        resource_key,last_token,current_token,owner_id,lease_id,acquired_at,expires_at,updated_at
                    ) VALUES(?,?,?,?,?,?,?,?)
                    """,
                    (resource_key, next_token, next_token, owner_id, lease_id, now_text, expires_at, now_text),
                )

            reservation = self.conn.execute(
                """
                SELECT * FROM exact_resource_reservations_v06
                 WHERE intent_digest=? AND pool_id=? AND status IN ('RESERVED','COMMITTED')
                """,
                (semantic_intent_digest, exact_pool_id),
            ).fetchone()
            if reservation:
                if int(reservation["units"]) != units:
                    raise HardeningError("CFHS_IDEMPOTENCY_CONFLICT", "Existing exact reservation has different units")
                reservation_id = reservation["reservation_id"]
            else:
                pool = self.conn.execute(
                    "SELECT * FROM exact_resource_pools_v06 WHERE pool_id=?",
                    (exact_pool_id,),
                ).fetchone()
                if not pool:
                    raise HardeningError("CFHS_NOT_FOUND", "Exact resource pool not found")
                available = int(pool["hard_limit_units"]) - int(pool["used_units"]) - int(pool["reserved_units"])
                if units > available:
                    raise HardeningError(
                        "CFHS_RESOURCE_EXHAUSTED",
                        "Distributed transaction exact reservation exceeds available units",
                        {"pool_id": exact_pool_id, "requested_units": units, "available_units": available},
                    )
                reservation_id = "xresv_" + secrets.token_hex(10)
                self.conn.execute(
                    "UPDATE exact_resource_pools_v06 SET reserved_units=reserved_units+?,updated_at=? WHERE pool_id=?",
                    (units, now_text, exact_pool_id),
                )
                self.conn.execute(
                    """
                    INSERT INTO exact_resource_reservations_v06(
                        reservation_id,intent_digest,pool_id,units,status,created_at,updated_at
                    ) VALUES(?,?,?,?, 'RESERVED', ?, ?)
                    """,
                    (reservation_id, semantic_intent_digest, exact_pool_id, units, now_text, now_text),
                )

            transaction_id = "dtx_" + secrets.token_hex(12)
            version = 1
            self.conn.execute(
                """
                INSERT INTO distributed_state_transactions_v07(
                    transaction_id,semantic_intent_digest,replay_nonce,identity_digest,provider_id,
                    resource_key,owner_id,lease_id,fence_token,fence_expires_at,exact_pool_id,
                    exact_units,exact_reservation_id,purpose,status,version,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?, 'EXECUTE','PREPARED',?,?,?)
                """,
                (
                    transaction_id,
                    semantic_intent_digest,
                    replay_nonce,
                    identity_digest,
                    provider_id,
                    resource_key,
                    owner_id,
                    lease_id,
                    next_token,
                    expires_at,
                    exact_pool_id,
                    units,
                    reservation_id,
                    version,
                    now_text,
                    now_text,
                ),
            )
            self._journal(transaction_id, version, next_token, owner_id, None, "PREPARED")
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self.get(transaction_id)

    def _assert_current_row(
        self,
        row: sqlite3.Row,
        fence_token: int,
        owner_id: str,
        now: datetime,
        require_active_lease: bool = True,
    ) -> None:
        if int(row["fence_token"]) != fence_token or row["owner_id"] != owner_id:
            raise HardeningError("CFHS_STALE_FENCE", "Distributed transaction ownership epoch is stale")
        fence = self.conn.execute(
            "SELECT * FROM fence_resources_v07 WHERE resource_key=?",
            (row["resource_key"],),
        ).fetchone()
        if (
            not fence
            or fence["current_token"] is None
            or int(fence["current_token"]) != fence_token
            or fence["owner_id"] != owner_id
            or fence["lease_id"] != row["lease_id"]
        ):
            raise HardeningError("CFHS_STALE_FENCE", "Distributed transaction no longer owns the business resource")
        if require_active_lease and self._expired(fence["expires_at"], now):
            raise HardeningError("CFHS_STALE_FENCE", "Distributed transaction fence lease has expired")

    def assert_current(self, transaction_id: str, fence_token: int, owner_id: str, now: datetime | None = None) -> DistributedStateTransaction:
        current_time = now or utcnow()
        row = self.conn.execute(
            "SELECT * FROM distributed_state_transactions_v07 WHERE transaction_id=?",
            (transaction_id,),
        ).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Distributed state transaction not found")
        self._assert_current_row(row, fence_token, owner_id, current_time)
        return self._row_to_tx(row)

    def transition(
        self,
        transaction_id: str,
        fence_token: int,
        owner_id: str,
        target: str,
        details: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> DistributedStateTransaction:
        current_time = now or utcnow()
        now_text = current_time.isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM distributed_state_transactions_v07 WHERE transaction_id=?",
                (transaction_id,),
            ).fetchone()
            if not row:
                raise HardeningError("CFHS_NOT_FOUND", "Distributed state transaction not found")
            self._assert_current_row(row, fence_token, owner_id, current_time)
            current = row["status"]
            if target not in self.TRANSITIONS.get(current, {current}):
                raise HardeningError("CFHS_CONFLICT", f"Distributed transaction cannot transition {current} → {target}")
            if target == current:
                self.conn.commit()
                return self._row_to_tx(row)
            version = int(row["version"]) + 1
            details_digest = sha256_hex(details or {}) if details is not None else row["details_digest"]

            business_target = {
                "EXECUTING": "EXECUTING",
                "COMMITTED": "COMMITTED",
                "FAILED_NOT_EXECUTED": "FAILED_NOT_EXECUTED",
                "RECONCILIATION_REQUIRED": "RECONCILIATION_REQUIRED",
                "COMPENSATED": "COMPENSATED",
            }.get(target)
            if business_target:
                business = self.conn.execute(
                    "SELECT status FROM business_identity_bindings_v07 WHERE identity_digest=?",
                    (row["identity_digest"],),
                ).fetchone()
                if not business:
                    raise HardeningError("CFHS_BUSINESS_IDENTITY_CONFLICT", "Business identity disappeared during distributed transaction")
                allowed_business = {
                    ("BOUND", "EXECUTING"),
                    ("EXECUTING", "COMMITTED"),
                    ("EXECUTING", "FAILED_NOT_EXECUTED"),
                    ("EXECUTING", "RECONCILIATION_REQUIRED"),
                    ("RECONCILIATION_REQUIRED", "COMMITTED"),
                    ("RECONCILIATION_REQUIRED", "FAILED_NOT_EXECUTED"),
                    ("RECONCILIATION_REQUIRED", "COMPENSATED"),
                    ("COMMITTED", "COMPENSATED"),
                }
                if business["status"] != business_target:
                    if (business["status"], business_target) not in allowed_business:
                        raise HardeningError("CFHS_CONFLICT", f"Business identity cannot transition {business['status']} → {business_target}")
                    self.conn.execute(
                        "UPDATE business_identity_bindings_v07 SET status=?,updated_at=? WHERE identity_digest=?",
                        (business_target, now_text, row["identity_digest"]),
                    )

            self.conn.execute(
                """
                UPDATE distributed_state_transactions_v07
                   SET status=?,version=?,details_digest=?,updated_at=?
                 WHERE transaction_id=?
                """,
                (target, version, details_digest, now_text, transaction_id),
            )
            self._journal(transaction_id, version, fence_token, owner_id, current, target, details)
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self.get(transaction_id)

    def release_epoch(
        self,
        transaction_id: str,
        fence_token: int,
        owner_id: str,
        now: datetime | None = None,
    ) -> DistributedStateTransaction:
        current_time = now or utcnow()
        now_text = current_time.isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM distributed_state_transactions_v07 WHERE transaction_id=?",
                (transaction_id,),
            ).fetchone()
            if not row:
                raise HardeningError("CFHS_NOT_FOUND", "Distributed state transaction not found")
            self._assert_current_row(row, fence_token, owner_id, current_time, require_active_lease=False)
            self.conn.execute(
                """
                UPDATE fence_resources_v07
                   SET current_token=NULL,owner_id=NULL,lease_id=NULL,acquired_at=NULL,expires_at=NULL,updated_at=?
                 WHERE resource_key=? AND current_token=? AND owner_id=? AND lease_id=?
                """,
                (now_text, row["resource_key"], fence_token, owner_id, row["lease_id"]),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self.get(transaction_id)

    def abort_pre_execute(
        self,
        transaction_id: str,
        fence_token: int,
        owner_id: str,
        reason: str,
        now: datetime | None = None,
    ) -> DistributedStateTransaction:
        current_time = now or utcnow()
        now_text = current_time.isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM distributed_state_transactions_v07 WHERE transaction_id=?",
                (transaction_id,),
            ).fetchone()
            if not row:
                raise HardeningError("CFHS_NOT_FOUND", "Distributed state transaction not found")
            self._assert_current_row(row, fence_token, owner_id, current_time, require_active_lease=False)
            if row["status"] != "PREPARED":
                raise HardeningError("CFHS_CONFLICT", "Only a PREPARED distributed transaction can abort safely")
            reservation = self.conn.execute(
                "SELECT * FROM exact_resource_reservations_v06 WHERE reservation_id=?",
                (row["exact_reservation_id"],),
            ).fetchone()
            if reservation and reservation["status"] == "RESERVED":
                self.conn.execute(
                    "UPDATE exact_resource_pools_v06 SET reserved_units=reserved_units-?,updated_at=? WHERE pool_id=?",
                    (reservation["units"], now_text, reservation["pool_id"]),
                )
                self.conn.execute(
                    "UPDATE exact_resource_reservations_v06 SET status='RELEASED',updated_at=? WHERE reservation_id=?",
                    (now_text, row["exact_reservation_id"]),
                )
            version = int(row["version"]) + 1
            details = {"reason": reason}
            self.conn.execute(
                "UPDATE distributed_state_transactions_v07 SET status='ABORTED',version=?,details_digest=?,updated_at=? WHERE transaction_id=?",
                (version, sha256_hex(details), now_text, transaction_id),
            )
            self.conn.execute(
                """
                UPDATE fence_resources_v07
                   SET current_token=NULL,owner_id=NULL,lease_id=NULL,acquired_at=NULL,expires_at=NULL,updated_at=?
                 WHERE resource_key=? AND current_token=? AND owner_id=? AND lease_id=?
                """,
                (now_text, row["resource_key"], fence_token, owner_id, row["lease_id"]),
            )
            self._journal(transaction_id, version, fence_token, owner_id, "PREPARED", "ABORTED", details)
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self.get(transaction_id)

    def takeover_for_reconciliation(
        self,
        transaction_id: str,
        owner_id: str,
        fence_ttl_seconds: int,
        now: datetime | None = None,
    ) -> DistributedStateTransaction:
        ttl = self._positive_int(fence_ttl_seconds, "Fence TTL", 86400)
        current_time = now or utcnow()
        now_text = current_time.isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM distributed_state_transactions_v07 WHERE transaction_id=?",
                (transaction_id,),
            ).fetchone()
            if not row:
                raise HardeningError("CFHS_NOT_FOUND", "Distributed state transaction not found")
            if row["status"] != "RECONCILIATION_REQUIRED":
                raise HardeningError("CFHS_CONFLICT", "Distributed transaction does not require reconciliation")
            fence = self.conn.execute(
                "SELECT * FROM fence_resources_v07 WHERE resource_key=?",
                (row["resource_key"],),
            ).fetchone()
            if fence and fence["current_token"] is not None and not self._expired(fence["expires_at"], current_time):
                raise HardeningError("CFHS_FENCE_BUSY", "Another kernel currently owns reconciliation")
            next_token = int(fence["last_token"] if fence else row["fence_token"]) + 1
            lease_id = "flease_" + secrets.token_hex(12)
            expires_at = (current_time + timedelta(seconds=ttl)).isoformat()
            if fence:
                self.conn.execute(
                    """
                    UPDATE fence_resources_v07
                       SET last_token=?,current_token=?,owner_id=?,lease_id=?,acquired_at=?,expires_at=?,updated_at=?
                     WHERE resource_key=?
                    """,
                    (next_token, next_token, owner_id, lease_id, now_text, expires_at, now_text, row["resource_key"]),
                )
            else:
                raise HardeningError("CFHS_CONFLICT", "Fence resource is missing during reconciliation takeover")
            version = int(row["version"]) + 1
            self.conn.execute(
                """
                UPDATE distributed_state_transactions_v07
                   SET owner_id=?,lease_id=?,fence_token=?,fence_expires_at=?,purpose='RECONCILE',
                       status='RECONCILING',version=?,updated_at=?
                 WHERE transaction_id=?
                """,
                (owner_id, lease_id, next_token, expires_at, version, now_text, transaction_id),
            )
            self._journal(transaction_id, version, next_token, owner_id, "RECONCILIATION_REQUIRED", "RECONCILING")
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self.get(transaction_id)
