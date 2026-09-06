from __future__ import annotations

import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .action_safety import digest as action_digest
from .distributed_state import DistributedStateTransaction
from .distributed_state_hardening import RecoverableSQLiteFencedStateCoordinator
from .hardening import HardeningError
from .live_adapter_safety import ProviderReceipt
from .trust import sha256_hex


@dataclass(frozen=True)
class DistributedCompensationBinding:
    compensation_intent_id: str
    compensation_intent_digest: str
    original_transaction_id: str
    original_intent_digest: str
    original_identity_digest: str
    provider_id: str
    original_provider_action_id: str
    compensation_operation: str
    compensation_identity_digest: str
    arguments_digest: str
    idempotency_key: str
    status: str
    reconciliation_case_id: str | None = None
    compensation_action_id: str | None = None

    def envelope(self) -> dict[str, Any]:
        return {
            "compensation_intent_id": self.compensation_intent_id,
            "compensation_intent_digest": self.compensation_intent_digest,
            "original_transaction_id": self.original_transaction_id,
            "original_intent_digest": self.original_intent_digest,
            "original_identity_digest": self.original_identity_digest,
            "provider_id": self.provider_id,
            "original_provider_action_id": self.original_provider_action_id,
            "compensation_operation": self.compensation_operation,
            "compensation_identity_digest": self.compensation_identity_digest,
            "arguments_digest": self.arguments_digest,
            "idempotency_key": self.idempotency_key,
            "status": self.status,
            "reconciliation_case_id": self.reconciliation_case_id,
            "compensation_action_id": self.compensation_action_id,
        }


class DistributedCompensationLedger:
    """Durable binding between approved compensation intent and original transaction."""

    STATUSES = {
        "APPROVED",
        "COMPENSATING",
        "FAILED_NOT_EXECUTED",
        "RECONCILIATION_REQUIRED",
        "RECONCILING",
        "COMPENSATED",
    }

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS distributed_compensation_v07(
                compensation_intent_id TEXT PRIMARY KEY,
                compensation_intent_digest TEXT NOT NULL UNIQUE,
                original_transaction_id TEXT NOT NULL,
                original_intent_digest TEXT NOT NULL,
                original_identity_digest TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                original_provider_action_id TEXT NOT NULL,
                compensation_operation TEXT NOT NULL,
                compensation_identity_digest TEXT NOT NULL UNIQUE,
                arguments_digest TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                reconciliation_case_id TEXT,
                compensation_action_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_distributed_compensation_original_v07
              ON distributed_compensation_v07(original_intent_digest)
              WHERE status IN ('APPROVED','COMPENSATING','FAILED_NOT_EXECUTED','RECONCILIATION_REQUIRED','RECONCILING');
            CREATE TABLE IF NOT EXISTS distributed_compensation_reconciliation_v07(
                case_id TEXT PRIMARY KEY,
                compensation_intent_digest TEXT NOT NULL UNIQUE,
                provider_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                status TEXT NOT NULL,
                compensation_action_id TEXT,
                evidence_digest TEXT NOT NULL,
                created_at TEXT NOT NULL,
                resolved_at TEXT
            );
            """
        )
        self.conn.commit()

    @staticmethod
    def compensation_identity(
        original_identity_digest: str,
        provider_id: str,
        original_provider_action_id: str,
        compensation_operation: str,
    ) -> str:
        return sha256_hex(
            {
                "kind": "provider-compensation",
                "original_identity_digest": original_identity_digest,
                "provider_id": provider_id,
                "original_provider_action_id": original_provider_action_id,
                "compensation_operation": compensation_operation,
            }
        )

    @staticmethod
    def _binding(row: sqlite3.Row) -> DistributedCompensationBinding:
        return DistributedCompensationBinding(
            compensation_intent_id=row["compensation_intent_id"],
            compensation_intent_digest=row["compensation_intent_digest"],
            original_transaction_id=row["original_transaction_id"],
            original_intent_digest=row["original_intent_digest"],
            original_identity_digest=row["original_identity_digest"],
            provider_id=row["provider_id"],
            original_provider_action_id=row["original_provider_action_id"],
            compensation_operation=row["compensation_operation"],
            compensation_identity_digest=row["compensation_identity_digest"],
            arguments_digest=row["arguments_digest"],
            idempotency_key=row["idempotency_key"],
            status=row["status"],
            reconciliation_case_id=row["reconciliation_case_id"],
            compensation_action_id=row["compensation_action_id"],
        )

    def bind(
        self,
        *,
        compensation_intent_id: str,
        compensation_intent_digest: str,
        original_transaction_id: str,
        original_intent_digest: str,
        original_identity_digest: str,
        provider_id: str,
        original_provider_action_id: str,
        compensation_operation: str,
        arguments: dict[str, Any],
        idempotency_key: str,
    ) -> DistributedCompensationBinding:
        identity_digest = self.compensation_identity(
            original_identity_digest,
            provider_id,
            original_provider_action_id,
            compensation_operation,
        )
        arguments_digest = action_digest(arguments)
        existing = self.conn.execute(
            "SELECT * FROM distributed_compensation_v07 WHERE compensation_intent_id=?",
            (compensation_intent_id,),
        ).fetchone()
        if existing:
            binding = self._binding(existing)
            expected = {
                "compensation_intent_digest": compensation_intent_digest,
                "original_transaction_id": original_transaction_id,
                "original_intent_digest": original_intent_digest,
                "original_identity_digest": original_identity_digest,
                "provider_id": provider_id,
                "original_provider_action_id": original_provider_action_id,
                "compensation_operation": compensation_operation,
                "compensation_identity_digest": identity_digest,
                "arguments_digest": arguments_digest,
                "idempotency_key": idempotency_key,
            }
            for key, value in expected.items():
                if getattr(binding, key) != value:
                    raise HardeningError("CFHS_CONFLICT", f"Distributed compensation binding changed: {key}")
            return binding
        now = datetime.now().astimezone().isoformat()
        try:
            self.conn.execute(
                """
                INSERT INTO distributed_compensation_v07(
                    compensation_intent_id,compensation_intent_digest,original_transaction_id,
                    original_intent_digest,original_identity_digest,provider_id,original_provider_action_id,
                    compensation_operation,compensation_identity_digest,arguments_digest,idempotency_key,
                    status,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,'APPROVED',?,?)
                """,
                (
                    compensation_intent_id,
                    compensation_intent_digest,
                    original_transaction_id,
                    original_intent_digest,
                    original_identity_digest,
                    provider_id,
                    original_provider_action_id,
                    compensation_operation,
                    identity_digest,
                    arguments_digest,
                    idempotency_key,
                    now,
                    now,
                ),
            )
            self.conn.commit()
        except sqlite3.IntegrityError as exc:
            self.conn.rollback()
            raise HardeningError("CFHS_CONFLICT", "Concurrent distributed compensation binding conflict") from exc
        return self.get(compensation_intent_id)

    def get(self, compensation_intent_id: str) -> DistributedCompensationBinding:
        row = self.conn.execute(
            "SELECT * FROM distributed_compensation_v07 WHERE compensation_intent_id=?",
            (compensation_intent_id,),
        ).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Distributed compensation binding not found")
        return self._binding(row)

    def find_for_original(self, original_intent_digest: str) -> DistributedCompensationBinding | None:
        row = self.conn.execute(
            "SELECT * FROM distributed_compensation_v07 WHERE original_intent_digest=? ORDER BY created_at DESC LIMIT 1",
            (original_intent_digest,),
        ).fetchone()
        return self._binding(row) if row else None

    def mark(
        self,
        compensation_intent_id: str,
        status: str,
        *,
        reconciliation_case_id: str | None = None,
        compensation_action_id: str | None = None,
    ) -> DistributedCompensationBinding:
        if status not in self.STATUSES:
            raise HardeningError("CFHS_INVALID_REQUEST", "Unsupported distributed compensation status")
        self.conn.execute(
            """
            UPDATE distributed_compensation_v07
               SET status=?,reconciliation_case_id=COALESCE(?,reconciliation_case_id),
                   compensation_action_id=COALESCE(?,compensation_action_id),updated_at=?
             WHERE compensation_intent_id=?
            """,
            (
                status,
                reconciliation_case_id,
                compensation_action_id,
                datetime.now().astimezone().isoformat(),
                compensation_intent_id,
            ),
        )
        self.conn.commit()
        return self.get(compensation_intent_id)

    def open_reconciliation(
        self,
        binding: DistributedCompensationBinding,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        existing = self.conn.execute(
            "SELECT * FROM distributed_compensation_reconciliation_v07 WHERE compensation_intent_digest=?",
            (binding.compensation_intent_digest,),
        ).fetchone()
        if existing:
            return dict(existing)
        case_id = "comp_recon_" + secrets.token_hex(10)
        now = datetime.now().astimezone().isoformat()
        self.conn.execute(
            """
            INSERT INTO distributed_compensation_reconciliation_v07(
                case_id,compensation_intent_digest,provider_id,idempotency_key,status,evidence_digest,created_at
            ) VALUES(?,?,?,?, 'OPEN', ?, ?)
            """,
            (
                case_id,
                binding.compensation_intent_digest,
                binding.provider_id,
                binding.idempotency_key,
                sha256_hex(evidence),
                now,
            ),
        )
        self.conn.commit()
        self.mark(binding.compensation_intent_id, "RECONCILIATION_REQUIRED", reconciliation_case_id=case_id)
        return self.reconciliation(case_id)

    def reconciliation(self, case_id: str) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM distributed_compensation_reconciliation_v07 WHERE case_id=?",
            (case_id,),
        ).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Distributed compensation reconciliation case not found")
        return dict(row)

    def resolve_reconciliation(
        self,
        case_id: str,
        status: str,
        compensation_action_id: str | None = None,
    ) -> dict[str, Any]:
        if status not in {"CONFIRMED_COMPENSATED", "CONFIRMED_NOT_EXECUTED"}:
            raise HardeningError("CFHS_INVALID_REQUEST", "Unsupported compensation reconciliation resolution")
        self.conn.execute(
            """
            UPDATE distributed_compensation_reconciliation_v07
               SET status=?,compensation_action_id=?,resolved_at=?
             WHERE case_id=?
            """,
            (status, compensation_action_id, datetime.now().astimezone().isoformat(), case_id),
        )
        self.conn.commit()
        return self.reconciliation(case_id)


class CompensationTransactionCoordinator:
    """Adds COMPENSATE ownership epochs to an existing distributed transaction."""

    def __init__(self, transactions: RecoverableSQLiteFencedStateCoordinator):
        self.transactions = transactions
        self.conn = transactions.conn

    def _acquire_epoch(
        self,
        transaction_id: str,
        owner_id: str,
        ttl_seconds: int,
        *,
        required_status: str,
        target_status: str,
        purpose: str,
        details: dict[str, Any],
        now: datetime | None = None,
    ) -> DistributedStateTransaction:
        ttl = self.transactions._positive_int(ttl_seconds, "Fence TTL", 86400)
        current_time = now or datetime.now().astimezone()
        now_text = current_time.isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM distributed_state_transactions_v07 WHERE transaction_id=?",
                (transaction_id,),
            ).fetchone()
            if not row:
                raise HardeningError("CFHS_NOT_FOUND", "Distributed transaction not found")
            if row["status"] != required_status:
                raise HardeningError(
                    "CFHS_CONFLICT",
                    f"Distributed transaction cannot enter {purpose} from {row['status']}",
                )
            fence = self.conn.execute(
                "SELECT * FROM fence_resources_v07 WHERE resource_key=?",
                (row["resource_key"],),
            ).fetchone()
            if not fence:
                raise HardeningError("CFHS_CONFLICT", "Fence resource missing for compensation")
            if fence["current_token"] is not None and not self.transactions._expired(fence["expires_at"], current_time):
                raise HardeningError("CFHS_FENCE_BUSY", "Another kernel owns the compensation resource")
            next_token = int(fence["last_token"]) + 1
            lease_id = "flease_" + secrets.token_hex(12)
            expires_at = (current_time + timedelta(seconds=ttl)).isoformat()
            self.conn.execute(
                """
                UPDATE fence_resources_v07
                   SET last_token=?,current_token=?,owner_id=?,lease_id=?,acquired_at=?,expires_at=?,updated_at=?
                 WHERE resource_key=?
                """,
                (next_token, next_token, owner_id, lease_id, now_text, expires_at, now_text, row["resource_key"]),
            )
            version = int(row["version"]) + 1
            self.conn.execute(
                """
                UPDATE distributed_state_transactions_v07
                   SET owner_id=?,lease_id=?,fence_token=?,fence_expires_at=?,purpose=?,status=?,
                       version=?,details_digest=?,updated_at=?
                 WHERE transaction_id=?
                """,
                (
                    owner_id,
                    lease_id,
                    next_token,
                    expires_at,
                    purpose,
                    target_status,
                    version,
                    sha256_hex(details),
                    now_text,
                    transaction_id,
                ),
            )
            self.transactions._journal(
                transaction_id,
                version,
                next_token,
                owner_id,
                required_status,
                target_status,
                details,
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self.transactions.get(transaction_id)

    def begin_compensation(
        self,
        transaction_id: str,
        owner_id: str,
        ttl_seconds: int,
        compensation_identity_digest: str,
        compensation_intent_digest: str,
        now: datetime | None = None,
    ) -> DistributedStateTransaction:
        return self._acquire_epoch(
            transaction_id,
            owner_id,
            ttl_seconds,
            required_status="COMMITTED",
            target_status="COMPENSATING",
            purpose="COMPENSATE",
            details={
                "compensation_identity_digest": compensation_identity_digest,
                "compensation_intent_digest": compensation_intent_digest,
            },
            now=now,
        )

    def begin_reconciliation(
        self,
        transaction_id: str,
        owner_id: str,
        ttl_seconds: int,
        reconciliation_case_id: str,
        now: datetime | None = None,
    ) -> DistributedStateTransaction:
        return self._acquire_epoch(
            transaction_id,
            owner_id,
            ttl_seconds,
            required_status="COMPENSATION_RECONCILIATION_REQUIRED",
            target_status="COMPENSATION_RECONCILING",
            purpose="COMPENSATION_RECONCILE",
            details={"reconciliation_case_id": reconciliation_case_id},
            now=now,
        )

    def transition(
        self,
        transaction_id: str,
        fence_token: int,
        owner_id: str,
        target: str,
        details: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> DistributedStateTransaction:
        allowed = {
            "COMPENSATING": {"COMMITTED", "COMPENSATED", "COMPENSATION_RECONCILIATION_REQUIRED"},
            "COMPENSATION_RECONCILING": {"COMMITTED", "COMPENSATED", "COMPENSATION_RECONCILIATION_REQUIRED"},
        }
        current_time = now or datetime.now().astimezone()
        now_text = current_time.isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM distributed_state_transactions_v07 WHERE transaction_id=?",
                (transaction_id,),
            ).fetchone()
            if not row:
                raise HardeningError("CFHS_NOT_FOUND", "Distributed transaction not found")
            self.transactions._assert_current_row(row, fence_token, owner_id, current_time)
            current = row["status"]
            if target not in allowed.get(current, set()):
                raise HardeningError("CFHS_CONFLICT", f"Compensation transaction cannot transition {current} → {target}")
            version = int(row["version"]) + 1
            self.conn.execute(
                """
                UPDATE distributed_state_transactions_v07
                   SET status=?,version=?,details_digest=?,updated_at=?
                 WHERE transaction_id=?
                """,
                (target, version, sha256_hex(details or {}), now_text, transaction_id),
            )
            self.transactions._journal(transaction_id, version, fence_token, owner_id, current, target, details)
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self.transactions.get(transaction_id)

    def release(self, tx: DistributedStateTransaction) -> DistributedStateTransaction:
        return self.transactions.release_epoch(tx.transaction_id, tx.fence_token, tx.owner_id)


def lookup_compensation(provider: Any, idempotency_key: str) -> ProviderReceipt | None:
    """Reference compensation lookup contract.

    A production provider adapter should expose `lookup_compensation`. The
    SQLite sandbox fallback is kept here so v0.7 can test unknown compensation
    outcomes without changing the frozen v0.6 provider contract.
    """

    method = getattr(provider, "lookup_compensation", None)
    if callable(method):
        return method(idempotency_key)
    conn = getattr(provider, "conn", None)
    provider_id = getattr(provider, "provider_id", None)
    if conn is None or not provider_id:
        raise HardeningError("CFHS_DEVICE_DENIED", "Provider lacks compensation reconciliation capability")
    row = conn.execute(
        "SELECT * FROM sandbox_provider_compensations WHERE provider_id=? AND idempotency_key=?",
        (provider_id, idempotency_key),
    ).fetchone()
    if not row:
        return None
    return ProviderReceipt(
        provider_id=row["provider_id"],
        provider_action_id=row["compensation_action_id"],
        operation=row["operation"],
        idempotency_key=row["idempotency_key"],
        request_digest=row["request_digest"],
        status=row["status"],
        result=json.loads(row["result_json"]),
    )
