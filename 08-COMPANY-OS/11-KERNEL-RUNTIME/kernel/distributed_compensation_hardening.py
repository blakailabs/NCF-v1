from __future__ import annotations

import secrets
from datetime import datetime
from typing import Any

from .distributed_compensation import DistributedCompensationBinding, DistributedCompensationLedger
from .distributed_compensation_gate import TrustKernelV07DistributedCompensationGate
from .trust import sha256_hex


class HardenedDistributedCompensationLedger(DistributedCompensationLedger):
    """Preserves reconciliation-attempt history and permits safe semantic retry."""

    def __init__(self, conn):
        super().__init__(conn)
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS distributed_compensation_reconciliation_history_v07(
                attempt_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                compensation_intent_digest TEXT NOT NULL,
                attempt_no INTEGER NOT NULL,
                status TEXT NOT NULL,
                evidence_digest TEXT NOT NULL,
                compensation_action_id TEXT,
                opened_at TEXT NOT NULL,
                resolved_at TEXT,
                UNIQUE(case_id,attempt_no)
            );

            CREATE TRIGGER IF NOT EXISTS trg_distributed_business_compensated_v07
            AFTER UPDATE OF status ON distributed_state_transactions_v07
            WHEN NEW.status='COMPENSATED' AND OLD.status<>NEW.status
            BEGIN
                UPDATE business_identity_bindings_v07
                   SET status='COMPENSATED', updated_at=NEW.updated_at
                 WHERE identity_digest=NEW.identity_digest;
            END;
            """
        )
        self.conn.commit()

    def _next_attempt_no(self, case_id: str) -> int:
        row = self.conn.execute(
            "SELECT COALESCE(MAX(attempt_no),0) AS n FROM distributed_compensation_reconciliation_history_v07 WHERE case_id=?",
            (case_id,),
        ).fetchone()
        return int(row["n"]) + 1

    def _record_attempt(self, case_id: str, binding: DistributedCompensationBinding, evidence: dict[str, Any]) -> None:
        attempt_no = self._next_attempt_no(case_id)
        self.conn.execute(
            """
            INSERT INTO distributed_compensation_reconciliation_history_v07(
                attempt_id,case_id,compensation_intent_digest,attempt_no,status,evidence_digest,opened_at
            ) VALUES(?,?,?,?, 'OPEN', ?, ?)
            """,
            (
                "comp_attempt_" + secrets.token_hex(10),
                case_id,
                binding.compensation_intent_digest,
                attempt_no,
                sha256_hex(evidence),
                datetime.now().astimezone().isoformat(),
            ),
        )
        self.conn.commit()

    def open_reconciliation(
        self,
        binding: DistributedCompensationBinding,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        existing = self.conn.execute(
            "SELECT * FROM distributed_compensation_reconciliation_v07 WHERE compensation_intent_digest=?",
            (binding.compensation_intent_digest,),
        ).fetchone()
        if not existing:
            case = super().open_reconciliation(binding, evidence)
            self._record_attempt(case["case_id"], binding, evidence)
            return case
        case = dict(existing)
        if case["status"] == "OPEN":
            self.mark(binding.compensation_intent_id, "RECONCILIATION_REQUIRED", reconciliation_case_id=case["case_id"])
            return case
        self.conn.execute(
            """
            UPDATE distributed_compensation_reconciliation_v07
               SET status='OPEN',compensation_action_id=NULL,evidence_digest=?,resolved_at=NULL
             WHERE case_id=?
            """,
            (sha256_hex(evidence), case["case_id"]),
        )
        self.conn.commit()
        self.mark(binding.compensation_intent_id, "RECONCILIATION_REQUIRED", reconciliation_case_id=case["case_id"])
        self._record_attempt(case["case_id"], binding, evidence)
        return self.reconciliation(case["case_id"])

    def resolve_reconciliation(
        self,
        case_id: str,
        status: str,
        compensation_action_id: str | None = None,
    ) -> dict[str, Any]:
        result = super().resolve_reconciliation(case_id, status, compensation_action_id)
        row = self.conn.execute(
            """
            SELECT attempt_id FROM distributed_compensation_reconciliation_history_v07
             WHERE case_id=? AND status='OPEN'
             ORDER BY attempt_no DESC LIMIT 1
            """,
            (case_id,),
        ).fetchone()
        if row:
            self.conn.execute(
                """
                UPDATE distributed_compensation_reconciliation_history_v07
                   SET status=?,compensation_action_id=?,resolved_at=?
                 WHERE attempt_id=?
                """,
                (
                    status,
                    compensation_action_id,
                    datetime.now().astimezone().isoformat(),
                    row["attempt_id"],
                ),
            )
            self.conn.commit()
        return result

    def reconciliation_history(self, case_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM distributed_compensation_reconciliation_history_v07 WHERE case_id=? ORDER BY attempt_no",
            (case_id,),
        ).fetchall()
        return [dict(row) for row in rows]


class TrustKernelV07DistributedCompensationFinalGate(TrustKernelV07DistributedCompensationGate):
    """Canonical candidate gate for distributed compensation certification."""

    def __init__(self, hardened, trusted_policy_keys=None, provider_anchor=None, kernel_instance_id="kernel:reference-v07"):
        super().__init__(hardened, trusted_policy_keys or {}, provider_anchor, kernel_instance_id)
        self.distributed_compensations = HardenedDistributedCompensationLedger(self.core.store.conn)
