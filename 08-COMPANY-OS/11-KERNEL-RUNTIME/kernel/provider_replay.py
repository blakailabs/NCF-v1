from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from .hardening import HardeningError


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ProviderReplayLedger:
    """Kernel-level semantic replay binding for provider-shaped actions."""

    ALLOWED_TRANSITIONS = {
        "PENDING": {"PENDING", "PREPARED", "FAILED_NOT_EXECUTED"},
        "PREPARED": {"PREPARED", "COMMITTED", "FAILED_NOT_EXECUTED", "RECONCILIATION_REQUIRED"},
        "RECONCILIATION_REQUIRED": {"RECONCILIATION_REQUIRED", "COMMITTED", "FAILED_NOT_EXECUTED", "COMPENSATED"},
        "COMMITTED": {"COMMITTED", "COMPENSATED"},
        "FAILED_NOT_EXECUTED": {"FAILED_NOT_EXECUTED"},
        "COMPENSATED": {"COMPENSATED"},
    }

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_replay_v06(
                replay_nonce TEXT PRIMARY KEY,
                intent_digest TEXT NOT NULL,
                intent_id TEXT NOT NULL,
                status TEXT NOT NULL,
                provider_action_id TEXT,
                reconciliation_case_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def get(self, replay_nonce: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM provider_replay_v06 WHERE replay_nonce=?",
            (replay_nonce,),
        ).fetchone()
        return dict(row) if row else None

    def bind(self, replay_nonce: str, intent_digest: str, intent_id: str) -> dict[str, Any]:
        now = utcnow().isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM provider_replay_v06 WHERE replay_nonce=?",
                (replay_nonce,),
            ).fetchone()
            if row:
                if row["intent_digest"] != intent_digest:
                    raise HardeningError(
                        "CFHS_IDEMPOTENCY_CONFLICT",
                        "Provider replay nonce is already bound to a different semantic intent",
                    )
                self.conn.commit()
                return dict(row)
            self.conn.execute(
                "INSERT INTO provider_replay_v06(replay_nonce,intent_digest,intent_id,status,created_at,updated_at) VALUES(?,?,?,'PENDING',?,?)",
                (replay_nonce, intent_digest, intent_id, now, now),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self.get(replay_nonce)  # type: ignore[return-value]

    def transition(
        self,
        replay_nonce: str,
        intent_digest: str,
        target: str,
        provider_action_id: str | None = None,
        reconciliation_case_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM provider_replay_v06 WHERE replay_nonce=?",
                (replay_nonce,),
            ).fetchone()
            if not row or row["intent_digest"] != intent_digest:
                raise HardeningError("CFHS_IDEMPOTENCY_CONFLICT", "Provider replay binding is missing or mismatched")
            current = str(row["status"])
            allowed = self.ALLOWED_TRANSITIONS.get(current, {current})
            if target not in allowed:
                raise HardeningError(
                    "CFHS_CONFLICT",
                    f"Provider replay state cannot transition {current} → {target}",
                )
            self.conn.execute(
                """
                UPDATE provider_replay_v06
                   SET status=?,
                       provider_action_id=COALESCE(?,provider_action_id),
                       reconciliation_case_id=COALESCE(?,reconciliation_case_id),
                       updated_at=?
                 WHERE replay_nonce=?
                """,
                (
                    target,
                    provider_action_id,
                    reconciliation_case_id,
                    utcnow().isoformat(),
                    replay_nonce,
                ),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self.get(replay_nonce)  # type: ignore[return-value]

    def require_intent(self, replay_nonce: str, intent_digest: str) -> dict[str, Any]:
        row = self.get(replay_nonce)
        if not row or row["intent_digest"] != intent_digest:
            raise HardeningError("CFHS_IDEMPOTENCY_CONFLICT", "Provider replay nonce is not bound to this intent")
        return row
