from __future__ import annotations

import json
import sqlite3
from typing import Any, Callable

from .action_safety import (
    ActionIntent,
    CompensationRegistry,
    ConsequentialActionCoordinator,
    MultiPartyApprovalLedger,
    ReplayNonceRegistry,
    ResourceReservationLedger,
    SQLiteActionAuditSink,
)
from .hardening import HardeningError


class DurableActionIntentIndex:
    """Maps ephemeral action attempts to stable semantic intent digests for recovery."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS action_intent_index(
                intent_id TEXT PRIMARY KEY,
                intent_digest TEXT NOT NULL,
                replay_nonce TEXT NOT NULL,
                side_effect_class TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def register(self, intent: ActionIntent) -> None:
        self.conn.execute(
            """
            INSERT OR IGNORE INTO action_intent_index(
                intent_id,intent_digest,replay_nonce,side_effect_class,envelope_json,status,created_at,updated_at
            ) VALUES(?,?,?,?,?,'ACTIVE',?,?)
            """,
            (
                intent.intent_id,
                intent.intent_digest(),
                intent.replay_nonce,
                intent.side_effect_class,
                json.dumps(intent.envelope(), sort_keys=True),
                intent.created_at,
                intent.created_at,
            ),
        )
        self.conn.commit()

    def set_status(self, intent_id: str, status: str, updated_at: str) -> None:
        self.conn.execute(
            "UPDATE action_intent_index SET status=?,updated_at=? WHERE intent_id=?",
            (status, updated_at, intent_id),
        )
        self.conn.commit()

    def active(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM action_intent_index WHERE status='ACTIVE' ORDER BY created_at,intent_id"
        ).fetchall()
        return [dict(r) for r in rows]


class ActionRecoveryManager:
    """Reconciles incomplete consequential actions after process/runtime failure.

    Recovery is intentionally conservative. If a durable audit PREPARE exists but
    no terminal audit result exists, the external side effect may have happened.
    The resource reservation is committed and replay state becomes
    UNKNOWN_SIDE_EFFECT so humans/agents must reconcile before retrying.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        intents: DurableActionIntentIndex,
        replay: ReplayNonceRegistry,
        resources: ResourceReservationLedger,
        audit: SQLiteActionAuditSink,
    ):
        self.conn = conn
        self.intents = intents
        self.replay = replay
        self.resources = resources
        self.audit = audit

    @staticmethod
    def _now(conn: sqlite3.Connection) -> str:
        row = conn.execute("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now') AS ts").fetchone()
        return row["ts"]

    def _reservation_ids(self, intent_id: str) -> list[str]:
        rows = self.conn.execute(
            "SELECT reservation_id FROM action_resource_reservations WHERE intent_id=? AND status='RESERVED' ORDER BY reservation_id",
            (intent_id,),
        ).fetchall()
        return [r["reservation_id"] for r in rows]

    def _latest_audit(self, intent_id: str):
        return self.conn.execute(
            "SELECT * FROM action_commit_audit WHERE intent_id=? ORDER BY prepared_at DESC,audit_id DESC LIMIT 1",
            (intent_id,),
        ).fetchone()

    def reconcile_intent(self, intent_id: str) -> dict[str, Any]:
        intent = self.conn.execute("SELECT * FROM action_intent_index WHERE intent_id=?", (intent_id,)).fetchone()
        if not intent:
            raise HardeningError("CFHS_NOT_FOUND", "Action intent recovery record not found")
        replay = self.replay.get(intent["replay_nonce"])
        reservations = self._reservation_ids(intent_id)
        audit = self._latest_audit(intent_id)
        now = self._now(self.conn)

        if replay and replay["status"] == "COMMITTED":
            if reservations:
                self.resources.commit_many(reservations)
            self.intents.set_status(intent_id, "COMMITTED", now)
            return {"intent_id": intent_id, "recovery": "ALREADY_COMMITTED"}

        if audit and audit["status"] == "COMMITTED":
            if reservations:
                self.resources.commit_many(reservations)
            if replay and replay["status"] == "RESERVED":
                self.replay.commit(intent["replay_nonce"], audit["result_digest"])
            self.intents.set_status(intent_id, "COMMITTED_RECOVERED", now)
            return {"intent_id": intent_id, "recovery": "COMMITTED_FROM_AUDIT"}

        if not audit:
            if reservations:
                self.resources.release_many(reservations)
            if replay and replay["status"] == "RESERVED":
                self.replay.fail(intent["replay_nonce"], "CFHS_PREEXECUTION_CRASH", unknown_side_effect=False)
            self.intents.set_status(intent_id, "FAILED_PREEXECUTION", now)
            return {"intent_id": intent_id, "recovery": "RELEASED_PREEXECUTION"}

        if audit["status"] == "FAILED":
            details = json.loads(audit["details_json"] or "{}")
            compensated = bool(details.get("compensated"))
            if compensated:
                if reservations:
                    self.resources.release_many(reservations)
                if replay and replay["status"] == "RESERVED":
                    self.replay.fail(intent["replay_nonce"], "CFHS_FAILED_COMPENSATED", unknown_side_effect=False)
                self.intents.set_status(intent_id, "FAILED_COMPENSATED", now)
                return {"intent_id": intent_id, "recovery": "FAILED_COMPENSATED"}

        # PREPARED, unresolved FAILED, or an unknown audit status: the external
        # effect cannot be disproven. Account conservatively and block replay.
        if reservations:
            self.resources.commit_many(reservations)
        if replay and replay["status"] == "RESERVED":
            self.replay.fail(intent["replay_nonce"], "CFHS_CRASH_RECOVERY_UNKNOWN", unknown_side_effect=True)
        if audit and audit["status"] == "PREPARED":
            try:
                self.audit.fail(
                    audit["audit_id"],
                    "CFHS_CRASH_RECOVERY_UNKNOWN",
                    {"recovered": True, "reason": "audit_prepared_without_terminal_commit"},
                )
            except Exception:
                pass
        self.intents.set_status(intent_id, "UNKNOWN_SIDE_EFFECT", now)
        return {"intent_id": intent_id, "recovery": "UNKNOWN_SIDE_EFFECT"}

    def reconcile_all(self) -> dict[str, Any]:
        results = []
        for row in self.intents.active():
            results.append(self.reconcile_intent(row["intent_id"]))
        return {"count": len(results), "results": results}


class CrashSafeConsequentialActionCoordinator(ConsequentialActionCoordinator):
    """Adds durable intent indexing and catch-all pre-execution recovery."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        replay: ReplayNonceRegistry,
        resources: ResourceReservationLedger,
        approvals: MultiPartyApprovalLedger,
        compensation: CompensationRegistry,
        audit: SQLiteActionAuditSink,
    ):
        super().__init__(replay, resources, approvals, compensation, audit)
        self.conn = conn
        self.intents = DurableActionIntentIndex(conn)
        self.recovery = ActionRecoveryManager(conn, self.intents, replay, resources, audit)

    def execute(
        self,
        intent: ActionIntent,
        arguments: dict[str, Any],
        authorize: Callable[[ActionIntent, dict[str, Any]], dict[str, Any]],
        invoke: Callable[[dict[str, Any]], Any],
        compensate: Callable[[dict[str, Any], Exception | None], Any] | None = None,
    ) -> dict[str, Any]:
        self.intents.register(intent)
        try:
            result = super().execute(intent, arguments, authorize, invoke, compensate)
            status = "REPLAYED" if result.get("status") == "REPLAYED" else "COMMITTED"
            self.intents.set_status(intent.intent_id, status, self.recovery._now(self.conn))
            return result
        except HardeningError:
            # The base coordinator already reconciles its explicit safety errors.
            # Persist a terminal intent status when replay state proves one.
            replay = self.replay.get(intent.replay_nonce)
            if replay and replay["status"] in {"FAILED", "UNKNOWN_SIDE_EFFECT"}:
                self.intents.set_status(intent.intent_id, replay["status"], self.recovery._now(self.conn))
            raise
        except Exception as exc:
            recovery = self.recovery.reconcile_intent(intent.intent_id)
            code = "CFHS_UNKNOWN_SIDE_EFFECT" if recovery["recovery"] == "UNKNOWN_SIDE_EFFECT" else "CFHS_PREEXECUTION_FAILED"
            raise HardeningError(code, "Unexpected action coordinator failure was crash-reconciled", {"error": str(exc), **recovery}) from exc
