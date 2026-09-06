from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Protocol

from .hardening import HardeningError, TamperEvidentAuditChain
from .provider_action_runtime import ProviderActionAudit
from .trust import sha256_hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuditAnchorProvider(Protocol):
    def anchor(self, head_hash: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]: ...


class AnchoredProviderActionAudit(ProviderActionAudit):
    """Provider action journal whose transitions are chain-appended and anchored.

    This is a kernel safety service, not a caller-controlled device. The caller
    does not receive authority to choose the anchor destination or skip a
    checkpoint. PREPARE returns only after the anchor provider confirms the
    resulting tamper-evident audit-chain head.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        audit_chain: TamperEvidentAuditChain,
        anchor_provider: AuditAnchorProvider,
    ):
        super().__init__(conn)
        self.audit_chain = audit_chain
        self.anchor_provider = anchor_provider
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_action_anchor_receipts_v06(
                receipt_key TEXT PRIMARY KEY,
                audit_id TEXT NOT NULL,
                transition_status TEXT NOT NULL,
                event_digest TEXT NOT NULL,
                audit_head_hash TEXT NOT NULL,
                anchor_receipt_json TEXT NOT NULL,
                anchored_at TEXT NOT NULL,
                UNIQUE(audit_id,transition_status,event_digest)
            )
            """
        )
        self.conn.commit()

    @staticmethod
    def _safe_anchor_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
        # Receipts may contain provider-specific fields, but must never include
        # caller business arguments or secret-bearing request material.
        return dict(receipt)

    def _existing_receipt(self, audit_id: str, status: str, event_digest: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM provider_action_anchor_receipts_v06 WHERE audit_id=? AND transition_status=? AND event_digest=?",
            (audit_id, status, event_digest),
        ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["anchor_receipt"] = json.loads(result.pop("anchor_receipt_json"))
        return result

    def _anchor_transition(self, audit_row: dict[str, Any], status: str) -> dict[str, Any]:
        details = json.loads(audit_row.get("details_json") or "{}")
        event = {
            "kind": "provider.action.transition.v06",
            "time": utcnow().isoformat(),
            "actor_id": "kernel:action-safety",
            "process_id": "kernel:action-safety",
            "trace_id": f"provider-action:{audit_row['intent_digest'][:24]}",
            "audit_id": audit_row["audit_id"],
            "intent_digest": audit_row["intent_digest"],
            "provider_id": audit_row["provider_id"],
            "provider_idempotency_key": audit_row["idempotency_key"],
            "transition_status": status,
            "provider_action_id": audit_row.get("provider_action_id"),
            "result_digest": audit_row.get("result_digest"),
            "details_digest": sha256_hex(details),
        }
        # `time` is excluded from the semantic event digest so repeated recovery
        # attempts recognize the same already-anchored state.
        digest_input = dict(event)
        digest_input.pop("time", None)
        event_digest = sha256_hex(digest_input)
        existing = self._existing_receipt(audit_row["audit_id"], status, event_digest)
        if existing:
            return existing

        chain_record = self.audit_chain.append(event)
        head_hash = chain_record["record_hash"]
        try:
            receipt = self.anchor_provider.anchor(
                head_hash,
                {
                    "kind": "provider_action",
                    "audit_id": audit_row["audit_id"],
                    "intent_digest": audit_row["intent_digest"],
                    "transition_status": status,
                    "event_digest": event_digest,
                },
            )
        except Exception as exc:
            # The local chain entry remains as evidence of the attempted state,
            # but no receipt is recorded and the caller fails closed.
            raise HardeningError(
                "CFHS_AUDIT_ANCHOR_FAILED",
                "Provider action transition could not be externally anchored",
                {
                    "audit_id": audit_row["audit_id"],
                    "transition_status": status,
                    "audit_head_hash": head_hash,
                    "error": str(exc),
                },
            ) from exc

        confirmed_hash = receipt.get("audit_head_hash")
        if confirmed_hash != head_hash:
            raise HardeningError(
                "CFHS_AUDIT_ANCHOR_FAILED",
                "Audit anchor receipt did not confirm the provider-action chain head",
                {"expected": head_hash, "received": confirmed_hash},
            )
        receipt_key = sha256_hex(
            {
                "audit_id": audit_row["audit_id"],
                "transition_status": status,
                "event_digest": event_digest,
                "audit_head_hash": head_hash,
            }
        )
        self.conn.execute(
            "INSERT OR IGNORE INTO provider_action_anchor_receipts_v06(receipt_key,audit_id,transition_status,event_digest,audit_head_hash,anchor_receipt_json,anchored_at) VALUES(?,?,?,?,?,?,?)",
            (
                receipt_key,
                audit_row["audit_id"],
                status,
                event_digest,
                head_hash,
                json.dumps(self._safe_anchor_receipt(receipt), sort_keys=True),
                utcnow().isoformat(),
            ),
        )
        self.conn.commit()
        saved = self._existing_receipt(audit_row["audit_id"], status, event_digest)
        if not saved:
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Audit anchor receipt could not be persisted")
        return saved

    def prepare(self, intent_digest: str, provider_id: str, idempotency_key: str, details: dict[str, Any]) -> dict[str, Any]:
        row = super().prepare(intent_digest, provider_id, idempotency_key, details)
        anchor = self._anchor_transition(row, "PREPARED")
        result = dict(row)
        result["anchor"] = anchor
        return result

    def set_status(
        self,
        audit_id: str,
        status: str,
        provider_action_id: str | None = None,
        result: Any | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        row = super().set_status(audit_id, status, provider_action_id, result, details)
        anchor = self._anchor_transition(row, status)
        result_row = dict(row)
        result_row["anchor"] = anchor
        return result_row

    def receipts(self, audit_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM provider_action_anchor_receipts_v06 WHERE audit_id=? ORDER BY anchored_at,receipt_key",
            (audit_id,),
        ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["anchor_receipt"] = json.loads(item.pop("anchor_receipt_json"))
            out.append(item)
        return out
