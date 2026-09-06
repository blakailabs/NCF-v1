from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .anchored_provider_audit import AnchoredProviderActionAudit
from .anchored_provider_authorization import AnchoredProviderAuthorizationEvidenceLedger
from .hardening import HardeningError
from .production_identity import TrustKernelV07ProductionIdentityFinalGate
from .trust import sha256_hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _anchor_failure(message: str, checkpoint: dict[str, Any], exc: Exception) -> HardeningError:
    details = {
        "audit_head_hash": checkpoint["audit_head_hash"],
        "event_digest": checkpoint["event_digest"],
        "error": str(exc),
    }
    if isinstance(exc, HardeningError):
        details["cause_code"] = exc.code
        if exc.details:
            details["cause_details"] = dict(exc.details)
            if exc.details.get("anchor_request_id"):
                details["anchor_request_id"] = exc.details["anchor_request_id"]
    return HardeningError("CFHS_AUDIT_ANCHOR_FAILED", message, details)


class RecoverableAnchoredProviderActionAudit(AnchoredProviderActionAudit):
    """Anchors each semantic provider transition against one durable chain head."""

    def __init__(self, conn, audit_chain, anchor_provider):
        super().__init__(conn, audit_chain, anchor_provider)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_action_anchor_pending_v07(
                audit_id TEXT NOT NULL,
                transition_status TEXT NOT NULL,
                event_digest TEXT NOT NULL,
                audit_head_hash TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(audit_id,transition_status,event_digest)
            )
            """
        )
        self.conn.commit()

    def _pending(self, audit_id: str, status: str, event_digest: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            """
            SELECT * FROM provider_action_anchor_pending_v07
             WHERE audit_id=? AND transition_status=? AND event_digest=?
            """,
            (audit_id, status, event_digest),
        ).fetchone()
        if not row:
            return None
        out = dict(row)
        out["metadata"] = json.loads(out.pop("metadata_json"))
        return out

    def _save_pending(
        self,
        audit_id: str,
        status: str,
        event_digest: str,
        head_hash: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        now = utcnow().isoformat()
        try:
            self.conn.execute(
                """
                INSERT INTO provider_action_anchor_pending_v07(
                    audit_id,transition_status,event_digest,audit_head_hash,metadata_json,state,created_at,updated_at
                ) VALUES(?,?,?,?,?,'PENDING',?,?)
                """,
                (audit_id, status, event_digest, head_hash, json.dumps(metadata, sort_keys=True), now, now),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        pending = self._pending(audit_id, status, event_digest)
        if not pending:
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Provider action pending anchor checkpoint was not persisted")
        return pending

    def _finalize_pending(self, pending: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
        if receipt.get("audit_head_hash") != pending["audit_head_hash"]:
            raise HardeningError(
                "CFHS_AUDIT_ANCHOR_FAILED",
                "Recovered anchor receipt did not confirm the original provider-action chain head",
                {"expected": pending["audit_head_hash"], "received": receipt.get("audit_head_hash")},
            )
        receipt_key = sha256_hex(
            {
                "audit_id": pending["audit_id"],
                "transition_status": pending["transition_status"],
                "event_digest": pending["event_digest"],
                "audit_head_hash": pending["audit_head_hash"],
            }
        )
        now = utcnow().isoformat()
        self.conn.execute(
            """
            INSERT OR IGNORE INTO provider_action_anchor_receipts_v06(
                receipt_key,audit_id,transition_status,event_digest,audit_head_hash,anchor_receipt_json,anchored_at
            ) VALUES(?,?,?,?,?,?,?)
            """,
            (
                receipt_key,
                pending["audit_id"],
                pending["transition_status"],
                pending["event_digest"],
                pending["audit_head_hash"],
                json.dumps(self._safe_anchor_receipt(receipt), sort_keys=True),
                now,
            ),
        )
        self.conn.execute(
            """
            UPDATE provider_action_anchor_pending_v07 SET state='CONFIRMED',updated_at=?
             WHERE audit_id=? AND transition_status=? AND event_digest=?
            """,
            (now, pending["audit_id"], pending["transition_status"], pending["event_digest"]),
        )
        self.conn.commit()
        saved = self._existing_receipt(pending["audit_id"], pending["transition_status"], pending["event_digest"])
        if not saved:
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Recovered provider-action anchor receipt could not be persisted")
        return saved

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
        semantic = dict(event)
        semantic.pop("time", None)
        event_digest = sha256_hex(semantic)
        existing = self._existing_receipt(audit_row["audit_id"], status, event_digest)
        if existing:
            return existing
        metadata = {
            "kind": "provider_action",
            "audit_id": audit_row["audit_id"],
            "intent_digest": audit_row["intent_digest"],
            "transition_status": status,
            "event_digest": event_digest,
        }
        pending = self._pending(audit_row["audit_id"], status, event_digest)
        if not pending:
            chain_record = self.audit_chain.append(event)
            pending = self._save_pending(
                audit_row["audit_id"],
                status,
                event_digest,
                chain_record["record_hash"],
                metadata,
            )
        try:
            receipt = self.anchor_provider.anchor(pending["audit_head_hash"], pending["metadata"])
        except Exception as exc:
            raise _anchor_failure(
                "Provider action transition could not reach durable external anchor confirmation",
                pending,
                exc,
            ) from exc
        return self._finalize_pending(pending, receipt)

    def pending_checkpoints(self, state: str | None = None) -> list[dict[str, Any]]:
        if state:
            rows = self.conn.execute(
                "SELECT * FROM provider_action_anchor_pending_v07 WHERE state=? ORDER BY created_at",
                (state,),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM provider_action_anchor_pending_v07 ORDER BY created_at"
            ).fetchall()
        return [dict(row) for row in rows]


class RecoverableAnchoredProviderAuthorizationEvidenceLedger(AnchoredProviderAuthorizationEvidenceLedger):
    """Reuses one local authorization chain head until external anchoring succeeds."""

    def __init__(self, conn, audit_chain, anchor_provider):
        super().__init__(conn, audit_chain, anchor_provider)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_authorization_anchor_pending_v07(
                intent_digest TEXT PRIMARY KEY,
                evidence_digest TEXT NOT NULL,
                event_digest TEXT NOT NULL,
                audit_head_hash TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def _pending(self, intent_digest: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM provider_authorization_anchor_pending_v07 WHERE intent_digest=?",
            (intent_digest,),
        ).fetchone()
        if not row:
            return None
        out = dict(row)
        out["metadata"] = json.loads(out.pop("metadata_json"))
        return out

    def _anchor(self, evidence: dict[str, Any]) -> dict[str, Any]:
        existing = self.receipt(evidence["intent_digest"])
        if existing:
            if existing["evidence_digest"] != evidence["evidence_digest"]:
                raise HardeningError("CFHS_CONFLICT", "Anchored authorization evidence digest mismatch")
            return existing

        event = {
            "kind": "provider.authorization.v06",
            "time": utcnow().isoformat(),
            "actor_id": "kernel:action-safety",
            "process_id": "kernel:action-safety",
            "trace_id": f"provider-authorization:{evidence['intent_digest'][:24]}",
            "intent_digest": evidence["intent_digest"],
            "authorized_actor_id": evidence["actor_id"],
            "authorized_process_id": evidence["process_id"],
            "authorization_decision_digest": evidence["authorization_decision_digest"],
            "approval_request_id": evidence.get("approval_request_id"),
            "approval_provenance_digest": evidence.get("approval_provenance_digest"),
            "evidence_digest": evidence["evidence_digest"],
        }
        semantic = dict(event)
        semantic.pop("time", None)
        event_digest = sha256_hex(semantic)
        metadata = {
            "kind": "provider_authorization",
            "intent_digest": evidence["intent_digest"],
            "evidence_digest": evidence["evidence_digest"],
            "event_digest": event_digest,
        }
        pending = self._pending(evidence["intent_digest"])
        if pending:
            if pending["evidence_digest"] != evidence["evidence_digest"] or pending["event_digest"] != event_digest:
                raise HardeningError("CFHS_CONFLICT", "Pending authorization anchor checkpoint changed")
        else:
            chain_record = self.audit_chain.append(event)
            now = utcnow().isoformat()
            self.conn.execute(
                """
                INSERT INTO provider_authorization_anchor_pending_v07(
                    intent_digest,evidence_digest,event_digest,audit_head_hash,metadata_json,state,created_at,updated_at
                ) VALUES(?,?,?,?,?,'PENDING',?,?)
                """,
                (
                    evidence["intent_digest"],
                    evidence["evidence_digest"],
                    event_digest,
                    chain_record["record_hash"],
                    json.dumps(metadata, sort_keys=True),
                    now,
                    now,
                ),
            )
            self.conn.commit()
            pending = self._pending(evidence["intent_digest"])
            if not pending:
                raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Authorization pending anchor checkpoint was not persisted")

        try:
            receipt = self.anchor_provider.anchor(pending["audit_head_hash"], pending["metadata"])
        except Exception as exc:
            raise _anchor_failure(
                "Provider authorization evidence could not reach durable external anchor confirmation",
                pending,
                exc,
            ) from exc
        if receipt.get("audit_head_hash") != pending["audit_head_hash"]:
            raise HardeningError(
                "CFHS_AUDIT_ANCHOR_FAILED",
                "Recovered authorization anchor receipt did not confirm the original chain head",
                {"expected": pending["audit_head_hash"], "received": receipt.get("audit_head_hash")},
            )
        now = utcnow().isoformat()
        self.conn.execute(
            """
            INSERT OR IGNORE INTO provider_authorization_anchor_receipts_v06(
                intent_digest,evidence_digest,event_digest,audit_head_hash,anchor_receipt_json,anchored_at
            ) VALUES(?,?,?,?,?,?)
            """,
            (
                evidence["intent_digest"],
                evidence["evidence_digest"],
                event_digest,
                pending["audit_head_hash"],
                json.dumps(dict(receipt), sort_keys=True),
                now,
            ),
        )
        self.conn.execute(
            "UPDATE provider_authorization_anchor_pending_v07 SET state='CONFIRMED',updated_at=? WHERE intent_digest=?",
            (now, evidence["intent_digest"]),
        )
        self.conn.commit()
        saved = self.receipt(evidence["intent_digest"])
        if not saved:
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Recovered authorization anchor receipt was not persisted")
        return saved

    def pending_checkpoints(self, state: str | None = None) -> list[dict[str, Any]]:
        if state:
            rows = self.conn.execute(
                "SELECT * FROM provider_authorization_anchor_pending_v07 WHERE state=? ORDER BY created_at",
                (state,),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM provider_authorization_anchor_pending_v07 ORDER BY created_at"
            ).fetchall()
        return [dict(row) for row in rows]


class TrustKernelV07RecoverableAnchorFinalGate(TrustKernelV07ProductionIdentityFinalGate):
    """Canonical candidate replacing anchor consumers with same-head recovery."""

    def __init__(self, hardened, trusted_policy_keys=None, provider_anchor=None, kernel_instance_id="kernel:reference-v07"):
        super().__init__(hardened, trusted_policy_keys or {}, provider_anchor, kernel_instance_id)
        conn = self.core.store.conn
        anchor_provider = self.provider_audit.anchor_provider
        recoverable_audit = RecoverableAnchoredProviderActionAudit(
            conn,
            self.hardened.audit_chain,
            anchor_provider,
        )
        self.provider_audit = recoverable_audit
        self.provider_actions.audit = recoverable_audit
        self.provider_authorizations = RecoverableAnchoredProviderAuthorizationEvidenceLedger(
            conn,
            self.hardened.audit_chain,
            anchor_provider,
        )

    def anchor_recovery_status(self) -> dict[str, Any]:
        action_pending = self.provider_audit.pending_checkpoints("PENDING")
        authorization_pending = self.provider_authorizations.pending_checkpoints("PENDING")
        return {
            "same_head_retry": True,
            "pending_provider_action_checkpoints": len(action_pending),
            "pending_authorization_checkpoints": len(authorization_pending),
        }
