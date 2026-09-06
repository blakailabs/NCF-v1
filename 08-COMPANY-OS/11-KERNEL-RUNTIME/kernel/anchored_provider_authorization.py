from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Protocol

from .hardening import HardeningError, TamperEvidentAuditChain
from .provider_authorization import ProviderAuthorizationEvidenceLedger
from .trust import sha256_hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuthorizationAnchorProvider(Protocol):
    def anchor(self, head_hash: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]: ...


class AnchoredProviderAuthorizationEvidenceLedger(ProviderAuthorizationEvidenceLedger):
    """Immutable provider authorization evidence plus fail-closed audit anchoring."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        audit_chain: TamperEvidentAuditChain,
        anchor_provider: AuthorizationAnchorProvider,
    ):
        super().__init__(conn)
        self.audit_chain = audit_chain
        self.anchor_provider = anchor_provider
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_authorization_anchor_receipts_v06(
                intent_digest TEXT PRIMARY KEY,
                evidence_digest TEXT NOT NULL,
                event_digest TEXT NOT NULL,
                audit_head_hash TEXT NOT NULL,
                anchor_receipt_json TEXT NOT NULL,
                anchored_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def receipt(self, intent_digest: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM provider_authorization_anchor_receipts_v06 WHERE intent_digest=?",
            (intent_digest,),
        ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["anchor_receipt"] = json.loads(result.pop("anchor_receipt_json"))
        return result

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
        chain_record = self.audit_chain.append(event)
        head_hash = chain_record["record_hash"]
        try:
            receipt = self.anchor_provider.anchor(
                head_hash,
                {
                    "kind": "provider_authorization",
                    "intent_digest": evidence["intent_digest"],
                    "evidence_digest": evidence["evidence_digest"],
                    "event_digest": event_digest,
                },
            )
        except Exception as exc:
            raise HardeningError(
                "CFHS_AUDIT_ANCHOR_FAILED",
                "Provider authorization evidence could not be externally anchored",
                {
                    "intent_digest": evidence["intent_digest"],
                    "audit_head_hash": head_hash,
                    "error": str(exc),
                },
            ) from exc
        if receipt.get("audit_head_hash") != head_hash:
            raise HardeningError(
                "CFHS_AUDIT_ANCHOR_FAILED",
                "Provider authorization anchor receipt did not confirm the exact chain head",
                {"expected": head_hash, "received": receipt.get("audit_head_hash")},
            )
        self.conn.execute(
            "INSERT INTO provider_authorization_anchor_receipts_v06(intent_digest,evidence_digest,event_digest,audit_head_hash,anchor_receipt_json,anchored_at) VALUES(?,?,?,?,?,?)",
            (
                evidence["intent_digest"],
                evidence["evidence_digest"],
                event_digest,
                head_hash,
                json.dumps(dict(receipt), sort_keys=True),
                utcnow().isoformat(),
            ),
        )
        self.conn.commit()
        saved = self.receipt(evidence["intent_digest"])
        if not saved:
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Provider authorization anchor receipt was not persisted")
        return saved

    def bind_and_anchor(
        self,
        intent_digest: str,
        actor_id: str,
        process_id: str,
        decision: dict[str, Any],
        approval_evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        evidence = super().bind(intent_digest, actor_id, process_id, decision, approval_evidence)
        anchor = self._anchor(evidence)
        return {"evidence": evidence, "anchor": anchor}
