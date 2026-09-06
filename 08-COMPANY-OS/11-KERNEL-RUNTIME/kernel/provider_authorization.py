from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from .hardening import HardeningError
from .trust import sha256_hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ProviderAuthorizationEvidenceLedger:
    """Immutable evidence binding for the authorization that released a provider action."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_authorization_evidence_v06(
                intent_digest TEXT PRIMARY KEY,
                actor_id TEXT NOT NULL,
                process_id TEXT NOT NULL,
                authorization_decision_digest TEXT NOT NULL,
                matched_policies_json TEXT NOT NULL,
                constraints_json TEXT NOT NULL,
                approval_request_id TEXT,
                approval_provenance_digest TEXT,
                evidence_digest TEXT NOT NULL,
                authorized_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def bind(
        self,
        intent_digest: str,
        actor_id: str,
        process_id: str,
        decision: dict[str, Any],
        approval_evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if decision.get("decision") != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Only an ALLOW decision can release provider execution", decision)
        approval_request_id = approval_evidence.get("request_id") if approval_evidence else None
        approval_provenance_digest = approval_evidence.get("provenance_digest") if approval_evidence else None
        decision_envelope = {
            "decision": decision.get("decision"),
            "matched_policies": sorted(str(x) for x in decision.get("matched_policies", [])),
            "constraints": decision.get("constraints") or {},
        }
        decision_digest = sha256_hex(decision_envelope)
        evidence_envelope = {
            "intent_digest": intent_digest,
            "actor_id": actor_id,
            "process_id": process_id,
            "authorization_decision_digest": decision_digest,
            "approval_request_id": approval_request_id,
            "approval_provenance_digest": approval_provenance_digest,
        }
        evidence_digest = sha256_hex(evidence_envelope)
        existing = self.conn.execute(
            "SELECT * FROM provider_authorization_evidence_v06 WHERE intent_digest=?",
            (intent_digest,),
        ).fetchone()
        if existing:
            if existing["evidence_digest"] != evidence_digest:
                raise HardeningError(
                    "CFHS_CONFLICT",
                    "Provider authorization evidence is immutable once an action is prepared",
                )
            return dict(existing)
        self.conn.execute(
            """
            INSERT INTO provider_authorization_evidence_v06(
                intent_digest,actor_id,process_id,authorization_decision_digest,matched_policies_json,
                constraints_json,approval_request_id,approval_provenance_digest,evidence_digest,authorized_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                intent_digest,
                actor_id,
                process_id,
                decision_digest,
                json.dumps(decision_envelope["matched_policies"], sort_keys=True),
                json.dumps(decision_envelope["constraints"], sort_keys=True),
                approval_request_id,
                approval_provenance_digest,
                evidence_digest,
                utcnow().isoformat(),
            ),
        )
        self.conn.commit()
        return self.get(intent_digest)

    def get(self, intent_digest: str) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM provider_authorization_evidence_v06 WHERE intent_digest=?",
            (intent_digest,),
        ).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Provider authorization evidence not found")
        result = dict(row)
        result["matched_policies"] = json.loads(result.pop("matched_policies_json"))
        result["constraints"] = json.loads(result.pop("constraints_json"))
        return result
