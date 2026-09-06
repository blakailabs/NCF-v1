from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .hardening import HardeningError
from .trust import sha256_hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ApprovalSessionEvidence:
    session_id: str
    principal_id: str
    session_created_at: str
    session_expires_at: str
    authentication_class: str
    external_identity_digest: str | None = None
    external_provider_id: str | None = None

    def envelope(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "principal_id": self.principal_id,
            "session_created_at": self.session_created_at,
            "session_expires_at": self.session_expires_at,
            "authentication_class": self.authentication_class,
            "external_identity_digest": self.external_identity_digest,
            "external_provider_id": self.external_provider_id,
        }

    def digest(self) -> str:
        return sha256_hex(self.envelope())


class SessionIdentityProvenanceLedger:
    """Persists verified external-identity provenance for kernel sessions.

    The ledger never stores an ID token. It stores only the verified issuer/subject
    relationship and a digest of the evidence envelope returned by the trusted
    identity provider boundary.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS session_identity_provenance_v06(
                session_id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                issuer TEXT NOT NULL,
                subject TEXT NOT NULL,
                auth_context_json TEXT NOT NULL,
                evidence_digest TEXT NOT NULL,
                verified_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def bind_verified_identity(
        self,
        session_id: str,
        principal_id: str,
        provider_id: str,
        issuer: str,
        subject: str,
        auth_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        session = self.conn.execute(
            "SELECT id,principal_id FROM kernel_sessions WHERE id=?",
            (session_id,),
        ).fetchone()
        if not session or session["principal_id"] != principal_id:
            raise HardeningError("CFHS_CONFLICT", "Verified identity does not match kernel session principal")
        envelope = {
            "session_id": session_id,
            "principal_id": principal_id,
            "provider_id": provider_id,
            "issuer": issuer,
            "subject": subject,
            "auth_context": auth_context or {},
        }
        evidence_digest = sha256_hex(envelope)
        existing = self.conn.execute(
            "SELECT * FROM session_identity_provenance_v06 WHERE session_id=?",
            (session_id,),
        ).fetchone()
        if existing:
            if existing["evidence_digest"] != evidence_digest:
                raise HardeningError("CFHS_CONFLICT", "Kernel session identity provenance is immutable")
            return dict(existing)
        self.conn.execute(
            "INSERT INTO session_identity_provenance_v06(session_id,principal_id,provider_id,issuer,subject,auth_context_json,evidence_digest,verified_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                session_id,
                principal_id,
                provider_id,
                issuer,
                subject,
                json.dumps(auth_context or {}, sort_keys=True),
                evidence_digest,
                utcnow().isoformat(),
            ),
        )
        self.conn.commit()
        return self.get(session_id)

    def get(self, session_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM session_identity_provenance_v06 WHERE session_id=?",
            (session_id,),
        ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["auth_context"] = json.loads(result.pop("auth_context_json"))
        return result


class ApprovalSessionResolver:
    """Resolves a bearer token to immutable approval-session evidence."""

    def __init__(self, conn: sqlite3.Connection, identity_provenance: SessionIdentityProvenanceLedger):
        self.conn = conn
        self.identity_provenance = identity_provenance

    def resolve(self, bearer_token: str, expected_principal: str) -> ApprovalSessionEvidence:
        if not bearer_token:
            raise HardeningError("CFHS_UNAUTHENTICATED", "Approval requires an authenticated kernel session")
        digest = token_hash(bearer_token)
        row = self.conn.execute(
            "SELECT * FROM kernel_sessions WHERE token_hash=?",
            (digest,),
        ).fetchone()
        if not row or not hmac.compare_digest(row["token_hash"], digest):
            raise HardeningError("CFHS_UNAUTHENTICATED", "Approval session is invalid")
        if row["principal_id"] != expected_principal:
            raise HardeningError("CFHS_POLICY_DENIED", "Approval session principal does not match approver")
        if row["revoked_at"]:
            raise HardeningError("CFHS_UNAUTHENTICATED", "Revoked session cannot supply approval evidence")
        if datetime.fromisoformat(row["expires_at"]) <= utcnow():
            raise HardeningError("CFHS_UNAUTHENTICATED", "Expired session cannot supply approval evidence")
        external = self.identity_provenance.get(row["id"])
        return ApprovalSessionEvidence(
            session_id=row["id"],
            principal_id=row["principal_id"],
            session_created_at=row["created_at"],
            session_expires_at=row["expires_at"],
            authentication_class="verified_external_identity" if external else "kernel_session",
            external_identity_digest=external["evidence_digest"] if external else None,
            external_provider_id=external["provider_id"] if external else None,
        )


class ApprovalProvenanceLedger:
    """Binds each approval to a live authenticated session and evidence digest."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS action_approval_provenance_v06(
                provenance_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                approver_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                session_evidence_digest TEXT NOT NULL,
                authentication_class TEXT NOT NULL,
                external_provider_id TEXT,
                external_identity_digest TEXT,
                approved_at TEXT NOT NULL,
                UNIQUE(request_id,approver_id)
            )
            """
        )
        self.conn.commit()

    def record(self, request_id: str, approver_id: str, evidence: ApprovalSessionEvidence) -> dict[str, Any]:
        if evidence.principal_id != approver_id:
            raise HardeningError("CFHS_CONFLICT", "Approval evidence principal differs from approver")
        approval = self.conn.execute(
            "SELECT approved_at FROM action_approvals WHERE request_id=? AND approver_id=?",
            (request_id, approver_id),
        ).fetchone()
        if not approval:
            raise HardeningError("CFHS_CONFLICT", "Approval provenance requires an existing approval record")
        existing = self.conn.execute(
            "SELECT * FROM action_approval_provenance_v06 WHERE request_id=? AND approver_id=?",
            (request_id, approver_id),
        ).fetchone()
        evidence_digest = evidence.digest()
        if existing:
            if existing["session_evidence_digest"] != evidence_digest:
                raise HardeningError("CFHS_CONFLICT", "Approval provenance cannot be replaced by another session")
            return dict(existing)
        provenance_id = "aprov_" + secrets.token_hex(10)
        self.conn.execute(
            """
            INSERT INTO action_approval_provenance_v06(
                provenance_id,request_id,approver_id,session_id,session_evidence_digest,
                authentication_class,external_provider_id,external_identity_digest,approved_at
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                provenance_id,
                request_id,
                approver_id,
                evidence.session_id,
                evidence_digest,
                evidence.authentication_class,
                evidence.external_provider_id,
                evidence.external_identity_digest,
                approval["approved_at"],
            ),
        )
        self.conn.commit()
        return self.get(request_id, approver_id)

    def get(self, request_id: str, approver_id: str) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM action_approval_provenance_v06 WHERE request_id=? AND approver_id=?",
            (request_id, approver_id),
        ).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Approval provenance not found")
        return dict(row)

    def require_complete(self, request_id: str) -> dict[str, Any]:
        request = self.conn.execute(
            "SELECT * FROM action_approval_requests WHERE request_id=?",
            (request_id,),
        ).fetchone()
        if not request or request["status"] != "APPROVED":
            raise HardeningError("CFHS_ELEVATION_REQUIRED", "Approval request is not approved")
        approvals = self.conn.execute(
            "SELECT approver_id FROM action_approvals WHERE request_id=? ORDER BY approver_id",
            (request_id,),
        ).fetchall()
        proven = self.conn.execute(
            "SELECT approver_id,session_id,session_evidence_digest,authentication_class,external_provider_id,external_identity_digest FROM action_approval_provenance_v06 WHERE request_id=? ORDER BY approver_id",
            (request_id,),
        ).fetchall()
        approval_ids = [r["approver_id"] for r in approvals]
        proven_ids = [r["approver_id"] for r in proven]
        required = int(request["required_count"])
        if len(approval_ids) < required or approval_ids != proven_ids:
            raise HardeningError(
                "CFHS_ELEVATION_REQUIRED",
                "Every counted approval must have authenticated session provenance",
                {"required": required, "approvals": approval_ids, "provenance": proven_ids},
            )
        evidence = [dict(r) for r in proven]
        return {
            "request_id": request_id,
            "required_count": required,
            "approval_count": len(approval_ids),
            "provenance_count": len(evidence),
            "approvers": evidence,
            "provenance_digest": sha256_hex(evidence),
        }
