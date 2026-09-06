from __future__ import annotations

import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .approval_provenance import ApprovalSessionEvidence
from .distributed_compensation_hardening import TrustKernelV07DistributedCompensationFinalGate
from .hardening import HardeningError
from .runtime import RequestContext
from .trust import sha256_hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ApprovalMutationFence:
    request_id: str
    owner_id: str
    lease_id: str
    fence_token: int
    expires_at: str


class FencedApprovalControlPlane:
    """Serializes approval mutations under monotonic kernel ownership epochs.

    Approval row, authenticated session provenance, approval request status and
    mutation journal are committed in one transaction. The fence acquisition is
    durable and may survive a crashed owner until lease expiry; a later owner
    then receives a strictly higher token.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS approval_control_v07(
                request_id TEXT PRIMARY KEY,
                version INTEGER NOT NULL DEFAULT 0,
                last_token INTEGER NOT NULL DEFAULT 0,
                current_token INTEGER,
                owner_id TEXT,
                lease_id TEXT,
                expires_at TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approval_control_journal_v07(
                request_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                fence_token INTEGER NOT NULL,
                owner_id TEXT NOT NULL,
                approver_id TEXT NOT NULL,
                mutation TEXT NOT NULL,
                approval_status TEXT NOT NULL,
                approval_count INTEGER NOT NULL,
                provenance_digest TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(request_id,version)
            );
            """
        )
        self.conn.commit()

    @staticmethod
    def _ttl(ttl_seconds: int) -> int:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds < 1 or ttl_seconds > 300:
            raise HardeningError("CFHS_INVALID_REQUEST", "Approval mutation TTL must be an integer from 1 to 300 seconds")
        return ttl_seconds

    @staticmethod
    def _expired(expires_at: str | None, now: datetime) -> bool:
        return not expires_at or datetime.fromisoformat(expires_at) <= now

    def _request(self, request_id: str) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT * FROM action_approval_requests WHERE request_id=?",
            (request_id,),
        ).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Approval request not found")
        return row

    def ensure(self, request_id: str) -> dict[str, Any]:
        self._request(request_id)
        now = utcnow().isoformat()
        self.conn.execute(
            "INSERT OR IGNORE INTO approval_control_v07(request_id,version,last_token,updated_at) VALUES(?,0,0,?)",
            (request_id, now),
        )
        self.conn.commit()
        row = self.conn.execute("SELECT * FROM approval_control_v07 WHERE request_id=?", (request_id,)).fetchone()
        return dict(row)

    def acquire(
        self,
        request_id: str,
        owner_id: str,
        ttl_seconds: int = 15,
        now: datetime | None = None,
    ) -> ApprovalMutationFence:
        ttl = self._ttl(ttl_seconds)
        if not owner_id:
            raise HardeningError("CFHS_INVALID_REQUEST", "Approval mutation owner is required")
        current_time = now or utcnow()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            request = self.conn.execute(
                "SELECT * FROM action_approval_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if not request:
                raise HardeningError("CFHS_NOT_FOUND", "Approval request not found")
            self.conn.execute(
                "INSERT OR IGNORE INTO approval_control_v07(request_id,version,last_token,updated_at) VALUES(?,0,0,?)",
                (request_id, current_time.isoformat()),
            )
            row = self.conn.execute("SELECT * FROM approval_control_v07 WHERE request_id=?", (request_id,)).fetchone()
            if row["current_token"] is not None and not self._expired(row["expires_at"], current_time):
                raise HardeningError(
                    "CFHS_FENCE_BUSY",
                    "Approval request is currently owned by another mutation epoch",
                    {"owner_id": row["owner_id"], "expires_at": row["expires_at"]},
                )
            token = int(row["last_token"]) + 1
            lease_id = "approval_lease_" + secrets.token_hex(12)
            expires_at = (current_time + timedelta(seconds=ttl)).isoformat()
            self.conn.execute(
                """
                UPDATE approval_control_v07
                   SET last_token=?,current_token=?,owner_id=?,lease_id=?,expires_at=?,updated_at=?
                 WHERE request_id=?
                """,
                (token, token, owner_id, lease_id, expires_at, current_time.isoformat(), request_id),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return ApprovalMutationFence(request_id, owner_id, lease_id, token, expires_at)

    def _assert_fence(self, fence: ApprovalMutationFence, now: datetime, require_unexpired: bool = True) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT * FROM approval_control_v07 WHERE request_id=?",
            (fence.request_id,),
        ).fetchone()
        if (
            not row
            or row["current_token"] is None
            or int(row["current_token"]) != fence.fence_token
            or row["owner_id"] != fence.owner_id
            or row["lease_id"] != fence.lease_id
        ):
            raise HardeningError("CFHS_STALE_FENCE", "Approval mutation fence is stale")
        if require_unexpired and self._expired(row["expires_at"], now):
            raise HardeningError("CFHS_STALE_FENCE", "Approval mutation fence expired")
        return row

    def release(self, fence: ApprovalMutationFence, now: datetime | None = None) -> None:
        current_time = now or utcnow()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            self._assert_fence(fence, current_time, require_unexpired=False)
            self.conn.execute(
                """
                UPDATE approval_control_v07
                   SET current_token=NULL,owner_id=NULL,lease_id=NULL,expires_at=NULL,updated_at=?
                 WHERE request_id=?
                """,
                (current_time.isoformat(), fence.request_id),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def approve_with_provenance(
        self,
        fence: ApprovalMutationFence,
        approver_id: str,
        evidence: ApprovalSessionEvidence,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current_time = now or utcnow()
        if evidence.principal_id != approver_id:
            raise HardeningError("CFHS_CONFLICT", "Approval evidence principal differs from approver")
        evidence_digest = evidence.digest()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            control = self._assert_fence(fence, current_time)
            request = self.conn.execute(
                "SELECT * FROM action_approval_requests WHERE request_id=?",
                (fence.request_id,),
            ).fetchone()
            if not request or request["status"] not in {"PENDING", "APPROVED"}:
                raise HardeningError("CFHS_NOT_FOUND", "Approval request is not active")
            if datetime.fromisoformat(request["expires_at"]) <= current_time:
                self.conn.execute(
                    "UPDATE action_approval_requests SET status='EXPIRED' WHERE request_id=?",
                    (fence.request_id,),
                )
                raise HardeningError("CFHS_ELEVATION_REQUIRED", "Approval request expired")
            if approver_id == request["requester_id"]:
                raise HardeningError("CFHS_POLICY_DENIED", "Requester cannot approve its own multi-party request")
            eligible = json.loads(request["eligible_json"] or "[]")
            if eligible and approver_id not in eligible:
                raise HardeningError("CFHS_POLICY_DENIED", "Principal is not an eligible approver")

            prior_approval = self.conn.execute(
                "SELECT * FROM action_approvals WHERE request_id=? AND approver_id=?",
                (fence.request_id, approver_id),
            ).fetchone()
            prior_provenance = self.conn.execute(
                "SELECT * FROM action_approval_provenance_v06 WHERE request_id=? AND approver_id=?",
                (fence.request_id, approver_id),
            ).fetchone()
            if prior_provenance and prior_provenance["session_evidence_digest"] != evidence_digest:
                raise HardeningError("CFHS_CONFLICT", "Approval provenance cannot be replaced by another session")

            mutation = "APPROVAL_REPLAY" if prior_approval else "APPROVAL_RECORDED"
            approved_at = prior_approval["approved_at"] if prior_approval else current_time.isoformat()
            if not prior_approval:
                self.conn.execute(
                    "INSERT INTO action_approvals(request_id,approver_id,approved_at) VALUES(?,?,?)",
                    (fence.request_id, approver_id, approved_at),
                )
            if not prior_provenance:
                self.conn.execute(
                    """
                    INSERT INTO action_approval_provenance_v06(
                        provenance_id,request_id,approver_id,session_id,session_evidence_digest,
                        authentication_class,external_provider_id,external_identity_digest,approved_at
                    ) VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        "aprov_" + secrets.token_hex(10),
                        fence.request_id,
                        approver_id,
                        evidence.session_id,
                        evidence_digest,
                        evidence.authentication_class,
                        evidence.external_provider_id,
                        evidence.external_identity_digest,
                        approved_at,
                    ),
                )

            count = int(
                self.conn.execute(
                    "SELECT COUNT(*) AS n FROM action_approvals WHERE request_id=?",
                    (fence.request_id,),
                ).fetchone()["n"]
            )
            status = "APPROVED" if count >= int(request["required_count"]) else "PENDING"
            self.conn.execute(
                "UPDATE action_approval_requests SET status=? WHERE request_id=?",
                (status, fence.request_id),
            )
            version = int(control["version"]) + 1
            self.conn.execute(
                """
                UPDATE approval_control_v07
                   SET version=?,current_token=NULL,owner_id=NULL,lease_id=NULL,expires_at=NULL,updated_at=?
                 WHERE request_id=?
                """,
                (version, current_time.isoformat(), fence.request_id),
            )
            self.conn.execute(
                """
                INSERT INTO approval_control_journal_v07(
                    request_id,version,fence_token,owner_id,approver_id,mutation,
                    approval_status,approval_count,provenance_digest,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    fence.request_id,
                    version,
                    fence.fence_token,
                    fence.owner_id,
                    approver_id,
                    mutation,
                    status,
                    count,
                    evidence_digest,
                    current_time.isoformat(),
                ),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return {
            "request_id": fence.request_id,
            "status": status,
            "approval_count": count,
            "required_count": int(request["required_count"]),
            "control_version": version,
            "fence_token": fence.fence_token,
            "mutation": mutation,
            "session_id": evidence.session_id,
            "authentication_class": evidence.authentication_class,
            "session_evidence_digest": evidence_digest,
        }

    def approve(
        self,
        request_id: str,
        owner_id: str,
        approver_id: str,
        evidence: ApprovalSessionEvidence,
        ttl_seconds: int = 15,
    ) -> dict[str, Any]:
        fence = self.acquire(request_id, owner_id, ttl_seconds)
        try:
            return self.approve_with_provenance(fence, approver_id, evidence)
        except Exception:
            try:
                self.release(fence)
            except Exception:
                pass
            raise

    def state(self, request_id: str) -> dict[str, Any]:
        self.ensure(request_id)
        control = self.conn.execute(
            "SELECT * FROM approval_control_v07 WHERE request_id=?",
            (request_id,),
        ).fetchone()
        request = self._request(request_id)
        return {"control": dict(control), "request": dict(request), "journal": self.journal(request_id)}

    def journal(self, request_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM approval_control_journal_v07 WHERE request_id=? ORDER BY version",
            (request_id,),
        ).fetchall()
        return [dict(row) for row in rows]


class TrustKernelV07ControlPlaneFinalGate(TrustKernelV07DistributedCompensationFinalGate):
    """Canonical candidate adding fenced approval mutations to v0.7."""

    def __init__(self, hardened, trusted_policy_keys=None, provider_anchor=None, kernel_instance_id="kernel:reference-v07"):
        super().__init__(hardened, trusted_policy_keys or {}, provider_anchor, kernel_instance_id)
        self.approval_control = FencedApprovalControlPlane(self.core.store.conn)

    def request_action_approval(
        self,
        ctx: RequestContext,
        intent_id: str,
        eligible_approvers: list[str],
        required_count: int | None = None,
        ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        result = super().request_action_approval(ctx, intent_id, eligible_approvers, required_count, ttl_seconds)
        control = self.approval_control.ensure(result["request_id"])
        safe = {**result, "control_version": int(control["version"]), "last_fence_token": int(control["last_token"])}
        self.hardened._chain(ctx, "action.approval.control.initialized.v07", safe)
        return safe

    def approve_action(self, ctx: RequestContext, request_id: str) -> dict[str, Any]:
        raise HardeningError(
            "CFHS_UNAUTHENTICATED",
            "v0.7 approval mutation requires authenticated session provenance",
            {"request_id": request_id},
        )

    def approve_action_with_session(self, ctx: RequestContext, bearer_token: str, request_id: str) -> dict[str, Any]:
        decision = self.authorize(ctx, "kernel.action.approval.approve", f"/run/actions/approvals/{request_id}", {})
        if decision.get("decision") != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Action approval denied", decision)
        evidence = self.approval_session_resolver.resolve(bearer_token, ctx.actor_id)
        result = self.approval_control.approve(
            request_id,
            f"{self.kernel_instance_id}:approval:{ctx.actor_id}",
            ctx.actor_id,
            evidence,
        )
        self.hardened._chain(ctx, "action.approval.fenced.provenance.v07", result)
        return result

    def provider_action_status(self, ctx: RequestContext, intent_id: str) -> dict[str, Any]:
        result = super().provider_action_status(ctx, intent_id)
        intent = self._load_intent(intent_id)
        request_id = intent.approval_request_id
        if request_id:
            result["approval_control"] = self.approval_control.state(request_id)
        else:
            result["approval_control"] = None
        return result
