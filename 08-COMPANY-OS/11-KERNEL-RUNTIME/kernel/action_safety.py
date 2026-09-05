from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol

from .hardening import HardeningError
from .trust import canonical_json, sha256_hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class ResourceRequest:
    pool_id: str
    amount: float


@dataclass(frozen=True)
class ActionIntent:
    intent_id: str
    actor_id: str
    process_id: str
    action: str
    resource: str
    side_effect_class: str
    purpose: str
    arguments_digest: str
    replay_nonce: str
    evidence_refs: tuple[str, ...] = ()
    resource_requests: tuple[ResourceRequest, ...] = ()
    approval_request_id: str | None = None
    created_at: str = field(default_factory=lambda: utcnow().isoformat())

    @classmethod
    def create(
        cls,
        actor_id: str,
        process_id: str,
        action: str,
        resource: str,
        side_effect_class: str,
        purpose: str,
        arguments: dict[str, Any],
        replay_nonce: str,
        evidence_refs: list[str] | None = None,
        resource_requests: list[ResourceRequest] | None = None,
        approval_request_id: str | None = None,
    ) -> "ActionIntent":
        if side_effect_class not in {"S0", "S1", "S2", "S3"}:
            raise HardeningError("CFHS_INVALID_REQUEST", "Invalid side-effect class")
        if not replay_nonce or len(replay_nonce) < 8:
            raise HardeningError("CFHS_INVALID_REQUEST", "Consequential action replay nonce is required")
        return cls(
            intent_id="intent_" + secrets.token_hex(12),
            actor_id=actor_id,
            process_id=process_id,
            action=action,
            resource=resource,
            side_effect_class=side_effect_class,
            purpose=purpose,
            arguments_digest=digest(arguments),
            replay_nonce=replay_nonce,
            evidence_refs=tuple(evidence_refs or []),
            resource_requests=tuple(resource_requests or []),
            approval_request_id=approval_request_id,
        )

    def envelope(self) -> dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "actor_id": self.actor_id,
            "process_id": self.process_id,
            "action": self.action,
            "resource": self.resource,
            "side_effect_class": self.side_effect_class,
            "purpose": self.purpose,
            "arguments_digest": self.arguments_digest,
            "replay_nonce": self.replay_nonce,
            "evidence_refs": list(self.evidence_refs),
            "resource_requests": [{"pool_id": x.pool_id, "amount": x.amount} for x in self.resource_requests],
            "approval_request_id": self.approval_request_id,
            "created_at": self.created_at,
        }

    def intent_digest(self) -> str:
        return sha256_hex(self.envelope())


class ReplayNonceRegistry:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS action_replay_nonces(
                nonce TEXT PRIMARY KEY,
                intent_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                result_digest TEXT,
                failure_code TEXT
            )
            """
        )
        self.conn.commit()

    def reserve(self, nonce: str, intent_digest: str) -> dict[str, Any]:
        now = utcnow().isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute("SELECT * FROM action_replay_nonces WHERE nonce=?", (nonce,)).fetchone()
            if row:
                if row["intent_digest"] != intent_digest:
                    raise HardeningError("CFHS_IDEMPOTENCY_CONFLICT", "Replay nonce was already used for a different action intent")
                if row["status"] == "COMMITTED":
                    self.conn.commit()
                    return {"status": "REPLAY_COMMITTED", "result_digest": row["result_digest"]}
                raise HardeningError("CFHS_IDEMPOTENCY_CONFLICT", f"Replay nonce is already in terminal/in-flight state: {row['status']}")
            self.conn.execute(
                "INSERT INTO action_replay_nonces(nonce,intent_digest,status,created_at,updated_at) VALUES(?,?,?,?,?)",
                (nonce, intent_digest, "RESERVED", now, now),
            )
            self.conn.commit()
            return {"status": "RESERVED"}
        except Exception:
            self.conn.rollback()
            raise

    def commit(self, nonce: str, result_digest: str) -> None:
        cur = self.conn.execute(
            "UPDATE action_replay_nonces SET status='COMMITTED',result_digest=?,updated_at=? WHERE nonce=? AND status='RESERVED'",
            (result_digest, utcnow().isoformat(), nonce),
        )
        self.conn.commit()
        if cur.rowcount != 1:
            raise HardeningError("CFHS_CONFLICT", "Replay nonce could not be committed")

    def fail(self, nonce: str, failure_code: str, unknown_side_effect: bool = False) -> None:
        status = "UNKNOWN_SIDE_EFFECT" if unknown_side_effect else "FAILED"
        cur = self.conn.execute(
            "UPDATE action_replay_nonces SET status=?,failure_code=?,updated_at=? WHERE nonce=? AND status='RESERVED'",
            (status, failure_code, utcnow().isoformat(), nonce),
        )
        self.conn.commit()
        if cur.rowcount != 1:
            raise HardeningError("CFHS_CONFLICT", "Replay nonce could not be marked failed")

    def get(self, nonce: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM action_replay_nonces WHERE nonce=?", (nonce,)).fetchone()
        return dict(row) if row else None


class ResourceReservationLedger:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS action_resource_pools(
                pool_id TEXT PRIMARY KEY,
                hard_limit REAL NOT NULL,
                used REAL NOT NULL DEFAULT 0,
                reserved REAL NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS action_resource_reservations(
                reservation_id TEXT PRIMARY KEY,
                intent_id TEXT NOT NULL,
                pool_id TEXT NOT NULL,
                amount REAL NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def configure_pool(self, pool_id: str, hard_limit: float, used: float = 0) -> None:
        if hard_limit < 0 or used < 0 or used > hard_limit:
            raise HardeningError("CFHS_INVALID_REQUEST", "Invalid resource pool limits")
        now = utcnow().isoformat()
        self.conn.execute(
            """
            INSERT INTO action_resource_pools(pool_id,hard_limit,used,reserved,updated_at)
            VALUES(?,?,?,0,?)
            ON CONFLICT(pool_id) DO UPDATE SET hard_limit=excluded.hard_limit,used=excluded.used,updated_at=excluded.updated_at
            """,
            (pool_id, float(hard_limit), float(used), now),
        )
        self.conn.commit()

    def reserve(self, intent_id: str, request: ResourceRequest) -> dict[str, Any]:
        if request.amount <= 0:
            raise HardeningError("CFHS_INVALID_REQUEST", "Resource reservation amount must be positive")
        rid = "resv_" + secrets.token_hex(10)
        now = utcnow().isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            pool = self.conn.execute("SELECT * FROM action_resource_pools WHERE pool_id=?", (request.pool_id,)).fetchone()
            if not pool:
                raise HardeningError("CFHS_NOT_FOUND", "Resource pool not found", {"pool_id": request.pool_id})
            available = float(pool["hard_limit"]) - float(pool["used"]) - float(pool["reserved"])
            if request.amount > available:
                raise HardeningError(
                    "CFHS_RESOURCE_EXHAUSTED",
                    "Resource reservation would exceed hard limit",
                    {"pool_id": request.pool_id, "requested": request.amount, "available": available},
                )
            self.conn.execute(
                "UPDATE action_resource_pools SET reserved=reserved+?,updated_at=? WHERE pool_id=?",
                (float(request.amount), now, request.pool_id),
            )
            self.conn.execute(
                "INSERT INTO action_resource_reservations(reservation_id,intent_id,pool_id,amount,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                (rid, intent_id, request.pool_id, float(request.amount), "RESERVED", now, now),
            )
            self.conn.commit()
            return {"reservation_id": rid, "pool_id": request.pool_id, "amount": request.amount, "status": "RESERVED"}
        except Exception:
            self.conn.rollback()
            raise

    def commit(self, reservation_id: str) -> None:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute("SELECT * FROM action_resource_reservations WHERE reservation_id=?", (reservation_id,)).fetchone()
            if not row or row["status"] != "RESERVED":
                raise HardeningError("CFHS_CONFLICT", "Resource reservation is not commit-ready")
            now = utcnow().isoformat()
            self.conn.execute(
                "UPDATE action_resource_pools SET reserved=reserved-?,used=used+?,updated_at=? WHERE pool_id=?",
                (row["amount"], row["amount"], now, row["pool_id"]),
            )
            self.conn.execute(
                "UPDATE action_resource_reservations SET status='COMMITTED',updated_at=? WHERE reservation_id=?",
                (now, reservation_id),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def release(self, reservation_id: str) -> None:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute("SELECT * FROM action_resource_reservations WHERE reservation_id=?", (reservation_id,)).fetchone()
            if not row or row["status"] != "RESERVED":
                raise HardeningError("CFHS_CONFLICT", "Resource reservation is not releasable")
            now = utcnow().isoformat()
            self.conn.execute(
                "UPDATE action_resource_pools SET reserved=reserved-?,updated_at=? WHERE pool_id=?",
                (row["amount"], now, row["pool_id"]),
            )
            self.conn.execute(
                "UPDATE action_resource_reservations SET status='RELEASED',updated_at=? WHERE reservation_id=?",
                (now, reservation_id),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def pool_state(self, pool_id: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM action_resource_pools WHERE pool_id=?", (pool_id,)).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Resource pool not found")
        return dict(row)


class MultiPartyApprovalLedger:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS action_approval_requests(
                request_id TEXT PRIMARY KEY,
                intent_digest TEXT NOT NULL,
                requester_id TEXT NOT NULL,
                required_count INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS action_approvals(
                request_id TEXT NOT NULL,
                approver_id TEXT NOT NULL,
                approved_at TEXT NOT NULL,
                PRIMARY KEY(request_id,approver_id)
            )
            """
        )
        self.conn.commit()

    def create(self, intent_digest: str, requester_id: str, required_count: int = 2, ttl_seconds: int = 900) -> dict[str, Any]:
        if required_count < 1:
            raise HardeningError("CFHS_INVALID_REQUEST", "At least one approval must be required")
        rid = "approval_" + secrets.token_hex(10)
        created = utcnow()
        expires = created + timedelta(seconds=max(60, min(int(ttl_seconds), 86400)))
        self.conn.execute(
            "INSERT INTO action_approval_requests(request_id,intent_digest,requester_id,required_count,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?)",
            (rid, intent_digest, requester_id, required_count, "PENDING", created.isoformat(), expires.isoformat()),
        )
        self.conn.commit()
        return {"request_id": rid, "required_count": required_count, "status": "PENDING", "expires_at": expires.isoformat()}

    def approve(self, request_id: str, approver_id: str) -> dict[str, Any]:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            request = self.conn.execute("SELECT * FROM action_approval_requests WHERE request_id=?", (request_id,)).fetchone()
            if not request or request["status"] not in {"PENDING", "APPROVED"}:
                raise HardeningError("CFHS_NOT_FOUND", "Approval request is not active")
            if datetime.fromisoformat(request["expires_at"]) <= utcnow():
                self.conn.execute("UPDATE action_approval_requests SET status='EXPIRED' WHERE request_id=?", (request_id,))
                raise HardeningError("CFHS_ELEVATION_REQUIRED", "Approval request expired")
            if approver_id == request["requester_id"]:
                raise HardeningError("CFHS_POLICY_DENIED", "Requester cannot approve its own multi-party request")
            self.conn.execute(
                "INSERT OR IGNORE INTO action_approvals(request_id,approver_id,approved_at) VALUES(?,?,?)",
                (request_id, approver_id, utcnow().isoformat()),
            )
            count = self.conn.execute("SELECT COUNT(*) AS n FROM action_approvals WHERE request_id=?", (request_id,)).fetchone()["n"]
            status = "APPROVED" if int(count) >= int(request["required_count"]) else "PENDING"
            self.conn.execute("UPDATE action_approval_requests SET status=? WHERE request_id=?", (status, request_id))
            self.conn.commit()
            return {"request_id": request_id, "status": status, "approval_count": int(count), "required_count": int(request["required_count"])}
        except Exception:
            self.conn.rollback()
            raise

    def require_satisfied(self, request_id: str | None, intent_digest: str) -> None:
        if not request_id:
            raise HardeningError("CFHS_ELEVATION_REQUIRED", "Multi-party approval is required")
        request = self.conn.execute("SELECT * FROM action_approval_requests WHERE request_id=?", (request_id,)).fetchone()
        if not request or request["intent_digest"] != intent_digest:
            raise HardeningError("CFHS_ELEVATION_REQUIRED", "Approval does not match action intent")
        if datetime.fromisoformat(request["expires_at"]) <= utcnow() or request["status"] != "APPROVED":
            raise HardeningError("CFHS_ELEVATION_REQUIRED", "Required approvals are not satisfied")


class CompensationRegistry:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS action_compensation_plans(
                intent_id TEXT PRIMARY KEY,
                compensation_action TEXT NOT NULL,
                compensation_resource TEXT NOT NULL,
                status TEXT NOT NULL,
                declared_at TEXT NOT NULL,
                completed_at TEXT,
                result_digest TEXT
            )
            """
        )
        self.conn.commit()

    def declare(self, intent_id: str, compensation_action: str, compensation_resource: str) -> dict[str, Any]:
        self.conn.execute(
            "INSERT OR REPLACE INTO action_compensation_plans(intent_id,compensation_action,compensation_resource,status,declared_at) VALUES(?,?,?,?,?)",
            (intent_id, compensation_action, compensation_resource, "DECLARED", utcnow().isoformat()),
        )
        self.conn.commit()
        return {"intent_id": intent_id, "status": "DECLARED", "compensation_action": compensation_action, "compensation_resource": compensation_resource}

    def require_declared(self, intent_id: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM action_compensation_plans WHERE intent_id=?", (intent_id,)).fetchone()
        if not row or row["status"] not in {"DECLARED", "PENDING"}:
            raise HardeningError("CFHS_POLICY_DENIED", "Compensatable action requires a declared compensation plan")
        return dict(row)

    def complete(self, intent_id: str, result: Any) -> None:
        self.conn.execute(
            "UPDATE action_compensation_plans SET status='COMPENSATED',completed_at=?,result_digest=? WHERE intent_id=?",
            (utcnow().isoformat(), digest(result), intent_id),
        )
        self.conn.commit()

    def fail(self, intent_id: str, result: Any) -> None:
        self.conn.execute(
            "UPDATE action_compensation_plans SET status='FAILED',completed_at=?,result_digest=? WHERE intent_id=?",
            (utcnow().isoformat(), digest(result), intent_id),
        )
        self.conn.commit()


class ActionAuditSink(Protocol):
    def prepare(self, intent: ActionIntent) -> str: ...
    def commit(self, audit_id: str, result_digest: str) -> None: ...
    def fail(self, audit_id: str, failure_code: str, details: dict[str, Any] | None = None) -> None: ...


class SQLiteActionAuditSink:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS action_commit_audit(
                audit_id TEXT PRIMARY KEY,
                intent_id TEXT NOT NULL,
                intent_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                prepared_at TEXT NOT NULL,
                completed_at TEXT,
                result_digest TEXT,
                failure_code TEXT,
                details_json TEXT
            )
            """
        )
        self.conn.commit()

    def prepare(self, intent: ActionIntent) -> str:
        aid = "actaudit_" + secrets.token_hex(10)
        self.conn.execute(
            "INSERT INTO action_commit_audit(audit_id,intent_id,intent_digest,status,prepared_at) VALUES(?,?,?,?,?)",
            (aid, intent.intent_id, intent.intent_digest(), "PREPARED", utcnow().isoformat()),
        )
        self.conn.commit()
        return aid

    def commit(self, audit_id: str, result_digest: str) -> None:
        cur = self.conn.execute(
            "UPDATE action_commit_audit SET status='COMMITTED',completed_at=?,result_digest=? WHERE audit_id=? AND status='PREPARED'",
            (utcnow().isoformat(), result_digest, audit_id),
        )
        self.conn.commit()
        if cur.rowcount != 1:
            raise HardeningError("CFHS_CONFLICT", "Action audit record is not commit-ready")

    def fail(self, audit_id: str, failure_code: str, details: dict[str, Any] | None = None) -> None:
        self.conn.execute(
            "UPDATE action_commit_audit SET status='FAILED',completed_at=?,failure_code=?,details_json=? WHERE audit_id=?",
            (utcnow().isoformat(), failure_code, json.dumps(details or {}, sort_keys=True), audit_id),
        )
        self.conn.commit()


class ConsequentialActionCoordinator:
    """Reference two-boundary coordinator for consequential device actions.

    This does not make an external side effect and a SQLite commit globally atomic.
    Instead it makes partial failure explicit, reserves resources before execution,
    requires pre-action audit durability, and records UNKNOWN_SIDE_EFFECT when the
    external action may have happened but local commit cannot be proven.
    """

    def __init__(
        self,
        replay: ReplayNonceRegistry,
        resources: ResourceReservationLedger,
        approvals: MultiPartyApprovalLedger,
        compensation: CompensationRegistry,
        audit: ActionAuditSink,
    ):
        self.replay = replay
        self.resources = resources
        self.approvals = approvals
        self.compensation = compensation
        self.audit = audit

    def execute(
        self,
        intent: ActionIntent,
        arguments: dict[str, Any],
        authorize: Callable[[ActionIntent, dict[str, Any]], dict[str, Any]],
        invoke: Callable[[dict[str, Any]], Any],
        compensate: Callable[[dict[str, Any], Exception | None], Any] | None = None,
    ) -> dict[str, Any]:
        if digest(arguments) != intent.arguments_digest:
            raise HardeningError("CFHS_CONFLICT", "Action arguments differ from signed intent envelope")

        decision = authorize(intent, arguments)
        if decision.get("decision") != "ALLOW":
            code = "CFHS_ELEVATION_REQUIRED" if decision.get("decision") == "ELEVATION_REQUIRED" else "CFHS_POLICY_DENIED"
            raise HardeningError(code, "Action authorization did not allow execution", decision)

        intent_digest = intent.intent_digest()
        if intent.side_effect_class == "S3":
            self.approvals.require_satisfied(intent.approval_request_id, intent_digest)
        if intent.side_effect_class == "S2":
            self.compensation.require_declared(intent.intent_id)

        replay_state = self.replay.reserve(intent.replay_nonce, intent_digest)
        if replay_state["status"] == "REPLAY_COMMITTED":
            return {"status": "REPLAYED", "result_digest": replay_state.get("result_digest"), "intent_id": intent.intent_id}

        reservations: list[str] = []
        audit_id: str | None = None
        invoked = False
        try:
            for request in intent.resource_requests:
                reservations.append(self.resources.reserve(intent.intent_id, request)["reservation_id"])

            # Fail closed before the external side effect if audit preparation is unavailable.
            audit_id = self.audit.prepare(intent)
            result = invoke(arguments)
            invoked = True
            result_digest = digest(result)

            try:
                self.audit.commit(audit_id, result_digest)
            except Exception as audit_exc:
                for rid in reservations:
                    try:
                        self.resources.commit(rid)
                    except Exception:
                        pass
                try:
                    self.replay.fail(intent.replay_nonce, "CFHS_AUDIT_COMMIT_FAILED", unknown_side_effect=True)
                except Exception:
                    pass
                if intent.side_effect_class in {"S1", "S2"} and compensate is not None:
                    try:
                        comp_result = compensate(arguments, audit_exc)
                        if intent.side_effect_class == "S2":
                            self.compensation.complete(intent.intent_id, comp_result)
                    except Exception as comp_exc:
                        if intent.side_effect_class == "S2":
                            self.compensation.fail(intent.intent_id, {"error": str(comp_exc)})
                        raise HardeningError("CFHS_COMPENSATION_FAILED", "Audit commit failed and compensation also failed") from comp_exc
                raise HardeningError("CFHS_AUDIT_COMMIT_FAILED", "External action may have succeeded but audit commit failed") from audit_exc

            for rid in reservations:
                self.resources.commit(rid)
            self.replay.commit(intent.replay_nonce, result_digest)
            return {"status": "COMMITTED", "intent_id": intent.intent_id, "audit_id": audit_id, "result": result, "result_digest": result_digest}

        except HardeningError:
            raise
        except Exception as exc:
            if audit_id:
                try:
                    self.audit.fail(audit_id, "CFHS_DEVICE_FAILED", {"error": str(exc), "invoked": invoked})
                except Exception:
                    pass
            for rid in reservations:
                try:
                    self.resources.release(rid)
                except Exception:
                    pass
            try:
                self.replay.fail(intent.replay_nonce, "CFHS_DEVICE_FAILED", unknown_side_effect=invoked)
            except Exception:
                pass
            if intent.side_effect_class in {"S1", "S2"} and invoked and compensate is not None:
                try:
                    comp_result = compensate(arguments, exc)
                    if intent.side_effect_class == "S2":
                        self.compensation.complete(intent.intent_id, comp_result)
                except Exception as comp_exc:
                    if intent.side_effect_class == "S2":
                        self.compensation.fail(intent.intent_id, {"error": str(comp_exc)})
                    raise HardeningError("CFHS_COMPENSATION_FAILED", "Action failed and compensation failed") from comp_exc
            raise HardeningError("CFHS_DEVICE_FAILED", "Consequential action failed", {"error": str(exc), "invoked": invoked}) from exc
