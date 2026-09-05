from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from dataclasses import dataclass, field, replace
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
    """Immutable intent. Raw arguments are represented only by a digest."""

    intent_id: str
    actor_id: str
    process_id: str
    action: str
    resource: str
    side_effect_class: str
    purpose: str
    arguments_digest: str
    replay_nonce: str
    required_approvals: int = 0
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
        required_approvals: int | None = None,
        evidence_refs: list[str] | None = None,
        resource_requests: list[ResourceRequest] | None = None,
    ) -> "ActionIntent":
        if side_effect_class not in {"S0", "S1", "S2", "S3"}:
            raise HardeningError("CFHS_INVALID_REQUEST", "Invalid side-effect class")
        if not replay_nonce or len(replay_nonce) < 8:
            raise HardeningError("CFHS_INVALID_REQUEST", "Action replay nonce is required")
        required = 2 if required_approvals is None and side_effect_class == "S3" else int(required_approvals or 0)
        if required < 0:
            raise HardeningError("CFHS_INVALID_REQUEST", "Required approvals cannot be negative")
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
            required_approvals=required,
            evidence_refs=tuple(evidence_refs or []),
            resource_requests=tuple(resource_requests or []),
        )

    def with_approval(self, request_id: str) -> "ActionIntent":
        return replace(self, approval_request_id=request_id)

    def binding_envelope(self) -> dict[str, Any]:
        """Stable semantic binding used by approvals and replay protection.

        Ephemeral intent_id, created_at, and approval_request_id are excluded so a
        retry of the same semantic request with the same nonce can be recognized.
        """
        return {
            "actor_id": self.actor_id,
            "process_id": self.process_id,
            "action": self.action,
            "resource": self.resource,
            "side_effect_class": self.side_effect_class,
            "purpose": self.purpose,
            "arguments_digest": self.arguments_digest,
            "replay_nonce": self.replay_nonce,
            "required_approvals": self.required_approvals,
            "evidence_refs": list(self.evidence_refs),
            "resource_requests": [{"pool_id": x.pool_id, "amount": x.amount} for x in self.resource_requests],
        }

    def envelope(self) -> dict[str, Any]:
        return {
            **self.binding_envelope(),
            "intent_id": self.intent_id,
            "approval_request_id": self.approval_request_id,
            "created_at": self.created_at,
        }

    def intent_digest(self) -> str:
        return sha256_hex(self.binding_envelope())


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
                    raise HardeningError("CFHS_IDEMPOTENCY_CONFLICT", "Replay nonce was already used for a different semantic action")
                if row["status"] == "COMMITTED":
                    self.conn.commit()
                    return {"status": "REPLAY_COMMITTED", "result_digest": row["result_digest"]}
                raise HardeningError("CFHS_IDEMPOTENCY_CONFLICT", f"Replay nonce is already in state: {row['status']}")
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
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS action_resource_pools(
                pool_id TEXT PRIMARY KEY,
                hard_limit REAL NOT NULL,
                used REAL NOT NULL DEFAULT 0,
                reserved REAL NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS action_resource_reservations(
                reservation_id TEXT PRIMARY KEY,
                intent_id TEXT NOT NULL,
                pool_id TEXT NOT NULL,
                amount REAL NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def configure_pool(self, pool_id: str, hard_limit: float, used: float | None = None) -> None:
        if hard_limit < 0 or (used is not None and used < 0):
            raise HardeningError("CFHS_INVALID_REQUEST", "Invalid resource pool limits")
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            current = self.conn.execute("SELECT * FROM action_resource_pools WHERE pool_id=?", (pool_id,)).fetchone()
            if current:
                new_used = float(current["used"] if used is None else used)
                reserved = float(current["reserved"])
                if new_used + reserved > float(hard_limit):
                    raise HardeningError("CFHS_CONFLICT", "Pool limit cannot be set below used plus reserved resources")
                self.conn.execute(
                    "UPDATE action_resource_pools SET hard_limit=?,used=?,updated_at=? WHERE pool_id=?",
                    (float(hard_limit), new_used, utcnow().isoformat(), pool_id),
                )
            else:
                new_used = float(used or 0)
                if new_used > float(hard_limit):
                    raise HardeningError("CFHS_INVALID_REQUEST", "Used resources exceed hard limit")
                self.conn.execute(
                    "INSERT INTO action_resource_pools(pool_id,hard_limit,used,reserved,updated_at) VALUES(?,?,?,0,?)",
                    (pool_id, float(hard_limit), new_used, utcnow().isoformat()),
                )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def reserve_many(self, intent_id: str, requests: tuple[ResourceRequest, ...] | list[ResourceRequest]) -> list[dict[str, Any]]:
        requests = list(requests)
        if not requests:
            return []
        totals: dict[str, float] = {}
        for request in requests:
            if request.amount <= 0:
                raise HardeningError("CFHS_INVALID_REQUEST", "Resource reservation amount must be positive")
            totals[request.pool_id] = totals.get(request.pool_id, 0.0) + float(request.amount)
        now = utcnow().isoformat()
        created: list[dict[str, Any]] = []
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            for pool_id, amount in totals.items():
                pool = self.conn.execute("SELECT * FROM action_resource_pools WHERE pool_id=?", (pool_id,)).fetchone()
                if not pool:
                    raise HardeningError("CFHS_NOT_FOUND", "Resource pool not found", {"pool_id": pool_id})
                available = float(pool["hard_limit"]) - float(pool["used"]) - float(pool["reserved"])
                if amount > available:
                    raise HardeningError(
                        "CFHS_RESOURCE_EXHAUSTED",
                        "Resource reservation would exceed hard limit",
                        {"pool_id": pool_id, "requested": amount, "available": available},
                    )
            for pool_id, amount in totals.items():
                self.conn.execute("UPDATE action_resource_pools SET reserved=reserved+?,updated_at=? WHERE pool_id=?", (amount, now, pool_id))
            for request in requests:
                rid = "resv_" + secrets.token_hex(10)
                self.conn.execute(
                    "INSERT INTO action_resource_reservations(reservation_id,intent_id,pool_id,amount,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                    (rid, intent_id, request.pool_id, float(request.amount), "RESERVED", now, now),
                )
                created.append({"reservation_id": rid, "pool_id": request.pool_id, "amount": float(request.amount), "status": "RESERVED"})
            self.conn.commit()
            return created
        except Exception:
            self.conn.rollback()
            raise

    def _transition_many(self, reservation_ids: list[str], target: str) -> None:
        if not reservation_ids:
            return
        if target not in {"COMMITTED", "RELEASED"}:
            raise ValueError(target)
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            rows = []
            for rid in reservation_ids:
                row = self.conn.execute("SELECT * FROM action_resource_reservations WHERE reservation_id=?", (rid,)).fetchone()
                if not row or row["status"] != "RESERVED":
                    raise HardeningError("CFHS_CONFLICT", "Resource reservation is not transition-ready", {"reservation_id": rid})
                rows.append(row)
            totals: dict[str, float] = {}
            for row in rows:
                totals[row["pool_id"]] = totals.get(row["pool_id"], 0.0) + float(row["amount"])
            now = utcnow().isoformat()
            for pool_id, amount in totals.items():
                if target == "COMMITTED":
                    self.conn.execute("UPDATE action_resource_pools SET reserved=reserved-?,used=used+?,updated_at=? WHERE pool_id=?", (amount, amount, now, pool_id))
                else:
                    self.conn.execute("UPDATE action_resource_pools SET reserved=reserved-?,updated_at=? WHERE pool_id=?", (amount, now, pool_id))
            for rid in reservation_ids:
                self.conn.execute("UPDATE action_resource_reservations SET status=?,updated_at=? WHERE reservation_id=?", (target, now, rid))
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def commit_many(self, reservation_ids: list[str]) -> None:
        self._transition_many(reservation_ids, "COMMITTED")

    def release_many(self, reservation_ids: list[str]) -> None:
        self._transition_many(reservation_ids, "RELEASED")

    def pool_state(self, pool_id: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM action_resource_pools WHERE pool_id=?", (pool_id,)).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Resource pool not found")
        return dict(row)


class MultiPartyApprovalLedger:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS action_approval_requests(
                request_id TEXT PRIMARY KEY,
                intent_digest TEXT NOT NULL,
                requester_id TEXT NOT NULL,
                required_count INTEGER NOT NULL,
                eligible_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS action_approvals(
                request_id TEXT NOT NULL,
                approver_id TEXT NOT NULL,
                approved_at TEXT NOT NULL,
                PRIMARY KEY(request_id,approver_id)
            );
            """
        )
        self.conn.commit()

    def create(
        self,
        intent_digest: str,
        requester_id: str,
        required_count: int = 2,
        ttl_seconds: int = 900,
        eligible_approvers: list[str] | None = None,
    ) -> dict[str, Any]:
        eligible = sorted(set(eligible_approvers or []))
        if required_count < 1:
            raise HardeningError("CFHS_INVALID_REQUEST", "At least one approval must be required")
        if eligible and required_count > len([x for x in eligible if x != requester_id]):
            raise HardeningError("CFHS_INVALID_REQUEST", "Not enough eligible non-requester approvers")
        rid = "approval_" + secrets.token_hex(10)
        created = utcnow()
        expires = created + timedelta(seconds=max(60, min(int(ttl_seconds), 86400)))
        self.conn.execute(
            "INSERT INTO action_approval_requests(request_id,intent_digest,requester_id,required_count,eligible_json,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)",
            (rid, intent_digest, requester_id, required_count, json.dumps(eligible), "PENDING", created.isoformat(), expires.isoformat()),
        )
        self.conn.commit()
        return {"request_id": rid, "required_count": required_count, "eligible_approvers": eligible, "status": "PENDING", "expires_at": expires.isoformat()}

    def approve(self, request_id: str, approver_id: str) -> dict[str, Any]:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            request = self.conn.execute("SELECT * FROM action_approval_requests WHERE request_id=?", (request_id,)).fetchone()
            if not request or request["status"] not in {"PENDING", "APPROVED"}:
                raise HardeningError("CFHS_NOT_FOUND", "Approval request is not active")
            if datetime.fromisoformat(request["expires_at"]) <= utcnow():
                self.conn.execute("UPDATE action_approval_requests SET status='EXPIRED' WHERE request_id=?", (request_id,))
                self.conn.commit()
                raise HardeningError("CFHS_ELEVATION_REQUIRED", "Approval request expired")
            if approver_id == request["requester_id"]:
                raise HardeningError("CFHS_POLICY_DENIED", "Requester cannot approve its own multi-party request")
            eligible = json.loads(request["eligible_json"] or "[]")
            if eligible and approver_id not in eligible:
                raise HardeningError("CFHS_POLICY_DENIED", "Principal is not an eligible approver")
            self.conn.execute("INSERT OR IGNORE INTO action_approvals(request_id,approver_id,approved_at) VALUES(?,?,?)", (request_id, approver_id, utcnow().isoformat()))
            count = int(self.conn.execute("SELECT COUNT(*) AS n FROM action_approvals WHERE request_id=?", (request_id,)).fetchone()["n"])
            status = "APPROVED" if count >= int(request["required_count"]) else "PENDING"
            self.conn.execute("UPDATE action_approval_requests SET status=? WHERE request_id=?", (status, request_id))
            self.conn.commit()
            return {"request_id": request_id, "status": status, "approval_count": count, "required_count": int(request["required_count"])}
        except Exception:
            self.conn.rollback()
            raise

    def require_satisfied(self, request_id: str | None, intent_digest: str, minimum_count: int) -> None:
        if minimum_count <= 0:
            return
        if not request_id:
            raise HardeningError("CFHS_ELEVATION_REQUIRED", "Multi-party approval is required")
        request = self.conn.execute("SELECT * FROM action_approval_requests WHERE request_id=?", (request_id,)).fetchone()
        if not request or request["intent_digest"] != intent_digest:
            raise HardeningError("CFHS_ELEVATION_REQUIRED", "Approval does not match action intent")
        if int(request["required_count"]) < minimum_count:
            raise HardeningError("CFHS_ELEVATION_REQUIRED", "Approval request does not require enough independent approvers")
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
        if self.conn.execute("SELECT 1 FROM action_compensation_plans WHERE intent_id=?", (intent_id,)).fetchone():
            raise HardeningError("CFHS_CONFLICT", "Compensation plan already exists for this intent")
        self.conn.execute(
            "INSERT INTO action_compensation_plans(intent_id,compensation_action,compensation_resource,status,declared_at) VALUES(?,?,?,?,?)",
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
        self.conn.execute("UPDATE action_compensation_plans SET status='COMPENSATED',completed_at=?,result_digest=? WHERE intent_id=?", (utcnow().isoformat(), digest(result), intent_id))
        self.conn.commit()

    def fail(self, intent_id: str, result: Any) -> None:
        self.conn.execute("UPDATE action_compensation_plans SET status='FAILED',completed_at=?,result_digest=? WHERE intent_id=?", (utcnow().isoformat(), digest(result), intent_id))
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
        self.conn.execute("INSERT INTO action_commit_audit(audit_id,intent_id,intent_digest,status,prepared_at) VALUES(?,?,?,?,?)", (aid, intent.intent_id, intent.intent_digest(), "PREPARED", utcnow().isoformat()))
        self.conn.commit()
        return aid

    def commit(self, audit_id: str, result_digest: str) -> None:
        cur = self.conn.execute("UPDATE action_commit_audit SET status='COMMITTED',completed_at=?,result_digest=? WHERE audit_id=? AND status='PREPARED'", (utcnow().isoformat(), result_digest, audit_id))
        self.conn.commit()
        if cur.rowcount != 1:
            raise HardeningError("CFHS_CONFLICT", "Action audit record is not commit-ready")

    def fail(self, audit_id: str, failure_code: str, details: dict[str, Any] | None = None) -> None:
        self.conn.execute("UPDATE action_commit_audit SET status='FAILED',completed_at=?,failure_code=?,details_json=? WHERE audit_id=?", (utcnow().isoformat(), failure_code, json.dumps(details or {}, sort_keys=True), audit_id))
        self.conn.commit()


class ConsequentialActionCoordinator:
    """Reference safety coordinator around one external action attempt."""

    def __init__(self, replay: ReplayNonceRegistry, resources: ResourceReservationLedger, approvals: MultiPartyApprovalLedger, compensation: CompensationRegistry, audit: ActionAuditSink):
        self.replay = replay
        self.resources = resources
        self.approvals = approvals
        self.compensation = compensation
        self.audit = audit

    @staticmethod
    def _safe(call: Callable[[], None]) -> Exception | None:
        try:
            call()
            return None
        except Exception as exc:
            return exc

    def _try_compensate(self, intent: ActionIntent, arguments: dict[str, Any], cause: Exception, compensate: Callable | None) -> tuple[bool, Exception | None]:
        if intent.side_effect_class not in {"S1", "S2"} or compensate is None:
            return False, None
        try:
            result = compensate(arguments, cause)
            if intent.side_effect_class == "S2":
                self.compensation.complete(intent.intent_id, result)
            return True, None
        except Exception as exc:
            if intent.side_effect_class == "S2":
                self._safe(lambda: self.compensation.fail(intent.intent_id, {"error": str(exc)}))
            return False, exc

    def execute(
        self,
        intent: ActionIntent,
        arguments: dict[str, Any],
        authorize: Callable[[ActionIntent, dict[str, Any]], dict[str, Any]],
        invoke: Callable[[dict[str, Any]], Any],
        compensate: Callable[[dict[str, Any], Exception | None], Any] | None = None,
    ) -> dict[str, Any]:
        if digest(arguments) != intent.arguments_digest:
            raise HardeningError("CFHS_CONFLICT", "Action arguments differ from intent")
        decision = authorize(intent, arguments)
        if decision.get("decision") != "ALLOW":
            code = "CFHS_ELEVATION_REQUIRED" if decision.get("decision") == "ELEVATION_REQUIRED" else "CFHS_POLICY_DENIED"
            raise HardeningError(code, "Action authorization did not allow execution", decision)

        intent_digest = intent.intent_digest()
        self.approvals.require_satisfied(intent.approval_request_id, intent_digest, intent.required_approvals)
        if intent.side_effect_class == "S2":
            self.compensation.require_declared(intent.intent_id)
        if intent.side_effect_class in {"S1", "S2"} and compensate is None:
            raise HardeningError("CFHS_POLICY_DENIED", "Reversible/compensatable action requires a compensation callback")

        replay_state = self.replay.reserve(intent.replay_nonce, intent_digest)
        if replay_state["status"] == "REPLAY_COMMITTED":
            return {"status": "REPLAYED", "result_digest": replay_state.get("result_digest"), "intent_digest": intent_digest}

        reservations: list[str] = []
        audit_id: str | None = None
        invoke_attempted = False
        try:
            reservations = [r["reservation_id"] for r in self.resources.reserve_many(intent.intent_id, intent.resource_requests)]
            audit_id = self.audit.prepare(intent)  # no external effect before durable PREPARE
            invoke_attempted = True
            try:
                result = invoke(arguments)
            except Exception as invoke_exc:
                compensated, comp_error = self._try_compensate(intent, arguments, invoke_exc, compensate)
                self._safe(lambda: self.audit.fail(audit_id, "CFHS_DEVICE_FAILED", {"error": str(invoke_exc), "compensated": compensated, "compensation_error": str(comp_error) if comp_error else None}))
                if compensated or intent.side_effect_class == "S0":
                    self._safe(lambda: self.resources.release_many(reservations))
                    self._safe(lambda: self.replay.fail(intent.replay_nonce, "CFHS_DEVICE_FAILED", False))
                    raise HardeningError("CFHS_DEVICE_FAILED", "Device invocation failed; side effects were absent or compensated") from invoke_exc
                self._safe(lambda: self.resources.commit_many(reservations))
                self._safe(lambda: self.replay.fail(intent.replay_nonce, "CFHS_UNKNOWN_SIDE_EFFECT", True))
                if comp_error:
                    raise HardeningError("CFHS_COMPENSATION_FAILED", "Device failed and compensation failed", {"error": str(comp_error)}) from comp_error
                raise HardeningError("CFHS_UNKNOWN_SIDE_EFFECT", "Device invocation failed after execution began; side-effect state is unknown") from invoke_exc

            result_digest = digest(result)
            try:
                self.audit.commit(audit_id, result_digest)
            except Exception as audit_exc:
                compensated, comp_error = self._try_compensate(intent, arguments, audit_exc, compensate)
                if compensated:
                    self._safe(lambda: self.resources.release_many(reservations))
                    self._safe(lambda: self.replay.fail(intent.replay_nonce, "CFHS_AUDIT_COMMIT_FAILED", False))
                    raise HardeningError("CFHS_AUDIT_COMMIT_FAILED", "Action was compensated because audit commit failed") from audit_exc
                self._safe(lambda: self.resources.commit_many(reservations))
                self._safe(lambda: self.replay.fail(intent.replay_nonce, "CFHS_AUDIT_COMMIT_FAILED", True))
                if comp_error:
                    raise HardeningError("CFHS_COMPENSATION_FAILED", "Audit commit failed and compensation failed", {"error": str(comp_error)}) from comp_error
                raise HardeningError("CFHS_UNKNOWN_SIDE_EFFECT", "Action succeeded but audit commit failed; reconciliation required") from audit_exc

            try:
                self.resources.commit_many(reservations)
            except Exception as resource_exc:
                self._safe(lambda: self.replay.fail(intent.replay_nonce, "CFHS_RESOURCE_COMMIT_FAILED", True))
                raise HardeningError("CFHS_RESOURCE_COMMIT_FAILED", "Action and audit committed but resource accounting failed") from resource_exc

            try:
                self.replay.commit(intent.replay_nonce, result_digest)
            except Exception as replay_exc:
                raise HardeningError("CFHS_REPLAY_COMMIT_FAILED", "Action, audit, and resources committed but replay state failed to commit") from replay_exc

            return {"status": "COMMITTED", "intent_id": intent.intent_id, "intent_digest": intent_digest, "audit_id": audit_id, "result": result, "result_digest": result_digest}

        except HardeningError:
            if not invoke_attempted:
                if audit_id:
                    self._safe(lambda: self.audit.fail(audit_id, "CFHS_PREEXECUTION_FAILED"))
                if reservations:
                    self._safe(lambda: self.resources.release_many(reservations))
                state = self.replay.get(intent.replay_nonce)
                if state and state["status"] == "RESERVED":
                    self._safe(lambda: self.replay.fail(intent.replay_nonce, "CFHS_PREEXECUTION_FAILED", False))
            raise
