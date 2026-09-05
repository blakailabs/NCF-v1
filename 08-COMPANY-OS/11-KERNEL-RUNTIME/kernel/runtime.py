#!/usr/bin/env python3
from __future__ import annotations
import json, sqlite3, uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

VERSION = "0.1"

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"

class KernelError(Exception):
    def __init__(self, code: str, message: str, retryable: bool = False, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.details = details or {}

    def as_dict(self, request_id: str, trace_id: str) -> dict[str, Any]:
        return {"error": {"code": self.code, "message": self.message, "request_id": request_id,
                          "trace_id": trace_id, "retryable": self.retryable, "details": self.details}}

@dataclass
class RequestContext:
    actor_id: str
    process_id: str
    trace_id: str
    correlation_id: str | None = None
    request_id: str = ""

    def __post_init__(self):
        if not self.request_id:
            self.request_id = uid("req")
        if not self.correlation_id:
            self.correlation_id = self.trace_id

class KernelStore:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init()

    def _init(self):
        c = self.conn.cursor()
        c.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS principals(
            id TEXT PRIMARY KEY, type TEXT NOT NULL, active INTEGER NOT NULL, capabilities_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS processes(
            id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL, state TEXT NOT NULL,
            parent_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, metadata_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS elevation_requests(
            id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, action TEXT NOT NULL, resource TEXT NOT NULL,
            scope_json TEXT NOT NULL, reason TEXT, status TEXT NOT NULL, requested_at TEXT NOT NULL,
            approved_by TEXT, approved_at TEXT, expires_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit(
            seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, time TEXT NOT NULL,
            actor_id TEXT NOT NULL, process_id TEXT NOT NULL, trace_id TEXT NOT NULL,
            correlation_id TEXT, kind TEXT NOT NULL, action TEXT, resource TEXT,
            decision TEXT, result_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS checkpoints(
            id TEXT PRIMARY KEY, process_id TEXT NOT NULL, created_at TEXT NOT NULL, state_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS idempotency(
            key TEXT PRIMARY KEY, device_id TEXT NOT NULL, operation TEXT NOT NULL, result_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS resource_usage(
            day TEXT NOT NULL, principal_id TEXT NOT NULL, resource_type TEXT NOT NULL, amount REAL NOT NULL,
            PRIMARY KEY(day, principal_id, resource_type)
        );
        """)
        self.conn.commit()

    def execute(self, sql: str, args: tuple = ()):
        cur = self.conn.execute(sql, args)
        self.conn.commit()
        return cur

    def one(self, sql: str, args: tuple = ()):
        return self.conn.execute(sql, args).fetchone()

    def all(self, sql: str, args: tuple = ()):
        return self.conn.execute(sql, args).fetchall()

class CompanyKernel:
    def __init__(self, state_dir: str | Path, config: dict[str, Any]):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.config = config
        self.store = KernelStore(self.state_dir / "kernel.db")
        self._bootstrap()

    @classmethod
    def from_file(cls, state_dir: str | Path, config_path: str | Path) -> "CompanyKernel":
        return cls(state_dir, json.loads(Path(config_path).read_text(encoding="utf-8")))

    def _bootstrap(self):
        for p in self.config.get("principals", []):
            self.store.execute(
                "INSERT OR REPLACE INTO principals(id,type,active,capabilities_json) VALUES(?,?,?,?)",
                (p["id"], p.get("type", "human"), 1 if p.get("active", True) else 0,
                 json.dumps(p.get("capabilities", []), sort_keys=True)),
            )

    def audit(self, ctx: RequestContext, kind: str, action: str | None, resource: str | None,
              decision: str | None, result: dict[str, Any]) -> str:
        aid = uid("audit")
        self.store.execute(
            "INSERT INTO audit(id,time,actor_id,process_id,trace_id,correlation_id,kind,action,resource,decision,result_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (aid, now_iso(), ctx.actor_id, ctx.process_id, ctx.trace_id, ctx.correlation_id,
             kind, action, resource, decision, json.dumps(result, sort_keys=True)),
        )
        return aid

    def _principal(self, principal_id: str) -> sqlite3.Row:
        row = self.store.one("SELECT * FROM principals WHERE id=?", (principal_id,))
        if not row or not row["active"]:
            raise KernelError("CFHS_UNAUTHENTICATED", "Unknown or inactive principal")
        return row

    def _match_capability(self, principal: sqlite3.Row, action: str, resource: str) -> dict[str, Any] | None:
        caps = json.loads(principal["capabilities_json"])
        for cap in caps:
            a = cap.get("action")
            r = cap.get("resource", "*")
            action_ok = a == action or a == "*"
            resource_ok = r == "*" or resource == r or resource.startswith(r.rstrip("*") if r.endswith("*") else r + "/")
            if action_ok and resource_ok:
                return cap
        return None

    def _active_elevation(self, principal_id: str, action: str, resource: str, context: dict[str, Any]) -> sqlite3.Row | None:
        rows = self.store.all(
            "SELECT * FROM elevation_requests WHERE principal_id=? AND action=? AND resource=? AND status='APPROVED'",
            (principal_id, action, resource),
        )
        now = datetime.now(timezone.utc)
        for row in rows:
            exp = datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None
            if exp and exp < now:
                continue
            scope = json.loads(row["scope_json"])
            if "max_amount" in scope and float(context.get("amount", 0)) > float(scope["max_amount"]):
                continue
            return row
        return None

    def authorize(self, ctx: RequestContext, action: str, resource: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        context = context or {}
        principal = self._principal(ctx.actor_id)
        cap = self._match_capability(principal, action, resource)
        decision_id = uid("dec")
        if cap is None:
            result = {"decision":"DENY","decision_id":decision_id,"principal_id":ctx.actor_id,"action":action,
                      "resource":resource,"matched_policies":["default-deny"],"constraints":{},"expires_at":None}
            self.audit(ctx, "authorization", action, resource, "DENY", result)
            return result

        constraints = dict(cap.get("conditions", {}))
        if "max_amount" in constraints and float(context.get("amount", 0)) > float(constraints["max_amount"]):
            elev = self._active_elevation(ctx.actor_id, action, resource, context)
            if elev is None:
                result = {"decision":"ELEVATION_REQUIRED","decision_id":decision_id,"principal_id":ctx.actor_id,
                          "action":action,"resource":resource,"matched_policies":[cap.get("id", "capability")],
                          "constraints":constraints,"expires_at":None}
                self.audit(ctx, "authorization", action, resource, "ELEVATION_REQUIRED", result)
                return result

        resource_type = constraints.get("resource_type")
        hard_limit = constraints.get("hard_limit")
        if resource_type and hard_limit is not None:
            day = datetime.now(timezone.utc).date().isoformat()
            row = self.store.one("SELECT amount FROM resource_usage WHERE day=? AND principal_id=? AND resource_type=?",
                                 (day, ctx.actor_id, resource_type))
            used = float(row["amount"]) if row else 0.0
            requested = float(context.get("resource_amount", 1))
            if used + requested > float(hard_limit):
                result = {"decision":"DENY","decision_id":decision_id,"principal_id":ctx.actor_id,"action":action,
                          "resource":resource,"matched_policies":["resource-hard-limit"],
                          "constraints":{"hard_limit":hard_limit,"used":used},"expires_at":None}
                self.audit(ctx, "authorization", action, resource, "DENY", result)
                return result

        result = {"decision":"ALLOW","decision_id":decision_id,"principal_id":ctx.actor_id,"action":action,
                  "resource":resource,"matched_policies":[cap.get("id", "capability")],
                  "constraints":constraints,"expires_at":None}
        self.audit(ctx, "authorization", action, resource, "ALLOW", result)
        return result

    def request_elevation(self, ctx: RequestContext, action: str, resource: str, scope: dict[str, Any], reason: str) -> dict[str, Any]:
        self._principal(ctx.actor_id)
        eid = uid("elev")
        self.store.execute(
            "INSERT INTO elevation_requests(id,principal_id,action,resource,scope_json,reason,status,requested_at) VALUES(?,?,?,?,?,?,?,?)",
            (eid, ctx.actor_id, action, resource, json.dumps(scope, sort_keys=True), reason, "PENDING", now_iso()),
        )
        result = {"elevation_id":eid,"status":"PENDING","principal_id":ctx.actor_id,"action":action,"resource":resource,"scope":scope}
        self.audit(ctx, "elevation.requested", action, resource, "PENDING", result)
        return result

    def approve_elevation(self, approver_ctx: RequestContext, elevation_id: str, ttl_seconds: int = 600) -> dict[str, Any]:
        principal = self._principal(approver_ctx.actor_id)
        caps = json.loads(principal["capabilities_json"])
        if not any(c.get("action") in ("kernel.elevation.approve", "*") for c in caps):
            raise KernelError("CFHS_POLICY_DENIED", "Principal cannot approve elevations")
        row = self.store.one("SELECT * FROM elevation_requests WHERE id=?", (elevation_id,))
        if not row or row["status"] != "PENDING":
            raise KernelError("CFHS_NOT_FOUND", "Pending elevation request not found")
        exp = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
        self.store.execute("UPDATE elevation_requests SET status='APPROVED',approved_by=?,approved_at=?,expires_at=? WHERE id=?",
                           (approver_ctx.actor_id, now_iso(), exp, elevation_id))
        result = {"elevation_id":elevation_id,"status":"APPROVED","approved_by":approver_ctx.actor_id,"expires_at":exp}
        self.audit(approver_ctx, "elevation.approved", row["action"], row["resource"], "ALLOW", result)
        return result

    def spawn_process(self, ctx: RequestContext, name: str, owner: str, metadata: dict[str, Any] | None = None,
                      parent_id: str | None = None) -> dict[str, Any]:
        self._principal(owner)
        pid = uid("proc")
        ts = now_iso()
        self.store.execute("INSERT INTO processes(id,name,owner,state,parent_id,created_at,updated_at,metadata_json) VALUES(?,?,?,?,?,?,?,?)",
                           (pid, name, owner, "READY", parent_id, ts, ts, json.dumps(metadata or {}, sort_keys=True)))
        result = {"process_id":pid,"name":name,"owner":owner,"state":"READY","parent_process_id":parent_id,"started_at":None}
        self.audit(ctx, "process.spawned", "process.spawn", f"/proc/{pid}", "ALLOW", result)
        return result

    def set_process_state(self, ctx: RequestContext, process_id: str, state: str):
        allowed = {"READY","RUNNING","WAITING","BLOCKED","PAUSED","COMPLETED","FAILED","CANCELLED","TERMINATED","TIMED_OUT"}
        if state not in allowed:
            raise KernelError("CFHS_PROCESS_INVALID_STATE", f"Invalid process state {state}")
        row = self.store.one("SELECT * FROM processes WHERE id=?", (process_id,))
        if not row:
            raise KernelError("CFHS_NOT_FOUND", "Process not found")
        self.store.execute("UPDATE processes SET state=?,updated_at=? WHERE id=?", (state, now_iso(), process_id))
        self.audit(ctx, "process.state", "process.signal", f"/proc/{process_id}", "ALLOW", {"state":state})

    def checkpoint(self, ctx: RequestContext, process_id: str, state: dict[str, Any]) -> dict[str, Any]:
        row = self.store.one("SELECT * FROM processes WHERE id=?", (process_id,))
        if not row:
            raise KernelError("CFHS_NOT_FOUND", "Process not found")
        cid = uid("ckpt")
        self.store.execute("INSERT INTO checkpoints(id,process_id,created_at,state_json) VALUES(?,?,?,?)",
                           (cid, process_id, now_iso(), json.dumps(state, sort_keys=True)))
        result = {"checkpoint_id":cid,"process_id":process_id,"state":state}
        self.audit(ctx, "process.checkpoint", "process.checkpoint", f"/proc/{process_id}", "ALLOW", result)
        return result

    def latest_checkpoint(self, process_id: str) -> dict[str, Any] | None:
        row = self.store.one("SELECT * FROM checkpoints WHERE process_id=? ORDER BY created_at DESC LIMIT 1", (process_id,))
        if not row:
            return None
        return {"checkpoint_id":row["id"],"process_id":row["process_id"],"created_at":row["created_at"],"state":json.loads(row["state_json"])}

    def invoke_device(self, ctx: RequestContext, device_id: str, operation: str, arguments: dict[str, Any], idempotency_key: str | None = None) -> dict[str, Any]:
        device = next((d for d in self.config.get("devices", []) if d["id"] == device_id), None)
        if not device:
            raise KernelError("CFHS_NOT_FOUND", "Device not found")
        op = next((o for o in device.get("operations", []) if o["name"] == operation), None)
        if not op:
            raise KernelError("CFHS_NOT_FOUND", "Device operation not found")
        if op.get("idempotency_required") and not idempotency_key:
            raise KernelError("CFHS_INVALID_REQUEST", "Idempotency-Key required")
        if idempotency_key:
            row = self.store.one("SELECT result_json FROM idempotency WHERE key=?", (idempotency_key,))
            if row:
                return json.loads(row["result_json"])

        resource = device.get("resource", f"/dev/{device_id}")
        auth = self.authorize(ctx, operation, resource, arguments)
        if auth["decision"] == "DENY":
            raise KernelError("CFHS_POLICY_DENIED", "Requested device action is not authorized", details=auth)
        if auth["decision"] == "ELEVATION_REQUIRED":
            raise KernelError("CFHS_ELEVATION_REQUIRED", "Requested device action requires elevated authority", details=auth)

        invocation_id = uid("invoke")
        result = {"invocation_id":invocation_id,"device_id":device_id,"operation":operation,
                  "side_effect_class":op.get("side_effect_class", "S0"),"status":"SUCCEEDED",
                  "result":{"mock":True,"accepted_arguments":arguments},"emitted_event_ids":[]}
        if op.get("resource_type"):
            day = datetime.now(timezone.utc).date().isoformat()
            amount = float(arguments.get("resource_amount", 1))
            self.store.execute(
                "INSERT INTO resource_usage(day,principal_id,resource_type,amount) VALUES(?,?,?,?) "
                "ON CONFLICT(day,principal_id,resource_type) DO UPDATE SET amount=amount+excluded.amount",
                (day, ctx.actor_id, op["resource_type"], amount),
            )
        audit_id = self.audit(ctx, "device.invoke", operation, resource, "ALLOW", result)
        result["audit_record_id"] = audit_id
        if idempotency_key:
            self.store.execute("INSERT INTO idempotency(key,device_id,operation,result_json,created_at) VALUES(?,?,?,?,?)",
                               (idempotency_key, device_id, operation, json.dumps(result, sort_keys=True), now_iso()))
        return result

    def audit_records(self) -> list[dict[str, Any]]:
        out = []
        for r in self.store.all("SELECT * FROM audit ORDER BY seq"):
            d = dict(r)
            d["result"] = json.loads(d.pop("result_json"))
            out.append(d)
        return out

    def health(self) -> dict[str, Any]:
        return {"status":"READY","kernel_version":VERSION,"cfhs_version":self.config.get("cfhs_version","0.1"),
                "database":str(self.state_dir / "kernel.db")}
