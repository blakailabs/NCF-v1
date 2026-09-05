from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .hardening import HardeningError, SessionManager
from .trust import PolicyPackageSigner, canonical_json, sha256_hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class DurableBootstrapCeremony:
    """Restart-safe, one-time bootstrap ceremony.

    Bootstrap state and the initial owner session are committed in one SQLite
    transaction. A completed ceremony cannot be reopened by a restart or by
    presenting the original bootstrap secret again.
    """

    SINGLETON = "company-kernel-bootstrap"

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS bootstrap_state(
                id TEXT PRIMARY KEY,
                secret_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                initialized_at TEXT NOT NULL,
                completed_at TEXT,
                completed_by TEXT,
                session_id TEXT
            )
            """
        )
        self.conn.commit()

    def initialize(self, bootstrap_secret: str) -> dict[str, Any]:
        if not bootstrap_secret or len(bootstrap_secret) < 16:
            raise HardeningError("CFHS_INVALID_REQUEST", "Bootstrap secret must be at least 16 characters")
        digest = _token_hash(bootstrap_secret)
        row = self.conn.execute("SELECT * FROM bootstrap_state WHERE id=?", (self.SINGLETON,)).fetchone()
        if row:
            if not hmac.compare_digest(row["secret_hash"], digest):
                raise HardeningError("CFHS_POLICY_DENIED", "Bootstrap secret differs from initialized ceremony")
            return self.status()
        self.conn.execute(
            "INSERT INTO bootstrap_state(id,secret_hash,status,initialized_at) VALUES(?,?,?,?)",
            (self.SINGLETON, digest, "PENDING", utcnow().isoformat()),
        )
        self.conn.commit()
        return self.status()

    def status(self) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM bootstrap_state WHERE id=?", (self.SINGLETON,)).fetchone()
        if not row:
            return {"initialized": False, "status": "UNINITIALIZED", "completed": False}
        return {
            "initialized": True,
            "status": row["status"],
            "completed": row["status"] == "COMPLETED",
            "initialized_at": row["initialized_at"],
            "completed_at": row["completed_at"],
            "completed_by": row["completed_by"],
            "session_id": row["session_id"],
        }

    def complete(self, sessions: SessionManager, bootstrap_secret: str, principal_id: str, ttl_seconds: int = 900) -> dict[str, Any]:
        if sessions.conn is not self.conn:
            raise HardeningError("CFHS_CONFLICT", "Bootstrap and session state must share the same transaction database")
        ttl = max(60, min(int(ttl_seconds), 3600))
        token = "cks_" + secrets.token_urlsafe(32)
        session_id = "sess_" + secrets.token_hex(10)
        created = utcnow()
        expires = created + timedelta(seconds=ttl)
        digest = _token_hash(bootstrap_secret)

        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute("SELECT * FROM bootstrap_state WHERE id=?", (self.SINGLETON,)).fetchone()
            if not row:
                raise HardeningError("CFHS_CONFLICT", "Bootstrap ceremony was not initialized")
            if row["status"] == "COMPLETED":
                raise HardeningError("CFHS_POLICY_DENIED", "Bootstrap ceremony is permanently completed")
            if not hmac.compare_digest(row["secret_hash"], digest):
                raise HardeningError("CFHS_UNAUTHENTICATED", "Bootstrap secret invalid")
            self.conn.execute(
                "INSERT INTO kernel_sessions(id,principal_id,token_hash,created_at,expires_at) VALUES(?,?,?,?,?)",
                (session_id, principal_id, _token_hash(token), created.isoformat(), expires.isoformat()),
            )
            self.conn.execute(
                "UPDATE bootstrap_state SET status='COMPLETED',completed_at=?,completed_by=?,session_id=? WHERE id=? AND status='PENDING'",
                (created.isoformat(), principal_id, session_id, self.SINGLETON),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

        return {
            "session_id": session_id,
            "principal_id": principal_id,
            "bearer_token": token,
            "expires_at": expires.isoformat(),
            "bootstrap_status": "COMPLETED",
        }


class RollbackProtectedPolicyStore:
    """Persistent signed-policy registry with monotonic semantic versions."""

    def __init__(self, conn: sqlite3.Connection, trusted_keys: dict[str, bytes]):
        self.conn = conn
        self.trusted_keys = dict(trusted_keys)
        self._active: dict[str, dict[str, Any]] = {}
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS policy_version_ledger(
                package_id TEXT PRIMARY KEY,
                version TEXT NOT NULL,
                package_digest TEXT NOT NULL,
                installed_at TEXT NOT NULL,
                key_id TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    @staticmethod
    def _semver(version: str) -> tuple[int, int, int]:
        parts = version.split(".")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            raise HardeningError("CFHS_INVALID_POLICY", "Policy version must be strict numeric MAJOR.MINOR.PATCH")
        return tuple(int(p) for p in parts)  # type: ignore[return-value]

    def _verify(self, envelope: dict[str, Any]) -> tuple[dict[str, Any], str, str]:
        package = envelope.get("package")
        sig = envelope.get("signature") or {}
        if not isinstance(package, dict):
            raise HardeningError("CFHS_INVALID_POLICY", "Missing signed policy package")
        if sig.get("algorithm") != PolicyPackageSigner.ALG:
            raise HardeningError("CFHS_INVALID_POLICY", "Unsupported reference signature algorithm")
        key_id = str(sig.get("key_id", ""))
        key = self.trusted_keys.get(key_id)
        if not key:
            raise HardeningError("CFHS_POLICY_DENIED", "Untrusted policy signing key")
        expected = hmac.new(key, canonical_json(package), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(sig.get("value", "")), expected):
            raise HardeningError("CFHS_POLICY_DENIED", "Policy signature verification failed")
        pid = str(package.get("id", "")).strip()
        version = str(package.get("version", "")).strip()
        if not pid or not isinstance(package.get("policies"), list):
            raise HardeningError("CFHS_INVALID_POLICY", "Package requires id and policies")
        self._semver(version)
        for policy in package["policies"]:
            if policy.get("effect") not in {"DENY", "ELEVATION_REQUIRED"}:
                raise HardeningError("CFHS_INVALID_POLICY", "Policy packages remain restrictive-only")
        return package, key_id, sha256_hex(package)

    def install_atomic(self, envelopes: list[dict[str, Any]]) -> dict[str, Any]:
        candidates: list[tuple[dict[str, Any], str, str]] = [self._verify(e) for e in envelopes]
        seen: set[str] = set()
        for package, _key_id, digest in candidates:
            pid, version = package["id"], package["version"]
            if pid in seen:
                raise HardeningError("CFHS_CONFLICT", "Duplicate package id in atomic activation set")
            seen.add(pid)
            row = self.conn.execute("SELECT version,package_digest FROM policy_version_ledger WHERE package_id=?", (pid,)).fetchone()
            if row:
                old_v, new_v = self._semver(row["version"]), self._semver(version)
                if new_v < old_v:
                    raise HardeningError("CFHS_POLICY_DENIED", "Policy rollback rejected", {"package_id": pid, "installed": row["version"], "requested": version})
                if new_v == old_v and row["package_digest"] != digest:
                    raise HardeningError("CFHS_CONFLICT", "Same policy version cannot be replaced with different content")

        installed_at = utcnow().isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            for package, key_id, digest in candidates:
                self.conn.execute(
                    "INSERT INTO policy_version_ledger(package_id,version,package_digest,installed_at,key_id) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(package_id) DO UPDATE SET version=excluded.version,package_digest=excluded.package_digest,installed_at=excluded.installed_at,key_id=excluded.key_id",
                    (package["id"], package["version"], digest, installed_at, key_id),
                )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

        for package, _key_id, _digest in candidates:
            self._active[package["id"]] = package
        return {"installed": sorted(seen), "package_count": len(seen), "installed_at": installed_at}

    def active_policies(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for package in self._active.values():
            for policy in package["policies"]:
                p = dict(policy)
                p["package_id"] = package["id"]
                p["package_version"] = package["version"]
                out.append(p)
        return out


@dataclass
class LeasedQueueMessage:
    id: str
    topic: str
    payload: dict[str, Any]
    attempts: int
    claim_expires_at: str


class LeasedDeadLetterEventBus:
    """Durable queue with expiring claims and dead-letter transition."""

    def __init__(self, conn: sqlite3.Connection, max_attempts: int = 5, claim_ttl_seconds: int = 30):
        self.conn = conn
        self.max_attempts = max(1, int(max_attempts))
        self.claim_ttl_seconds = max(1, int(claim_ttl_seconds))
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS trust_events_v04(
                id TEXT PRIMARY KEY,
                topic TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                available_at TEXT NOT NULL,
                claimed_by TEXT,
                claim_expires_at TEXT,
                acked_at TEXT,
                attempts INTEGER NOT NULL DEFAULT 0,
                dead_lettered_at TEXT,
                dead_letter_reason TEXT
            )
            """
        )
        self.conn.commit()

    def publish(self, topic: str, payload: dict[str, Any], delay_seconds: int = 0) -> dict[str, Any]:
        eid = "evt_" + secrets.token_hex(10)
        created = utcnow()
        available = created + timedelta(seconds=max(0, int(delay_seconds)))
        self.conn.execute(
            "INSERT INTO trust_events_v04(id,topic,payload_json,created_at,available_at) VALUES(?,?,?,?,?)",
            (eid, topic, json.dumps(payload, sort_keys=True), created.isoformat(), available.isoformat()),
        )
        self.conn.commit()
        return {"event_id": eid, "topic": topic, "available_at": available.isoformat()}

    def _reap_expired_claims(self) -> None:
        now_iso = utcnow().isoformat()
        rows = self.conn.execute(
            "SELECT id,attempts FROM trust_events_v04 WHERE acked_at IS NULL AND dead_lettered_at IS NULL AND claimed_by IS NOT NULL AND claim_expires_at<=?",
            (now_iso,),
        ).fetchall()
        for row in rows:
            if int(row["attempts"]) >= self.max_attempts:
                self.conn.execute(
                    "UPDATE trust_events_v04 SET claimed_by=NULL,claim_expires_at=NULL,dead_lettered_at=?,dead_letter_reason='max_attempts_after_claim_expiry' WHERE id=?",
                    (now_iso, row["id"]),
                )
            else:
                self.conn.execute(
                    "UPDATE trust_events_v04 SET claimed_by=NULL,claim_expires_at=NULL WHERE id=?",
                    (row["id"],),
                )
        self.conn.commit()

    def poll(self, consumer_id: str, topics: list[str]) -> LeasedQueueMessage | None:
        self._reap_expired_claims()
        if not topics:
            return None
        placeholders = ",".join("?" for _ in topics)
        now = utcnow()
        row = self.conn.execute(
            f"SELECT * FROM trust_events_v04 WHERE acked_at IS NULL AND dead_lettered_at IS NULL AND claimed_by IS NULL AND available_at<=? AND topic IN ({placeholders}) ORDER BY created_at,id LIMIT 1",
            (now.isoformat(), *topics),
        ).fetchone()
        if not row:
            return None
        next_attempt = int(row["attempts"]) + 1
        if next_attempt > self.max_attempts:
            self.conn.execute(
                "UPDATE trust_events_v04 SET dead_lettered_at=?,dead_letter_reason='max_attempts_before_claim' WHERE id=?",
                (now.isoformat(), row["id"]),
            )
            self.conn.commit()
            return None
        expires = now + timedelta(seconds=self.claim_ttl_seconds)
        cur = self.conn.execute(
            "UPDATE trust_events_v04 SET claimed_by=?,claim_expires_at=?,attempts=? WHERE id=? AND claimed_by IS NULL AND acked_at IS NULL AND dead_lettered_at IS NULL",
            (consumer_id, expires.isoformat(), next_attempt, row["id"]),
        )
        self.conn.commit()
        if cur.rowcount != 1:
            return None
        return LeasedQueueMessage(row["id"], row["topic"], json.loads(row["payload_json"]), next_attempt, expires.isoformat())

    def ack(self, consumer_id: str, event_id: str) -> None:
        now_iso = utcnow().isoformat()
        cur = self.conn.execute(
            "UPDATE trust_events_v04 SET acked_at=? WHERE id=? AND claimed_by=? AND acked_at IS NULL AND dead_lettered_at IS NULL AND claim_expires_at>?",
            (now_iso, event_id, consumer_id, now_iso),
        )
        self.conn.commit()
        if cur.rowcount != 1:
            raise HardeningError("CFHS_CONFLICT", "Queue acknowledgement requires a live claim owned by this consumer")

    def release(self, consumer_id: str, event_id: str, delay_seconds: int = 0, reason: str = "retry") -> None:
        now = utcnow()
        row = self.conn.execute("SELECT attempts FROM trust_events_v04 WHERE id=? AND claimed_by=? AND acked_at IS NULL", (event_id, consumer_id)).fetchone()
        if not row:
            raise HardeningError("CFHS_CONFLICT", "Queue message is not owned by this consumer")
        if int(row["attempts"]) >= self.max_attempts:
            self.conn.execute(
                "UPDATE trust_events_v04 SET claimed_by=NULL,claim_expires_at=NULL,dead_lettered_at=?,dead_letter_reason=? WHERE id=?",
                (now.isoformat(), reason or "max_attempts", event_id),
            )
        else:
            available = now + timedelta(seconds=max(0, int(delay_seconds)))
            self.conn.execute(
                "UPDATE trust_events_v04 SET claimed_by=NULL,claim_expires_at=NULL,available_at=? WHERE id=?",
                (available.isoformat(), event_id),
            )
        self.conn.commit()

    def dead_letters(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT id,topic,payload_json,attempts,dead_lettered_at,dead_letter_reason FROM trust_events_v04 WHERE dead_lettered_at IS NOT NULL ORDER BY dead_lettered_at,id"
        ).fetchall()
        return [
            {
                "id": r["id"],
                "topic": r["topic"],
                "payload": json.loads(r["payload_json"]),
                "attempts": int(r["attempts"]),
                "dead_lettered_at": r["dead_lettered_at"],
                "reason": r["dead_letter_reason"],
            }
            for r in rows
        ]
