from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

from .hardening import HardeningError, SessionManager


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(value: Any) -> str:
    raw = value if isinstance(value, (bytes, bytearray)) else canonical_json(value)
    return hashlib.sha256(raw).hexdigest()


class PolicyPackageSigner:
    """Reference package signer.

    HMAC-SHA256 is deliberately used only as a dependency-free reference mechanism.
    Production policy distribution should use an asymmetric signing service/HSM.
    """

    ALG = "HMAC-SHA256-REFERENCE"

    @staticmethod
    def sign(package: dict[str, Any], key_id: str, key: bytes) -> dict[str, Any]:
        signature = hmac.new(key, canonical_json(package), hashlib.sha256).hexdigest()
        return {
            "package": package,
            "signature": {"algorithm": PolicyPackageSigner.ALG, "key_id": key_id, "value": signature},
        }


class SignedPolicyStore:
    def __init__(self, trusted_keys: dict[str, bytes]):
        self.trusted_keys = dict(trusted_keys)
        self._packages: dict[str, dict[str, Any]] = {}
        self._digests: dict[str, str] = {}

    def verify(self, envelope: dict[str, Any]) -> dict[str, Any]:
        package = envelope.get("package")
        signature = envelope.get("signature") or {}
        if not isinstance(package, dict):
            raise HardeningError("CFHS_INVALID_POLICY", "Signed policy envelope is missing package")
        if signature.get("algorithm") != PolicyPackageSigner.ALG:
            raise HardeningError("CFHS_INVALID_POLICY", "Unsupported reference policy signature algorithm")
        key_id = signature.get("key_id")
        key = self.trusted_keys.get(str(key_id))
        if not key:
            raise HardeningError("CFHS_POLICY_DENIED", "Policy signing key is not trusted")
        claimed = str(signature.get("value", ""))
        expected = hmac.new(key, canonical_json(package), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(claimed, expected):
            raise HardeningError("CFHS_POLICY_DENIED", "Policy package signature verification failed")
        package_id = str(package.get("id", "")).strip()
        version = str(package.get("version", "")).strip()
        policies = package.get("policies")
        if not package_id or not version or not isinstance(policies, list):
            raise HardeningError("CFHS_INVALID_POLICY", "Policy package requires id, version, and policies")
        for policy in policies:
            if policy.get("effect") not in {"DENY", "ELEVATION_REQUIRED"}:
                raise HardeningError("CFHS_INVALID_POLICY", "Trust-layer policies are restrictive-only")
        return package

    def install_atomic(self, envelopes: list[dict[str, Any]]) -> dict[str, Any]:
        verified: dict[str, dict[str, Any]] = {}
        digests: dict[str, str] = {}
        for envelope in envelopes:
            package = self.verify(envelope)
            pid = package["id"]
            key = f"{pid}@{package['version']}"
            digest = sha256_hex(package)
            old = self._digests.get(key)
            if old and old != digest:
                raise HardeningError("CFHS_CONFLICT", "Same policy package version has different content")
            verified[pid] = package
            digests[key] = digest
        # Atomic in-memory replacement happens only after every package verifies.
        self._packages = verified
        self._digests.update(digests)
        return {"installed": sorted(verified), "package_count": len(verified), "digest_count": len(digests)}

    def policies(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for package in self._packages.values():
            for policy in package["policies"]:
                item = dict(policy)
                item["package_id"] = package["id"]
                item["package_version"] = package["version"]
                out.append(item)
        return out


class AuditAnchorProvider(Protocol):
    def anchor(self, head_hash: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]: ...
    def verify(self) -> dict[str, Any]: ...


class FileAuditAnchorProvider:
    """Reference anchor provider.

    The provider is intentionally separate from the kernel database. A production
    deployment should replace this with a remote append-only/transparency service.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def _records(self) -> list[dict[str, Any]]:
        return [json.loads(x) for x in self.path.read_text().splitlines() if x.strip()]

    def anchor(self, head_hash: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        records = self._records()
        previous_anchor_hash = records[-1]["anchor_hash"] if records else "GENESIS"
        record = {
            "anchor_id": "anchor_" + secrets.token_hex(10),
            "time": utcnow().isoformat(),
            "audit_head_hash": head_hash,
            "previous_anchor_hash": previous_anchor_hash,
            "metadata": metadata or {},
        }
        record["anchor_hash"] = sha256_hex(record)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def verify(self) -> dict[str, Any]:
        previous = "GENESIS"
        count = 0
        for line_no, record in enumerate(self._records(), 1):
            claimed = record.get("anchor_hash")
            base = dict(record)
            base.pop("anchor_hash", None)
            if base.get("previous_anchor_hash") != previous:
                return {"valid": False, "line": line_no, "reason": "previous_anchor_hash_mismatch", "count": count}
            expected = sha256_hex(base)
            if not hmac.compare_digest(str(claimed), expected):
                return {"valid": False, "line": line_no, "reason": "anchor_hash_mismatch", "count": count}
            previous = str(claimed)
            count += 1
        return {"valid": True, "count": count, "head_anchor_hash": previous}


class VaultProvider(Protocol):
    def resolve(self, provider_ref: str) -> bytes: ...


class MemoryVaultProvider:
    """Test/reference provider only; never use for production secrets."""

    def __init__(self, values: dict[str, bytes]):
        self.values = dict(values)

    def resolve(self, provider_ref: str) -> bytes:
        if provider_ref not in self.values:
            raise HardeningError("CFHS_SECRET_DENIED", "Vault reference not found")
        return self.values[provider_ref]


class VaultSecretBroker:
    def __init__(self, provider: VaultProvider):
        self.provider = provider
        self._leases: dict[str, dict[str, Any]] = {}

    def lease(self, provider_ref: str, audience: str, ttl_seconds: int = 60) -> dict[str, Any]:
        ttl = max(5, min(int(ttl_seconds), 300))
        lease_id = "lease_" + secrets.token_hex(10)
        expires = utcnow() + timedelta(seconds=ttl)
        # Validate existence without exposing the value to the lease caller.
        self.provider.resolve(provider_ref)
        self._leases[lease_id] = {"provider_ref": provider_ref, "audience": audience, "expires": expires}
        return {"lease_id": lease_id, "provider_ref": provider_ref, "audience": audience, "expires_at": expires.isoformat()}

    def resolve_for_adapter(self, lease_id: str, audience: str) -> bytes:
        lease = self._leases.get(lease_id)
        if not lease or lease["expires"] <= utcnow() or lease["audience"] != audience:
            raise HardeningError("CFHS_SECRET_DENIED", "Invalid, expired, or wrong-audience secret lease")
        return self.provider.resolve(lease["provider_ref"])

    def revoke(self, lease_id: str) -> None:
        self._leases.pop(lease_id, None)


class RotatingSessionManager:
    def __init__(self, sessions: SessionManager):
        self.sessions = sessions

    def rotate(self, current_token: str, ttl_seconds: int = 3600) -> dict[str, Any]:
        principal_id = self.sessions.authenticate(current_token)
        digest = self.sessions._hash(current_token)
        row = self.sessions.conn.execute("SELECT id FROM kernel_sessions WHERE token_hash=?", (digest,)).fetchone()
        if not row:
            raise HardeningError("CFHS_UNAUTHENTICATED", "Current session not found")
        replacement = self.sessions.issue(principal_id, ttl_seconds)
        self.sessions.revoke(row["id"])
        return replacement


class CapabilityBoundingEngine:
    NUMERIC_MAX_KEYS = {"max_amount", "hard_limit", "max_bytes", "max_duration_seconds"}

    @staticmethod
    def _pattern_covers(parent: str, child: str) -> bool:
        if parent == "*":
            return True
        if parent.endswith("*"):
            return child.startswith(parent[:-1])
        return parent == child

    @classmethod
    def capability_covers(cls, parent: dict[str, Any], child: dict[str, Any]) -> bool:
        if not cls._pattern_covers(str(parent.get("action", "")), str(child.get("action", ""))):
            return False
        if not cls._pattern_covers(str(parent.get("resource", "")), str(child.get("resource", ""))):
            return False
        pcond = parent.get("conditions") or {}
        ccond = child.get("conditions") or {}
        for key, pvalue in pcond.items():
            if key not in ccond:
                return False
            cvalue = ccond[key]
            if key in cls.NUMERIC_MAX_KEYS:
                try:
                    if float(cvalue) > float(pvalue):
                        return False
                except (TypeError, ValueError):
                    return False
            elif cvalue != pvalue:
                return False
        return True

    @classmethod
    def assert_bounded(cls, parent_caps: list[dict[str, Any]], child_caps: list[dict[str, Any]]) -> None:
        for child in child_caps:
            if not any(cls.capability_covers(parent, child) for parent in parent_caps):
                raise HardeningError("CFHS_POLICY_DENIED", "Child capability exceeds parent authority", {"child": child})


@dataclass
class QueueMessage:
    id: str
    topic: str
    payload: dict[str, Any]
    attempts: int
    created_at: str


class DurableEventBus:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS trust_events(
              id TEXT PRIMARY KEY,
              topic TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              available_at TEXT NOT NULL,
              claimed_by TEXT,
              claimed_at TEXT,
              acked_at TEXT,
              attempts INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        self.conn.commit()

    def publish(self, topic: str, payload: dict[str, Any], delay_seconds: int = 0) -> dict[str, Any]:
        event_id = "evt_" + secrets.token_hex(10)
        created = utcnow()
        available = created + timedelta(seconds=max(0, int(delay_seconds)))
        self.conn.execute(
            "INSERT INTO trust_events(id,topic,payload_json,created_at,available_at) VALUES(?,?,?,?,?)",
            (event_id, topic, json.dumps(payload, sort_keys=True), created.isoformat(), available.isoformat()),
        )
        self.conn.commit()
        return {"event_id": event_id, "topic": topic, "created_at": created.isoformat(), "available_at": available.isoformat()}

    def poll(self, consumer_id: str, topics: list[str]) -> QueueMessage | None:
        if not topics:
            return None
        placeholders = ",".join("?" for _ in topics)
        now_iso = utcnow().isoformat()
        row = self.conn.execute(
            f"SELECT * FROM trust_events WHERE acked_at IS NULL AND claimed_by IS NULL AND available_at<=? AND topic IN ({placeholders}) ORDER BY created_at,id LIMIT 1",
            (now_iso, *topics),
        ).fetchone()
        if not row:
            return None
        updated = self.conn.execute(
            "UPDATE trust_events SET claimed_by=?,claimed_at=?,attempts=attempts+1 WHERE id=? AND claimed_by IS NULL AND acked_at IS NULL",
            (consumer_id, now_iso, row["id"]),
        )
        self.conn.commit()
        if updated.rowcount != 1:
            return None
        fresh = self.conn.execute("SELECT * FROM trust_events WHERE id=?", (row["id"],)).fetchone()
        return QueueMessage(fresh["id"], fresh["topic"], json.loads(fresh["payload_json"]), int(fresh["attempts"]), fresh["created_at"])

    def ack(self, consumer_id: str, event_id: str) -> None:
        cur = self.conn.execute(
            "UPDATE trust_events SET acked_at=? WHERE id=? AND claimed_by=? AND acked_at IS NULL",
            (utcnow().isoformat(), event_id, consumer_id),
        )
        self.conn.commit()
        if cur.rowcount != 1:
            raise HardeningError("CFHS_CONFLICT", "Message is not owned by this consumer or is already acknowledged")

    def release(self, consumer_id: str, event_id: str, delay_seconds: int = 0) -> None:
        available = utcnow() + timedelta(seconds=max(0, int(delay_seconds)))
        cur = self.conn.execute(
            "UPDATE trust_events SET claimed_by=NULL,claimed_at=NULL,available_at=? WHERE id=? AND claimed_by=? AND acked_at IS NULL",
            (available.isoformat(), event_id, consumer_id),
        )
        self.conn.commit()
        if cur.rowcount != 1:
            raise HardeningError("CFHS_CONFLICT", "Message cannot be released by this consumer")
