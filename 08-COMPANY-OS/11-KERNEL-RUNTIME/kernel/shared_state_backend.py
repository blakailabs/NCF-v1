from __future__ import annotations

import json
import secrets
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

from .hardening import HardeningError
from .trust import sha256_hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class SharedBackendCapabilities:
    backend_id: str
    serializable_transactions: bool
    compare_and_swap: bool
    monotonic_fencing: bool
    durable_ordered_journal: bool
    multi_connection_visibility: bool
    synchronous_durability: bool
    authoritative_time: bool
    distributed_quorum: bool

    def envelope(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class BackendCertification:
    production_ready: bool
    missing_requirements: tuple[str, ...]
    capabilities: SharedBackendCapabilities

    def envelope(self) -> dict[str, Any]:
        return {
            "production_ready": self.production_ready,
            "missing_requirements": list(self.missing_requirements),
            "capabilities": self.capabilities.envelope(),
        }


PRODUCTION_REQUIREMENTS = (
    "serializable_transactions",
    "compare_and_swap",
    "monotonic_fencing",
    "durable_ordered_journal",
    "multi_connection_visibility",
    "synchronous_durability",
    "authoritative_time",
    "distributed_quorum",
)


def certify_backend(capabilities: SharedBackendCapabilities) -> BackendCertification:
    missing = tuple(name for name in PRODUCTION_REQUIREMENTS if not bool(getattr(capabilities, name)))
    return BackendCertification(not missing, missing, capabilities)


@dataclass(frozen=True)
class SharedObject:
    object_key: str
    version: int
    value_digest: str
    value: dict[str, Any]


@dataclass(frozen=True)
class SharedFence:
    resource_key: str
    owner_id: str
    lease_id: str
    fence_token: int
    expires_at: str


class SharedFencedPersistenceBackend(Protocol):
    def capabilities(self) -> SharedBackendCapabilities: ...
    def read(self, object_key: str) -> SharedObject | None: ...
    def put_if_absent(self, object_key: str, value: dict[str, Any]) -> SharedObject: ...
    def compare_and_swap(self, object_key: str, expected_version: int, value: dict[str, Any]) -> SharedObject: ...
    def acquire_fence(self, resource_key: str, owner_id: str, ttl_seconds: int) -> SharedFence: ...
    def assert_fence(self, fence: SharedFence) -> None: ...
    def release_fence(self, fence: SharedFence) -> None: ...
    def append_event(self, stream_key: str, expected_version: int, event: dict[str, Any]) -> dict[str, Any]: ...


class SQLiteSharedStateBackend:
    """Reference shared-store contract implementation.

    Multiple independent connections can target the same SQLite file and prove
    the required CAS/fencing/journal semantics. It is intentionally *not*
    production-certified because it does not provide distributed quorum or an
    authoritative server clock across hosts.
    """

    def __init__(self, path: str | Path, backend_id: str = "sqlite-shared-reference-v07"):
        self.path = str(path)
        self.backend_id = backend_id
        self.conn = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute("PRAGMA busy_timeout=10000")
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS shared_objects_v07(
                object_key TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                value_digest TEXT NOT NULL,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS shared_fences_v07(
                resource_key TEXT PRIMARY KEY,
                last_token INTEGER NOT NULL,
                current_token INTEGER,
                owner_id TEXT,
                lease_id TEXT,
                expires_at TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS shared_journal_v07(
                stream_key TEXT NOT NULL,
                version INTEGER NOT NULL,
                event_digest TEXT NOT NULL,
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(stream_key,version)
            );
            """
        )

    def close(self) -> None:
        self.conn.close()

    def capabilities(self) -> SharedBackendCapabilities:
        return SharedBackendCapabilities(
            backend_id=self.backend_id,
            serializable_transactions=True,
            compare_and_swap=True,
            monotonic_fencing=True,
            durable_ordered_journal=True,
            multi_connection_visibility=True,
            synchronous_durability=True,
            authoritative_time=False,
            distributed_quorum=False,
        )

    @staticmethod
    def _ttl(value: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > 86400:
            raise HardeningError("CFHS_INVALID_REQUEST", "Shared fence TTL must be an integer from 1 to 86400 seconds")
        return value

    @staticmethod
    def _expired(expires_at: str | None, now: datetime) -> bool:
        return not expires_at or datetime.fromisoformat(expires_at) <= now

    @staticmethod
    def _object(row: sqlite3.Row) -> SharedObject:
        return SharedObject(
            object_key=row["object_key"],
            version=int(row["version"]),
            value_digest=row["value_digest"],
            value=json.loads(row["value_json"]),
        )

    def read(self, object_key: str) -> SharedObject | None:
        row = self.conn.execute(
            "SELECT * FROM shared_objects_v07 WHERE object_key=?",
            (object_key,),
        ).fetchone()
        return self._object(row) if row else None

    def put_if_absent(self, object_key: str, value: dict[str, Any]) -> SharedObject:
        if not object_key or not isinstance(value, dict):
            raise HardeningError("CFHS_INVALID_REQUEST", "Shared object key and object value are required")
        digest = sha256_hex(value)
        value_json = json.dumps(value, sort_keys=True, separators=(",", ":"))
        now = utcnow().isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM shared_objects_v07 WHERE object_key=?",
                (object_key,),
            ).fetchone()
            if row:
                if row["value_digest"] != digest:
                    raise HardeningError("CFHS_CONFLICT", "Shared object already exists with different content")
                self.conn.execute("COMMIT")
                return self._object(row)
            self.conn.execute(
                "INSERT INTO shared_objects_v07(object_key,version,value_digest,value_json,updated_at) VALUES(?,1,?,?,?)",
                (object_key, digest, value_json, now),
            )
            self.conn.execute("COMMIT")
        except Exception:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        return self.read(object_key)  # type: ignore[return-value]

    def compare_and_swap(self, object_key: str, expected_version: int, value: dict[str, Any]) -> SharedObject:
        if isinstance(expected_version, bool) or not isinstance(expected_version, int) or expected_version < 1:
            raise HardeningError("CFHS_INVALID_REQUEST", "Expected shared-object version must be a positive integer")
        digest = sha256_hex(value)
        value_json = json.dumps(value, sort_keys=True, separators=(",", ":"))
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM shared_objects_v07 WHERE object_key=?",
                (object_key,),
            ).fetchone()
            if not row:
                raise HardeningError("CFHS_NOT_FOUND", "Shared object not found")
            if int(row["version"]) != expected_version:
                raise HardeningError(
                    "CFHS_CONFLICT",
                    "Shared object compare-and-swap version mismatch",
                    {"expected_version": expected_version, "actual_version": int(row["version"])},
                )
            next_version = expected_version + 1
            self.conn.execute(
                "UPDATE shared_objects_v07 SET version=?,value_digest=?,value_json=?,updated_at=? WHERE object_key=?",
                (next_version, digest, value_json, utcnow().isoformat(), object_key),
            )
            self.conn.execute("COMMIT")
        except Exception:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        return self.read(object_key)  # type: ignore[return-value]

    def acquire_fence(
        self,
        resource_key: str,
        owner_id: str,
        ttl_seconds: int,
        now: datetime | None = None,
    ) -> SharedFence:
        ttl = self._ttl(ttl_seconds)
        current_time = now or utcnow()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM shared_fences_v07 WHERE resource_key=?",
                (resource_key,),
            ).fetchone()
            if row and row["current_token"] is not None and not self._expired(row["expires_at"], current_time):
                raise HardeningError(
                    "CFHS_FENCE_BUSY",
                    "Shared resource already has an active owner",
                    {"owner_id": row["owner_id"], "expires_at": row["expires_at"]},
                )
            next_token = int(row["last_token"] if row else 0) + 1
            lease_id = "shared_lease_" + secrets.token_hex(12)
            expires_at = (current_time + timedelta(seconds=ttl)).isoformat()
            if row:
                self.conn.execute(
                    """
                    UPDATE shared_fences_v07
                       SET last_token=?,current_token=?,owner_id=?,lease_id=?,expires_at=?,updated_at=?
                     WHERE resource_key=?
                    """,
                    (next_token, next_token, owner_id, lease_id, expires_at, current_time.isoformat(), resource_key),
                )
            else:
                self.conn.execute(
                    """
                    INSERT INTO shared_fences_v07(resource_key,last_token,current_token,owner_id,lease_id,expires_at,updated_at)
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (resource_key, next_token, next_token, owner_id, lease_id, expires_at, current_time.isoformat()),
                )
            self.conn.execute("COMMIT")
        except Exception:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        return SharedFence(resource_key, owner_id, lease_id, next_token, expires_at)

    def _assert_fence_row(self, fence: SharedFence, now: datetime, require_unexpired: bool = True) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT * FROM shared_fences_v07 WHERE resource_key=?",
            (fence.resource_key,),
        ).fetchone()
        if (
            not row
            or row["current_token"] is None
            or int(row["current_token"]) != fence.fence_token
            or row["owner_id"] != fence.owner_id
            or row["lease_id"] != fence.lease_id
        ):
            raise HardeningError("CFHS_STALE_FENCE", "Shared fence is stale or no longer owns the resource")
        if require_unexpired and self._expired(row["expires_at"], now):
            raise HardeningError("CFHS_STALE_FENCE", "Shared fence has expired")
        return row

    def assert_fence(self, fence: SharedFence, now: datetime | None = None) -> None:
        self._assert_fence_row(fence, now or utcnow())

    def renew_fence(self, fence: SharedFence, ttl_seconds: int, now: datetime | None = None) -> SharedFence:
        ttl = self._ttl(ttl_seconds)
        current_time = now or utcnow()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            self._assert_fence_row(fence, current_time)
            expires_at = (current_time + timedelta(seconds=ttl)).isoformat()
            self.conn.execute(
                "UPDATE shared_fences_v07 SET expires_at=?,updated_at=? WHERE resource_key=?",
                (expires_at, current_time.isoformat(), fence.resource_key),
            )
            self.conn.execute("COMMIT")
        except Exception:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        return SharedFence(fence.resource_key, fence.owner_id, fence.lease_id, fence.fence_token, expires_at)

    def release_fence(self, fence: SharedFence, now: datetime | None = None) -> None:
        current_time = now or utcnow()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            self._assert_fence_row(fence, current_time, require_unexpired=False)
            self.conn.execute(
                """
                UPDATE shared_fences_v07
                   SET current_token=NULL,owner_id=NULL,lease_id=NULL,expires_at=NULL,updated_at=?
                 WHERE resource_key=?
                """,
                (current_time.isoformat(), fence.resource_key),
            )
            self.conn.execute("COMMIT")
        except Exception:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise

    def stream_version(self, stream_key: str) -> int:
        row = self.conn.execute(
            "SELECT COALESCE(MAX(version),0) AS version FROM shared_journal_v07 WHERE stream_key=?",
            (stream_key,),
        ).fetchone()
        return int(row["version"])

    def append_event(self, stream_key: str, expected_version: int, event: dict[str, Any]) -> dict[str, Any]:
        if isinstance(expected_version, bool) or not isinstance(expected_version, int) or expected_version < 0:
            raise HardeningError("CFHS_INVALID_REQUEST", "Expected journal version must be a nonnegative integer")
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            current = self.stream_version(stream_key)
            if current != expected_version:
                raise HardeningError(
                    "CFHS_CONFLICT",
                    "Shared journal version mismatch",
                    {"expected_version": expected_version, "actual_version": current},
                )
            version = current + 1
            digest = sha256_hex(event)
            self.conn.execute(
                "INSERT INTO shared_journal_v07(stream_key,version,event_digest,event_json,created_at) VALUES(?,?,?,?,?)",
                (stream_key, version, digest, json.dumps(event, sort_keys=True), utcnow().isoformat()),
            )
            self.conn.execute("COMMIT")
        except Exception:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        return {"stream_key": stream_key, "version": version, "event_digest": digest}

    def journal(self, stream_key: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM shared_journal_v07 WHERE stream_key=? ORDER BY version",
            (stream_key,),
        ).fetchall()
        return [
            {
                "stream_key": row["stream_key"],
                "version": int(row["version"]),
                "event_digest": row["event_digest"],
                "event": json.loads(row["event_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def fenced_compare_and_swap_with_event(
        self,
        *,
        fence: SharedFence,
        object_key: str,
        expected_object_version: int,
        value: dict[str, Any],
        stream_key: str,
        expected_stream_version: int,
        event: dict[str, Any],
        now: datetime | None = None,
    ) -> tuple[SharedObject, dict[str, Any]]:
        """Atomically applies a CAS mutation and appends its ordered event under one fence."""
        current_time = now or utcnow()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            self._assert_fence_row(fence, current_time)
            obj = self.conn.execute(
                "SELECT * FROM shared_objects_v07 WHERE object_key=?",
                (object_key,),
            ).fetchone()
            if not obj:
                raise HardeningError("CFHS_NOT_FOUND", "Shared object not found")
            if int(obj["version"]) != expected_object_version:
                raise HardeningError("CFHS_CONFLICT", "Fenced object version mismatch")
            current_stream = self.stream_version(stream_key)
            if current_stream != expected_stream_version:
                raise HardeningError("CFHS_CONFLICT", "Fenced journal version mismatch")
            next_object_version = expected_object_version + 1
            next_stream_version = expected_stream_version + 1
            value_digest = sha256_hex(value)
            event_envelope = {
                "fence_token": fence.fence_token,
                "owner_id": fence.owner_id,
                "object_key": object_key,
                "object_version": next_object_version,
                "event": event,
            }
            event_digest = sha256_hex(event_envelope)
            self.conn.execute(
                "UPDATE shared_objects_v07 SET version=?,value_digest=?,value_json=?,updated_at=? WHERE object_key=?",
                (
                    next_object_version,
                    value_digest,
                    json.dumps(value, sort_keys=True, separators=(",", ":")),
                    current_time.isoformat(),
                    object_key,
                ),
            )
            self.conn.execute(
                "INSERT INTO shared_journal_v07(stream_key,version,event_digest,event_json,created_at) VALUES(?,?,?,?,?)",
                (
                    stream_key,
                    next_stream_version,
                    event_digest,
                    json.dumps(event_envelope, sort_keys=True),
                    current_time.isoformat(),
                ),
            )
            self.conn.execute("COMMIT")
        except Exception:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        return (
            self.read(object_key),  # type: ignore[arg-type]
            {"stream_key": stream_key, "version": next_stream_version, "event_digest": event_digest},
        )
