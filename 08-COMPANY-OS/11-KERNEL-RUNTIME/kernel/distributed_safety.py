from __future__ import annotations

import json
import math
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .hardening import HardeningError
from .trust import sha256_hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _extract_path(source: dict[str, Any], path: str) -> Any:
    current: Any = source
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise HardeningError("CFHS_INVALID_REQUEST", f"Business identity field is missing: {path}")
        current = current[part]
    if current is None:
        raise HardeningError("CFHS_INVALID_REQUEST", f"Business identity field is null: {path}")
    return current


def _validate_identity_value(value: Any, path: str = "identity") -> None:
    if value is None:
        raise HardeningError("CFHS_INVALID_REQUEST", f"Business identity value is null: {path}")
    if isinstance(value, float) and not math.isfinite(value):
        raise HardeningError("CFHS_INVALID_REQUEST", f"Business identity value must be finite: {path}")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise HardeningError("CFHS_INVALID_REQUEST", f"Business identity object keys must be strings: {path}")
            _validate_identity_value(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _validate_identity_value(child, f"{path}[{index}]")
    elif not isinstance(value, (str, int, float, bool)):
        raise HardeningError("CFHS_INVALID_REQUEST", f"Unsupported business identity value type: {path}")


@dataclass(frozen=True)
class BusinessObjectIdentity:
    contract_id: str
    contract_version: int
    operation: str
    identity_digest: str
    component_digest: str

    def resource_key(self) -> str:
        return f"business-object:{self.operation}:{self.identity_digest}"


@dataclass(frozen=True)
class BusinessIdentityContract:
    contract_id: str
    contract_version: int
    operation: str
    fields: tuple[str, ...]

    def derive(self, arguments: dict[str, Any]) -> BusinessObjectIdentity:
        if not self.contract_id or self.contract_version < 1 or not self.operation or not self.fields:
            raise HardeningError("CFHS_INVALID_POLICY", "Business identity contract is incomplete")
        if len(set(self.fields)) != len(self.fields):
            raise HardeningError("CFHS_INVALID_POLICY", "Business identity contract contains duplicate fields")
        components: dict[str, Any] = {}
        for path in self.fields:
            value = _extract_path(arguments, path)
            _validate_identity_value(value, path)
            components[path] = value
        component_digest = sha256_hex(components)
        identity_digest = sha256_hex(
            {
                "contract_id": self.contract_id,
                "contract_version": self.contract_version,
                "operation": self.operation,
                "component_digest": component_digest,
            }
        )
        return BusinessObjectIdentity(
            contract_id=self.contract_id,
            contract_version=self.contract_version,
            operation=self.operation,
            identity_digest=identity_digest,
            component_digest=component_digest,
        )


class BusinessIdentityLedger:
    """Durably binds one business-object identity to one semantic action.

    Raw business identity components are never persisted. Only digests and
    contract metadata are stored. Retries must continue the original semantic
    intent rather than creating a new meaning for the same business object.
    """

    ALLOWED_TRANSITIONS = {
        "BOUND": {"BOUND", "EXECUTING", "FAILED_NOT_EXECUTED"},
        "EXECUTING": {"EXECUTING", "COMMITTED", "FAILED_NOT_EXECUTED", "RECONCILIATION_REQUIRED"},
        "RECONCILIATION_REQUIRED": {"RECONCILIATION_REQUIRED", "COMMITTED", "FAILED_NOT_EXECUTED", "COMPENSATED"},
        "COMMITTED": {"COMMITTED", "COMPENSATED"},
        "FAILED_NOT_EXECUTED": {"FAILED_NOT_EXECUTED"},
        "COMPENSATED": {"COMPENSATED"},
    }

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS business_identity_bindings_v07(
                identity_digest TEXT PRIMARY KEY,
                contract_id TEXT NOT NULL,
                contract_version INTEGER NOT NULL,
                operation TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                semantic_intent_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(provider_id,operation,semantic_intent_digest)
            );
            """
        )
        self.conn.commit()

    def bind(self, identity: BusinessObjectIdentity, provider_id: str, semantic_intent_digest: str) -> dict[str, Any]:
        if not provider_id or not semantic_intent_digest:
            raise HardeningError("CFHS_INVALID_REQUEST", "Provider and semantic intent digest are required")
        now = utcnow().isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            existing = self.conn.execute(
                "SELECT * FROM business_identity_bindings_v07 WHERE identity_digest=?",
                (identity.identity_digest,),
            ).fetchone()
            if existing:
                if (
                    existing["contract_id"] != identity.contract_id
                    or int(existing["contract_version"]) != identity.contract_version
                    or existing["operation"] != identity.operation
                    or existing["provider_id"] != provider_id
                    or existing["semantic_intent_digest"] != semantic_intent_digest
                ):
                    raise HardeningError(
                        "CFHS_BUSINESS_IDENTITY_CONFLICT",
                        "Business-object identity is already bound to a different semantic action",
                        {"identity_digest": identity.identity_digest},
                    )
                self.conn.commit()
                return dict(existing)
            try:
                self.conn.execute(
                    """
                    INSERT INTO business_identity_bindings_v07(
                        identity_digest,contract_id,contract_version,operation,provider_id,
                        semantic_intent_digest,status,created_at,updated_at
                    ) VALUES(?,?,?,?,?,?,'BOUND',?,?)
                    """,
                    (
                        identity.identity_digest,
                        identity.contract_id,
                        identity.contract_version,
                        identity.operation,
                        provider_id,
                        semantic_intent_digest,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise HardeningError(
                    "CFHS_BUSINESS_IDENTITY_CONFLICT",
                    "Semantic action is already bound to another business-object identity",
                ) from exc
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self.get(identity.identity_digest)

    def get(self, identity_digest: str) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM business_identity_bindings_v07 WHERE identity_digest=?",
            (identity_digest,),
        ).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Business-object identity binding not found")
        return dict(row)

    def transition(self, identity_digest: str, semantic_intent_digest: str, target: str) -> dict[str, Any]:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM business_identity_bindings_v07 WHERE identity_digest=?",
                (identity_digest,),
            ).fetchone()
            if not row or row["semantic_intent_digest"] != semantic_intent_digest:
                raise HardeningError("CFHS_BUSINESS_IDENTITY_CONFLICT", "Business identity binding is missing or mismatched")
            current = str(row["status"])
            if target not in self.ALLOWED_TRANSITIONS.get(current, {current}):
                raise HardeningError("CFHS_CONFLICT", f"Business identity cannot transition {current} → {target}")
            self.conn.execute(
                "UPDATE business_identity_bindings_v07 SET status=?,updated_at=? WHERE identity_digest=?",
                (target, utcnow().isoformat(), identity_digest),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self.get(identity_digest)


@dataclass(frozen=True)
class FenceLease:
    resource_key: str
    owner_id: str
    lease_id: str
    fence_token: int
    expires_at: str

    def envelope(self) -> dict[str, Any]:
        return {
            "resource_key": self.resource_key,
            "owner_id": self.owner_id,
            "lease_id": self.lease_id,
            "fence_token": self.fence_token,
            "expires_at": self.expires_at,
        }


class SQLiteFenceStore:
    """Single-database reference implementation of monotonic fencing.

    v0.7 treats this as the contract model. A production distributed backend
    must preserve the same monotonic-token and stale-owner rejection semantics.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fence_resources_v07(
                resource_key TEXT PRIMARY KEY,
                last_token INTEGER NOT NULL,
                current_token INTEGER,
                owner_id TEXT,
                lease_id TEXT,
                acquired_at TEXT,
                expires_at TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    @staticmethod
    def _ttl(ttl_seconds: int) -> int:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds < 1 or ttl_seconds > 86400:
            raise HardeningError("CFHS_INVALID_REQUEST", "Fence TTL must be an integer from 1 to 86400 seconds")
        return ttl_seconds

    @staticmethod
    def _expired(expires_at: str | None, now: datetime) -> bool:
        return not expires_at or datetime.fromisoformat(expires_at) <= now

    def acquire(self, resource_key: str, owner_id: str, ttl_seconds: int, now: datetime | None = None) -> FenceLease:
        if not resource_key or not owner_id:
            raise HardeningError("CFHS_INVALID_REQUEST", "Fence resource and owner are required")
        ttl = self._ttl(ttl_seconds)
        current_time = now or utcnow()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM fence_resources_v07 WHERE resource_key=?",
                (resource_key,),
            ).fetchone()
            if row and row["current_token"] is not None and not self._expired(row["expires_at"], current_time):
                raise HardeningError(
                    "CFHS_FENCE_BUSY",
                    "Fence is currently owned by an active lease",
                    {"resource_key": resource_key, "owner_id": row["owner_id"], "expires_at": row["expires_at"]},
                )
            next_token = int(row["last_token"] if row else 0) + 1
            lease_id = "flease_" + secrets.token_hex(12)
            expires_at = (current_time + timedelta(seconds=ttl)).isoformat()
            if row:
                self.conn.execute(
                    """
                    UPDATE fence_resources_v07
                       SET last_token=?,current_token=?,owner_id=?,lease_id=?,acquired_at=?,expires_at=?,updated_at=?
                     WHERE resource_key=?
                    """,
                    (next_token, next_token, owner_id, lease_id, current_time.isoformat(), expires_at, current_time.isoformat(), resource_key),
                )
            else:
                self.conn.execute(
                    """
                    INSERT INTO fence_resources_v07(
                        resource_key,last_token,current_token,owner_id,lease_id,acquired_at,expires_at,updated_at
                    ) VALUES(?,?,?,?,?,?,?,?)
                    """,
                    (resource_key, next_token, next_token, owner_id, lease_id, current_time.isoformat(), expires_at, current_time.isoformat()),
                )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return FenceLease(resource_key, owner_id, lease_id, next_token, expires_at)

    def renew(self, lease: FenceLease, ttl_seconds: int, now: datetime | None = None) -> FenceLease:
        ttl = self._ttl(ttl_seconds)
        current_time = now or utcnow()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM fence_resources_v07 WHERE resource_key=?",
                (lease.resource_key,),
            ).fetchone()
            self._assert_row_matches(row, lease, current_time, require_unexpired=True)
            expires_at = (current_time + timedelta(seconds=ttl)).isoformat()
            self.conn.execute(
                "UPDATE fence_resources_v07 SET expires_at=?,updated_at=? WHERE resource_key=?",
                (expires_at, current_time.isoformat(), lease.resource_key),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return FenceLease(lease.resource_key, lease.owner_id, lease.lease_id, lease.fence_token, expires_at)

    def release(self, lease: FenceLease, now: datetime | None = None) -> None:
        current_time = now or utcnow()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM fence_resources_v07 WHERE resource_key=?",
                (lease.resource_key,),
            ).fetchone()
            self._assert_row_matches(row, lease, current_time, require_unexpired=False)
            self.conn.execute(
                """
                UPDATE fence_resources_v07
                   SET current_token=NULL,owner_id=NULL,lease_id=NULL,acquired_at=NULL,expires_at=NULL,updated_at=?
                 WHERE resource_key=?
                """,
                (current_time.isoformat(), lease.resource_key),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def assert_current(self, lease: FenceLease, now: datetime | None = None) -> None:
        current_time = now or utcnow()
        row = self.conn.execute(
            "SELECT * FROM fence_resources_v07 WHERE resource_key=?",
            (lease.resource_key,),
        ).fetchone()
        self._assert_row_matches(row, lease, current_time, require_unexpired=True)

    @staticmethod
    def _assert_row_matches(row: sqlite3.Row | None, lease: FenceLease, now: datetime, require_unexpired: bool) -> None:
        if (
            not row
            or row["current_token"] is None
            or int(row["current_token"]) != lease.fence_token
            or row["owner_id"] != lease.owner_id
            or row["lease_id"] != lease.lease_id
        ):
            raise HardeningError("CFHS_STALE_FENCE", "Fence lease is stale or no longer owns the resource")
        if require_unexpired and SQLiteFenceStore._expired(row["expires_at"], now):
            raise HardeningError("CFHS_STALE_FENCE", "Fence lease has expired and cannot be revived")


class ProviderFenceGuard:
    """Reference provider-side stale-token rejection contract.

    A production consequential provider adapter must either enforce equivalent
    fencing itself or sit behind a gateway that does. Tokens below the highest
    observed epoch are rejected even if the stale caller still has credentials.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_fence_observations_v07(
                provider_id TEXT NOT NULL,
                resource_key TEXT NOT NULL,
                highest_token INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(provider_id,resource_key)
            )
            """
        )
        self.conn.commit()

    def accept(self, provider_id: str, resource_key: str, fence_token: int) -> dict[str, Any]:
        if not provider_id or not resource_key or isinstance(fence_token, bool) or not isinstance(fence_token, int) or fence_token < 1:
            raise HardeningError("CFHS_INVALID_REQUEST", "Valid provider fence identity and positive token are required")
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT highest_token FROM provider_fence_observations_v07 WHERE provider_id=? AND resource_key=?",
                (provider_id, resource_key),
            ).fetchone()
            if row and fence_token < int(row["highest_token"]):
                raise HardeningError(
                    "CFHS_STALE_FENCE",
                    "Provider rejected a stale fencing token",
                    {"provider_id": provider_id, "resource_key": resource_key, "received": fence_token, "highest": int(row["highest_token"])},
                )
            if row:
                if fence_token > int(row["highest_token"]):
                    self.conn.execute(
                        "UPDATE provider_fence_observations_v07 SET highest_token=?,updated_at=? WHERE provider_id=? AND resource_key=?",
                        (fence_token, utcnow().isoformat(), provider_id, resource_key),
                    )
            else:
                self.conn.execute(
                    "INSERT INTO provider_fence_observations_v07(provider_id,resource_key,highest_token,updated_at) VALUES(?,?,?,?)",
                    (provider_id, resource_key, fence_token, utcnow().isoformat()),
                )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return {"provider_id": provider_id, "resource_key": resource_key, "accepted_token": fence_token}


@dataclass(frozen=True)
class DistributedActionPermit:
    identity: BusinessObjectIdentity
    semantic_intent_digest: str
    provider_id: str
    lease: FenceLease

    def envelope(self) -> dict[str, Any]:
        return {
            "identity_digest": self.identity.identity_digest,
            "contract_id": self.identity.contract_id,
            "contract_version": self.identity.contract_version,
            "operation": self.identity.operation,
            "semantic_intent_digest": self.semantic_intent_digest,
            "provider_id": self.provider_id,
            "fence": self.lease.envelope(),
        }


class DistributedActionGuard:
    """Composes business identity and fencing for a distributed action epoch."""

    def __init__(self, identities: BusinessIdentityLedger, fences: SQLiteFenceStore):
        self.identities = identities
        self.fences = fences

    def prepare(
        self,
        contract: BusinessIdentityContract,
        arguments: dict[str, Any],
        semantic_intent_digest: str,
        provider_id: str,
        owner_id: str,
        ttl_seconds: int,
        now: datetime | None = None,
    ) -> DistributedActionPermit:
        identity = contract.derive(arguments)
        self.identities.bind(identity, provider_id, semantic_intent_digest)
        lease = self.fences.acquire(identity.resource_key(), owner_id, ttl_seconds, now)
        return DistributedActionPermit(identity, semantic_intent_digest, provider_id, lease)

    def assert_current(self, permit: DistributedActionPermit, now: datetime | None = None) -> None:
        self.fences.assert_current(permit.lease, now)
        binding = self.identities.get(permit.identity.identity_digest)
        if binding["semantic_intent_digest"] != permit.semantic_intent_digest or binding["provider_id"] != permit.provider_id:
            raise HardeningError("CFHS_BUSINESS_IDENTITY_CONFLICT", "Distributed action permit no longer matches business identity binding")

    def transition(self, permit: DistributedActionPermit, target: str, now: datetime | None = None) -> dict[str, Any]:
        self.assert_current(permit, now)
        return self.identities.transition(permit.identity.identity_digest, permit.semantic_intent_digest, target)
