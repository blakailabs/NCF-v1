from __future__ import annotations

import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from .ha_persistence import HADeploymentEvidence, HAPersistenceCertification
from .hardening import HardeningError
from .shared_state_backend import SharedBackendCapabilities, SharedFence, SharedObject
from .trust import sha256_hex


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise HardeningError("CFHS_INVALID_EVIDENCE", "HA certification timestamp is invalid") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class AuthoritativeHABackend(Protocol):
    def capabilities(self) -> SharedBackendCapabilities: ...
    def authoritative_now(self) -> datetime: ...
    def read(self, object_key: str) -> SharedObject | None: ...
    def put_if_absent(self, object_key: str, value: dict[str, Any]) -> SharedObject: ...
    def compare_and_swap(self, object_key: str, expected_version: int, value: dict[str, Any]) -> SharedObject: ...
    def acquire_fence(self, resource_key: str, owner_id: str, ttl_seconds: int) -> SharedFence: ...
    def assert_fence(self, fence: SharedFence) -> None: ...
    def release_fence(self, fence: SharedFence) -> None: ...
    def append_event(self, stream_key: str, expected_version: int, event: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class HACertificationRecord:
    certification_id: str
    backend_id: str
    cluster_id: str
    topology_epoch: int
    evidence_nonce: str
    evidence_digest: str
    attestation_digest: str
    certification_digest: str
    certified_at: str
    valid_until: str
    status: str

    def envelope(self) -> dict[str, Any]:
        return {
            "certification_id": self.certification_id,
            "backend_id": self.backend_id,
            "cluster_id": self.cluster_id,
            "topology_epoch": self.topology_epoch,
            "evidence_nonce": self.evidence_nonce,
            "evidence_digest": self.evidence_digest,
            "attestation_digest": self.attestation_digest,
            "certification_digest": self.certification_digest,
            "certified_at": self.certified_at,
            "valid_until": self.valid_until,
            "status": self.status,
        }


class SQLiteHACertificationLedger:
    """Reference certification lifecycle ledger.

    This models rollback/idempotency/expiry semantics. The SQLite ledger itself
    is not the production HA control plane; a production implementation must
    place equivalent state behind the certified shared persistence boundary.
    """

    def __init__(self, conn: sqlite3.Connection, *, max_evidence_age_seconds: int = 300):
        if (
            isinstance(max_evidence_age_seconds, bool)
            or not isinstance(max_evidence_age_seconds, int)
            or max_evidence_age_seconds < 30
            or max_evidence_age_seconds > 3600
        ):
            raise HardeningError("CFHS_INVALID_POLICY", "HA certification lifetime policy is invalid")
        self.conn = conn
        self.max_evidence_age_seconds = max_evidence_age_seconds
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS ha_backend_identity_v08(
                backend_id TEXT PRIMARY KEY,
                cluster_id TEXT NOT NULL,
                highest_topology_epoch INTEGER NOT NULL,
                active_certification_id TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ha_persistence_certifications_v08(
                certification_id TEXT PRIMARY KEY,
                backend_id TEXT NOT NULL,
                cluster_id TEXT NOT NULL,
                topology_epoch INTEGER NOT NULL,
                evidence_nonce TEXT NOT NULL,
                evidence_digest TEXT NOT NULL,
                attestation_digest TEXT NOT NULL,
                certification_digest TEXT NOT NULL,
                certified_at TEXT NOT NULL,
                valid_until TEXT NOT NULL,
                status TEXT NOT NULL,
                invalidation_reason TEXT,
                UNIQUE(backend_id,topology_epoch),
                UNIQUE(backend_id,evidence_nonce)
            );
            """
        )
        self.conn.commit()

    @staticmethod
    def _record(row: sqlite3.Row) -> HACertificationRecord:
        return HACertificationRecord(
            certification_id=row["certification_id"],
            backend_id=row["backend_id"],
            cluster_id=row["cluster_id"],
            topology_epoch=int(row["topology_epoch"]),
            evidence_nonce=row["evidence_nonce"],
            evidence_digest=row["evidence_digest"],
            attestation_digest=row["attestation_digest"],
            certification_digest=row["certification_digest"],
            certified_at=row["certified_at"],
            valid_until=row["valid_until"],
            status=row["status"],
        )

    def _valid_until(self, evidence: HADeploymentEvidence, certification: HAPersistenceCertification) -> datetime:
        if not certification.attestation:
            raise HardeningError("CFHS_HA_PERSISTENCE_NOT_READY", "HA certification lacks trusted attestation")
        timestamps = [_parse_time(evidence.observed_at), _parse_time(certification.attestation.verified_at)]
        timestamps.extend(_parse_time(probe.observed_at) for probe in evidence.probes)
        return min(ts + timedelta(seconds=self.max_evidence_age_seconds) for ts in timestamps)

    def active(self, backend_id: str) -> HACertificationRecord | None:
        row = self.conn.execute(
            """
            SELECT c.* FROM ha_backend_identity_v08 b
            JOIN ha_persistence_certifications_v08 c ON c.certification_id=b.active_certification_id
            WHERE b.backend_id=?
            """,
            (backend_id,),
        ).fetchone()
        return self._record(row) if row else None

    def history(self, backend_id: str) -> list[HACertificationRecord]:
        rows = self.conn.execute(
            "SELECT * FROM ha_persistence_certifications_v08 WHERE backend_id=? ORDER BY topology_epoch",
            (backend_id,),
        ).fetchall()
        return [self._record(row) for row in rows]

    def record(
        self,
        certification: HAPersistenceCertification,
        evidence: HADeploymentEvidence,
        *,
        certified_at: datetime,
    ) -> HACertificationRecord:
        if certified_at.tzinfo is None:
            raise HardeningError("CFHS_INVALID_EVIDENCE", "HA certification time must be timezone-aware")
        certified_at = certified_at.astimezone(timezone.utc)
        if not certification.production_ready or certification.missing_requirements:
            raise HardeningError(
                "CFHS_HA_PERSISTENCE_NOT_READY",
                "Only fully production-ready HA evidence may enter the active certification ledger",
                certification.envelope(),
            )
        if certification.backend_id != evidence.backend_id or certification.evidence_digest != evidence.digest():
            raise HardeningError("CFHS_CONFLICT", "HA certification does not bind the supplied deployment evidence")
        if not certification.attestation:
            raise HardeningError("CFHS_HA_PERSISTENCE_NOT_READY", "HA certification lacks trusted attestation")
        valid_until = self._valid_until(evidence, certification)
        if valid_until <= certified_at:
            raise HardeningError("CFHS_HA_CERTIFICATION_EXPIRED", "HA certification evidence is already expired")

        attestation_digest = sha256_hex(certification.attestation.envelope())
        certification_digest = sha256_hex(
            {
                "backend_id": evidence.backend_id,
                "cluster_id": evidence.cluster_id,
                "topology_epoch": evidence.topology_epoch,
                "evidence_nonce": evidence.evidence_nonce,
                "evidence_digest": evidence.digest(),
                "attestation_digest": attestation_digest,
                "valid_until": valid_until.isoformat(),
            }
        )
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            identity = self.conn.execute(
                "SELECT * FROM ha_backend_identity_v08 WHERE backend_id=?",
                (evidence.backend_id,),
            ).fetchone()
            if identity:
                if identity["cluster_id"] != evidence.cluster_id:
                    raise HardeningError("CFHS_CLUSTER_IDENTITY_CONFLICT", "HA backend cluster identity changed")
                highest = int(identity["highest_topology_epoch"])
                if evidence.topology_epoch < highest:
                    raise HardeningError(
                        "CFHS_TOPOLOGY_ROLLBACK",
                        "HA topology epoch cannot move backward",
                        {"highest_topology_epoch": highest, "received_topology_epoch": evidence.topology_epoch},
                    )

            nonce_row = self.conn.execute(
                "SELECT * FROM ha_persistence_certifications_v08 WHERE backend_id=? AND evidence_nonce=?",
                (evidence.backend_id, evidence.evidence_nonce),
            ).fetchone()
            if nonce_row:
                if (
                    nonce_row["evidence_digest"] != evidence.digest()
                    or int(nonce_row["topology_epoch"]) != evidence.topology_epoch
                ):
                    raise HardeningError("CFHS_IDEMPOTENCY_CONFLICT", "HA evidence nonce was reused for different evidence")
                self.conn.execute("COMMIT")
                return self._record(nonce_row)

            epoch_row = self.conn.execute(
                "SELECT * FROM ha_persistence_certifications_v08 WHERE backend_id=? AND topology_epoch=?",
                (evidence.backend_id, evidence.topology_epoch),
            ).fetchone()
            if epoch_row:
                if epoch_row["evidence_digest"] != evidence.digest():
                    raise HardeningError("CFHS_TOPOLOGY_CONFLICT", "HA topology epoch is already bound to different evidence")
                self.conn.execute("COMMIT")
                return self._record(epoch_row)

            certification_id = "hacert_" + secrets.token_hex(12)
            now_text = certified_at.isoformat()
            self.conn.execute(
                "UPDATE ha_persistence_certifications_v08 SET status='SUPERSEDED' WHERE backend_id=? AND status='ACTIVE'",
                (evidence.backend_id,),
            )
            self.conn.execute(
                """
                INSERT INTO ha_persistence_certifications_v08(
                    certification_id,backend_id,cluster_id,topology_epoch,evidence_nonce,
                    evidence_digest,attestation_digest,certification_digest,certified_at,
                    valid_until,status
                ) VALUES(?,?,?,?,?,?,?,?,?,?,'ACTIVE')
                """,
                (
                    certification_id,
                    evidence.backend_id,
                    evidence.cluster_id,
                    evidence.topology_epoch,
                    evidence.evidence_nonce,
                    evidence.digest(),
                    attestation_digest,
                    certification_digest,
                    now_text,
                    valid_until.isoformat(),
                ),
            )
            if identity:
                self.conn.execute(
                    """
                    UPDATE ha_backend_identity_v08
                    SET highest_topology_epoch=?,active_certification_id=?,updated_at=?
                    WHERE backend_id=?
                    """,
                    (evidence.topology_epoch, certification_id, now_text, evidence.backend_id),
                )
            else:
                self.conn.execute(
                    """
                    INSERT INTO ha_backend_identity_v08(
                        backend_id,cluster_id,highest_topology_epoch,active_certification_id,updated_at
                    ) VALUES(?,?,?,?,?)
                    """,
                    (evidence.backend_id, evidence.cluster_id, evidence.topology_epoch, certification_id, now_text),
                )
            self.conn.execute("COMMIT")
        except Exception:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        active = self.active(evidence.backend_id)
        if not active:
            raise HardeningError("CFHS_HA_PERSISTENCE_NOT_READY", "HA certification did not become active")
        return active

    def invalidate(self, backend_id: str, reason: str, *, at: datetime) -> HACertificationRecord:
        if not reason.strip():
            raise HardeningError("CFHS_INVALID_REQUEST", "HA certification invalidation reason is required")
        current = self.active(backend_id)
        if not current:
            raise HardeningError("CFHS_NOT_FOUND", "No active HA certification exists")
        self.conn.execute(
            """
            UPDATE ha_persistence_certifications_v08
            SET status='INVALIDATED',invalidation_reason=? WHERE certification_id=?
            """,
            (reason, current.certification_id),
        )
        self.conn.execute(
            "UPDATE ha_backend_identity_v08 SET active_certification_id=NULL,updated_at=? WHERE backend_id=?",
            (at.astimezone(timezone.utc).isoformat(), backend_id),
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT * FROM ha_persistence_certifications_v08 WHERE certification_id=?",
            (current.certification_id,),
        ).fetchone()
        return self._record(row)

    def require_active(self, backend_id: str, *, authoritative_now: datetime) -> HACertificationRecord:
        if authoritative_now.tzinfo is None:
            raise HardeningError("CFHS_HA_PERSISTENCE_NOT_READY", "Backend authoritative time must be timezone-aware")
        record = self.active(backend_id)
        if not record:
            raise HardeningError("CFHS_HA_PERSISTENCE_NOT_READY", "No active HA persistence certification exists")
        if record.status != "ACTIVE":
            raise HardeningError("CFHS_HA_PERSISTENCE_NOT_READY", "HA persistence certification is not active")
        if authoritative_now.astimezone(timezone.utc) >= _parse_time(record.valid_until):
            raise HardeningError(
                "CFHS_HA_CERTIFICATION_EXPIRED",
                "HA persistence certification has expired",
                {"certification_id": record.certification_id, "valid_until": record.valid_until},
            )
        return record


class CertifiedSharedPersistence:
    """Reference guard that refuses all shared-state access without a live HA certificate."""

    def __init__(self, backend: AuthoritativeHABackend, ledger: SQLiteHACertificationLedger):
        self.backend = backend
        self.ledger = ledger
        self.backend_id = backend.capabilities().backend_id

    def _guard(self) -> HACertificationRecord:
        now = self.backend.authoritative_now()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise HardeningError("CFHS_HA_PERSISTENCE_NOT_READY", "Backend did not provide authoritative timezone-aware time")
        return self.ledger.require_active(self.backend_id, authoritative_now=now)

    def certification_status(self) -> dict[str, Any]:
        now = self.backend.authoritative_now()
        record = self.ledger.require_active(self.backend_id, authoritative_now=now)
        return {"backend_id": self.backend_id, "authoritative_now": now.isoformat(), "certification": record.envelope()}

    def capabilities(self) -> SharedBackendCapabilities:
        self._guard()
        return self.backend.capabilities()

    def read(self, object_key: str):
        self._guard()
        return self.backend.read(object_key)

    def put_if_absent(self, object_key: str, value: dict[str, Any]):
        self._guard()
        return self.backend.put_if_absent(object_key, value)

    def compare_and_swap(self, object_key: str, expected_version: int, value: dict[str, Any]):
        self._guard()
        return self.backend.compare_and_swap(object_key, expected_version, value)

    def acquire_fence(self, resource_key: str, owner_id: str, ttl_seconds: int):
        self._guard()
        return self.backend.acquire_fence(resource_key, owner_id, ttl_seconds)

    def assert_fence(self, fence):
        self._guard()
        return self.backend.assert_fence(fence)

    def renew_fence(self, fence, ttl_seconds: int):
        self._guard()
        method = getattr(self.backend, "renew_fence", None)
        if not callable(method):
            raise HardeningError("CFHS_HA_PERSISTENCE_NOT_READY", "Certified backend lacks fence renewal")
        return method(fence, ttl_seconds)

    def release_fence(self, fence):
        self._guard()
        return self.backend.release_fence(fence)

    def append_event(self, stream_key: str, expected_version: int, event: dict[str, Any]):
        self._guard()
        return self.backend.append_event(stream_key, expected_version, event)

    def stream_version(self, stream_key: str):
        self._guard()
        method = getattr(self.backend, "stream_version", None)
        if not callable(method):
            raise HardeningError("CFHS_HA_PERSISTENCE_NOT_READY", "Certified backend lacks stream version query")
        return method(stream_key)

    def journal(self, stream_key: str):
        self._guard()
        method = getattr(self.backend, "journal", None)
        if not callable(method):
            raise HardeningError("CFHS_HA_PERSISTENCE_NOT_READY", "Certified backend lacks ordered journal query")
        return method(stream_key)

    def fenced_compare_and_swap_with_event(self, **kwargs):
        self._guard()
        method = getattr(self.backend, "fenced_compare_and_swap_with_event", None)
        if not callable(method):
            raise HardeningError("CFHS_HA_PERSISTENCE_NOT_READY", "Certified backend lacks atomic fenced mutation")
        return method(**kwargs)
