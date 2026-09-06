from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from .ha_persistence import HADeploymentEvidence, HAPersistenceCertification
from .hardening import HardeningError
from .shared_state_backend import SharedBackendCapabilities, SharedObject
from .trust import sha256_hex


BOOTSTRAP_PURPOSE = "initialize_ha_certification_state_v08"
ALLOWED_BOOTSTRAP_AUTHORITY_CLASSES = {
    "external_certification_authority",
    "independent_release_authority",
}


def _parse_time(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise HardeningError("CFHS_INVALID_EVIDENCE", f"{field} timestamp is invalid") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class HABootstrapBinding:
    backend_id: str
    cluster_id: str
    topology_epoch: int
    evidence_digest: str
    certification_decision_digest: str
    attestation_digest: str

    def envelope(self) -> dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return sha256_hex(self.envelope())

    @classmethod
    def from_certification(
        cls,
        certification: HAPersistenceCertification,
        evidence: HADeploymentEvidence,
    ) -> "HABootstrapBinding":
        if not certification.production_ready or certification.missing_requirements:
            raise HardeningError(
                "CFHS_HA_PERSISTENCE_NOT_READY",
                "Bootstrap requires a fully production-ready HA certification decision",
                certification.envelope(),
            )
        if certification.backend_id != evidence.backend_id:
            raise HardeningError("CFHS_CONFLICT", "Bootstrap certification backend does not match deployment evidence")
        if certification.evidence_digest != evidence.digest():
            raise HardeningError("CFHS_CONFLICT", "Bootstrap certification does not bind the supplied deployment evidence")
        if not certification.attestation:
            raise HardeningError("CFHS_HA_PERSISTENCE_NOT_READY", "Bootstrap certification lacks trusted attestation")
        return cls(
            backend_id=evidence.backend_id,
            cluster_id=evidence.cluster_id,
            topology_epoch=evidence.topology_epoch,
            evidence_digest=evidence.digest(),
            certification_decision_digest=sha256_hex(certification.envelope()),
            attestation_digest=sha256_hex(certification.attestation.envelope()),
        )


@dataclass(frozen=True)
class HABootstrapPermit:
    permit_id: str
    purpose: str
    backend_id: str
    cluster_id: str
    topology_epoch: int
    evidence_digest: str
    certification_decision_digest: str
    attestation_digest: str
    authority_id: str
    authority_class: str
    issued_at: str
    expires_at: str
    permit_nonce: str

    def envelope(self) -> dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return sha256_hex(self.envelope())

    def binding(self) -> HABootstrapBinding:
        return HABootstrapBinding(
            backend_id=self.backend_id,
            cluster_id=self.cluster_id,
            topology_epoch=self.topology_epoch,
            evidence_digest=self.evidence_digest,
            certification_decision_digest=self.certification_decision_digest,
            attestation_digest=self.attestation_digest,
        )


@dataclass(frozen=True)
class VerifiedHABootstrapPermit:
    permit_digest: str
    binding_digest: str
    authority_id: str
    authority_class: str
    verified_at: str
    authority_receipt_digest: str

    def envelope(self) -> dict[str, Any]:
        return asdict(self)


class HABootstrapPermitVerifier(Protocol):
    """External trust boundary for first-certification bootstrap permits.

    A production verifier should validate an asymmetric/HSM/mTLS-backed permit
    outside the uncertified persistence backend and return its own trusted
    verification timestamp. The backend/client clock is not permit authority.
    """

    def verify(
        self,
        permit: HABootstrapPermit,
        expected_binding: HABootstrapBinding,
    ) -> VerifiedHABootstrapPermit: ...


class BootstrapWritableBackend(Protocol):
    """Minimal raw backend surface available before the first certificate.

    Deliberately excludes generic CAS, fencing, journal, application writes and
    other runtime operations. The coordinator derives the only object key/value
    it is allowed to initialize.
    """

    def capabilities(self) -> SharedBackendCapabilities: ...
    def read(self, object_key: str) -> SharedObject | None: ...
    def put_if_absent(self, object_key: str, value: dict[str, Any]) -> SharedObject: ...


@dataclass(frozen=True)
class HABootstrapResult:
    object_key: str
    object_version: int
    bootstrap_state_digest: str
    permit_digest: str
    authority_receipt_digest: str
    idempotent_replay: bool

    def envelope(self) -> dict[str, Any]:
        return asdict(self)


class SQLiteHABootstrapPermitUseLedger:
    """Reference one-time permit ledger.

    Production single-use enforcement must ultimately live in an independent
    certification authority/control plane or equivalently strong shared trust
    service. This SQLite implementation only certifies the lifecycle contract.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ha_bootstrap_permit_use_v08(
                permit_id TEXT PRIMARY KEY,
                permit_digest TEXT NOT NULL,
                binding_digest TEXT NOT NULL,
                backend_id TEXT NOT NULL,
                cluster_id TEXT NOT NULL,
                topology_epoch INTEGER NOT NULL,
                bootstrap_object_key TEXT,
                bootstrap_state_digest TEXT,
                state TEXT NOT NULL,
                reserved_at TEXT NOT NULL,
                consumed_at TEXT
            )
            """
        )
        self.conn.commit()

    def get(self, permit_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM ha_bootstrap_permit_use_v08 WHERE permit_id=?",
            (permit_id,),
        ).fetchone()
        return dict(row) if row else None

    def reserve(
        self,
        permit: HABootstrapPermit,
        binding: HABootstrapBinding,
        *,
        verified_at: datetime,
    ) -> dict[str, Any]:
        permit_digest = permit.digest()
        binding_digest = binding.digest()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM ha_bootstrap_permit_use_v08 WHERE permit_id=?",
                (permit.permit_id,),
            ).fetchone()
            if row:
                if row["permit_digest"] != permit_digest or row["binding_digest"] != binding_digest:
                    raise HardeningError(
                        "CFHS_IDEMPOTENCY_CONFLICT",
                        "Bootstrap permit id was reused for different content",
                    )
                self.conn.execute("COMMIT")
                return dict(row)
            self.conn.execute(
                """
                INSERT INTO ha_bootstrap_permit_use_v08(
                    permit_id,permit_digest,binding_digest,backend_id,cluster_id,
                    topology_epoch,state,reserved_at
                ) VALUES(?,?,?,?,?,?,'RESERVED',?)
                """,
                (
                    permit.permit_id,
                    permit_digest,
                    binding_digest,
                    binding.backend_id,
                    binding.cluster_id,
                    binding.topology_epoch,
                    verified_at.isoformat(),
                ),
            )
            self.conn.execute("COMMIT")
        except Exception:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        reserved = self.get(permit.permit_id)
        if not reserved:
            raise HardeningError("CFHS_HA_BOOTSTRAP_DENIED", "Bootstrap permit reservation was not persisted")
        return reserved

    def consume(
        self,
        permit_id: str,
        *,
        object_key: str,
        bootstrap_state_digest: str,
        consumed_at: datetime,
    ) -> dict[str, Any]:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM ha_bootstrap_permit_use_v08 WHERE permit_id=?",
                (permit_id,),
            ).fetchone()
            if not row:
                raise HardeningError("CFHS_HA_BOOTSTRAP_DENIED", "Bootstrap permit was not reserved")
            if row["state"] == "CONSUMED":
                if (
                    row["bootstrap_object_key"] != object_key
                    or row["bootstrap_state_digest"] != bootstrap_state_digest
                ):
                    raise HardeningError(
                        "CFHS_IDEMPOTENCY_CONFLICT",
                        "Consumed bootstrap permit is bound to different initialized state",
                    )
                self.conn.execute("COMMIT")
                return dict(row)
            if row["state"] != "RESERVED":
                raise HardeningError("CFHS_HA_BOOTSTRAP_DENIED", "Bootstrap permit is not consumable")
            self.conn.execute(
                """
                UPDATE ha_bootstrap_permit_use_v08
                SET bootstrap_object_key=?,bootstrap_state_digest=?,state='CONSUMED',consumed_at=?
                WHERE permit_id=?
                """,
                (object_key, bootstrap_state_digest, consumed_at.isoformat(), permit_id),
            )
            self.conn.execute("COMMIT")
        except Exception:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        consumed = self.get(permit_id)
        if not consumed:
            raise HardeningError("CFHS_HA_BOOTSTRAP_DENIED", "Bootstrap permit consumption was not persisted")
        return consumed


class HACertificationBootstrapCoordinator:
    """Initializes only the reserved HA certification bootstrap state.

    It intentionally has no caller-supplied object key and no generic write
    method. The narrow exception exists solely to break first-certification
    circularity after external authority verifies the exact certification.
    """

    def __init__(
        self,
        backend: BootstrapWritableBackend,
        verifier: HABootstrapPermitVerifier,
        permit_ledger: SQLiteHABootstrapPermitUseLedger,
        *,
        max_permit_lifetime_seconds: int = 300,
        max_issue_future_skew_seconds: int = 60,
    ):
        if (
            isinstance(max_permit_lifetime_seconds, bool)
            or not isinstance(max_permit_lifetime_seconds, int)
            or max_permit_lifetime_seconds < 30
            or max_permit_lifetime_seconds > 900
        ):
            raise HardeningError("CFHS_INVALID_POLICY", "HA bootstrap permit lifetime policy is invalid")
        if (
            isinstance(max_issue_future_skew_seconds, bool)
            or not isinstance(max_issue_future_skew_seconds, int)
            or max_issue_future_skew_seconds < 0
            or max_issue_future_skew_seconds > 300
        ):
            raise HardeningError("CFHS_INVALID_POLICY", "HA bootstrap future-skew policy is invalid")
        self.backend = backend
        self.verifier = verifier
        self.permit_ledger = permit_ledger
        self.max_permit_lifetime_seconds = max_permit_lifetime_seconds
        self.max_issue_future_skew_seconds = max_issue_future_skew_seconds

    @staticmethod
    def bootstrap_object_key(backend_id: str) -> str:
        return "/_cfhs/ha/certification/bootstrap/" + sha256_hex(backend_id)[:32]

    def _verify_permit(
        self,
        permit: HABootstrapPermit,
        binding: HABootstrapBinding,
    ) -> VerifiedHABootstrapPermit:
        if permit.purpose != BOOTSTRAP_PURPOSE:
            raise HardeningError("CFHS_HA_BOOTSTRAP_DENIED", "Bootstrap permit purpose is not allowed")
        if permit.binding() != binding:
            raise HardeningError("CFHS_HA_BOOTSTRAP_DENIED", "Bootstrap permit does not bind the exact certification")
        if not permit.permit_id or not permit.permit_nonce or not permit.authority_id:
            raise HardeningError("CFHS_HA_BOOTSTRAP_DENIED", "Bootstrap permit identity/provenance is incomplete")
        if permit.authority_class not in ALLOWED_BOOTSTRAP_AUTHORITY_CLASSES:
            raise HardeningError("CFHS_HA_BOOTSTRAP_DENIED", "Bootstrap authority class is not accepted")

        issued = _parse_time(permit.issued_at, "bootstrap permit issued_at")
        expires = _parse_time(permit.expires_at, "bootstrap permit expires_at")
        if expires <= issued:
            raise HardeningError("CFHS_HA_BOOTSTRAP_DENIED", "Bootstrap permit expiry must follow issuance")
        if (expires - issued).total_seconds() > self.max_permit_lifetime_seconds:
            raise HardeningError("CFHS_HA_BOOTSTRAP_DENIED", "Bootstrap permit lifetime exceeds policy")

        try:
            verified = self.verifier.verify(permit, binding)
        except Exception as exc:
            raise HardeningError("CFHS_HA_BOOTSTRAP_DENIED", "External bootstrap permit verification failed") from exc
        if verified.permit_digest != permit.digest() or verified.binding_digest != binding.digest():
            raise HardeningError("CFHS_HA_BOOTSTRAP_DENIED", "Verified bootstrap receipt does not bind the permit/certification")
        if verified.authority_id != permit.authority_id or verified.authority_class != permit.authority_class:
            raise HardeningError("CFHS_HA_BOOTSTRAP_DENIED", "Verified bootstrap authority identity/class mismatch")
        if not verified.authority_receipt_digest:
            raise HardeningError("CFHS_HA_BOOTSTRAP_DENIED", "Verified bootstrap authority receipt digest is missing")
        verified_at = _parse_time(verified.verified_at, "bootstrap permit verification")
        if issued - verified_at > __import__("datetime").timedelta(seconds=self.max_issue_future_skew_seconds):
            raise HardeningError("CFHS_HA_BOOTSTRAP_DENIED", "Bootstrap permit issuance is unreasonably in the future")
        if verified_at >= expires:
            raise HardeningError("CFHS_HA_BOOTSTRAP_EXPIRED", "Bootstrap permit is expired")
        return verified

    def initialize(
        self,
        certification: HAPersistenceCertification,
        evidence: HADeploymentEvidence,
        permit: HABootstrapPermit,
    ) -> HABootstrapResult:
        binding = HABootstrapBinding.from_certification(certification, evidence)
        backend_id = self.backend.capabilities().backend_id
        if backend_id != binding.backend_id:
            raise HardeningError("CFHS_HA_BOOTSTRAP_DENIED", "Bootstrap target backend identity mismatch")
        verified = self._verify_permit(permit, binding)
        verified_at = _parse_time(verified.verified_at, "bootstrap permit verification")

        prior_use = self.permit_ledger.reserve(
            permit,
            binding,
            verified_at=verified_at,
        )
        object_key = self.bootstrap_object_key(binding.backend_id)
        bootstrap_state = {
            "contract": "ha-certification-bootstrap/v0.8",
            "status": "BOOTSTRAPPED",
            "backend_id": binding.backend_id,
            "cluster_id": binding.cluster_id,
            "topology_epoch": binding.topology_epoch,
            "evidence_digest": binding.evidence_digest,
            "certification_decision_digest": binding.certification_decision_digest,
            "attestation_digest": binding.attestation_digest,
            "permit_id": permit.permit_id,
            "permit_digest": permit.digest(),
            "binding_digest": binding.digest(),
            "authority_id": verified.authority_id,
            "authority_class": verified.authority_class,
            "authority_receipt_digest": verified.authority_receipt_digest,
            "verified_at": verified.verified_at,
        }
        state_digest = sha256_hex(bootstrap_state)
        existing = self.backend.read(object_key)
        if existing is None:
            created = self.backend.put_if_absent(object_key, bootstrap_state)
        else:
            created = existing
        if created.value_digest != state_digest or created.value != bootstrap_state:
            raise HardeningError(
                "CFHS_HA_BOOTSTRAP_CONFLICT",
                "Reserved HA bootstrap object already contains different state",
                {"object_key": object_key},
            )
        observed = self.backend.read(object_key)
        if observed is None or observed.value_digest != state_digest or observed.value != bootstrap_state:
            raise HardeningError("CFHS_HA_BOOTSTRAP_DENIED", "HA bootstrap state failed read-after-write verification")

        consumed = self.permit_ledger.consume(
            permit.permit_id,
            object_key=object_key,
            bootstrap_state_digest=state_digest,
            consumed_at=verified_at,
        )
        return HABootstrapResult(
            object_key=object_key,
            object_version=observed.version,
            bootstrap_state_digest=state_digest,
            permit_digest=permit.digest(),
            authority_receipt_digest=verified.authority_receipt_digest,
            idempotent_replay=prior_use["state"] == "CONSUMED" or consumed["reserved_at"] != consumed["consumed_at"],
        )
