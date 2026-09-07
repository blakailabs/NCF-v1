from __future__ import annotations

import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .ha_bootstrap_authority import HABootstrapBinding, HABootstrapResult, HACertificationBootstrapCoordinator
from .ha_certification_runtime import CertifiedSharedPersistence, HACertificationRecord, SQLiteHACertificationLedger
from .ha_persistence import HADeploymentEvidence, HAPersistenceCertification
from .hardening import HardeningError
from .shared_state_backend import SharedBackendCapabilities, SharedObject, certify_backend
from .trust import sha256_hex


HANDOFF_CONTRACT = "ha-certification-handoff/v0.8"
CONTROL_CONTRACT = "ha-certification-control/v0.8"


@dataclass(frozen=True)
class HAHandoffRecord:
    backend_id: str
    cluster_id: str
    topology_epoch: int
    handoff_digest: str
    bootstrap_state_digest: str
    control_object_key: str | None
    control_state_digest: str | None
    certification_id: str | None
    status: str
    prepared_at: str
    activated_at: str | None
    closed_at: str | None

    def envelope(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HAHandoffResult:
    backend_id: str
    cluster_id: str
    topology_epoch: int
    handoff_digest: str
    control_object_key: str
    control_state_digest: str
    certification_id: str
    status: str
    idempotent_replay: bool

    def envelope(self) -> dict[str, Any]:
        return asdict(self)


class SQLiteHAHandoffLedger:
    """Reference durable lifecycle for the one-time bootstrap-to-steady-state handoff.

    Production deployment must place equivalent state in an independently trusted
    control plane or the certified shared persistence system. SQLite is used only
    to certify transition, rollback, concurrency and idempotency semantics.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ha_certification_handoff_v08(
                backend_id TEXT PRIMARY KEY,
                cluster_id TEXT NOT NULL,
                topology_epoch INTEGER NOT NULL,
                handoff_digest TEXT NOT NULL,
                bootstrap_state_digest TEXT NOT NULL,
                control_object_key TEXT,
                control_state_digest TEXT,
                certification_id TEXT,
                status TEXT NOT NULL,
                prepared_at TEXT NOT NULL,
                activated_at TEXT,
                closed_at TEXT
            )
            """
        )
        self.conn.commit()

    @staticmethod
    def _record(row: sqlite3.Row) -> HAHandoffRecord:
        return HAHandoffRecord(
            backend_id=row["backend_id"],
            cluster_id=row["cluster_id"],
            topology_epoch=int(row["topology_epoch"]),
            handoff_digest=row["handoff_digest"],
            bootstrap_state_digest=row["bootstrap_state_digest"],
            control_object_key=row["control_object_key"],
            control_state_digest=row["control_state_digest"],
            certification_id=row["certification_id"],
            status=row["status"],
            prepared_at=row["prepared_at"],
            activated_at=row["activated_at"],
            closed_at=row["closed_at"],
        )

    def get(self, backend_id: str) -> HAHandoffRecord | None:
        row = self.conn.execute(
            "SELECT * FROM ha_certification_handoff_v08 WHERE backend_id=?",
            (backend_id,),
        ).fetchone()
        return self._record(row) if row else None

    def begin(
        self,
        *,
        backend_id: str,
        cluster_id: str,
        topology_epoch: int,
        handoff_digest: str,
        bootstrap_state_digest: str,
        at: datetime,
    ) -> HAHandoffRecord:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM ha_certification_handoff_v08 WHERE backend_id=?",
                (backend_id,),
            ).fetchone()
            if row:
                record = self._record(row)
                if record.cluster_id != cluster_id:
                    raise HardeningError("CFHS_CLUSTER_IDENTITY_CONFLICT", "HA handoff cluster identity changed")
                if topology_epoch < record.topology_epoch:
                    raise HardeningError("CFHS_TOPOLOGY_ROLLBACK", "HA handoff topology epoch cannot move backward")
                if record.status == "CLOSED" and record.handoff_digest != handoff_digest:
                    raise HardeningError("CFHS_HA_BOOTSTRAP_CLOSED", "First-bootstrap authority is permanently closed for this backend lineage")
                if (
                    record.handoff_digest != handoff_digest
                    or record.topology_epoch != topology_epoch
                    or record.bootstrap_state_digest != bootstrap_state_digest
                ):
                    raise HardeningError("CFHS_HA_HANDOFF_CONFLICT", "Existing HA handoff is bound to different bootstrap/certification state")
                self.conn.execute("COMMIT")
                return record
            self.conn.execute(
                """
                INSERT INTO ha_certification_handoff_v08(
                    backend_id,cluster_id,topology_epoch,handoff_digest,
                    bootstrap_state_digest,status,prepared_at
                ) VALUES(?,?,?,?,?,'PREPARED',?)
                """,
                (
                    backend_id,
                    cluster_id,
                    topology_epoch,
                    handoff_digest,
                    bootstrap_state_digest,
                    at.astimezone(timezone.utc).isoformat(),
                ),
            )
            self.conn.execute("COMMIT")
        except Exception:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        record = self.get(backend_id)
        if not record:
            raise HardeningError("CFHS_HA_HANDOFF_DENIED", "HA handoff preparation was not persisted")
        return record

    def bind_control(self, backend_id: str, *, object_key: str, state_digest: str) -> HAHandoffRecord:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM ha_certification_handoff_v08 WHERE backend_id=?",
                (backend_id,),
            ).fetchone()
            if not row:
                raise HardeningError("CFHS_HA_HANDOFF_DENIED", "HA handoff was not prepared")
            record = self._record(row)
            if record.control_object_key is not None and (
                record.control_object_key != object_key or record.control_state_digest != state_digest
            ):
                raise HardeningError("CFHS_HA_HANDOFF_CONFLICT", "HA handoff control object changed")
            self.conn.execute(
                """
                UPDATE ha_certification_handoff_v08
                SET control_object_key=?,control_state_digest=?
                WHERE backend_id=?
                """,
                (object_key, state_digest, backend_id),
            )
            self.conn.execute("COMMIT")
        except Exception:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        return self.get(backend_id)  # type: ignore[return-value]

    def mark_activated(self, backend_id: str, certification_id: str, *, at: datetime) -> HAHandoffRecord:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM ha_certification_handoff_v08 WHERE backend_id=?",
                (backend_id,),
            ).fetchone()
            if not row:
                raise HardeningError("CFHS_HA_HANDOFF_DENIED", "HA handoff was not prepared")
            record = self._record(row)
            if record.certification_id and record.certification_id != certification_id:
                raise HardeningError("CFHS_HA_HANDOFF_CONFLICT", "HA handoff activation changed certification identity")
            self.conn.execute(
                """
                UPDATE ha_certification_handoff_v08
                SET certification_id=?,status=CASE WHEN status='CLOSED' THEN status ELSE 'ACTIVATED' END,
                    activated_at=COALESCE(activated_at,?)
                WHERE backend_id=?
                """,
                (certification_id, at.astimezone(timezone.utc).isoformat(), backend_id),
            )
            self.conn.execute("COMMIT")
        except Exception:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        return self.get(backend_id)  # type: ignore[return-value]

    def close(self, backend_id: str, *, certification_id: str, at: datetime) -> HAHandoffRecord:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM ha_certification_handoff_v08 WHERE backend_id=?",
                (backend_id,),
            ).fetchone()
            if not row:
                raise HardeningError("CFHS_HA_HANDOFF_DENIED", "HA handoff was not prepared")
            record = self._record(row)
            if not record.control_object_key or not record.control_state_digest:
                raise HardeningError("CFHS_HA_HANDOFF_DENIED", "HA handoff control object is not bound")
            if record.certification_id != certification_id:
                raise HardeningError("CFHS_HA_HANDOFF_DENIED", "HA handoff is not activated with the expected certificate")
            self.conn.execute(
                """
                UPDATE ha_certification_handoff_v08
                SET status='CLOSED',closed_at=COALESCE(closed_at,?)
                WHERE backend_id=?
                """,
                (at.astimezone(timezone.utc).isoformat(), backend_id),
            )
            self.conn.execute("COMMIT")
        except Exception:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        return self.get(backend_id)  # type: ignore[return-value]

    def require_closed(self, backend_id: str) -> HAHandoffRecord:
        record = self.get(backend_id)
        if not record or record.status != "CLOSED":
            raise HardeningError("CFHS_HA_HANDOFF_INCOMPLETE", "HA bootstrap-to-steady-state handoff is not fully closed")
        return record


class HACertificationHandoffCoordinator:
    """Moves one externally bootstrapped HA certificate into steady-state authority.

    The coordinator uses raw backend access only for two reserved control objects:
    the already-created bootstrap object and the deterministic shared certificate
    control object. Ordinary shared-state access remains unavailable until the
    handoff ledger is CLOSED and the same certificate is still active.
    """

    def __init__(
        self,
        backend,
        certification_ledger: SQLiteHACertificationLedger,
        handoff_ledger: SQLiteHAHandoffLedger,
        *,
        phase_hook: Callable[[str], None] | None = None,
    ):
        self.backend = backend
        self.certification_ledger = certification_ledger
        self.handoff_ledger = handoff_ledger
        self.phase_hook = phase_hook

    @staticmethod
    def control_object_key(backend_id: str) -> str:
        return "/_cfhs/ha/certification/control/" + sha256_hex(backend_id)[:32]

    def _phase(self, name: str) -> None:
        if self.phase_hook:
            self.phase_hook(name)

    def _now(self) -> datetime:
        now = self.backend.authoritative_now()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise HardeningError("CFHS_HA_HANDOFF_DENIED", "HA handoff requires backend-authoritative timezone-aware time")
        return now.astimezone(timezone.utc)

    def _verify_bootstrap(
        self,
        binding: HABootstrapBinding,
        bootstrap: HABootstrapResult,
    ) -> dict[str, Any]:
        expected_key = HACertificationBootstrapCoordinator.bootstrap_object_key(binding.backend_id)
        if bootstrap.object_key != expected_key:
            raise HardeningError("CFHS_HA_HANDOFF_DENIED", "Bootstrap result object key is not canonical")
        observed = self.backend.read(expected_key)
        if observed is None:
            raise HardeningError("CFHS_HA_HANDOFF_DENIED", "Reserved HA bootstrap object is missing")
        if observed.value_digest != bootstrap.bootstrap_state_digest or sha256_hex(observed.value) != bootstrap.bootstrap_state_digest:
            raise HardeningError("CFHS_HA_BOOTSTRAP_CONFLICT", "Reserved HA bootstrap object was tampered with")
        value = observed.value
        expected = {
            "contract": "ha-certification-bootstrap/v0.8",
            "status": "BOOTSTRAPPED",
            "backend_id": binding.backend_id,
            "cluster_id": binding.cluster_id,
            "topology_epoch": binding.topology_epoch,
            "evidence_digest": binding.evidence_digest,
            "certification_decision_digest": binding.certification_decision_digest,
            "attestation_digest": binding.attestation_digest,
            "permit_digest": bootstrap.permit_digest,
            "authority_receipt_digest": bootstrap.authority_receipt_digest,
        }
        for field, expected_value in expected.items():
            if value.get(field) != expected_value:
                raise HardeningError("CFHS_HA_HANDOFF_DENIED", f"Bootstrap object field {field} does not match handoff binding")
        if not value.get("permit_id") or not value.get("authority_id") or not value.get("binding_digest"):
            raise HardeningError("CFHS_HA_HANDOFF_DENIED", "Bootstrap object provenance is incomplete")
        if value.get("binding_digest") != binding.digest():
            raise HardeningError("CFHS_HA_HANDOFF_DENIED", "Bootstrap object binding digest mismatch")
        return value

    def handoff(
        self,
        certification: HAPersistenceCertification,
        evidence: HADeploymentEvidence,
        bootstrap: HABootstrapResult,
    ) -> HAHandoffResult:
        binding = HABootstrapBinding.from_certification(certification, evidence)
        capabilities: SharedBackendCapabilities = self.backend.capabilities()
        capability_result = certify_backend(capabilities)
        if capabilities.backend_id != binding.backend_id or not capability_result.production_ready:
            raise HardeningError("CFHS_HA_HANDOFF_DENIED", "HA handoff target backend does not satisfy the certified capability contract")

        bootstrap_state = self._verify_bootstrap(binding, bootstrap)
        handoff_digest = sha256_hex(
            {
                "contract": HANDOFF_CONTRACT,
                "binding_digest": binding.digest(),
                "bootstrap_state_digest": bootstrap.bootstrap_state_digest,
                "permit_digest": bootstrap.permit_digest,
                "authority_receipt_digest": bootstrap.authority_receipt_digest,
            }
        )
        current = self._now()
        before = self.handoff_ledger.get(binding.backend_id)
        state = self.handoff_ledger.begin(
            backend_id=binding.backend_id,
            cluster_id=binding.cluster_id,
            topology_epoch=binding.topology_epoch,
            handoff_digest=handoff_digest,
            bootstrap_state_digest=bootstrap.bootstrap_state_digest,
            at=current,
        )

        if state.status == "CLOSED":
            active = self.certification_ledger.require_active(binding.backend_id, authoritative_now=current)
            self._verify_active(active, binding, evidence)
            return HAHandoffResult(
                backend_id=binding.backend_id,
                cluster_id=binding.cluster_id,
                topology_epoch=binding.topology_epoch,
                handoff_digest=handoff_digest,
                control_object_key=state.control_object_key or "",
                control_state_digest=state.control_state_digest or "",
                certification_id=active.certification_id,
                status="CLOSED",
                idempotent_replay=True,
            )

        control_key = self.control_object_key(binding.backend_id)
        control_value = {
            "contract": CONTROL_CONTRACT,
            "status": "STEADY_STATE",
            "backend_id": binding.backend_id,
            "cluster_id": binding.cluster_id,
            "topology_epoch": binding.topology_epoch,
            "evidence_nonce": evidence.evidence_nonce,
            "evidence_digest": binding.evidence_digest,
            "certification_decision_digest": binding.certification_decision_digest,
            "attestation_digest": binding.attestation_digest,
            "bootstrap_state_digest": bootstrap.bootstrap_state_digest,
            "bootstrap_object_key": bootstrap.object_key,
            "permit_digest": bootstrap.permit_digest,
            "authority_receipt_digest": bootstrap.authority_receipt_digest,
            "handoff_digest": handoff_digest,
        }
        control_digest = sha256_hex(control_value)
        observed_control: SharedObject | None = self.backend.read(control_key)
        if observed_control is None:
            observed_control = self.backend.put_if_absent(control_key, control_value)
        if observed_control.value != control_value or observed_control.value_digest != control_digest:
            raise HardeningError("CFHS_HA_HANDOFF_CONFLICT", "Shared HA certification control object contains different state")
        reread = self.backend.read(control_key)
        if reread is None or reread.value != control_value or reread.value_digest != control_digest:
            raise HardeningError("CFHS_HA_HANDOFF_DENIED", "Shared HA certification control object failed read-after-write verification")
        self.handoff_ledger.bind_control(binding.backend_id, object_key=control_key, state_digest=control_digest)
        self._phase("after_control_write")

        activation_time = self._now()
        active = self.certification_ledger.record(certification, evidence, certified_at=activation_time)
        self._verify_active(active, binding, evidence)
        self.handoff_ledger.mark_activated(binding.backend_id, active.certification_id, at=activation_time)
        self._phase("after_activation")

        close_time = self._now()
        active = self.certification_ledger.require_active(binding.backend_id, authoritative_now=close_time)
        self._verify_active(active, binding, evidence)
        closed = self.handoff_ledger.close(binding.backend_id, certification_id=active.certification_id, at=close_time)
        return HAHandoffResult(
            backend_id=binding.backend_id,
            cluster_id=binding.cluster_id,
            topology_epoch=binding.topology_epoch,
            handoff_digest=handoff_digest,
            control_object_key=control_key,
            control_state_digest=control_digest,
            certification_id=active.certification_id,
            status=closed.status,
            idempotent_replay=before is not None,
        )

    @staticmethod
    def _verify_active(active: HACertificationRecord, binding: HABootstrapBinding, evidence: HADeploymentEvidence) -> None:
        if (
            active.backend_id != binding.backend_id
            or active.cluster_id != binding.cluster_id
            or active.topology_epoch != binding.topology_epoch
            or active.evidence_digest != binding.evidence_digest
            or active.evidence_nonce != evidence.evidence_nonce
            or active.attestation_digest != binding.attestation_digest
        ):
            raise HardeningError("CFHS_HA_HANDOFF_CONFLICT", "Active HA certification does not match bootstrap handoff binding")


class HandoffCertifiedSharedPersistence(CertifiedSharedPersistence):
    """Steady-state shared persistence that additionally requires bootstrap closure."""

    def __init__(self, backend, certification_ledger: SQLiteHACertificationLedger, handoff_ledger: SQLiteHAHandoffLedger):
        super().__init__(backend, certification_ledger)
        self.handoff_ledger = handoff_ledger

    def _guard(self) -> HACertificationRecord:
        self.handoff_ledger.require_closed(self.backend_id)
        return super()._guard()
