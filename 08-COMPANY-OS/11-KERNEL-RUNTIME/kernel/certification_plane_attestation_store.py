from __future__ import annotations

import sqlite3
from typing import Any

from .certification_plane_attestation import (
    AdapterTrustStoreReadiness,
    CertificationPlaneAdapterAttestation,
    CertificationPlaneDeploymentIdentity,
    VerifiedCertificationPlaneAdapterAttestation,
)
from .hardening import HardeningError


class SQLiteReferenceAdapterAttestationTrustStore:
    """Durable reference replay/rollback ledger for adapter attestations.

    Persistence is deliberate so restart semantics can be certified. This class
    still reports production_ready=False; SQLite durability is not an external
    production release authority or distributed trust service.
    """

    def __init__(self, conn: sqlite3.Connection, *, trust_store_id: str = "sqlite-reference-adapter-trust-v08"):
        self.conn = conn
        self.trust_store_id = trust_store_id
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS adapter_deployment_trust_v08(
                deployment_id TEXT PRIMARY KEY,
                backend_id TEXT NOT NULL,
                cluster_id TEXT NOT NULL,
                deployment_digest TEXT NOT NULL,
                authority_id TEXT NOT NULL,
                key_id TEXT NOT NULL,
                authority_generation INTEGER NOT NULL,
                attestation_digest TEXT NOT NULL,
                verifier_receipt_digest TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS adapter_attestation_nonce_v08(
                deployment_id TEXT NOT NULL,
                attestation_nonce TEXT NOT NULL,
                attestation_digest TEXT NOT NULL,
                PRIMARY KEY(deployment_id,attestation_nonce)
            );
            """
        )
        self.conn.commit()

    def readiness(self) -> AdapterTrustStoreReadiness:
        return AdapterTrustStoreReadiness(
            production_ready=False,
            trust_store_id=self.trust_store_id,
            reason="sqlite_reference_trust_store_not_production_authority",
        )

    def current(self, deployment_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM adapter_deployment_trust_v08 WHERE deployment_id=?",
            (deployment_id,),
        ).fetchone()
        return dict(row) if row else None

    def accept(
        self,
        deployment: CertificationPlaneDeploymentIdentity,
        attestation: CertificationPlaneAdapterAttestation,
        verified: VerifiedCertificationPlaneAdapterAttestation,
    ) -> None:
        deployment_digest = deployment.digest()
        attestation_digest = attestation.digest()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            nonce_row = self.conn.execute(
                "SELECT attestation_digest FROM adapter_attestation_nonce_v08 WHERE deployment_id=? AND attestation_nonce=?",
                (deployment.deployment_id, attestation.attestation_nonce),
            ).fetchone()
            if nonce_row and nonce_row["attestation_digest"] != attestation_digest:
                raise HardeningError("CFHS_EVIDENCE_REPLAY", "Adapter attestation nonce was reused for different content")

            row = self.conn.execute(
                "SELECT * FROM adapter_deployment_trust_v08 WHERE deployment_id=?",
                (deployment.deployment_id,),
            ).fetchone()
            if row:
                if row["backend_id"] != deployment.backend_id or row["cluster_id"] != deployment.cluster_id:
                    raise HardeningError("CFHS_CLUSTER_IDENTITY_CONFLICT", "Adapter deployment backend/cluster identity changed")
                previous_generation = int(row["authority_generation"])
                if attestation.authority_generation < previous_generation:
                    raise HardeningError("CFHS_AUTHORITY_ROLLBACK", "Adapter attestation authority generation cannot move backward")
                if attestation.authority_generation == previous_generation:
                    if row["authority_id"] != attestation.authority_id or row["key_id"] != attestation.key_id:
                        raise HardeningError("CFHS_AUTHORITY_CONFLICT", "Adapter authority/key changed without a generation advance")
                    if row["deployment_digest"] != deployment_digest:
                        raise HardeningError("CFHS_HA_CERTIFICATION_CONFLICT", "Adapter deployment changed within the same authority generation")

            self.conn.execute(
                """
                INSERT INTO adapter_deployment_trust_v08(
                    deployment_id,backend_id,cluster_id,deployment_digest,
                    authority_id,key_id,authority_generation,attestation_digest,
                    verifier_receipt_digest
                ) VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(deployment_id) DO UPDATE SET
                    deployment_digest=excluded.deployment_digest,
                    authority_id=excluded.authority_id,
                    key_id=excluded.key_id,
                    authority_generation=excluded.authority_generation,
                    attestation_digest=excluded.attestation_digest,
                    verifier_receipt_digest=excluded.verifier_receipt_digest
                """,
                (
                    deployment.deployment_id,
                    deployment.backend_id,
                    deployment.cluster_id,
                    deployment_digest,
                    attestation.authority_id,
                    attestation.key_id,
                    attestation.authority_generation,
                    attestation_digest,
                    verified.verifier_receipt_digest,
                ),
            )
            self.conn.execute(
                """
                INSERT INTO adapter_attestation_nonce_v08(deployment_id,attestation_nonce,attestation_digest)
                VALUES(?,?,?)
                ON CONFLICT(deployment_id,attestation_nonce) DO NOTHING
                """,
                (deployment.deployment_id, attestation.attestation_nonce, attestation_digest),
            )
            self.conn.execute("COMMIT")
        except Exception:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
