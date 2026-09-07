import sqlite3
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kernel.certification_plane_attestation import (
    AdapterTrustStoreReadiness,
    CertificationPlaneAdapterAttestation,
    CertificationPlaneAdapterCertifier,
    CertificationPlaneDeploymentIdentity,
    VerifiedCertificationPlaneAdapterAttestation,
)
from kernel.certification_plane_attestation_store import SQLiteReferenceAdapterAttestationTrustStore
from kernel.hardening import HardeningError
from kernel.shared_certification_plane import SharedStateCertificationPlane
from kernel.shared_state_backend import SharedBackendCapabilities, SQLiteSharedStateBackend
from kernel.trust import sha256_hex


class AttestationBackend(SQLiteSharedStateBackend):
    def __init__(self, path, *, backend_id="attested-plane-backend-v08", now=None):
        super().__init__(path, backend_id=backend_id)
        self.now = now or datetime.now(timezone.utc)

    def authoritative_now(self):
        return self.now

    def capabilities(self):
        return SharedBackendCapabilities(
            backend_id=self.backend_id,
            serializable_transactions=True,
            compare_and_swap=True,
            monotonic_fencing=True,
            durable_ordered_journal=True,
            multi_connection_visibility=True,
            synchronous_durability=True,
            authoritative_time=True,
            distributed_quorum=True,
        )


class ExactVerifier:
    def __init__(self, now):
        self.now = now

    def verify(self, attestation, deployment):
        return VerifiedCertificationPlaneAdapterAttestation(
            attestation_digest=attestation.digest(),
            deployment_digest=deployment.digest(),
            authority_id=attestation.authority_id,
            authority_class=attestation.authority_class,
            key_id=attestation.key_id,
            authority_generation=attestation.authority_generation,
            verified_at=self.now.isoformat(),
            verifier_receipt_digest=sha256_hex(
                {
                    "attestation": attestation.digest(),
                    "deployment": deployment.digest(),
                    "verified_at": self.now.isoformat(),
                }
            ),
        )


class TestProductionTrustStore(SQLiteReferenceAdapterAttestationTrustStore):
    """Test double only: proves the certifier contract, not production infrastructure."""

    def readiness(self):
        return AdapterTrustStoreReadiness(True, self.trust_store_id, None)


class CertificationPlaneAttestationV08Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.backend_path = self.root / "plane.db"
        self.trust_path = self.root / "trust.db"
        self.now = datetime(2026, 9, 7, 4, 0, tzinfo=timezone.utc)
        self.backend = AttestationBackend(self.backend_path, now=self.now)
        self.plane = SharedStateCertificationPlane(self.backend)
        self.cluster_id = "attested-cluster-001"
        self.adapter_name = "company-os-ha-certification-plane"
        self.adapter_digest = sha256_hex({"release": "certification-plane-v0.8.1"})
        self.topology_digest = sha256_hex({"topology": "observed-001"})
        self.probe_digest = sha256_hex({"probe-report": "observed-001"})
        self.plane.prepare_handoff(
            cluster_id=self.cluster_id,
            topology_epoch=41,
            handoff_digest="attestation-seed-handoff",
            bootstrap_state_digest="b" * 64,
            control_state_digest="c" * 64,
            owner_id="seed-certifier",
        )
        self.verifier = ExactVerifier(self.now)
        self.certifier = CertificationPlaneAdapterCertifier(
            expected_adapter_name=self.adapter_name,
            expected_adapter_implementation_digest=self.adapter_digest,
            max_attestation_age_seconds=300,
            max_attestation_lifetime_seconds=600,
        )
        self.trust_conn = self._conn(self.trust_path)
        self.reference_store = SQLiteReferenceAdapterAttestationTrustStore(self.trust_conn)

    @staticmethod
    def _conn(path):
        conn = sqlite3.connect(path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def tearDown(self):
        self.backend.close()
        self.trust_conn.close()
        self.tmp.cleanup()

    def deployment(self, **overrides):
        values = {
            "deployment_id": "cert-plane-deployment-001",
            "cluster_id": self.cluster_id,
            "adapter_name": self.adapter_name,
            "adapter_version": "0.8.1",
            "adapter_implementation_digest": self.adapter_digest,
            "topology_evidence_digest": self.topology_digest,
            "probe_evidence_digest": self.probe_digest,
        }
        values.update(overrides)
        return CertificationPlaneDeploymentIdentity.from_plane(self.plane, **values)

    def attestation(self, deployment, **overrides):
        values = {
            "attestation_id": "adapter-attestation-001",
            "deployment_digest": deployment.digest(),
            "authority_id": "release-authority",
            "authority_class": "independent_release_attestation",
            "key_id": "release-key-1",
            "authority_generation": 1,
            "attestation_nonce": "adapter-attestation-nonce-001",
            "issued_at": (self.now - timedelta(seconds=10)).isoformat(),
            "expires_at": (self.now + timedelta(seconds=180)).isoformat(),
        }
        values.update(overrides)
        return CertificationPlaneAdapterAttestation(**values)

    def production_store(self, conn=None):
        return TestProductionTrustStore(conn or self.trust_conn, trust_store_id="test-production-trust-store")

    def certify(self, deployment=None, attestation=None, store=None, verifier=None, now=None):
        deployment = deployment or self.deployment()
        if attestation is None:
            attestation = self.attestation(deployment)
        return self.certifier.certify(
            self.plane,
            deployment,
            attestation,
            verifier if verifier is not None else self.verifier,
            store or self.production_store(),
            now=now or self.now,
        )

    def test_missing_adapter_attestation_is_rejected(self):
        deployment = self.deployment()
        result = self.certifier.certify(
            self.plane,
            deployment,
            None,
            self.verifier,
            self.production_store(),
            now=self.now,
        )
        self.assertFalse(result.production_ready)
        self.assertIn("adapter_attestation", result.missing_requirements)

    def test_stale_adapter_attestation_is_rejected(self):
        deployment = self.deployment()
        attestation = self.attestation(
            deployment,
            issued_at=(self.now - timedelta(seconds=301)).isoformat(),
            expires_at=(self.now + timedelta(seconds=100)).isoformat(),
        )
        result = self.certify(deployment, attestation)
        self.assertFalse(result.production_ready)
        self.assertIn("adapter_attestation_freshness", result.missing_requirements)

    def test_wrong_backend_identity_is_rejected(self):
        deployment = replace(self.deployment(), backend_id="other-backend")
        attestation = self.attestation(deployment)
        result = self.certify(deployment, attestation)
        self.assertFalse(result.production_ready)
        self.assertIn("deployment_backend_identity", result.missing_requirements)

    def test_wrong_cluster_identity_is_rejected(self):
        deployment = self.deployment(cluster_id="other-cluster")
        attestation = self.attestation(deployment)
        result = self.certify(deployment, attestation)
        self.assertFalse(result.production_ready)
        self.assertIn("deployment_cluster_identity", result.missing_requirements)

    def test_wrong_adapter_implementation_digest_is_rejected(self):
        deployment = self.deployment(adapter_implementation_digest="0" * 64)
        attestation = self.attestation(deployment)
        result = self.certify(deployment, attestation)
        self.assertFalse(result.production_ready)
        self.assertIn("trusted_adapter_implementation_digest", result.missing_requirements)

    def test_tampered_capability_binding_is_rejected(self):
        deployment = replace(self.deployment(), backend_capabilities_digest="f" * 64)
        attestation = self.attestation(deployment)
        result = self.certify(deployment, attestation)
        self.assertFalse(result.production_ready)
        self.assertIn("backend_capability_binding", result.missing_requirements)

    def test_attestation_replay_across_deployments_is_rejected(self):
        original = self.deployment()
        attestation = self.attestation(original)
        other = self.deployment(deployment_id="cert-plane-deployment-002")
        result = self.certify(other, attestation)
        self.assertFalse(result.production_ready)
        self.assertIn("adapter_attestation_deployment_binding", result.missing_requirements)

    def test_authority_key_rotation_requires_monotonic_generation(self):
        deployment = self.deployment()
        first = self.attestation(deployment)
        self.assertTrue(self.certify(deployment, first).production_ready)
        rotated = self.attestation(
            deployment,
            attestation_id="adapter-attestation-002",
            key_id="release-key-2",
            authority_generation=2,
            attestation_nonce="adapter-attestation-nonce-002",
        )
        self.assertTrue(self.certify(deployment, rotated).production_ready)
        current = self.reference_store.current(deployment.deployment_id)
        self.assertEqual(current["authority_generation"], 2)
        self.assertEqual(current["key_id"], "release-key-2")

    def test_older_authority_generation_is_rejected_after_rotation(self):
        deployment = self.deployment()
        generation_two = self.attestation(
            deployment,
            attestation_id="adapter-attestation-002",
            key_id="release-key-2",
            authority_generation=2,
            attestation_nonce="adapter-attestation-nonce-002",
        )
        self.assertTrue(self.certify(deployment, generation_two).production_ready)
        old = self.attestation(
            deployment,
            attestation_id="adapter-attestation-old",
            key_id="release-key-1",
            authority_generation=1,
            attestation_nonce="adapter-attestation-old-nonce",
        )
        with self.assertRaises(HardeningError) as cm:
            self.certify(deployment, old)
        self.assertEqual(cm.exception.code, "CFHS_AUTHORITY_ROLLBACK")

    def test_restart_preserves_accepted_adapter_identity_and_generation(self):
        deployment = self.deployment()
        rotated = self.attestation(
            deployment,
            attestation_id="adapter-attestation-003",
            key_id="release-key-3",
            authority_generation=3,
            attestation_nonce="adapter-attestation-nonce-003",
        )
        self.assertTrue(self.certify(deployment, rotated).production_ready)
        self.trust_conn.close()
        restarted_conn = self._conn(self.trust_path)
        try:
            restarted = SQLiteReferenceAdapterAttestationTrustStore(restarted_conn)
            current = restarted.current(deployment.deployment_id)
            self.assertEqual(current["backend_id"], deployment.backend_id)
            self.assertEqual(current["cluster_id"], deployment.cluster_id)
            self.assertEqual(current["authority_generation"], 3)
            self.assertEqual(current["deployment_digest"], deployment.digest())
        finally:
            restarted_conn.close()
            self.trust_conn = self._conn(self.trust_path)
            self.reference_store = SQLiteReferenceAdapterAttestationTrustStore(self.trust_conn)

    def test_reference_trust_store_keeps_adapter_non_production(self):
        deployment = self.deployment()
        attestation = self.attestation(deployment)
        result = self.certifier.certify(
            self.plane,
            deployment,
            attestation,
            self.verifier,
            self.reference_store,
            now=self.now,
        )
        self.assertFalse(result.production_ready)
        self.assertIn("production_adapter_attestation_trust_store", result.missing_requirements)
        self.assertFalse(self.plane.readiness().production_ready)

    def test_production_ready_requires_semantics_verification_and_production_trust_store(self):
        deployment = self.deployment()
        attestation = self.attestation(deployment)
        ready = self.certify(deployment, attestation)
        self.assertTrue(ready.production_ready)
        self.assertEqual(ready.missing_requirements, ())
        self.assertEqual(ready.deployment_digest, deployment.digest())
        self.assertEqual(ready.attestation_digest, attestation.digest())
        self.assertTrue(ready.verifier_receipt_digest)
        no_verifier = self.certifier.certify(
            self.plane,
            deployment,
            attestation,
            None,
            self.production_store(),
            now=self.now,
        )
        self.assertFalse(no_verifier.production_ready)
        self.assertIn("adapter_attestation_verifier", no_verifier.missing_requirements)


if __name__ == "__main__":
    unittest.main()
