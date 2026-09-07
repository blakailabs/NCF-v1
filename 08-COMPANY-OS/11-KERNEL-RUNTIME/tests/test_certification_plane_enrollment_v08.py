import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kernel.certification_plane_attestation import (
    CertificationPlaneAdapterAttestation,
    CertificationPlaneAdapterReadiness,
    CertificationPlaneDeploymentIdentity,
)
from kernel.certification_plane_enrollment import (
    EnrolledCertificationPlaneRuntime,
    SharedAdapterEnrollmentRegistry,
)
from kernel.ha_certification_runtime import HACertificationRecord
from kernel.hardening import HardeningError
from kernel.shared_certification_plane import SharedStateCertificationPlane
from kernel.shared_state_backend import SharedBackendCapabilities, SQLiteSharedStateBackend
from kernel.trust import sha256_hex


class EnrollmentBackend(SQLiteSharedStateBackend):
    def __init__(self, path, *, backend_id="enrollment-plane-backend-v08", now=None):
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


class CertificationPlaneEnrollmentV08Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "runtime-enrollment.db"
        self.now = datetime(2026, 9, 7, 4, 20, tzinfo=timezone.utc)
        self.backend = EnrollmentBackend(self.db_path, now=self.now)
        self.plane = SharedStateCertificationPlane(self.backend, fence_ttl_seconds=5)
        self.registry = SharedAdapterEnrollmentRegistry(self.plane, fence_ttl_seconds=5)
        self.cluster_id = "runtime-enrollment-cluster-001"
        self.adapter_name = "company-os-ha-certification-plane"
        self.adapter_version = "0.8.2"
        self.adapter_digest = sha256_hex({"adapter": self.adapter_name, "version": self.adapter_version})
        self.topology_digest = sha256_hex({"topology": "runtime-observed-001"})
        self.probe_digest = sha256_hex({"probes": "runtime-observed-001"})
        self._close_initial_plane()
        self.current_deployment = self.deployment()
        self.runtime = EnrolledCertificationPlaneRuntime(
            self.plane,
            self.registry,
            lambda: self.current_deployment,
        )

    def tearDown(self):
        self.backend.close()
        self.tmp.cleanup()

    def _close_initial_plane(self):
        record = HACertificationRecord(
            certification_id="ha_cert_runtime_enrollment_001",
            backend_id=self.backend.backend_id,
            cluster_id=self.cluster_id,
            topology_epoch=51,
            evidence_nonce="runtime-plane-evidence-51",
            evidence_digest=sha256_hex({"evidence": 51}),
            attestation_digest=sha256_hex({"attestation": 51}),
            certification_digest=sha256_hex({"certification": 51}),
            certified_at=self.now.isoformat(),
            valid_until=(self.now + timedelta(seconds=600)).isoformat(),
            status="ACTIVE",
        )
        handoff = "runtime-enrollment-handoff-51"
        self.plane.prepare_handoff(
            cluster_id=self.cluster_id,
            topology_epoch=51,
            handoff_digest=handoff,
            bootstrap_state_digest="b" * 64,
            control_state_digest="c" * 64,
            owner_id="seed-runtime-plane",
        )
        self.plane.activate(record, owner_id="seed-runtime-plane", handoff_digest=handoff)
        self.plane.close_handoff(
            cluster_id=self.cluster_id,
            topology_epoch=51,
            handoff_digest=handoff,
            certification_id=record.certification_id,
            owner_id="seed-runtime-plane",
        )

    def deployment(self, **overrides):
        values = {
            "deployment_id": "runtime-plane-deployment-001",
            "cluster_id": self.cluster_id,
            "adapter_name": self.adapter_name,
            "adapter_version": self.adapter_version,
            "adapter_implementation_digest": self.adapter_digest,
            "topology_evidence_digest": self.topology_digest,
            "probe_evidence_digest": self.probe_digest,
        }
        values.update(overrides)
        return CertificationPlaneDeploymentIdentity.from_plane(self.plane, **values)

    def attestation(self, deployment=None, **overrides):
        deployment = deployment or self.current_deployment
        values = {
            "attestation_id": "runtime-adapter-attestation-001",
            "deployment_digest": deployment.digest(),
            "authority_id": "runtime-release-authority",
            "authority_class": "independent_release_attestation",
            "key_id": "runtime-release-key-1",
            "authority_generation": 1,
            "attestation_nonce": "runtime-attestation-nonce-001",
            "issued_at": (self.now - timedelta(seconds=5)).isoformat(),
            "expires_at": (self.now + timedelta(seconds=120)).isoformat(),
        }
        values.update(overrides)
        return CertificationPlaneAdapterAttestation(**values)

    def readiness(self, deployment=None, attestation=None):
        deployment = deployment or self.current_deployment
        attestation = attestation or self.attestation(deployment)
        return CertificationPlaneAdapterReadiness(
            production_ready=True,
            missing_requirements=(),
            deployment_digest=deployment.digest(),
            attestation_digest=attestation.digest(),
            verifier_receipt_digest=sha256_hex({"receipt": attestation.digest()}),
            trust_store_id="test-production-trust-store",
        )

    def enroll(self, *, deployment=None, attestation=None, readiness=None, generation=1, owner="enroller-a"):
        deployment = deployment or self.current_deployment
        attestation = attestation or self.attestation(deployment)
        readiness = readiness or self.readiness(deployment, attestation)
        return self.registry.enroll(
            readiness,
            deployment,
            attestation,
            generation=generation,
            owner_id=owner,
        )

    def second_registry(self, *, now=None):
        backend = EnrollmentBackend(self.db_path, backend_id=self.backend.backend_id, now=now or self.backend.now)
        plane = SharedStateCertificationPlane(backend, fence_ttl_seconds=5)
        return backend, SharedAdapterEnrollmentRegistry(plane, fence_ttl_seconds=5)

    def test_no_enrollment_denies_runtime_access(self):
        with self.assertRaises(HardeningError) as cm:
            self.runtime.require_active()
        self.assertEqual(cm.exception.code, "CFHS_HA_ENROLLMENT_REQUIRED")

    def test_valid_enrollment_allows_guarded_runtime_access(self):
        enrolled = self.enroll()
        active = self.runtime.require_active()
        self.assertEqual(active["backend_id"], self.backend.backend_id)
        self.assertEqual(enrolled.status, "ACTIVE")
        self.assertEqual(self.runtime.current().cluster_id, self.cluster_id)

    def test_readiness_for_different_deployment_digest_is_denied(self):
        attestation = self.attestation(self.current_deployment)
        wrong = replace(self.readiness(self.current_deployment, attestation), deployment_digest="0" * 64)
        with self.assertRaises(HardeningError) as cm:
            self.enroll(attestation=attestation, readiness=wrong)
        self.assertEqual(cm.exception.code, "CFHS_HA_ENROLLMENT_DENIED")

    def test_changed_adapter_implementation_is_runtime_drift(self):
        self.enroll()
        self.current_deployment = self.deployment(adapter_implementation_digest="f" * 64)
        with self.assertRaises(HardeningError) as cm:
            self.runtime.current()
        self.assertEqual(cm.exception.code, "CFHS_HA_ENROLLMENT_DRIFT")

    def test_changed_backend_capability_digest_is_runtime_drift(self):
        self.enroll()
        self.current_deployment = replace(self.current_deployment, backend_capabilities_digest="e" * 64)
        with self.assertRaises(HardeningError) as cm:
            self.runtime.require_active()
        self.assertEqual(cm.exception.code, "CFHS_HA_ENROLLMENT_DRIFT")

    def test_cluster_drift_is_runtime_drift(self):
        self.enroll()
        self.current_deployment = self.deployment(cluster_id="drifted-cluster")
        with self.assertRaises(HardeningError) as cm:
            self.runtime.require_active()
        self.assertEqual(cm.exception.code, "CFHS_HA_ENROLLMENT_DRIFT")

    def test_topology_or_probe_evidence_drift_is_runtime_drift(self):
        self.enroll()
        topology_drift = self.deployment(topology_evidence_digest=sha256_hex({"topology": "changed"}))
        self.current_deployment = topology_drift
        with self.assertRaises(HardeningError) as topology_cm:
            self.runtime.current()
        self.assertEqual(topology_cm.exception.code, "CFHS_HA_ENROLLMENT_DRIFT")
        self.current_deployment = self.deployment(probe_evidence_digest=sha256_hex({"probes": "changed"}))
        with self.assertRaises(HardeningError) as probe_cm:
            self.runtime.current()
        self.assertEqual(probe_cm.exception.code, "CFHS_HA_ENROLLMENT_DRIFT")

    def test_enrollment_expiry_uses_backend_authoritative_time(self):
        attestation = self.attestation(expires_at=(self.now + timedelta(seconds=20)).isoformat())
        self.enroll(attestation=attestation, readiness=self.readiness(self.current_deployment, attestation))
        self.backend.now = self.now + timedelta(seconds=21)
        with self.assertRaises(HardeningError) as cm:
            self.runtime.require_active()
        self.assertEqual(cm.exception.code, "CFHS_HA_ENROLLMENT_EXPIRED")

    def test_cross_process_revocation_is_immediately_visible(self):
        self.enroll()
        backend2, registry2 = self.second_registry()
        try:
            registry2.revoke(self.current_deployment.deployment_id, "release revoked", owner_id="revoker-b")
            with self.assertRaises(HardeningError) as cm:
                self.runtime.require_active()
            self.assertEqual(cm.exception.code, "CFHS_HA_ENROLLMENT_REVOKED")
        finally:
            backend2.close()

    def test_monotonic_enrollment_rotation_advances_generation(self):
        first = self.enroll(generation=1)
        rotated_deployment = self.deployment(adapter_version="0.8.3", adapter_implementation_digest=sha256_hex({"adapter": "0.8.3"}))
        rotated_attestation = self.attestation(
            rotated_deployment,
            attestation_id="runtime-adapter-attestation-002",
            deployment_digest=rotated_deployment.digest(),
            key_id="runtime-release-key-2",
            authority_generation=2,
            attestation_nonce="runtime-attestation-nonce-002",
        )
        rotated = self.enroll(
            deployment=rotated_deployment,
            attestation=rotated_attestation,
            readiness=self.readiness(rotated_deployment, rotated_attestation),
            generation=2,
            owner="enroller-b",
        )
        self.assertEqual(first.generation, 1)
        self.assertEqual(rotated.generation, 2)
        self.current_deployment = rotated_deployment
        self.assertEqual(self.runtime.require_active()["backend_id"], self.backend.backend_id)

    def test_older_enrollment_generation_is_rejected_after_rotation(self):
        self.enroll(generation=1)
        rotated_deployment = self.deployment(adapter_version="0.8.3", adapter_implementation_digest=sha256_hex({"adapter": "0.8.3"}))
        rotated_attestation = self.attestation(
            rotated_deployment,
            attestation_id="runtime-adapter-attestation-002",
            deployment_digest=rotated_deployment.digest(),
            key_id="runtime-release-key-2",
            authority_generation=2,
            attestation_nonce="runtime-attestation-nonce-002",
        )
        self.enroll(
            deployment=rotated_deployment,
            attestation=rotated_attestation,
            readiness=self.readiness(rotated_deployment, rotated_attestation),
            generation=2,
            owner="enroller-b",
        )
        with self.assertRaises(HardeningError) as cm:
            self.enroll(generation=1, owner="stale-enroller")
        self.assertEqual(cm.exception.code, "CFHS_AUTHORITY_ROLLBACK")

    def test_restart_preserves_enrollment_and_revocation_state(self):
        self.enroll()
        self.registry.revoke(self.current_deployment.deployment_id, "maintenance revoke", owner_id="revoker-a")
        backend2, registry2 = self.second_registry()
        try:
            recovered = registry2.get(self.current_deployment.deployment_id)
            self.assertEqual(recovered.status, "REVOKED")
            self.assertEqual(recovered.revocation_reason, "maintenance revoke")
            runtime2 = EnrolledCertificationPlaneRuntime(
                registry2.plane,
                registry2,
                lambda: self.current_deployment,
            )
            with self.assertRaises(HardeningError) as cm:
                runtime2.require_active()
            self.assertEqual(cm.exception.code, "CFHS_HA_ENROLLMENT_REVOKED")
        finally:
            backend2.close()


if __name__ == "__main__":
    unittest.main()
