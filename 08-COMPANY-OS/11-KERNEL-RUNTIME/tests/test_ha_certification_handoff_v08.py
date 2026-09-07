import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kernel.ha_bootstrap_authority import (
    BOOTSTRAP_PURPOSE,
    HABootstrapBinding,
    HABootstrapPermit,
    HACertificationBootstrapCoordinator,
    SQLiteHABootstrapPermitUseLedger,
    VerifiedHABootstrapPermit,
)
from kernel.ha_certification_handoff import (
    HACertificationHandoffCoordinator,
    HandoffCertifiedSharedPersistence,
    SQLiteHAHandoffLedger,
)
from kernel.ha_certification_runtime import SQLiteHACertificationLedger
from kernel.ha_handoff_guard import HandoffAwareBootstrapCoordinator
from kernel.ha_persistence import (
    HADeploymentEvidence,
    HAMemberEvidence,
    HAPersistenceCertifier,
    HAProbeEvidence,
    REQUIRED_PROBES,
    VerifiedDeploymentAttestation,
)
from kernel.hardening import HardeningError
from kernel.shared_state_backend import SharedBackendCapabilities, SQLiteSharedStateBackend
from kernel.trust import sha256_hex


class HandoffBackend(SQLiteSharedStateBackend):
    def __init__(self, path, *, backend_id="handoff-ha-backend-v08", now=None):
        super().__init__(path, backend_id=backend_id)
        self.now = now or datetime.now(timezone.utc)

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

    def authoritative_now(self):
        return self.now


class DeploymentVerifier:
    def verify(self, evidence):
        return VerifiedDeploymentAttestation(
            issuer_id="handoff-deployment-verifier",
            evidence_digest=evidence.digest(),
            verification_class="independent_observer",
            verified_at=evidence.observed_at,
            verifier_receipt_digest=sha256_hex({"deployment": evidence.digest()}),
        )


class BootstrapVerifier:
    def __init__(self, now):
        self.now = now

    def verify(self, permit, expected_binding):
        return VerifiedHABootstrapPermit(
            permit_digest=permit.digest(),
            binding_digest=expected_binding.digest(),
            authority_id=permit.authority_id,
            authority_class=permit.authority_class,
            verified_at=self.now.isoformat(),
            authority_receipt_digest=sha256_hex(
                {
                    "permit": permit.digest(),
                    "binding": expected_binding.digest(),
                    "verified_at": self.now.isoformat(),
                }
            ),
        )


class HACertificationHandoffV08Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.backend_path = self.root / "shared.db"
        self.cert_path = self.root / "cert.db"
        self.handoff_path = self.root / "handoff.db"
        self.permit_path = self.root / "permit.db"
        self.now = datetime(2026, 9, 7, 3, 0, tzinfo=timezone.utc)
        self.backend = HandoffBackend(self.backend_path, now=self.now)
        self.cert_conn = self._conn(self.cert_path)
        self.handoff_conn = self._conn(self.handoff_path)
        self.permit_conn = self._conn(self.permit_path)
        self.cert_ledger = SQLiteHACertificationLedger(self.cert_conn, max_evidence_age_seconds=300)
        self.handoff_ledger = SQLiteHAHandoffLedger(self.handoff_conn)
        self.permit_ledger = SQLiteHABootstrapPermitUseLedger(self.permit_conn)
        self.deployment_verifier = DeploymentVerifier()
        self.bootstrap_verifier = BootstrapVerifier(self.now)

    @staticmethod
    def _conn(path):
        conn = sqlite3.connect(path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def tearDown(self):
        self.backend.close()
        self.cert_conn.close()
        self.handoff_conn.close()
        self.permit_conn.close()
        self.tmp.cleanup()

    def evidence(self, **overrides):
        probes = tuple(
            HAProbeEvidence(
                name=name,
                passed=True,
                observed_at=self.now.isoformat(),
                evidence_digest=sha256_hex({"probe": name, "at": self.now.isoformat()}),
            )
            for name in REQUIRED_PROBES
        )
        values = {
            "backend_id": self.backend.backend_id,
            "cluster_id": "handoff-cluster-001",
            "topology_epoch": 21,
            "observed_at": self.now.isoformat(),
            "members": (
                HAMemberEvidence("node-a", True, True, "zone-a"),
                HAMemberEvidence("node-b", True, True, "zone-b"),
                HAMemberEvidence("node-c", True, True, "zone-c"),
            ),
            "consensus_protocol": "reference-consensus",
            "write_quorum": 2,
            "read_consistency_mode": "leader_linearizable",
            "read_quorum": 1,
            "synchronous_commit": True,
            "synchronous_replica_acks": 1,
            "authoritative_time_source": "database_server",
            "lease_time_source": "database_server",
            "split_brain_protection": True,
            "probes": probes,
            "evidence_issuer": "handoff-evidence-pipeline",
            "evidence_nonce": "handoff-evidence-001",
        }
        values.update(overrides)
        return HADeploymentEvidence(**values)

    def certification(self, evidence):
        result = HAPersistenceCertifier(max_evidence_age_seconds=300).certify(
            self.backend,
            evidence,
            self.deployment_verifier,
            now=self.now,
        )
        self.assertTrue(result.production_ready)
        return result

    def permit(self, binding, *, permit_id="handoff-permit-001"):
        return HABootstrapPermit(
            permit_id=permit_id,
            purpose=BOOTSTRAP_PURPOSE,
            backend_id=binding.backend_id,
            cluster_id=binding.cluster_id,
            topology_epoch=binding.topology_epoch,
            evidence_digest=binding.evidence_digest,
            certification_decision_digest=binding.certification_decision_digest,
            attestation_digest=binding.attestation_digest,
            authority_id="external-release-ca",
            authority_class="external_certification_authority",
            issued_at=(self.now - timedelta(seconds=5)).isoformat(),
            expires_at=(self.now + timedelta(seconds=120)).isoformat(),
            permit_nonce="handoff-permit-nonce",
        )

    def material(self):
        evidence = self.evidence()
        certification = self.certification(evidence)
        binding = HABootstrapBinding.from_certification(certification, evidence)
        permit = self.permit(binding)
        bootstrap_coordinator = HACertificationBootstrapCoordinator(
            self.backend,
            self.bootstrap_verifier,
            self.permit_ledger,
        )
        bootstrap = bootstrap_coordinator.initialize(certification, evidence, permit)
        return evidence, certification, binding, permit, bootstrap, bootstrap_coordinator

    def coordinator(self, *, phase_hook=None, backend=None, cert_ledger=None, handoff_ledger=None):
        return HACertificationHandoffCoordinator(
            backend or self.backend,
            cert_ledger or self.cert_ledger,
            handoff_ledger or self.handoff_ledger,
            phase_hook=phase_hook,
        )

    def test_successful_handoff_closes_bootstrap_and_enables_steady_state(self):
        evidence, certification, _, _, bootstrap, _ = self.material()
        result = self.coordinator().handoff(certification, evidence, bootstrap)
        self.assertEqual(result.status, "CLOSED")
        self.assertEqual(self.handoff_ledger.require_closed(evidence.backend_id).certification_id, result.certification_id)
        guarded = HandoffCertifiedSharedPersistence(self.backend, self.cert_ledger, self.handoff_ledger)
        created = guarded.put_if_absent("company/test", {"ready": True})
        self.assertEqual(guarded.read("company/test").value_digest, created.value_digest)

    def test_repeated_same_handoff_is_idempotent(self):
        evidence, certification, _, _, bootstrap, _ = self.material()
        first = self.coordinator().handoff(certification, evidence, bootstrap)
        second = self.coordinator().handoff(certification, evidence, bootstrap)
        self.assertEqual(first.certification_id, second.certification_id)
        self.assertEqual(first.control_state_digest, second.control_state_digest)
        self.assertTrue(second.idempotent_replay)

    def test_crash_before_shared_activation_recovers_without_unlocking_access(self):
        evidence, certification, _, _, bootstrap, _ = self.material()
        def crash(phase):
            if phase == "after_control_write":
                raise RuntimeError("simulated crash before shared activation")
        with self.assertRaises(RuntimeError):
            self.coordinator(phase_hook=crash).handoff(certification, evidence, bootstrap)
        self.assertIsNone(self.cert_ledger.active(evidence.backend_id))
        with self.assertRaises(HardeningError) as cm:
            HandoffCertifiedSharedPersistence(self.backend, self.cert_ledger, self.handoff_ledger).read("company/x")
        self.assertEqual(cm.exception.code, "CFHS_HA_HANDOFF_INCOMPLETE")
        recovered = self.coordinator().handoff(certification, evidence, bootstrap)
        self.assertEqual(recovered.status, "CLOSED")

    def test_crash_after_activation_before_closure_still_denies_then_recovers(self):
        evidence, certification, _, _, bootstrap, _ = self.material()
        def crash(phase):
            if phase == "after_activation":
                raise RuntimeError("simulated crash after activation")
        with self.assertRaises(RuntimeError):
            self.coordinator(phase_hook=crash).handoff(certification, evidence, bootstrap)
        self.assertIsNotNone(self.cert_ledger.active(evidence.backend_id))
        self.assertEqual(self.handoff_ledger.get(evidence.backend_id).status, "ACTIVATED")
        with self.assertRaises(HardeningError) as cm:
            HandoffCertifiedSharedPersistence(self.backend, self.cert_ledger, self.handoff_ledger).read("company/x")
        self.assertEqual(cm.exception.code, "CFHS_HA_HANDOFF_INCOMPLETE")
        recovered = self.coordinator().handoff(certification, evidence, bootstrap)
        self.assertEqual(recovered.status, "CLOSED")

    def test_bootstrap_object_tampering_is_rejected(self):
        evidence, certification, _, _, bootstrap, _ = self.material()
        observed = self.backend.read(bootstrap.object_key)
        self.backend.compare_and_swap(bootstrap.object_key, observed.version, {"tampered": True})
        with self.assertRaises(HardeningError) as cm:
            self.coordinator().handoff(certification, evidence, bootstrap)
        self.assertEqual(cm.exception.code, "CFHS_HA_BOOTSTRAP_CONFLICT")
        self.assertIsNone(self.cert_ledger.active(evidence.backend_id))

    def test_certificate_evidence_mismatch_is_rejected(self):
        evidence, certification, _, _, bootstrap, _ = self.material()
        other = replace(evidence, evidence_nonce="different-evidence-nonce")
        with self.assertRaises(HardeningError) as cm:
            self.coordinator().handoff(certification, other, bootstrap)
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")

    def test_cluster_mismatch_is_rejected(self):
        evidence, _, _, _, bootstrap, _ = self.material()
        other = replace(evidence, cluster_id="other-cluster", evidence_nonce="other-cluster-evidence")
        other_cert = self.certification(other)
        with self.assertRaises(HardeningError) as cm:
            self.coordinator().handoff(other_cert, other, bootstrap)
        self.assertEqual(cm.exception.code, "CFHS_HA_HANDOFF_DENIED")

    def test_topology_rollback_is_rejected_by_handoff_lineage(self):
        evidence, certification, _, _, bootstrap, _ = self.material()
        result = self.coordinator().handoff(certification, evidence, bootstrap)
        self.assertEqual(result.status, "CLOSED")
        with self.assertRaises(HardeningError) as cm:
            self.handoff_ledger.begin(
                backend_id=evidence.backend_id,
                cluster_id=evidence.cluster_id,
                topology_epoch=evidence.topology_epoch - 1,
                handoff_digest="different",
                bootstrap_state_digest="different",
                at=self.now,
            )
        self.assertEqual(cm.exception.code, "CFHS_TOPOLOGY_ROLLBACK")

    def test_second_first_bootstrap_attempt_is_denied_after_closure(self):
        evidence, certification, _, permit, bootstrap, bootstrap_coordinator = self.material()
        self.coordinator().handoff(certification, evidence, bootstrap)
        guarded_bootstrap = HandoffAwareBootstrapCoordinator(bootstrap_coordinator, self.handoff_ledger)
        with self.assertRaises(HardeningError) as cm:
            guarded_bootstrap.initialize(certification, evidence, permit)
        self.assertEqual(cm.exception.code, "CFHS_HA_BOOTSTRAP_CLOSED")

    def test_concurrent_handoff_attempts_converge_on_one_closed_certificate(self):
        evidence, certification, _, _, bootstrap, _ = self.material()

        def worker(_):
            backend = HandoffBackend(self.backend_path, backend_id=self.backend.backend_id, now=self.now)
            cert_conn = self._conn(self.cert_path)
            handoff_conn = self._conn(self.handoff_path)
            try:
                coordinator = HACertificationHandoffCoordinator(
                    backend,
                    SQLiteHACertificationLedger(cert_conn, max_evidence_age_seconds=300),
                    SQLiteHAHandoffLedger(handoff_conn),
                )
                return coordinator.handoff(certification, evidence, bootstrap)
            finally:
                backend.close()
                cert_conn.close()
                handoff_conn.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(worker, range(2)))
        self.assertEqual({r.status for r in results}, {"CLOSED"})
        self.assertEqual(len({r.certification_id for r in results}), 1)
        self.assertEqual(self.handoff_ledger.require_closed(evidence.backend_id).certification_id, results[0].certification_id)

    def test_activation_expiry_during_handoff_prevents_closure(self):
        evidence, certification, _, _, bootstrap, _ = self.material()
        def advance(phase):
            if phase == "after_activation":
                self.backend.now = self.now + timedelta(seconds=301)
        with self.assertRaises(HardeningError) as cm:
            self.coordinator(phase_hook=advance).handoff(certification, evidence, bootstrap)
        self.assertEqual(cm.exception.code, "CFHS_HA_CERTIFICATION_EXPIRED")
        self.assertEqual(self.handoff_ledger.get(evidence.backend_id).status, "ACTIVATED")
        with self.assertRaises(HardeningError):
            HandoffCertifiedSharedPersistence(self.backend, self.cert_ledger, self.handoff_ledger).read("company/x")

    def test_steady_state_access_is_denied_until_handoff_is_fully_complete(self):
        evidence, certification, _, _, bootstrap, _ = self.material()
        guarded = HandoffCertifiedSharedPersistence(self.backend, self.cert_ledger, self.handoff_ledger)
        with self.assertRaises(HardeningError) as before:
            guarded.read("company/x")
        self.assertEqual(before.exception.code, "CFHS_HA_HANDOFF_INCOMPLETE")
        self.coordinator().handoff(certification, evidence, bootstrap)
        guarded.put_if_absent("company/x", {"phase": "steady"})
        self.assertEqual(guarded.read("company/x").value["phase"], "steady")


if __name__ == "__main__":
    unittest.main()
