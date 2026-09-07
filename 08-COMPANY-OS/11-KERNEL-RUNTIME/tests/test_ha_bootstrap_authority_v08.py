import sqlite3
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kernel.ha_bootstrap_authority import (
    ALLOWED_BOOTSTRAP_AUTHORITY_CLASSES,
    BOOTSTRAP_PURPOSE,
    HABootstrapBinding,
    HABootstrapPermit,
    HACertificationBootstrapCoordinator,
    SQLiteHABootstrapPermitUseLedger,
    VerifiedHABootstrapPermit,
)
from kernel.ha_persistence import (
    HADeploymentEvidence,
    HAMemberEvidence,
    HAPersistenceCertifier,
    HAProbeEvidence,
    REQUIRED_PROBES,
    SharedBackendCapabilities,
    VerifiedDeploymentAttestation,
)
from kernel.hardening import HardeningError
from kernel.shared_state_backend import SQLiteSharedStateBackend
from kernel.trust import sha256_hex


class BootstrapBackend(SQLiteSharedStateBackend):
    def __init__(self, path, *, backend_id="bootstrap-ha-backend-v08", full_capabilities=True):
        super().__init__(path, backend_id=backend_id)
        self.full_capabilities = full_capabilities
        self.put_count = 0

    def capabilities(self):
        if not self.full_capabilities:
            return super().capabilities()
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

    def put_if_absent(self, object_key, value):
        self.put_count += 1
        return super().put_if_absent(object_key, value)


class DeploymentVerifier:
    def verify(self, evidence):
        return VerifiedDeploymentAttestation(
            issuer_id="independent-deployment-verifier",
            evidence_digest=evidence.digest(),
            verification_class="independent_observer",
            verified_at=evidence.observed_at,
            verifier_receipt_digest=sha256_hex({"deployment": evidence.digest()}),
        )


class BootstrapVerifier:
    def __init__(
        self,
        verified_at,
        *,
        authority_id=None,
        authority_class=None,
        permit_digest=None,
        binding_digest=None,
        fail=False,
    ):
        self.verified_at = verified_at
        self.authority_id = authority_id
        self.authority_class = authority_class
        self.permit_digest = permit_digest
        self.binding_digest = binding_digest
        self.fail = fail
        self.calls = 0

    def verify(self, permit, expected_binding):
        self.calls += 1
        if self.fail:
            raise RuntimeError("external authority verification failed")
        authority_id = self.authority_id or permit.authority_id
        authority_class = self.authority_class or permit.authority_class
        permit_digest = self.permit_digest or permit.digest()
        binding_digest = self.binding_digest or expected_binding.digest()
        return VerifiedHABootstrapPermit(
            permit_digest=permit_digest,
            binding_digest=binding_digest,
            authority_id=authority_id,
            authority_class=authority_class,
            verified_at=self.verified_at.isoformat(),
            authority_receipt_digest=sha256_hex(
                {
                    "permit": permit_digest,
                    "binding": binding_digest,
                    "authority": authority_id,
                    "verified_at": self.verified_at.isoformat(),
                }
            ),
        )


class FailFirstConsumeLedger(SQLiteHABootstrapPermitUseLedger):
    def __init__(self, conn):
        super().__init__(conn)
        self.fail_next_consume = True

    def consume(self, permit_id, *, object_key, bootstrap_state_digest, consumed_at):
        if self.fail_next_consume:
            self.fail_next_consume = False
            raise RuntimeError("simulated crash after backend bootstrap write")
        return super().consume(
            permit_id,
            object_key=object_key,
            bootstrap_state_digest=bootstrap_state_digest,
            consumed_at=consumed_at,
        )


class HABootstrapAuthorityV08Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.now = datetime(2026, 9, 7, 1, 30, tzinfo=timezone.utc)
        self.backend = BootstrapBackend(self.root / "bootstrap.db")
        self.ledger_conn = sqlite3.connect(self.root / "permit-ledger.db")
        self.ledger_conn.row_factory = sqlite3.Row
        self.ledger = SQLiteHABootstrapPermitUseLedger(self.ledger_conn)
        self.deployment_verifier = DeploymentVerifier()
        self.verifier = BootstrapVerifier(self.now)

    def tearDown(self):
        self.backend.close()
        self.ledger_conn.close()
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
            "cluster_id": "bootstrap-cluster-001",
            "topology_epoch": 11,
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
            "evidence_issuer": "bootstrap-evidence-pipeline",
            "evidence_nonce": "bootstrap-evidence-001",
        }
        values.update(overrides)
        return HADeploymentEvidence(**values)

    def certification(self, evidence=None):
        evidence = evidence or self.evidence()
        result = HAPersistenceCertifier(max_evidence_age_seconds=300).certify(
            self.backend,
            evidence,
            self.deployment_verifier,
            now=self.now,
        )
        self.assertTrue(result.production_ready)
        return result

    def binding(self, certification=None, evidence=None):
        evidence = evidence or self.evidence()
        certification = certification or self.certification(evidence)
        return HABootstrapBinding.from_certification(certification, evidence)

    def permit(self, binding=None, **overrides):
        binding = binding or self.binding()
        values = {
            "permit_id": "bootstrap-permit-001",
            "purpose": BOOTSTRAP_PURPOSE,
            "backend_id": binding.backend_id,
            "cluster_id": binding.cluster_id,
            "topology_epoch": binding.topology_epoch,
            "evidence_digest": binding.evidence_digest,
            "certification_decision_digest": binding.certification_decision_digest,
            "attestation_digest": binding.attestation_digest,
            "authority_id": "external-release-ca",
            "authority_class": "external_certification_authority",
            "issued_at": (self.now - timedelta(seconds=10)).isoformat(),
            "expires_at": (self.now + timedelta(seconds=110)).isoformat(),
            "permit_nonce": "permit-nonce-001",
        }
        values.update(overrides)
        return HABootstrapPermit(**values)

    def coordinator(self, *, backend=None, verifier=None, ledger=None):
        return HACertificationBootstrapCoordinator(
            backend or self.backend,
            verifier or self.verifier,
            ledger or self.ledger,
            max_permit_lifetime_seconds=300,
        )

    def valid_material(self):
        evidence = self.evidence()
        certification = self.certification(evidence)
        binding = self.binding(certification, evidence)
        permit = self.permit(binding)
        return evidence, certification, binding, permit

    def test_valid_bootstrap_initializes_only_reserved_certification_object(self):
        evidence, certification, binding, permit = self.valid_material()
        result = self.coordinator().initialize(certification, evidence, permit)
        self.assertEqual(
            result.object_key,
            HACertificationBootstrapCoordinator.bootstrap_object_key(binding.backend_id),
        )
        self.assertEqual(result.object_version, 1)
        self.assertFalse(result.idempotent_replay)
        self.assertEqual(self.backend.put_count, 1)
        state = self.backend.read(result.object_key)
        self.assertEqual(state.value["contract"], "ha-certification-bootstrap/v0.8")
        self.assertEqual(state.value["permit_id"], permit.permit_id)
        self.assertEqual(self.ledger.get(permit.permit_id)["state"], "CONSUMED")

    def test_same_consumed_permit_replay_is_idempotent_and_does_not_write_again(self):
        evidence, certification, _, permit = self.valid_material()
        first = self.coordinator().initialize(certification, evidence, permit)
        second = self.coordinator().initialize(certification, evidence, permit)
        self.assertEqual(first.object_key, second.object_key)
        self.assertEqual(first.bootstrap_state_digest, second.bootstrap_state_digest)
        self.assertTrue(second.idempotent_replay)
        self.assertEqual(self.backend.put_count, 1)
        self.assertEqual(self.ledger.get(permit.permit_id)["state"], "CONSUMED")

    def test_expired_permit_is_rejected_before_reservation_or_write(self):
        evidence, certification, binding, _ = self.valid_material()
        permit = self.permit(
            binding,
            issued_at=(self.now - timedelta(seconds=200)).isoformat(),
            expires_at=(self.now - timedelta(seconds=1)).isoformat(),
        )
        with self.assertRaises(HardeningError) as cm:
            self.coordinator().initialize(certification, evidence, permit)
        self.assertEqual(cm.exception.code, "CFHS_HA_BOOTSTRAP_EXPIRED")
        self.assertIsNone(self.ledger.get(permit.permit_id))
        self.assertEqual(self.backend.put_count, 0)

    def test_incorrect_purpose_is_rejected(self):
        evidence, certification, binding, _ = self.valid_material()
        permit = self.permit(binding, purpose="initialize_application_state")
        with self.assertRaises(HardeningError) as cm:
            self.coordinator().initialize(certification, evidence, permit)
        self.assertEqual(cm.exception.code, "CFHS_HA_BOOTSTRAP_DENIED")
        self.assertEqual(self.backend.put_count, 0)

    def test_incorrect_target_backend_is_rejected(self):
        evidence, certification, binding, permit = self.valid_material()
        other = BootstrapBackend(self.root / "other.db", backend_id="different-backend")
        try:
            with self.assertRaises(HardeningError) as cm:
                self.coordinator(backend=other).initialize(certification, evidence, permit)
        finally:
            other.close()
        self.assertEqual(cm.exception.code, "CFHS_HA_BOOTSTRAP_DENIED")

    def test_incorrect_cluster_binding_is_rejected(self):
        evidence, certification, binding, _ = self.valid_material()
        permit = self.permit(binding, cluster_id="other-cluster")
        with self.assertRaises(HardeningError) as cm:
            self.coordinator().initialize(certification, evidence, permit)
        self.assertEqual(cm.exception.code, "CFHS_HA_BOOTSTRAP_DENIED")

    def test_incorrect_topology_epoch_binding_is_rejected(self):
        evidence, certification, binding, _ = self.valid_material()
        permit = self.permit(binding, topology_epoch=binding.topology_epoch + 1)
        with self.assertRaises(HardeningError) as cm:
            self.coordinator().initialize(certification, evidence, permit)
        self.assertEqual(cm.exception.code, "CFHS_HA_BOOTSTRAP_DENIED")

    def test_incorrect_evidence_digest_binding_is_rejected(self):
        evidence, certification, binding, _ = self.valid_material()
        permit = self.permit(binding, evidence_digest="0" * 64)
        with self.assertRaises(HardeningError) as cm:
            self.coordinator().initialize(certification, evidence, permit)
        self.assertEqual(cm.exception.code, "CFHS_HA_BOOTSTRAP_DENIED")

    def test_authority_verifier_identity_mismatch_is_rejected(self):
        evidence, certification, binding, permit = self.valid_material()
        verifier = BootstrapVerifier(self.now, authority_id="different-authority")
        with self.assertRaises(HardeningError) as cm:
            self.coordinator(verifier=verifier).initialize(certification, evidence, permit)
        self.assertEqual(cm.exception.code, "CFHS_HA_BOOTSTRAP_DENIED")
        self.assertEqual(self.backend.put_count, 0)

    def test_authority_verifier_binding_digest_mismatch_is_rejected(self):
        evidence, certification, binding, permit = self.valid_material()
        verifier = BootstrapVerifier(self.now, binding_digest="f" * 64)
        with self.assertRaises(HardeningError) as cm:
            self.coordinator(verifier=verifier).initialize(certification, evidence, permit)
        self.assertEqual(cm.exception.code, "CFHS_HA_BOOTSTRAP_DENIED")

    def test_same_permit_id_reused_with_different_content_conflicts(self):
        evidence, certification, binding, permit = self.valid_material()
        self.coordinator().initialize(certification, evidence, permit)
        altered = self.permit(binding, permit_nonce="different-nonce")
        with self.assertRaises(HardeningError) as cm:
            self.coordinator().initialize(certification, evidence, altered)
        self.assertEqual(cm.exception.code, "CFHS_IDEMPOTENCY_CONFLICT")
        self.assertEqual(self.backend.put_count, 1)

    def test_crash_after_backend_write_before_permit_consumption_recovers_without_second_write(self):
        crash_conn = sqlite3.connect(self.root / "crash-ledger.db")
        crash_conn.row_factory = sqlite3.Row
        crash_ledger = FailFirstConsumeLedger(crash_conn)
        evidence, certification, _, permit = self.valid_material()
        coordinator = self.coordinator(ledger=crash_ledger)
        try:
            with self.assertRaises(RuntimeError):
                coordinator.initialize(certification, evidence, permit)
            self.assertEqual(self.backend.put_count, 1)
            self.assertEqual(crash_ledger.get(permit.permit_id)["state"], "RESERVED")
            recovered = coordinator.initialize(certification, evidence, permit)
            self.assertTrue(recovered.idempotent_replay)
            self.assertEqual(self.backend.put_count, 1)
            self.assertEqual(crash_ledger.get(permit.permit_id)["state"], "CONSUMED")
        finally:
            crash_conn.close()

    def test_conflicting_preexisting_bootstrap_state_fails_closed_and_does_not_consume_permit(self):
        evidence, certification, binding, permit = self.valid_material()
        key = HACertificationBootstrapCoordinator.bootstrap_object_key(binding.backend_id)
        self.backend.put_if_absent(key, {"unexpected": "preexisting-state"})
        puts_before = self.backend.put_count
        with self.assertRaises(HardeningError) as cm:
            self.coordinator().initialize(certification, evidence, permit)
        self.assertEqual(cm.exception.code, "CFHS_HA_BOOTSTRAP_CONFLICT")
        self.assertEqual(self.backend.put_count, puts_before)
        self.assertEqual(self.ledger.get(permit.permit_id)["state"], "RESERVED")

    def test_non_production_ready_certification_cannot_bootstrap(self):
        evidence, certification, binding, permit = self.valid_material()
        denied = replace(
            certification,
            production_ready=False,
            missing_requirements=("quorum_loss_fail_closed",),
        )
        with self.assertRaises(HardeningError) as cm:
            self.coordinator().initialize(denied, evidence, permit)
        self.assertEqual(cm.exception.code, "CFHS_HA_PERSISTENCE_NOT_READY")
        self.assertEqual(self.verifier.calls, 0)
        self.assertEqual(self.backend.put_count, 0)

    def test_backend_with_same_id_but_non_production_capabilities_cannot_be_substituted(self):
        evidence, certification, binding, permit = self.valid_material()
        weak = BootstrapBackend(
            self.root / "weak.db",
            backend_id=self.backend.backend_id,
            full_capabilities=False,
        )
        try:
            with self.assertRaises(HardeningError) as cm:
                self.coordinator(backend=weak).initialize(certification, evidence, permit)
        finally:
            weak.close()
        self.assertEqual(cm.exception.code, "CFHS_HA_BOOTSTRAP_DENIED")


if __name__ == "__main__":
    unittest.main()
