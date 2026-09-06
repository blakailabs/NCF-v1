import sqlite3
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kernel.ha_certification_runtime import CertifiedSharedPersistence, SQLiteHACertificationLedger
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


class ReferenceHABackend(SQLiteSharedStateBackend):
    def __init__(self, path, now):
        super().__init__(path, backend_id="reference-ha-runtime-v08")
        self.current_time = now

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
        return self.current_time


class TrustedVerifier:
    def verify(self, evidence):
        return VerifiedDeploymentAttestation(
            issuer_id="independent-ha-observer",
            evidence_digest=evidence.digest(),
            verification_class="independent_observer",
            verified_at=evidence.observed_at,
            verifier_receipt_digest=sha256_hex({"evidence": evidence.digest(), "issuer": "independent-ha-observer"}),
        )


class HACertificationRuntimeV08Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.now = datetime(2026, 9, 6, 21, 0, tzinfo=timezone.utc)
        self.backend = ReferenceHABackend(self.root / "shared.db", self.now)
        self.ledger_conn = sqlite3.connect(self.root / "certifications.db")
        self.ledger_conn.row_factory = sqlite3.Row
        self.ledger = SQLiteHACertificationLedger(self.ledger_conn, max_evidence_age_seconds=300)
        self.certifier = HAPersistenceCertifier(max_evidence_age_seconds=300)
        self.verifier = TrustedVerifier()

    def tearDown(self):
        self.backend.close()
        self.ledger_conn.close()
        self.tmp.cleanup()

    def probes(self, observed_at=None):
        observed_at = observed_at or self.now
        return tuple(
            HAProbeEvidence(
                name=name,
                passed=True,
                observed_at=observed_at.isoformat(),
                evidence_digest=sha256_hex({"name": name, "observed_at": observed_at.isoformat()}),
            )
            for name in REQUIRED_PROBES
        )

    def evidence(self, **overrides):
        values = {
            "backend_id": self.backend.backend_id,
            "cluster_id": "cluster-ha-runtime-001",
            "topology_epoch": 17,
            "observed_at": self.now.isoformat(),
            "members": (
                HAMemberEvidence("node-a", True, True, "zone-a"),
                HAMemberEvidence("node-b", True, True, "zone-b"),
                HAMemberEvidence("node-c", True, True, "zone-c"),
            ),
            "consensus_protocol": "raft-compatible-consensus",
            "write_quorum": 2,
            "read_consistency_mode": "leader_linearizable",
            "read_quorum": 1,
            "synchronous_commit": True,
            "synchronous_replica_acks": 1,
            "authoritative_time_source": "database_server",
            "lease_time_source": "database_server",
            "split_brain_protection": True,
            "probes": self.probes(),
            "evidence_issuer": "cluster-control-plane",
            "evidence_nonce": "nonce-17",
        }
        values.update(overrides)
        return HADeploymentEvidence(**values)

    def certify(self, evidence):
        result = self.certifier.certify(self.backend, evidence, self.verifier, now=self.now)
        self.assertTrue(result.production_ready)
        return result

    def activate(self, evidence=None):
        evidence = evidence or self.evidence()
        certification = self.certify(evidence)
        return self.ledger.record(certification, evidence, certified_at=self.now)

    def test_valid_certification_becomes_active_with_bounded_lifetime(self):
        record = self.activate()
        self.assertEqual(record.status, "ACTIVE")
        self.assertEqual(record.topology_epoch, 17)
        self.assertEqual(record.valid_until, (self.now + timedelta(seconds=300)).isoformat())
        self.assertEqual(self.ledger.active(self.backend.backend_id).certification_id, record.certification_id)

    def test_certificate_lifetime_is_bounded_by_oldest_probe_evidence(self):
        oldest = self.now - timedelta(seconds=100)
        evidence = self.evidence(probes=self.probes(oldest))
        certification = self.certifier.certify(self.backend, evidence, self.verifier, now=self.now)
        self.assertTrue(certification.production_ready)
        record = self.ledger.record(certification, evidence, certified_at=self.now)
        self.assertEqual(record.valid_until, (self.now + timedelta(seconds=200)).isoformat())

    def test_same_evidence_nonce_and_digest_is_idempotent(self):
        evidence = self.evidence()
        certification = self.certify(evidence)
        first = self.ledger.record(certification, evidence, certified_at=self.now)
        second = self.ledger.record(certification, evidence, certified_at=self.now)
        self.assertEqual(first.certification_id, second.certification_id)
        self.assertEqual(len(self.ledger.history(self.backend.backend_id)), 1)

    def test_higher_topology_epoch_supersedes_prior_certificate(self):
        first = self.activate()
        evidence2 = self.evidence(topology_epoch=18, evidence_nonce="nonce-18")
        second = self.ledger.record(self.certify(evidence2), evidence2, certified_at=self.now)
        self.assertNotEqual(first.certification_id, second.certification_id)
        history = self.ledger.history(self.backend.backend_id)
        self.assertEqual([record.status for record in history], ["SUPERSEDED", "ACTIVE"])
        self.assertEqual(self.ledger.active(self.backend.backend_id).topology_epoch, 18)

    def test_lower_topology_epoch_is_rejected_as_rollback(self):
        self.activate()
        old = self.evidence(topology_epoch=16, evidence_nonce="nonce-16")
        with self.assertRaises(HardeningError) as cm:
            self.ledger.record(self.certify(old), old, certified_at=self.now)
        self.assertEqual(cm.exception.code, "CFHS_TOPOLOGY_ROLLBACK")
        self.assertEqual(self.ledger.active(self.backend.backend_id).topology_epoch, 17)

    def test_same_topology_epoch_cannot_bind_different_evidence(self):
        self.activate()
        changed = self.evidence(evidence_nonce="nonce-17b", consensus_protocol="different-consensus")
        with self.assertRaises(HardeningError) as cm:
            self.ledger.record(self.certify(changed), changed, certified_at=self.now)
        self.assertEqual(cm.exception.code, "CFHS_TOPOLOGY_CONFLICT")

    def test_evidence_nonce_cannot_be_reused_for_new_topology(self):
        self.activate()
        changed = self.evidence(topology_epoch=18, evidence_nonce="nonce-17")
        with self.assertRaises(HardeningError) as cm:
            self.ledger.record(self.certify(changed), changed, certified_at=self.now)
        self.assertEqual(cm.exception.code, "CFHS_IDEMPOTENCY_CONFLICT")

    def test_backend_cluster_identity_cannot_silently_change(self):
        self.activate()
        changed = self.evidence(cluster_id="cluster-other", topology_epoch=18, evidence_nonce="nonce-18")
        with self.assertRaises(HardeningError) as cm:
            self.ledger.record(self.certify(changed), changed, certified_at=self.now)
        self.assertEqual(cm.exception.code, "CFHS_CLUSTER_IDENTITY_CONFLICT")

    def test_non_production_certification_cannot_enter_active_ledger(self):
        evidence = self.evidence(split_brain_protection=False)
        certification = self.certifier.certify(self.backend, evidence, self.verifier, now=self.now)
        self.assertFalse(certification.production_ready)
        with self.assertRaises(HardeningError) as cm:
            self.ledger.record(certification, evidence, certified_at=self.now)
        self.assertEqual(cm.exception.code, "CFHS_HA_PERSISTENCE_NOT_READY")

    def test_expired_certificate_is_rejected_using_backend_authoritative_time(self):
        self.activate()
        self.backend.current_time = self.now + timedelta(seconds=300)
        with self.assertRaises(HardeningError) as cm:
            self.ledger.require_active(self.backend.backend_id, authoritative_now=self.backend.authoritative_now())
        self.assertEqual(cm.exception.code, "CFHS_HA_CERTIFICATION_EXPIRED")

    def test_invalidation_removes_active_authority(self):
        record = self.activate()
        invalidated = self.ledger.invalidate(
            self.backend.backend_id,
            "partition probe failed",
            at=self.now + timedelta(seconds=10),
        )
        self.assertEqual(invalidated.certification_id, record.certification_id)
        self.assertEqual(invalidated.status, "INVALIDATED")
        self.assertIsNone(self.ledger.active(self.backend.backend_id))

    def test_guarded_persistence_denies_reads_and_writes_without_active_certificate(self):
        guarded = CertifiedSharedPersistence(self.backend, self.ledger)
        with self.assertRaises(HardeningError) as cm_read:
            guarded.read("company/object/1")
        self.assertEqual(cm_read.exception.code, "CFHS_HA_PERSISTENCE_NOT_READY")
        with self.assertRaises(HardeningError) as cm_write:
            guarded.put_if_absent("company/object/1", {"status": "PENDING"})
        self.assertEqual(cm_write.exception.code, "CFHS_HA_PERSISTENCE_NOT_READY")

    def test_guarded_persistence_allows_shared_operations_with_live_certificate(self):
        self.activate()
        guarded = CertifiedSharedPersistence(self.backend, self.ledger)
        created = guarded.put_if_absent("company/object/1", {"status": "PENDING"})
        self.assertEqual(created.version, 1)
        updated = guarded.compare_and_swap("company/object/1", 1, {"status": "PREPARED"})
        self.assertEqual(updated.version, 2)
        observed = guarded.read("company/object/1")
        self.assertEqual(observed.value["status"], "PREPARED")
        status = guarded.certification_status()
        self.assertEqual(status["certification"]["topology_epoch"], 17)

    def test_guarded_persistence_stops_immediately_after_certificate_invalidation(self):
        self.activate()
        guarded = CertifiedSharedPersistence(self.backend, self.ledger)
        guarded.put_if_absent("company/object/1", {"status": "PENDING"})
        self.ledger.invalidate(self.backend.backend_id, "quorum lost", at=self.now + timedelta(seconds=1))
        with self.assertRaises(HardeningError) as cm:
            guarded.read("company/object/1")
        self.assertEqual(cm.exception.code, "CFHS_HA_PERSISTENCE_NOT_READY")

    def test_guard_requires_timezone_aware_authoritative_backend_time(self):
        self.activate()
        guarded = CertifiedSharedPersistence(self.backend, self.ledger)
        self.backend.current_time = datetime(2026, 9, 6, 21, 0)
        with self.assertRaises(HardeningError) as cm:
            guarded.read("company/object/1")
        self.assertEqual(cm.exception.code, "CFHS_HA_PERSISTENCE_NOT_READY")


if __name__ == "__main__":
    unittest.main()
