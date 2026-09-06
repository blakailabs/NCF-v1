import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

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


class FullCapabilityBackend:
    def __init__(self, backend_id="ha-reference-capability-test"):
        self.backend_id = backend_id

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


class TrustedVerifier:
    def __init__(
        self,
        *,
        issuer_id="independent-ha-observer",
        verification_class="independent_observer",
        verified_at=None,
        digest_override=None,
        fail=False,
    ):
        self.issuer_id = issuer_id
        self.verification_class = verification_class
        self.verified_at = verified_at
        self.digest_override = digest_override
        self.fail = fail

    def verify(self, evidence):
        if self.fail:
            raise RuntimeError("attestation verification failed")
        verified_at = self.verified_at or evidence.observed_at
        digest = self.digest_override or evidence.digest()
        return VerifiedDeploymentAttestation(
            issuer_id=self.issuer_id,
            evidence_digest=digest,
            verification_class=self.verification_class,
            verified_at=verified_at,
            verifier_receipt_digest=sha256_hex(
                {"issuer": self.issuer_id, "evidence_digest": digest, "verified_at": verified_at}
            ),
        )


class HAPersistenceV08Tests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 9, 6, 20, 0, tzinfo=timezone.utc)
        self.backend = FullCapabilityBackend()
        self.certifier = HAPersistenceCertifier(max_evidence_age_seconds=300)

    def probes(self, *, failed=None, missing=None, stale=None):
        out = []
        for name in REQUIRED_PROBES:
            if name == missing:
                continue
            observed_at = self.now
            if name == stale:
                observed_at = self.now - timedelta(seconds=301)
            passed = name != failed
            out.append(
                HAProbeEvidence(
                    name=name,
                    passed=passed,
                    observed_at=observed_at.isoformat(),
                    evidence_digest=sha256_hex(
                        {"name": name, "passed": passed, "observed_at": observed_at.isoformat()}
                    ),
                )
            )
        return tuple(out)

    def evidence(self, **overrides):
        values = {
            "backend_id": self.backend.backend_id,
            "cluster_id": "cluster-prod-001",
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
            "evidence_nonce": "evidence-nonce-001",
        }
        values.update(overrides)
        return HADeploymentEvidence(**values)

    def certify(self, evidence=None, verifier=None, backend=None):
        evidence = evidence or self.evidence()
        verifier = TrustedVerifier() if verifier is None else verifier
        backend = backend or self.backend
        return self.certifier.certify(backend, evidence, verifier, now=self.now)

    def test_valid_leader_linearizable_cluster_can_reach_production_ready(self):
        result = self.certify()
        self.assertTrue(result.capability_contract_ready)
        self.assertTrue(result.deployment_structure_ready)
        self.assertTrue(result.trusted_attestation_ready)
        self.assertTrue(result.production_ready)
        self.assertEqual(result.missing_requirements, ())

    def test_valid_quorum_read_model_requires_and_accepts_intersection(self):
        evidence = self.evidence(read_consistency_mode="quorum", read_quorum=2)
        result = self.certify(evidence)
        self.assertTrue(result.production_ready)

    def test_sqlite_reference_cannot_become_production_ready_from_evidence_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            sqlite_backend = SQLiteSharedStateBackend(Path(tmp) / "shared.db")
            try:
                evidence = replace(self.evidence(), backend_id=sqlite_backend.backend_id)
                result = self.certifier.certify(
                    sqlite_backend,
                    evidence,
                    TrustedVerifier(),
                    now=self.now,
                )
            finally:
                sqlite_backend.close()
        self.assertFalse(result.capability_contract_ready)
        self.assertFalse(result.production_ready)
        self.assertIn("authoritative_time", result.missing_requirements)
        self.assertIn("distributed_quorum", result.missing_requirements)

    def test_missing_independent_attestation_blocks_production(self):
        result = self.certifier.certify(self.backend, self.evidence(), None, now=self.now)
        self.assertFalse(result.trusted_attestation_ready)
        self.assertFalse(result.production_ready)
        self.assertIn("trusted_attestation_missing", result.missing_requirements)

    def test_failed_attestation_verification_blocks_production(self):
        result = self.certify(verifier=TrustedVerifier(fail=True))
        self.assertFalse(result.production_ready)
        self.assertIn("trusted_attestation_failed", result.missing_requirements)

    def test_attestation_digest_must_bind_exact_deployment_evidence(self):
        result = self.certify(verifier=TrustedVerifier(digest_override="0" * 64))
        self.assertFalse(result.production_ready)
        self.assertIn("trusted_attestation_digest_mismatch", result.missing_requirements)

    def test_stale_attestation_is_rejected(self):
        stale = (self.now - timedelta(seconds=301)).isoformat()
        result = self.certify(verifier=TrustedVerifier(verified_at=stale))
        self.assertFalse(result.production_ready)
        self.assertIn("trusted_attestation_stale", result.missing_requirements)

    def test_backend_identity_must_match_deployment_evidence(self):
        result = self.certify(self.evidence(backend_id="other-backend"))
        self.assertFalse(result.deployment_structure_ready)
        self.assertIn("backend_identity_mismatch", result.missing_requirements)

    def test_stale_topology_evidence_is_rejected(self):
        evidence = self.evidence(observed_at=(self.now - timedelta(seconds=301)).isoformat())
        result = self.certify(evidence)
        self.assertFalse(result.production_ready)
        self.assertIn("evidence_stale", result.missing_requirements)

    def test_future_topology_evidence_beyond_clock_skew_is_rejected(self):
        evidence = self.evidence(observed_at=(self.now + timedelta(seconds=61)).isoformat())
        result = self.certify(evidence)
        self.assertFalse(result.production_ready)
        self.assertIn("evidence_time_in_future", result.missing_requirements)

    def test_company_os_default_policy_requires_three_voting_members(self):
        evidence = self.evidence(
            members=(
                HAMemberEvidence("node-a", True, True, "zone-a"),
                HAMemberEvidence("node-b", True, True, "zone-b"),
            ),
            write_quorum=2,
        )
        result = self.certify(evidence)
        self.assertIn("minimum_voting_members_not_met", result.missing_requirements)
        self.assertFalse(result.production_ready)

    def test_company_os_default_policy_requires_three_failure_domains(self):
        evidence = self.evidence(
            members=(
                HAMemberEvidence("node-a", True, True, "zone-a"),
                HAMemberEvidence("node-b", True, True, "zone-a"),
                HAMemberEvidence("node-c", True, True, "zone-b"),
            )
        )
        result = self.certify(evidence)
        self.assertIn("minimum_failure_domains_not_met", result.missing_requirements)

    def test_healthy_voting_majority_must_be_available(self):
        evidence = self.evidence(
            members=(
                HAMemberEvidence("node-a", True, True, "zone-a"),
                HAMemberEvidence("node-b", True, False, "zone-b"),
                HAMemberEvidence("node-c", True, False, "zone-c"),
            )
        )
        result = self.certify(evidence)
        self.assertIn("healthy_voting_quorum_unavailable", result.missing_requirements)

    def test_write_quorum_cannot_be_below_voting_majority(self):
        result = self.certify(self.evidence(write_quorum=1, synchronous_replica_acks=1))
        self.assertIn("write_quorum_below_majority", result.missing_requirements)
        self.assertFalse(result.production_ready)

    def test_quorum_read_model_must_prove_read_write_intersection(self):
        evidence = self.evidence(read_consistency_mode="quorum", read_quorum=1)
        result = self.certify(evidence)
        self.assertIn("read_write_quorum_intersection_not_proven", result.missing_requirements)

    def test_synchronous_commit_is_required(self):
        result = self.certify(self.evidence(synchronous_commit=False))
        self.assertIn("synchronous_commit_disabled", result.missing_requirements)

    def test_synchronous_replica_ack_must_cover_write_quorum(self):
        result = self.certify(self.evidence(synchronous_replica_acks=0))
        self.assertIn("synchronous_replica_ack_insufficient", result.missing_requirements)

    def test_client_or_unrecognized_time_source_cannot_authorize_leases(self):
        evidence = self.evidence(
            authoritative_time_source="client_clock",
            lease_time_source="client_clock",
        )
        result = self.certify(evidence)
        self.assertIn("authoritative_time_source_invalid", result.missing_requirements)
        self.assertIn("lease_time_source_invalid", result.missing_requirements)

    def test_split_brain_protection_is_required(self):
        result = self.certify(self.evidence(split_brain_protection=False))
        self.assertIn("split_brain_protection_missing", result.missing_requirements)
        self.assertFalse(result.production_ready)

    def test_required_behavioral_probes_must_exist_pass_and_be_fresh(self):
        cases = [
            (self.probes(missing="network_partition_single_writer"), "probe_missing:network_partition_single_writer"),
            (self.probes(failed="monotonic_fencing"), "probe_failed:monotonic_fencing"),
            (self.probes(stale="authoritative_time"), "probe_stale:authoritative_time"),
        ]
        for probes, expected in cases:
            with self.subTest(expected=expected):
                result = self.certify(self.evidence(probes=probes))
                self.assertIn(expected, result.missing_requirements)
                self.assertFalse(result.production_ready)

    def test_require_production_ready_fails_closed_with_structured_reasons(self):
        evidence = self.evidence(split_brain_protection=False)
        with self.assertRaises(HardeningError) as cm:
            self.certifier.require_production_ready(
                self.backend,
                evidence,
                TrustedVerifier(),
                now=self.now,
            )
        self.assertEqual(cm.exception.code, "CFHS_HA_PERSISTENCE_NOT_READY")
        self.assertIn("split_brain_protection_missing", cm.exception.details["missing_requirements"])
        self.assertFalse(cm.exception.details["production_ready"])


if __name__ == "__main__":
    unittest.main()
