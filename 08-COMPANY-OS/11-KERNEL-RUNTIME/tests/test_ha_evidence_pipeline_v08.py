import unittest
from datetime import datetime, timedelta, timezone

from kernel.ha_evidence_pipeline import HAEvidenceAssembler, HATopologySnapshot
from kernel.ha_persistence import (
    HAMemberEvidence,
    HAPersistenceCertifier,
    REQUIRED_PROBES,
    SharedBackendCapabilities,
    VerifiedDeploymentAttestation,
)
from kernel.ha_probe_harness import HAProbeRunReport, ProbeResult
from kernel.hardening import HardeningError
from kernel.trust import sha256_hex


class FullCapabilityBackend:
    backend_id = "pipeline-ha-backend-v08"

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
    def verify(self, evidence):
        return VerifiedDeploymentAttestation(
            issuer_id="independent-pipeline-verifier",
            evidence_digest=evidence.digest(),
            verification_class="independent_observer",
            verified_at=evidence.observed_at,
            verifier_receipt_digest=sha256_hex({"evidence": evidence.digest(), "issuer": "pipeline"}),
        )


class HAEvidencePipelineV08Tests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 9, 6, 23, 0, tzinfo=timezone.utc)
        self.assembler = HAEvidenceAssembler(max_topology_probe_skew_seconds=120)
        self.backend = FullCapabilityBackend()

    def snapshot(self, **overrides):
        values = {
            "backend_id": self.backend.backend_id,
            "cluster_id": "pipeline-cluster-001",
            "topology_epoch": 4,
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
            "source_id": "control-plane-observer",
            "source_class": "provider_control_plane",
            "source_receipt_digest": sha256_hex({"snapshot": "receipt-v1"}),
        }
        values.update(overrides)
        return HATopologySnapshot(**values)

    def probe_result(self, name, status="PASS", digest_suffix="base"):
        observation = {"name": name, "observed": True, "suffix": digest_suffix}
        return ProbeResult(
            name=name,
            status=status,
            observed_at=self.now.isoformat(),
            observation_digest=sha256_hex({"name": name, "status": status, "suffix": digest_suffix}),
            observation=observation,
            reason=None if status == "PASS" else "test negative evidence",
        )

    def report(self, *, blocked=None, failed=None, report_suffix="base", duplicate=None):
        results = []
        for name in REQUIRED_PROBES:
            status = "PASS"
            if name == blocked:
                status = "BLOCKED"
            elif name == failed:
                status = "FAIL"
            results.append(self.probe_result(name, status, report_suffix))
        if duplicate:
            results.append(self.probe_result(duplicate, "PASS", "duplicate"))
        payload = {
            "backend": self.backend.backend_id,
            "suffix": report_suffix,
            "results": [item.envelope() for item in results],
        }
        return HAProbeRunReport(
            run_id="probe-run-" + report_suffix,
            backend_id=self.backend.backend_id,
            started_at=(self.now - timedelta(seconds=10)).isoformat(),
            completed_at=(self.now + timedelta(seconds=10)).isoformat(),
            results=tuple(results),
            report_digest=sha256_hex(payload),
        )

    def test_valid_observed_sources_assemble_certifiable_digest_bound_evidence(self):
        assembly = self.assembler.require_certifiable_candidate(self.snapshot(), self.report())
        self.assertTrue(assembly.certifiable_candidate)
        self.assertEqual(assembly.blocking_reasons, ())
        self.assertEqual(len(assembly.deployment_evidence.probes), len(REQUIRED_PROBES))
        self.assertTrue(assembly.deployment_evidence.evidence_nonce.startswith("haevidence_"))
        self.assertEqual(len(assembly.assembly_digest), 64)
        self.assertIn("control-plane-observer", assembly.deployment_evidence.evidence_issuer)

    def test_assembled_evidence_passes_existing_certifier_with_independent_attestation(self):
        assembly = self.assembler.require_certifiable_candidate(self.snapshot(), self.report())
        certification = HAPersistenceCertifier(max_evidence_age_seconds=300).certify(
            self.backend,
            assembly.deployment_evidence,
            TrustedVerifier(),
            now=self.now,
        )
        self.assertTrue(certification.production_ready)
        self.assertEqual(certification.missing_requirements, ())

    def test_probe_backend_must_match_topology_backend(self):
        report = self.report()
        wrong = HAProbeRunReport(
            run_id=report.run_id,
            backend_id="other-backend",
            started_at=report.started_at,
            completed_at=report.completed_at,
            results=report.results,
            report_digest=report.report_digest,
        )
        with self.assertRaises(HardeningError) as cm:
            self.assembler.assemble(self.snapshot(), wrong)
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")

    def test_topology_requires_digest_bound_source_receipt(self):
        with self.assertRaises(HardeningError) as cm:
            self.assembler.assemble(self.snapshot(source_receipt_digest=""), self.report())
        self.assertEqual(cm.exception.code, "CFHS_INVALID_EVIDENCE")

    def test_topology_source_class_must_be_explicitly_accepted(self):
        with self.assertRaises(HardeningError) as cm:
            self.assembler.assemble(self.snapshot(source_class="self_asserted_config"), self.report())
        self.assertEqual(cm.exception.code, "CFHS_INVALID_EVIDENCE")

    def test_topology_and_probe_observations_must_share_bounded_time_window(self):
        old = self.snapshot(observed_at=(self.now - timedelta(seconds=131)).isoformat())
        with self.assertRaises(HardeningError) as cm:
            self.assembler.assemble(old, self.report())
        self.assertEqual(cm.exception.code, "CFHS_EVIDENCE_WINDOW_MISMATCH")

    def test_blocked_probe_produces_noncertifiable_assembly_and_no_positive_probe_evidence(self):
        report = self.report(blocked="network_partition_single_writer")
        assembly = self.assembler.assemble(self.snapshot(), report)
        self.assertFalse(assembly.certifiable_candidate)
        self.assertIn("probe_blocked:network_partition_single_writer", assembly.blocking_reasons)
        self.assertNotIn(
            "network_partition_single_writer",
            {probe.name for probe in assembly.deployment_evidence.probes},
        )
        with self.assertRaises(HardeningError) as cm:
            self.assembler.require_certifiable_candidate(self.snapshot(), report)
        self.assertEqual(cm.exception.code, "CFHS_HA_EVIDENCE_INCOMPLETE")

    def test_failed_probe_remains_negative_evidence_for_existing_certifier(self):
        report = self.report(failed="monotonic_fencing")
        assembly = self.assembler.assemble(self.snapshot(), report)
        self.assertIn("probe_failed:monotonic_fencing", assembly.blocking_reasons)
        certification = HAPersistenceCertifier(max_evidence_age_seconds=300).certify(
            self.backend,
            assembly.deployment_evidence,
            TrustedVerifier(),
            now=self.now,
        )
        self.assertFalse(certification.production_ready)
        self.assertIn("probe_failed:monotonic_fencing", certification.missing_requirements)

    def test_probe_report_digest_changes_final_evidence_nonce(self):
        one = self.assembler.assemble(self.snapshot(), self.report(report_suffix="one"))
        two = self.assembler.assemble(self.snapshot(), self.report(report_suffix="two"))
        self.assertNotEqual(one.probe_report_digest, two.probe_report_digest)
        self.assertNotEqual(one.deployment_evidence.evidence_nonce, two.deployment_evidence.evidence_nonce)
        self.assertNotEqual(one.deployment_evidence.digest(), two.deployment_evidence.digest())

    def test_topology_source_receipt_changes_final_evidence_nonce(self):
        one = self.assembler.assemble(self.snapshot(), self.report())
        two = self.assembler.assemble(
            self.snapshot(source_receipt_digest=sha256_hex({"snapshot": "receipt-v2"})),
            self.report(),
        )
        self.assertNotEqual(one.topology_source_receipt_digest, two.topology_source_receipt_digest)
        self.assertNotEqual(one.deployment_evidence.evidence_nonce, two.deployment_evidence.evidence_nonce)

    def test_duplicate_probe_identity_is_rejected_before_assembly(self):
        with self.assertRaises(HardeningError) as cm:
            self.assembler.assemble(
                self.snapshot(),
                self.report(duplicate="compare_and_swap"),
            )
        self.assertEqual(cm.exception.code, "CFHS_INVALID_EVIDENCE")


if __name__ == "__main__":
    unittest.main()
