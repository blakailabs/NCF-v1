import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kernel.ha_persistence import (
    HADeploymentEvidence,
    HAMemberEvidence,
    HAPersistenceCertifier,
    REQUIRED_PROBES,
    VerifiedDeploymentAttestation,
)
from kernel.ha_probe_harness import (
    DurabilityObservation,
    FaultLease,
    SerializableConflictObservation,
)
from kernel.ha_probe_harness_hardening import ResilientHAConformanceProbeHarness
from kernel.hardening import HardeningError
from kernel.shared_state_backend import SharedBackendCapabilities, SharedObject, SQLiteSharedStateBackend
from kernel.trust import sha256_hex


class ReferenceProbeClient:
    def __init__(self, target, client_id, member_id):
        self.target = target
        self.client_id = client_id
        self.member_id = member_id or target.members[0]
        self.backend = SQLiteSharedStateBackend(target.path, backend_id=target.backend_id)
        target.clients.append(self.backend)

    def _write_allowed(self):
        if self.target.quorum_lost and self.target.quorum_loss_effective:
            raise HardeningError("CFHS_QUORUM_UNAVAILABLE", "reference quorum unavailable")

    def read(self, object_key):
        if self.target.visibility_broken and self.client_id == "probe-visibility-b":
            return None
        return self.backend.read(object_key)

    def put_if_absent(self, object_key, value):
        self._write_allowed()
        return self.backend.put_if_absent(object_key, value)

    def compare_and_swap(self, object_key, expected_version, value):
        self._write_allowed()
        if self.target.partition_groups and self.member_id in self.target.partition_groups[-1]:
            if self.target.partition_allows_minority:
                return SharedObject(
                    object_key=object_key,
                    version=expected_version + 1,
                    value_digest=sha256_hex(value),
                    value=value,
                )
            raise HardeningError("CFHS_QUORUM_UNAVAILABLE", "minority partition cannot commit")
        if self.target.cas_accepts_stale and self.client_id == "probe-cas-b":
            current = self.backend.read(object_key)
            return self.backend.compare_and_swap(object_key, current.version, value)
        return self.backend.compare_and_swap(object_key, expected_version, value)

    def acquire_fence(self, resource_key, owner_id, ttl_seconds):
        self._write_allowed()
        return self.backend.acquire_fence(
            resource_key,
            owner_id,
            ttl_seconds,
            now=self.target.current_time,
        )

    def assert_fence(self, fence):
        if self.target.stale_fence_accepted and fence.owner_id in {"probe-owner-a", "takeover-owner-a"}:
            return None
        return self.backend.assert_fence(fence, now=self.target.current_time)

    def release_fence(self, fence):
        return self.backend.release_fence(fence, now=self.target.current_time)

    def append_event(self, stream_key, expected_version, event):
        self._write_allowed()
        if self.target.journal_accepts_stale and event.get("step") == "stale":
            return self.backend.append_event(stream_key, self.backend.stream_version(stream_key), event)
        return self.backend.append_event(stream_key, expected_version, event)

    def stream_version(self, stream_key):
        return self.backend.stream_version(stream_key)

    def journal(self, stream_key):
        return self.backend.journal(stream_key)


class ReferenceProbeTarget:
    def __init__(self, path, now):
        self.path = path
        self.backend_id = "probe-reference-ha-v08"
        self.current_time = now
        self.members = ("node-a", "node-b", "node-c")
        self.clients = []
        self.quorum_lost = False
        self.quorum_loss_effective = True
        self.partition_groups = None
        self.partition_allows_minority = False
        self.cas_accepts_stale = False
        self.stale_fence_accepted = False
        self.journal_accepts_stale = False
        self.visibility_broken = False
        self.durability_failover_broken = False
        self.serializable_anomaly = False
        self.serializable_raises = False
        self.time_sequence = []

    def close(self):
        seen = set()
        for backend in self.clients:
            if id(backend) not in seen:
                seen.add(id(backend))
                try:
                    backend.close()
                except Exception:
                    pass

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

    def member_ids(self):
        return self.members

    def open_client(self, client_id, member_id=None):
        return ReferenceProbeClient(self, client_id, member_id)

    def authoritative_now(self):
        if self.time_sequence:
            return self.time_sequence.pop(0)
        return self.current_time

    def wait_until_authoritative(self, instant):
        if instant > self.current_time:
            self.current_time = instant
        return self.current_time

    def run_serializable_conflict(self, probe_key):
        if self.serializable_raises:
            raise RuntimeError("reference transaction observer failed")
        if self.serializable_anomaly:
            return SerializableConflictObservation(
                initial_value=0,
                transaction_a_read=0,
                transaction_b_read=0,
                transaction_a_result="COMMITTED",
                transaction_b_result="COMMITTED",
                final_value=1,
                trace=(
                    {"tx": "A", "event": "read", "value": 0},
                    {"tx": "B", "event": "read", "value": 0},
                    {"tx": "A", "event": "commit"},
                    {"tx": "B", "event": "commit"},
                ),
            )
        return SerializableConflictObservation(
            initial_value=0,
            transaction_a_read=0,
            transaction_b_read=0,
            transaction_a_result="COMMITTED",
            transaction_b_result="SERIALIZATION_FAILURE",
            final_value=1,
            trace=(
                {"tx": "A", "event": "read", "value": 0},
                {"tx": "B", "event": "read", "value": 0},
                {"tx": "A", "event": "commit"},
                {"tx": "B", "event": "serialization_failure"},
            ),
        )

    def run_durability_roundtrip(self, probe_key, value):
        writer = self.open_client("durability-writer", "node-a")
        created = writer.put_if_absent(probe_key, value)
        reconnect = self.open_client("durability-reconnect", "node-a").read(probe_key)
        failover = self.open_client("durability-failover", "node-b").read(probe_key)
        return DurabilityObservation(
            acknowledged=True,
            value_digest=created.value_digest,
            reconnect_value_digest=reconnect.value_digest if reconnect else None,
            failover_value_digest=(
                None
                if self.durability_failover_broken
                else (failover.value_digest if failover else None)
            ),
            trace=(
                {"event": "acknowledged", "member": "node-a"},
                {"event": "reconnect_read", "member": "node-a"},
                {"event": "failover_read", "member": "node-b"},
            ),
        )


class ReferenceChaosController:
    def __init__(self):
        self.faults = []

    def begin_quorum_loss(self, target):
        target.quorum_lost = True
        fault = FaultLease(
            "fault-quorum",
            "quorum_loss",
            target.current_time.isoformat(),
            {"controller": "independent-reference-chaos"},
        )
        self.faults.append(fault)
        return fault

    def begin_partition(self, target, groups):
        target.partition_groups = groups
        fault = FaultLease(
            "fault-partition",
            "network_partition",
            target.current_time.isoformat(),
            {"groups": [list(group) for group in groups], "controller": "independent-reference-chaos"},
        )
        self.faults.append(fault)
        return fault

    def heal(self, fault):
        for target in getattr(self, "targets", []):
            target.quorum_lost = False
            target.partition_groups = None

    def attach(self, target):
        if not hasattr(self, "targets"):
            self.targets = []
        self.targets.append(target)
        return self


class TrustedVerifier:
    def verify(self, evidence):
        return VerifiedDeploymentAttestation(
            issuer_id="probe-observer",
            evidence_digest=evidence.digest(),
            verification_class="independent_observer",
            verified_at=evidence.observed_at,
            verifier_receipt_digest=sha256_hex({"probe": evidence.digest()}),
        )


class HAProbeHarnessV08Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.now = datetime(2026, 9, 6, 22, 0, tzinfo=timezone.utc)
        self.target = ReferenceProbeTarget(Path(self.tmp.name) / "probe.db", self.now)
        self.chaos = ReferenceChaosController().attach(self.target)

    def tearDown(self):
        self.target.close()
        self.tmp.cleanup()

    def harness(self, chaos=True):
        return ResilientHAConformanceProbeHarness(
            self.target,
            self.chaos if chaos else None,
            fence_ttl_seconds=1,
        )

    def result(self, report, name):
        return next(item for item in report.results if item.name == name)

    def deployment_evidence(self, report):
        return HADeploymentEvidence(
            backend_id=self.target.backend_id,
            cluster_id="probe-cluster-001",
            topology_epoch=1,
            observed_at=self.target.current_time.isoformat(),
            members=(
                HAMemberEvidence("node-a", True, True, "zone-a"),
                HAMemberEvidence("node-b", True, True, "zone-b"),
                HAMemberEvidence("node-c", True, True, "zone-c"),
            ),
            consensus_protocol="reference-consensus",
            write_quorum=2,
            read_consistency_mode="leader_linearizable",
            read_quorum=1,
            synchronous_commit=True,
            synchronous_replica_acks=1,
            authoritative_time_source="database_server",
            lease_time_source="database_server",
            split_brain_protection=True,
            probes=report.evidence(),
            evidence_issuer="active-probe-harness",
            evidence_nonce=report.run_id,
        )

    def test_full_reference_run_generates_ten_observed_passing_probes(self):
        report = self.harness().run()
        self.assertEqual(len(report.results), len(REQUIRED_PROBES))
        self.assertEqual(report.blocked(), ())
        self.assertEqual(report.failed(), ())
        self.assertTrue(report.complete())
        self.assertEqual({e.name for e in report.evidence()}, set(REQUIRED_PROBES))

    def test_without_independent_chaos_controller_fault_probes_are_blocked_not_passed(self):
        report = self.harness(chaos=False).run()
        self.assertEqual(
            set(report.blocked()),
            {"quorum_loss_fail_closed", "network_partition_single_writer"},
        )
        self.assertEqual(len(report.evidence()), 8)
        self.assertFalse(report.complete())

    def test_blocked_fault_probes_keep_ha_certification_incomplete(self):
        report = self.harness(chaos=False).run()
        evidence = self.deployment_evidence(report)
        result = HAPersistenceCertifier(max_evidence_age_seconds=300).certify(
            self.target,
            evidence,
            TrustedVerifier(),
            now=self.target.current_time,
        )
        self.assertFalse(result.production_ready)
        self.assertIn("probe_missing:quorum_loss_fail_closed", result.missing_requirements)
        self.assertIn("probe_missing:network_partition_single_writer", result.missing_requirements)

    def test_serializable_stale_snapshot_double_commit_is_detected(self):
        self.target.serializable_anomaly = True
        report = self.harness().run()
        self.assertIn("serializable_transaction", report.failed())
        self.assertEqual(
            self.result(report, "serializable_transaction").observation["stale_snapshot_commit_count"],
            2,
        )

    def test_stale_compare_and_swap_acceptance_is_detected(self):
        self.target.cas_accepts_stale = True
        report = self.harness().run()
        self.assertIn("compare_and_swap", report.failed())
        self.assertFalse(self.result(report, "compare_and_swap").observation["stale_rejected"])

    def test_stale_fence_acceptance_is_detected_in_fencing_and_takeover_probes(self):
        self.target.stale_fence_accepted = True
        report = self.harness().run()
        self.assertIn("monotonic_fencing", report.failed())
        self.assertIn("stale_owner_rejected_after_takeover", report.failed())

    def test_unordered_or_stale_journal_append_acceptance_is_detected(self):
        self.target.journal_accepts_stale = True
        report = self.harness().run()
        self.assertIn("ordered_journal", report.failed())
        self.assertFalse(self.result(report, "ordered_journal").observation["stale_append_rejected"])

    def test_cross_connection_visibility_failure_is_detected(self):
        self.target.visibility_broken = True
        report = self.harness().run()
        self.assertIn("multi_connection_visibility", report.failed())
        self.assertIsNone(self.result(report, "multi_connection_visibility").observation["reader_version"])

    def test_acknowledged_value_missing_after_failover_fails_durability_probe(self):
        self.target.durability_failover_broken = True
        report = self.harness().run()
        self.assertIn("synchronous_durability", report.failed())
        self.assertIsNone(self.result(report, "synchronous_durability").observation["failover_value_digest"])

    def test_regressing_authoritative_time_is_detected(self):
        self.target.time_sequence = [self.now, self.now - timedelta(seconds=1)]
        result = self.harness()._probe_time()
        self.assertEqual(result.status, "FAIL")
        self.assertFalse(result.observation["nondecreasing"])

    def test_ineffective_quorum_loss_fault_is_a_failed_probe_not_a_run_crash(self):
        self.target.quorum_loss_effective = False
        report = self.harness().run()
        result = self.result(report, "quorum_loss_fail_closed")
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(result.observation["write_committed_during_quorum_loss"])
        self.assertFalse(result.observation["write_after_heal_succeeded"])

    def test_partition_that_allows_minority_writer_is_detected_as_split_brain(self):
        self.target.partition_allows_minority = True
        report = self.harness().run()
        result = self.result(report, "network_partition_single_writer")
        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.observation["outcomes"], {"majority": "COMMITTED", "minority": "COMMITTED"})

    def test_individual_probe_exception_is_preserved_as_negative_evidence(self):
        self.target.serializable_raises = True
        report = self.harness().run()
        result = self.result(report, "serializable_transaction")
        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.observation["exception_class"], "RuntimeError")
        self.assertEqual(len(report.results), len(REQUIRED_PROBES))

    def test_report_and_probe_evidence_are_digest_bound(self):
        report = self.harness().run()
        self.assertTrue(report.report_digest)
        self.assertEqual(len(report.report_digest), 64)
        for result in report.results:
            self.assertTrue(result.observation_digest)
            self.assertEqual(len(result.observation_digest), 64)
        for evidence in report.evidence():
            self.assertTrue(evidence.evidence_digest)
            self.assertEqual(len(evidence.evidence_digest), 64)


if __name__ == "__main__":
    unittest.main()
