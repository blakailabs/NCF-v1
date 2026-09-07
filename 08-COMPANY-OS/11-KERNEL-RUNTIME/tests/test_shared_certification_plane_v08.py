import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kernel.ha_certification_runtime import HACertificationRecord
from kernel.hardening import HardeningError
from kernel.shared_certification_plane import SharedStateCertificationPlane
from kernel.shared_state_backend import SharedBackendCapabilities, SQLiteSharedStateBackend
from kernel.trust import sha256_hex


class PlaneBackend(SQLiteSharedStateBackend):
    def __init__(self, path, *, backend_id="shared-cert-plane-v08", now=None, full_capabilities=True):
        super().__init__(path, backend_id=backend_id)
        self.now = now or datetime.now(timezone.utc)
        self.full_capabilities = full_capabilities

    def authoritative_now(self):
        return self.now

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


class SharedCertificationPlaneV08Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "plane.db"
        self.now = datetime(2026, 9, 7, 3, 30, tzinfo=timezone.utc)
        self.backend = PlaneBackend(self.db_path, now=self.now)
        self.plane = SharedStateCertificationPlane(self.backend, fence_ttl_seconds=5)

    def tearDown(self):
        self.backend.close()
        self.tmp.cleanup()

    def record(self, *, epoch=31, nonce=None, evidence_digest=None, cluster_id="plane-cluster-001", valid_for=120):
        nonce = nonce or f"evidence-{epoch}"
        evidence_digest = evidence_digest or sha256_hex({"epoch": epoch, "nonce": nonce, "cluster": cluster_id})
        return HACertificationRecord(
            certification_id="ha_cert_" + sha256_hex({"epoch": epoch, "nonce": nonce, "digest": evidence_digest})[:24],
            backend_id=self.backend.backend_id,
            cluster_id=cluster_id,
            topology_epoch=epoch,
            evidence_nonce=nonce,
            evidence_digest=evidence_digest,
            attestation_digest=sha256_hex({"attestation": epoch, "nonce": nonce}),
            certification_digest=sha256_hex({"certification": epoch, "nonce": nonce}),
            certified_at=self.now.isoformat(),
            valid_until=(self.now + timedelta(seconds=valid_for)).isoformat(),
            status="ACTIVE",
        )

    def bootstrap_closed(self, *, owner="certifier-a", record=None, handoff_digest="handoff-31"):
        record = record or self.record()
        self.plane.prepare_handoff(
            cluster_id=record.cluster_id,
            topology_epoch=record.topology_epoch,
            handoff_digest=handoff_digest,
            bootstrap_state_digest=sha256_hex({"bootstrap": record.certification_id}),
            control_state_digest=sha256_hex({"control": record.certification_id}),
            owner_id=owner,
        )
        self.plane.activate(record, owner_id=owner, handoff_digest=handoff_digest)
        self.plane.close_handoff(
            cluster_id=record.cluster_id,
            topology_epoch=record.topology_epoch,
            handoff_digest=handoff_digest,
            certification_id=record.certification_id,
            owner_id=owner,
        )
        return record

    def second_plane(self, *, now=None):
        backend = PlaneBackend(self.db_path, backend_id=self.backend.backend_id, now=now or self.backend.now)
        return backend, SharedStateCertificationPlane(backend, fence_ttl_seconds=5)

    def test_cross_process_active_certificate_visibility(self):
        record = self.bootstrap_closed()
        backend2, plane2 = self.second_plane()
        try:
            active = plane2.require_active()
            self.assertEqual(active["certification_id"], record.certification_id)
            self.assertTrue(plane2.current().bootstrap_closed)
        finally:
            backend2.close()

    def test_concurrent_activation_conflict_allows_only_one_same_epoch_evidence(self):
        self.bootstrap_closed()
        record_a = self.record(epoch=32, nonce="epoch32-a")
        record_b = self.record(epoch=32, nonce="epoch32-b")

        def worker(record, owner):
            backend, plane = self.second_plane()
            try:
                try:
                    state = plane.activate(record, owner_id=owner)
                    return ("ok", state.active_certification["evidence_nonce"])
                except HardeningError as exc:
                    return (exc.code, None)
            finally:
                backend.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda args: worker(*args), [(record_a, "writer-a"), (record_b, "writer-b")]))
        self.assertEqual(sum(1 for status, _ in results if status == "ok"), 1)
        self.assertEqual(sum(1 for status, _ in results if status != "ok"), 1)
        active_nonce = self.plane.require_active()["evidence_nonce"]
        self.assertIn(active_nonce, {"epoch32-a", "epoch32-b"})

    def test_same_evidence_activation_is_idempotent(self):
        self.bootstrap_closed()
        record = self.record(epoch=32, nonce="same-evidence")
        first = self.plane.activate(record, owner_id="writer-a")
        version = first.version
        second = self.plane.activate(record, owner_id="writer-b")
        self.assertEqual(second.version, version)
        self.assertEqual(second.active_certification["certification_id"], record.certification_id)

    def test_higher_epoch_supersedes_visible_active_certificate(self):
        first = self.bootstrap_closed()
        higher = self.record(epoch=first.topology_epoch + 1)
        self.plane.activate(higher, owner_id="writer-next")
        active = self.plane.require_active()
        self.assertEqual(active["topology_epoch"], higher.topology_epoch)
        self.assertEqual(active["certification_id"], higher.certification_id)

    def test_lower_epoch_activation_is_rejected_as_rollback(self):
        first = self.bootstrap_closed()
        higher = self.record(epoch=first.topology_epoch + 2)
        self.plane.activate(higher, owner_id="writer-next")
        with self.assertRaises(HardeningError) as cm:
            self.plane.activate(self.record(epoch=first.topology_epoch + 1), owner_id="stale-writer")
        self.assertEqual(cm.exception.code, "CFHS_TOPOLOGY_ROLLBACK")

    def test_cluster_identity_conflict_is_rejected(self):
        self.bootstrap_closed()
        other_cluster = self.record(epoch=32, cluster_id="different-cluster")
        with self.assertRaises(HardeningError) as cm:
            self.plane.activate(other_cluster, owner_id="writer-other-cluster")
        self.assertEqual(cm.exception.code, "CFHS_CLUSTER_IDENTITY_CONFLICT")

    def test_invalidation_is_immediately_visible_across_processes(self):
        self.bootstrap_closed()
        backend2, plane2 = self.second_plane()
        try:
            plane2.invalidate("operator revoked deployment", owner_id="revoker")
            with self.assertRaises(HardeningError) as cm:
                self.plane.require_active()
            self.assertEqual(cm.exception.code, "CFHS_HA_CERTIFICATION_REQUIRED")
            state = self.plane.current()
            self.assertEqual(state.last_invalidation["reason"], "operator revoked deployment")
        finally:
            backend2.close()

    def test_certificate_expiry_uses_backend_authoritative_time_across_processes(self):
        self.bootstrap_closed(record=self.record(valid_for=20))
        backend2, plane2 = self.second_plane(now=self.now + timedelta(seconds=21))
        try:
            with self.assertRaises(HardeningError) as cm:
                plane2.require_active()
            self.assertEqual(cm.exception.code, "CFHS_HA_CERTIFICATION_EXPIRED")
        finally:
            backend2.close()

    def test_shared_handoff_closure_is_visible_to_other_processes(self):
        record = self.record()
        handoff = "shared-handoff"
        self.plane.prepare_handoff(
            cluster_id=record.cluster_id,
            topology_epoch=record.topology_epoch,
            handoff_digest=handoff,
            bootstrap_state_digest="b" * 64,
            control_state_digest="c" * 64,
            owner_id="writer-a",
        )
        self.plane.activate(record, owner_id="writer-a", handoff_digest=handoff)
        backend2, plane2 = self.second_plane()
        try:
            with self.assertRaises(HardeningError) as cm:
                plane2.require_active()
            self.assertEqual(cm.exception.code, "CFHS_HA_HANDOFF_INCOMPLETE")
            plane2.close_handoff(
                cluster_id=record.cluster_id,
                topology_epoch=record.topology_epoch,
                handoff_digest=handoff,
                certification_id=record.certification_id,
                owner_id="writer-b",
            )
            self.assertEqual(self.plane.require_active()["certification_id"], record.certification_id)
        finally:
            backend2.close()

    def test_stale_certifier_fence_is_rejected_after_takeover(self):
        old_fence = self.plane.acquire_writer_fence("old-certifier")
        backend2, plane2 = self.second_plane(now=self.now + timedelta(seconds=6))
        self.backend.now = self.now + timedelta(seconds=6)
        try:
            new_fence = plane2.acquire_writer_fence("new-certifier")
            try:
                with self.assertRaises(HardeningError) as cm:
                    self.plane.prepare_handoff(
                        cluster_id="plane-cluster-001",
                        topology_epoch=31,
                        handoff_digest="stale-handoff",
                        bootstrap_state_digest="b" * 64,
                        control_state_digest="c" * 64,
                        owner_id="old-certifier",
                        fence=old_fence,
                    )
                self.assertEqual(cm.exception.code, "CFHS_STALE_FENCE")
            finally:
                plane2.backend.release_fence(new_fence, now=plane2.backend.authoritative_now())
        finally:
            backend2.close()

    def test_control_plane_restart_recovers_shared_state_and_history_position(self):
        first = self.bootstrap_closed()
        self.backend.close()
        restarted_backend = PlaneBackend(self.db_path, backend_id="shared-cert-plane-v08", now=self.now)
        restarted = SharedStateCertificationPlane(restarted_backend, fence_ttl_seconds=5)
        try:
            state = restarted.current()
            self.assertTrue(state.bootstrap_closed)
            self.assertEqual(state.active_certification["certification_id"], first.certification_id)
            self.assertGreater(state.version, 1)
            self.assertGreater(restarted_backend.stream_version(restarted.stream_key(restarted.backend_id)), 0)
        finally:
            restarted_backend.close()
            self.backend = PlaneBackend(self.db_path, backend_id="shared-cert-plane-v08", now=self.now)
            self.plane = SharedStateCertificationPlane(self.backend, fence_ttl_seconds=5)

    def test_reference_adapter_cannot_claim_production_readiness(self):
        readiness = self.plane.readiness()
        self.assertFalse(readiness.production_ready)
        self.assertTrue(readiness.reference_adapter_only)
        self.assertIn("production_certification_plane_adapter_attestation", readiness.missing_requirements)
        weak_backend = PlaneBackend(self.root / "weak.db", backend_id="weak-plane", now=self.now, full_capabilities=False)
        try:
            weak = SharedStateCertificationPlane(weak_backend).readiness()
            self.assertFalse(weak.production_ready)
            self.assertIn("authoritative_time", weak.missing_requirements)
            self.assertIn("distributed_quorum", weak.missing_requirements)
        finally:
            weak_backend.close()


if __name__ == "__main__":
    unittest.main()
