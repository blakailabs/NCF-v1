import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kernel.hardening import HardeningError
from kernel.shared_state_backend import SQLiteSharedStateBackend, certify_backend


class SharedStateBackendV07Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "shared-backend.db"
        self.a = SQLiteSharedStateBackend(self.path, "node-a-backend")
        self.b = SQLiteSharedStateBackend(self.path, "node-b-backend")
        self.t0 = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)

    def tearDown(self):
        self.a.close()
        self.b.close()
        self.tmp.cleanup()

    def test_reference_backend_explicitly_fails_production_certification_for_quorum_and_time(self):
        result = certify_backend(self.a.capabilities())
        self.assertFalse(result.production_ready)
        self.assertIn("authoritative_time", result.missing_requirements)
        self.assertIn("distributed_quorum", result.missing_requirements)
        self.assertTrue(result.capabilities.serializable_transactions)
        self.assertTrue(result.capabilities.monotonic_fencing)

    def test_multi_connection_visibility(self):
        created = self.a.put_if_absent("company/object/1", {"status": "PENDING"})
        observed = self.b.read("company/object/1")
        self.assertEqual(created.version, 1)
        self.assertEqual(observed.version, 1)
        self.assertEqual(observed.value, {"status": "PENDING"})

    def test_put_if_absent_is_idempotent_for_same_value(self):
        first = self.a.put_if_absent("company/object/1", {"status": "PENDING"})
        second = self.b.put_if_absent("company/object/1", {"status": "PENDING"})
        self.assertEqual(first.version, second.version)
        self.assertEqual(first.value_digest, second.value_digest)

    def test_put_if_absent_rejects_different_value(self):
        self.a.put_if_absent("company/object/1", {"status": "PENDING"})
        with self.assertRaises(HardeningError) as cm:
            self.b.put_if_absent("company/object/1", {"status": "COMMITTED"})
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")
        self.assertEqual(self.a.read("company/object/1").value["status"], "PENDING")

    def test_compare_and_swap_advances_version_across_connections(self):
        self.a.put_if_absent("company/object/1", {"status": "PENDING"})
        updated = self.b.compare_and_swap("company/object/1", 1, {"status": "PREPARED"})
        self.assertEqual(updated.version, 2)
        self.assertEqual(self.a.read("company/object/1").value["status"], "PREPARED")

    def test_stale_compare_and_swap_is_rejected(self):
        self.a.put_if_absent("company/object/1", {"status": "PENDING"})
        self.a.compare_and_swap("company/object/1", 1, {"status": "PREPARED"})
        with self.assertRaises(HardeningError) as cm:
            self.b.compare_and_swap("company/object/1", 1, {"status": "COMMITTED"})
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")
        self.assertEqual(self.b.read("company/object/1").version, 2)

    def test_active_shared_fence_blocks_second_connection(self):
        first = self.a.acquire_fence("business:refund:1", "kernel:A", 30, self.t0)
        self.assertEqual(first.fence_token, 1)
        with self.assertRaises(HardeningError) as cm:
            self.b.acquire_fence("business:refund:1", "kernel:B", 30, self.t0 + timedelta(seconds=1))
        self.assertEqual(cm.exception.code, "CFHS_FENCE_BUSY")

    def test_expired_shared_fence_takeover_increments_epoch(self):
        first = self.a.acquire_fence("business:refund:1", "kernel:A", 10, self.t0)
        second = self.b.acquire_fence("business:refund:1", "kernel:B", 30, self.t0 + timedelta(seconds=11))
        self.assertEqual(first.fence_token, 1)
        self.assertEqual(second.fence_token, 2)
        with self.assertRaises(HardeningError) as cm:
            self.a.assert_fence(first, self.t0 + timedelta(seconds=12))
        self.assertEqual(cm.exception.code, "CFHS_STALE_FENCE")

    def test_clean_release_still_advances_next_fence_epoch(self):
        first = self.a.acquire_fence("business:refund:1", "kernel:A", 30, self.t0)
        self.a.release_fence(first, self.t0 + timedelta(seconds=1))
        second = self.b.acquire_fence("business:refund:1", "kernel:B", 30, self.t0 + timedelta(seconds=2))
        self.assertEqual(second.fence_token, 2)

    def test_journal_compare_and_append_is_linear_across_connections(self):
        one = self.a.append_event("transaction:1", 0, {"state": "PREPARED"})
        two = self.b.append_event("transaction:1", 1, {"state": "EXECUTING"})
        self.assertEqual(one["version"], 1)
        self.assertEqual(two["version"], 2)
        self.assertEqual([x["version"] for x in self.a.journal("transaction:1")], [1, 2])
        with self.assertRaises(HardeningError) as cm:
            self.a.append_event("transaction:1", 1, {"state": "STALE"})
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")

    def test_fenced_mutation_atomically_updates_object_and_journal(self):
        self.a.put_if_absent("transaction:1", {"status": "PREPARED"})
        fence = self.a.acquire_fence("business:refund:1", "kernel:A", 30, self.t0)
        obj, event = self.a.fenced_compare_and_swap_with_event(
            fence=fence,
            object_key="transaction:1",
            expected_object_version=1,
            value={"status": "EXECUTING"},
            stream_key="transaction:1",
            expected_stream_version=0,
            event={"transition": "PREPARED->EXECUTING"},
            now=self.t0 + timedelta(seconds=1),
        )
        self.assertEqual(obj.version, 2)
        self.assertEqual(obj.value["status"], "EXECUTING")
        self.assertEqual(event["version"], 1)
        journal = self.b.journal("transaction:1")
        self.assertEqual(journal[0]["event"]["fence_token"], 1)
        self.assertEqual(journal[0]["event"]["object_version"], 2)

    def test_stale_fenced_mutation_changes_neither_object_nor_journal(self):
        self.a.put_if_absent("transaction:1", {"status": "PREPARED"})
        stale = self.a.acquire_fence("business:refund:1", "kernel:A", 10, self.t0)
        current = self.b.acquire_fence("business:refund:1", "kernel:B", 30, self.t0 + timedelta(seconds=11))
        self.assertEqual(current.fence_token, 2)
        with self.assertRaises(HardeningError) as cm:
            self.a.fenced_compare_and_swap_with_event(
                fence=stale,
                object_key="transaction:1",
                expected_object_version=1,
                value={"status": "EXECUTING"},
                stream_key="transaction:1",
                expected_stream_version=0,
                event={"transition": "stale"},
                now=self.t0 + timedelta(seconds=12),
            )
        self.assertEqual(cm.exception.code, "CFHS_STALE_FENCE")
        self.assertEqual(self.b.read("transaction:1").version, 1)
        self.assertEqual(self.b.stream_version("transaction:1"), 0)

    def test_failed_journal_version_rolls_back_object_mutation(self):
        self.a.put_if_absent("transaction:1", {"status": "PREPARED"})
        self.a.append_event("transaction:1", 0, {"state": "PREPARED"})
        fence = self.a.acquire_fence("business:refund:1", "kernel:A", 30, self.t0)
        with self.assertRaises(HardeningError) as cm:
            self.a.fenced_compare_and_swap_with_event(
                fence=fence,
                object_key="transaction:1",
                expected_object_version=1,
                value={"status": "EXECUTING"},
                stream_key="transaction:1",
                expected_stream_version=0,
                event={"transition": "PREPARED->EXECUTING"},
                now=self.t0 + timedelta(seconds=1),
            )
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")
        self.assertEqual(self.b.read("transaction:1").version, 1)
        self.assertEqual(self.b.read("transaction:1").value["status"], "PREPARED")
        self.assertEqual(self.b.stream_version("transaction:1"), 1)


if __name__ == "__main__":
    unittest.main()
