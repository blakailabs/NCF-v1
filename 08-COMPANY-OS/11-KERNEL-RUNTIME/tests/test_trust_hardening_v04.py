import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from kernel.hardening import HardeningError, SessionManager
from kernel.policy_hardening import PersistentRollbackProtectedPolicyStore
from kernel.trust import PolicyPackageSigner
from kernel.trust_hardening import DurableBootstrapCeremony, LeasedDeadLetterEventBus


class TrustHardeningV04Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "v04.db"
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def _signed(self, version="1.0.0", amount=100, key=b"policy-key"):
        package = {
            "id": "finance-guard",
            "version": version,
            "policies": [
                {
                    "id": "refund-guard",
                    "effect": "ELEVATION_REQUIRED",
                    "principal": "agent:*",
                    "action": "payments.refund",
                    "resource": "/dev/payments/*",
                    "conditions": {"amount_gt": amount},
                }
            ],
        }
        return PolicyPackageSigner.sign(package, "root-1", key)

    def test_bootstrap_is_durable_and_single_use_across_restart(self):
        sessions = SessionManager(self.conn)
        ceremony = DurableBootstrapCeremony(self.conn)
        ceremony.initialize("bootstrap-secret-value-123")
        first = ceremony.complete(sessions, "bootstrap-secret-value-123", "human:owner", 300)
        self.assertEqual(sessions.authenticate(first["bearer_token"]), "human:owner")
        self.conn.close()

        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        sessions2 = SessionManager(self.conn)
        ceremony2 = DurableBootstrapCeremony(self.conn)
        self.assertTrue(ceremony2.status()["completed"])
        with self.assertRaises(HardeningError) as cm:
            ceremony2.complete(sessions2, "bootstrap-secret-value-123", "human:owner", 300)
        self.assertEqual(cm.exception.code, "CFHS_POLICY_DENIED")

    def test_bootstrap_wrong_secret_rejected_without_consuming_ceremony(self):
        sessions = SessionManager(self.conn)
        ceremony = DurableBootstrapCeremony(self.conn)
        ceremony.initialize("bootstrap-secret-value-123")
        with self.assertRaises(HardeningError):
            ceremony.complete(sessions, "wrong-bootstrap-secret-456", "human:owner")
        self.assertEqual(ceremony.status()["status"], "PENDING")

    def test_policy_store_survives_restart(self):
        store = PersistentRollbackProtectedPolicyStore(self.conn, {"root-1": b"policy-key"})
        store.install_atomic([self._signed("1.0.0", 100)])
        self.assertEqual(store.active_policies()[0]["conditions"]["amount_gt"], 100)
        self.conn.close()

        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        store2 = PersistentRollbackProtectedPolicyStore(self.conn, {"root-1": b"policy-key"})
        self.assertEqual(store2.active_policies()[0]["conditions"]["amount_gt"], 100)
        self.assertEqual(store2.state()[0]["version"], "1.0.0")

    def test_policy_rollback_rejected(self):
        store = PersistentRollbackProtectedPolicyStore(self.conn, {"root-1": b"policy-key"})
        store.install_atomic([self._signed("2.0.0", 100)])
        with self.assertRaises(HardeningError) as cm:
            store.install_atomic([self._signed("1.9.9", 50)])
        self.assertEqual(cm.exception.code, "CFHS_POLICY_DENIED")
        self.assertEqual(store.state()[0]["version"], "2.0.0")

    def test_same_policy_version_different_content_rejected(self):
        store = PersistentRollbackProtectedPolicyStore(self.conn, {"root-1": b"policy-key"})
        store.install_atomic([self._signed("1.0.0", 100)])
        with self.assertRaises(HardeningError) as cm:
            store.install_atomic([self._signed("1.0.0", 999)])
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")

    def test_queue_claim_expires_and_can_be_reclaimed(self):
        bus = LeasedDeadLetterEventBus(self.conn, max_attempts=3, claim_ttl_seconds=1)
        created = bus.publish("company.invoice.ready", {"invoice_id": "i-1"})
        first = bus.poll("worker-a", ["company.invoice.ready"])
        self.assertEqual(first.id, created["event_id"])
        time.sleep(1.1)
        second = bus.poll("worker-b", ["company.invoice.ready"])
        self.assertEqual(second.id, first.id)
        self.assertEqual(second.attempts, 2)

    def test_expired_claim_cannot_be_acknowledged(self):
        bus = LeasedDeadLetterEventBus(self.conn, max_attempts=3, claim_ttl_seconds=1)
        bus.publish("company.job", {"job": 1})
        msg = bus.poll("worker-a", ["company.job"])
        time.sleep(1.1)
        with self.assertRaises(HardeningError):
            bus.ack("worker-a", msg.id)

    def test_queue_moves_to_dead_letter_at_max_attempts(self):
        bus = LeasedDeadLetterEventBus(self.conn, max_attempts=2, claim_ttl_seconds=30)
        bus.publish("company.job", {"job": 2})
        first = bus.poll("worker-a", ["company.job"])
        bus.release("worker-a", first.id, 0, "attempt-one-failed")
        second = bus.poll("worker-b", ["company.job"])
        bus.release("worker-b", second.id, 0, "attempt-two-failed")
        dead = bus.dead_letters()
        self.assertEqual(len(dead), 1)
        self.assertEqual(dead[0]["id"], first.id)
        self.assertEqual(dead[0]["attempts"], 2)


if __name__ == "__main__":
    unittest.main()
