import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from kernel.hardening import HardeningError, SessionManager
from kernel.trust import (
    CapabilityBoundingEngine,
    DurableEventBus,
    FileAuditAnchorProvider,
    MemoryVaultProvider,
    PolicyPackageSigner,
    RotatingSessionManager,
    SignedPolicyStore,
    VaultSecretBroker,
)


class TrustLayerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = sqlite3.connect(Path(self.tmp.name) / "trust.db")
        self.conn.row_factory = sqlite3.Row

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def _signed_policy(self, key=b"test-signing-key", amount=100):
        package = {
            "id": "finance-restrictions",
            "version": "0.3.0",
            "issued_at": "2026-09-05T00:00:00Z",
            "policies": [
                {
                    "id": "refund-elevation",
                    "effect": "ELEVATION_REQUIRED",
                    "principal": "agent:*",
                    "action": "payments.refund",
                    "resource": "/dev/payments/*",
                    "conditions": {"amount_gt": amount},
                }
            ],
        }
        return PolicyPackageSigner.sign(package, "root-1", key)

    def test_signed_policy_accepts_valid_signature(self):
        store = SignedPolicyStore({"root-1": b"test-signing-key"})
        result = store.install_atomic([self._signed_policy()])
        self.assertEqual(result["package_count"], 1)
        self.assertEqual(store.policies()[0]["package_id"], "finance-restrictions")

    def test_signed_policy_rejects_tampering(self):
        store = SignedPolicyStore({"root-1": b"test-signing-key"})
        envelope = self._signed_policy()
        envelope["package"]["policies"][0]["conditions"]["amount_gt"] = 999999
        with self.assertRaises(HardeningError) as cm:
            store.install_atomic([envelope])
        self.assertEqual(cm.exception.code, "CFHS_POLICY_DENIED")

    def test_signed_policy_install_is_atomic(self):
        store = SignedPolicyStore({"root-1": b"test-signing-key"})
        store.install_atomic([self._signed_policy()])
        good_before = list(store.policies())
        bad = self._signed_policy()
        bad["signature"]["value"] = "00" * 32
        with self.assertRaises(HardeningError):
            store.install_atomic([self._signed_policy(amount=50), bad])
        self.assertEqual(store.policies(), good_before)

    def test_audit_anchor_detects_tampering(self):
        path = Path(self.tmp.name) / "anchors.jsonl"
        anchors = FileAuditAnchorProvider(path)
        anchors.anchor("audit-head-1", {"node": "kernel-a"})
        anchors.anchor("audit-head-2", {"node": "kernel-a"})
        self.assertTrue(anchors.verify()["valid"])
        lines = path.read_text().splitlines()
        record = json.loads(lines[0])
        record["audit_head_hash"] = "rewritten"
        lines[0] = json.dumps(record)
        path.write_text("\n".join(lines) + "\n")
        self.assertFalse(anchors.verify()["valid"])

    def test_vault_lease_is_audience_bound(self):
        broker = VaultSecretBroker(MemoryVaultProvider({"vault://github/token": b"test-value"}))
        lease = broker.lease("vault://github/token", "github-reader", 30)
        self.assertNotIn("value", lease)
        self.assertEqual(broker.resolve_for_adapter(lease["lease_id"], "github-reader"), b"test-value")
        with self.assertRaises(HardeningError):
            broker.resolve_for_adapter(lease["lease_id"], "other-adapter")

    def test_session_rotation_revokes_old_token(self):
        sessions = SessionManager(self.conn)
        current = sessions.issue("agent:ops", 300)
        rotating = RotatingSessionManager(sessions)
        replacement = rotating.rotate(current["bearer_token"], 300)
        self.assertEqual(sessions.authenticate(replacement["bearer_token"]), "agent:ops")
        with self.assertRaises(HardeningError):
            sessions.authenticate(current["bearer_token"])

    def test_child_capabilities_must_be_bounded(self):
        parent = [
            {
                "action": "payments.refund",
                "resource": "/dev/payments/*",
                "conditions": {"max_amount": 250, "hard_limit": 20},
            }
        ]
        child_ok = [
            {
                "action": "payments.refund",
                "resource": "/dev/payments/primary",
                "conditions": {"max_amount": 100, "hard_limit": 5},
            }
        ]
        CapabilityBoundingEngine.assert_bounded(parent, child_ok)
        child_bad = [
            {
                "action": "payments.refund",
                "resource": "/dev/payments/primary",
                "conditions": {"max_amount": 500, "hard_limit": 5},
            }
        ]
        with self.assertRaises(HardeningError):
            CapabilityBoundingEngine.assert_bounded(parent, child_bad)

    def test_durable_event_bus_claim_ack_and_conflict(self):
        bus = DurableEventBus(self.conn)
        created = bus.publish("customer.created", {"customer_id": "c-1"})
        msg = bus.poll("worker-a", ["customer.created"])
        self.assertEqual(msg.id, created["event_id"])
        self.assertIsNone(bus.poll("worker-b", ["customer.created"]))
        with self.assertRaises(HardeningError):
            bus.ack("worker-b", msg.id)
        bus.ack("worker-a", msg.id)
        self.assertIsNone(bus.poll("worker-a", ["customer.created"]))

    def test_durable_event_bus_release_for_retry(self):
        bus = DurableEventBus(self.conn)
        bus.publish("invoice.ready", {"invoice_id": "i-1"})
        first = bus.poll("worker-a", ["invoice.ready"])
        self.assertEqual(first.attempts, 1)
        bus.release("worker-a", first.id, 0)
        second = bus.poll("worker-b", ["invoice.ready"])
        self.assertEqual(second.id, first.id)
        self.assertEqual(second.attempts, 2)


if __name__ == "__main__":
    unittest.main()
