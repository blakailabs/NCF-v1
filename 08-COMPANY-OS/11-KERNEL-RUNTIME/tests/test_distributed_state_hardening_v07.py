import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kernel.distributed_safety import BusinessIdentityContract, BusinessIdentityLedger, SQLiteFenceStore
from kernel.distributed_state_hardening import RecoverableSQLiteFencedStateCoordinator
from kernel.exact_units import ExactResourceLedger
from kernel.hardening import HardeningError
from kernel.provider_replay import ProviderReplayLedger


class DistributedStateHardeningV07Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = sqlite3.connect(Path(self.tmp.name) / "distributed-state-hardening.db")
        self.conn.row_factory = sqlite3.Row
        self.identities = BusinessIdentityLedger(self.conn)
        self.replay = ProviderReplayLedger(self.conn)
        self.fences = SQLiteFenceStore(self.conn)
        self.resources = ExactResourceLedger(self.conn)
        self.coordinator = RecoverableSQLiteFencedStateCoordinator(self.conn)
        self.resources.configure_pool(
            "refund-usd-minor",
            100_000,
            "currency_minor",
            {"currency": "USD", "minor_exponent": 2},
        )
        contract = BusinessIdentityContract(
            "payments.refund.target",
            1,
            "payments.refund",
            ("provider_account_id", "charge_id", "refund_reference"),
        )
        self.identity = contract.derive(
            {
                "provider_account_id": "acct-test",
                "charge_id": "charge-123",
                "refund_reference": "case-456",
            }
        )
        self.intent_digest = "d" * 64
        self.replay_nonce = "recoverable-distributed-nonce-001"
        self.identities.bind(self.identity, "sandbox-payments", self.intent_digest)
        self.replay.reserve(self.replay_nonce, self.intent_digest)
        self.replay.attach_intent(self.replay_nonce, self.intent_digest, "intent-recoverable")
        self.t0 = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def prepare(self, owner="kernel:A", units=1000, now=None):
        return self.coordinator.prepare(
            semantic_intent_digest=self.intent_digest,
            replay_nonce=self.replay_nonce,
            identity_digest=self.identity.identity_digest,
            provider_id="sandbox-payments",
            resource_key=self.identity.resource_key(),
            owner_id=owner,
            fence_ttl_seconds=30,
            exact_pool_id="refund-usd-minor",
            exact_units=units,
            now=now or self.t0,
        )

    def test_safe_abort_can_reprepare_under_higher_epoch(self):
        first = self.prepare()
        aborted = self.coordinator.abort_pre_execute(
            first.transaction_id,
            first.fence_token,
            first.owner_id,
            "temporary audit outage",
            self.t0 + timedelta(seconds=1),
        )
        retried = self.prepare(owner="kernel:A", now=self.t0 + timedelta(seconds=2))
        self.assertEqual(retried.transaction_id, first.transaction_id)
        self.assertEqual(aborted.status, "ABORTED")
        self.assertEqual(retried.status, "PREPARED")
        self.assertEqual(retried.fence_token, 2)
        self.assertNotEqual(retried.exact_reservation_id, first.exact_reservation_id)
        self.assertEqual(self.resources.reservation(first.exact_reservation_id)["status"], "RELEASED")
        self.assertEqual(self.resources.reservation(retried.exact_reservation_id)["status"], "RESERVED")
        self.assertEqual(self.resources.pool_state("refund-usd-minor")["reserved_units"], 1000)
        self.assertEqual(
            [(x["version"], x["to_status"]) for x in self.coordinator.journal(first.transaction_id)],
            [(1, "PREPARED"), (2, "ABORTED"), (3, "PREPARED")],
        )

    def test_retry_cannot_change_exact_units(self):
        first = self.prepare(units=1000)
        self.coordinator.abort_pre_execute(
            first.transaction_id,
            first.fence_token,
            first.owner_id,
            "temporary failure",
            self.t0 + timedelta(seconds=1),
        )
        with self.assertRaises(HardeningError) as cm:
            self.prepare(units=2000, now=self.t0 + timedelta(seconds=2))
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")
        self.assertEqual(self.resources.pool_state("refund-usd-minor")["reserved_units"], 0)

    def test_prepared_takeover_before_expiry_is_blocked(self):
        first = self.prepare()
        with self.assertRaises(HardeningError) as cm:
            self.coordinator.takeover_prepared(
                first.transaction_id,
                "kernel:B",
                30,
                self.t0 + timedelta(seconds=10),
            )
        self.assertEqual(cm.exception.code, "CFHS_FENCE_BUSY")

    def test_prepared_takeover_after_expiry_uses_higher_token_without_double_reserve(self):
        first = self.prepare()
        takeover = self.coordinator.takeover_prepared(
            first.transaction_id,
            "kernel:B",
            30,
            self.t0 + timedelta(seconds=31),
        )
        self.assertEqual(takeover.transaction_id, first.transaction_id)
        self.assertEqual(takeover.fence_token, 2)
        self.assertEqual(takeover.owner_id, "kernel:B")
        self.assertEqual(takeover.exact_reservation_id, first.exact_reservation_id)
        self.assertEqual(self.resources.pool_state("refund-usd-minor")["reserved_units"], 1000)
        journal = self.coordinator.journal(first.transaction_id)
        self.assertEqual(journal[-1]["from_status"], "PREPARED")
        self.assertEqual(journal[-1]["to_status"], "PREPARED")
        self.assertEqual(journal[-1]["fence_token"], 2)

    def test_old_owner_is_stale_after_prepared_takeover(self):
        first = self.prepare()
        takeover = self.coordinator.takeover_prepared(
            first.transaction_id,
            "kernel:B",
            30,
            self.t0 + timedelta(seconds=31),
        )
        with self.assertRaises(HardeningError) as cm:
            self.coordinator.transition(
                first.transaction_id,
                first.fence_token,
                first.owner_id,
                "EXECUTING",
                now=self.t0 + timedelta(seconds=32),
            )
        self.assertEqual(cm.exception.code, "CFHS_STALE_FENCE")
        running = self.coordinator.transition(
            takeover.transaction_id,
            takeover.fence_token,
            takeover.owner_id,
            "EXECUTING",
            now=self.t0 + timedelta(seconds=32),
        )
        self.assertEqual(running.status, "EXECUTING")

    def test_retry_resource_exhaustion_rolls_back_new_epoch_and_capacity(self):
        first = self.prepare()
        self.coordinator.abort_pre_execute(
            first.transaction_id,
            first.fence_token,
            first.owner_id,
            "temporary failure",
            self.t0 + timedelta(seconds=1),
        )
        self.resources.configure_pool(
            "refund-usd-minor",
            500,
            "currency_minor",
            {"currency": "USD", "minor_exponent": 2},
        )
        with self.assertRaises(HardeningError) as cm:
            self.prepare(now=self.t0 + timedelta(seconds=2))
        self.assertEqual(cm.exception.code, "CFHS_RESOURCE_EXHAUSTED")
        fence = self.conn.execute(
            "SELECT * FROM fence_resources_v07 WHERE resource_key=?",
            (self.identity.resource_key(),),
        ).fetchone()
        self.assertIsNone(fence["current_token"])
        self.assertEqual(self.resources.pool_state("refund-usd-minor")["reserved_units"], 0)


if __name__ == "__main__":
    unittest.main()
