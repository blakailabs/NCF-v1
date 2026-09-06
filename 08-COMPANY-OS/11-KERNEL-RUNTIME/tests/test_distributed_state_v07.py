import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kernel.distributed_safety import BusinessIdentityContract, BusinessIdentityLedger, SQLiteFenceStore
from kernel.distributed_state import SQLiteFencedStateCoordinator
from kernel.exact_units import ExactResourceLedger
from kernel.hardening import HardeningError
from kernel.provider_replay import ProviderReplayLedger


class DistributedStateCoordinatorV07Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = sqlite3.connect(Path(self.tmp.name) / "distributed-state.db")
        self.conn.row_factory = sqlite3.Row
        self.identities = BusinessIdentityLedger(self.conn)
        self.replay = ProviderReplayLedger(self.conn)
        self.fences = SQLiteFenceStore(self.conn)
        self.resources = ExactResourceLedger(self.conn)
        self.coordinator = SQLiteFencedStateCoordinator(self.conn)
        self.resources.configure_pool(
            "refund-usd-minor",
            100_000,
            "currency_minor",
            {"currency": "USD", "minor_exponent": 2},
        )
        self.contract = BusinessIdentityContract(
            "payments.refund.target",
            1,
            "payments.refund",
            ("provider_account_id", "charge_id", "refund_reference"),
        )
        self.arguments = {
            "provider_account_id": "acct-test",
            "charge_id": "charge-123",
            "refund_reference": "case-456",
            "amount": "10.00",
        }
        self.identity = self.contract.derive(self.arguments)
        self.intent_digest = "a" * 64
        self.replay_nonce = "distributed-state-nonce-001"
        self.intent_id = "intent-test-001"
        self.t0 = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)
        self.identities.bind(self.identity, "sandbox-payments", self.intent_digest)
        self.replay.reserve(self.replay_nonce, self.intent_digest)
        self.replay.attach_intent(self.replay_nonce, self.intent_digest, self.intent_id)

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

    def test_prepare_atomically_acquires_fence_and_exact_capacity(self):
        tx = self.prepare()
        self.assertEqual(tx.status, "PREPARED")
        self.assertEqual(tx.version, 1)
        self.assertEqual(tx.fence_token, 1)
        self.assertEqual(tx.exact_units, 1000)
        pool = self.resources.pool_state("refund-usd-minor")
        self.assertEqual(pool["reserved_units"], 1000)
        reservation = self.resources.reservation(tx.exact_reservation_id)
        self.assertEqual(reservation["status"], "RESERVED")
        fence = self.conn.execute(
            "SELECT * FROM fence_resources_v07 WHERE resource_key=?",
            (self.identity.resource_key(),),
        ).fetchone()
        self.assertEqual(fence["current_token"], 1)
        self.assertEqual(fence["owner_id"], "kernel:A")

    def test_prepare_writes_version_one_journal_record(self):
        tx = self.prepare()
        journal = self.coordinator.journal(tx.transaction_id)
        self.assertEqual(len(journal), 1)
        self.assertEqual(journal[0]["version"], 1)
        self.assertIsNone(journal[0]["from_status"])
        self.assertEqual(journal[0]["to_status"], "PREPARED")
        self.assertTrue(journal[0]["event_digest"])

    def test_prepare_same_owner_same_binding_is_idempotent(self):
        first = self.prepare()
        second = self.prepare()
        self.assertEqual(first.transaction_id, second.transaction_id)
        self.assertEqual(first.fence_token, second.fence_token)
        self.assertEqual(first.exact_reservation_id, second.exact_reservation_id)
        self.assertEqual(self.resources.pool_state("refund-usd-minor")["reserved_units"], 1000)
        self.assertEqual(len(self.coordinator.journal(first.transaction_id)), 1)

    def test_prepare_different_units_conflicts_without_additional_reservation(self):
        self.prepare(units=1000)
        with self.assertRaises(HardeningError) as cm:
            self.prepare(units=2000)
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")
        self.assertEqual(self.resources.pool_state("refund-usd-minor")["reserved_units"], 1000)

    def test_competing_owner_is_blocked_while_transaction_epoch_is_active(self):
        self.prepare(owner="kernel:A")
        with self.assertRaises(HardeningError) as cm:
            self.prepare(owner="kernel:B")
        self.assertEqual(cm.exception.code, "CFHS_FENCE_BUSY")

    def test_missing_business_identity_rolls_back_without_fence_or_resource(self):
        other_digest = "b" * 64
        other_nonce = "distributed-state-nonce-002"
        self.replay.reserve(other_nonce, other_digest)
        self.replay.attach_intent(other_nonce, other_digest, "intent-other")
        with self.assertRaises(HardeningError) as cm:
            self.coordinator.prepare(
                semantic_intent_digest=other_digest,
                replay_nonce=other_nonce,
                identity_digest="missing-identity",
                provider_id="sandbox-payments",
                resource_key="business-object:missing",
                owner_id="kernel:A",
                fence_ttl_seconds=30,
                exact_pool_id="refund-usd-minor",
                exact_units=1000,
                now=self.t0,
            )
        self.assertEqual(cm.exception.code, "CFHS_NOT_FOUND")
        self.assertEqual(self.resources.pool_state("refund-usd-minor")["reserved_units"], 0)
        self.assertIsNone(
            self.conn.execute("SELECT 1 FROM fence_resources_v07 WHERE resource_key='business-object:missing'").fetchone()
        )

    def test_missing_attached_replay_rolls_back_without_fence_or_resource(self):
        identity = self.contract.derive({**self.arguments, "charge_id": "charge-other"})
        digest = "c" * 64
        self.identities.bind(identity, "sandbox-payments", digest)
        with self.assertRaises(HardeningError) as cm:
            self.coordinator.prepare(
                semantic_intent_digest=digest,
                replay_nonce="unattached-replay-001",
                identity_digest=identity.identity_digest,
                provider_id="sandbox-payments",
                resource_key=identity.resource_key(),
                owner_id="kernel:A",
                fence_ttl_seconds=30,
                exact_pool_id="refund-usd-minor",
                exact_units=1000,
                now=self.t0,
            )
        self.assertEqual(cm.exception.code, "CFHS_IDEMPOTENCY_CONFLICT")
        self.assertEqual(self.resources.pool_state("refund-usd-minor")["reserved_units"], 0)
        self.assertIsNone(
            self.conn.execute("SELECT 1 FROM fence_resources_v07 WHERE resource_key=?", (identity.resource_key(),)).fetchone()
        )

    def test_resource_exhaustion_rolls_back_new_fence_epoch(self):
        self.resources.configure_pool(
            "tiny",
            500,
            "currency_minor",
            {"currency": "USD", "minor_exponent": 2},
        )
        with self.assertRaises(HardeningError) as cm:
            self.coordinator.prepare(
                semantic_intent_digest=self.intent_digest,
                replay_nonce=self.replay_nonce,
                identity_digest=self.identity.identity_digest,
                provider_id="sandbox-payments",
                resource_key=self.identity.resource_key(),
                owner_id="kernel:A",
                fence_ttl_seconds=30,
                exact_pool_id="tiny",
                exact_units=1000,
                now=self.t0,
            )
        self.assertEqual(cm.exception.code, "CFHS_RESOURCE_EXHAUSTED")
        self.assertEqual(self.resources.pool_state("tiny")["reserved_units"], 0)
        self.assertIsNone(
            self.conn.execute("SELECT 1 FROM fence_resources_v07 WHERE resource_key=?", (self.identity.resource_key(),)).fetchone()
        )
        self.assertIsNone(self.coordinator.find_for_intent(self.intent_digest))

    def test_assert_current_rejects_expired_epoch(self):
        tx = self.prepare()
        with self.assertRaises(HardeningError) as cm:
            self.coordinator.assert_current(
                tx.transaction_id,
                tx.fence_token,
                tx.owner_id,
                self.t0 + timedelta(seconds=31),
            )
        self.assertEqual(cm.exception.code, "CFHS_STALE_FENCE")

    def test_transition_to_executing_updates_business_and_journal_atomically(self):
        tx = self.prepare()
        executing = self.coordinator.transition(
            tx.transaction_id,
            tx.fence_token,
            tx.owner_id,
            "EXECUTING",
            {"provider_prepare": "confirmed"},
            self.t0 + timedelta(seconds=1),
        )
        self.assertEqual(executing.status, "EXECUTING")
        self.assertEqual(executing.version, 2)
        business = self.identities.get(self.identity.identity_digest)
        self.assertEqual(business["status"], "EXECUTING")
        journal = self.coordinator.journal(tx.transaction_id)
        self.assertEqual([(x["version"], x["to_status"]) for x in journal], [(1, "PREPARED"), (2, "EXECUTING")])

    def test_stale_fence_cannot_transition_transaction_after_takeover(self):
        tx = self.prepare()
        self.conn.execute(
            "UPDATE fence_resources_v07 SET expires_at='2000-01-01T00:00:00+00:00' WHERE resource_key=?",
            (tx.resource_key,),
        )
        self.conn.commit()
        takeover = self.fences.acquire(tx.resource_key, "kernel:B", 30, self.t0 + timedelta(seconds=31))
        self.assertEqual(takeover.fence_token, 2)
        with self.assertRaises(HardeningError) as cm:
            self.coordinator.transition(
                tx.transaction_id,
                tx.fence_token,
                tx.owner_id,
                "EXECUTING",
                now=self.t0 + timedelta(seconds=32),
            )
        self.assertEqual(cm.exception.code, "CFHS_STALE_FENCE")
        self.assertEqual(self.coordinator.get(tx.transaction_id).version, 1)
        self.assertEqual(self.identities.get(self.identity.identity_digest)["status"], "BOUND")

    def test_abort_pre_execute_releases_exact_capacity_and_fence(self):
        tx = self.prepare()
        aborted = self.coordinator.abort_pre_execute(
            tx.transaction_id,
            tx.fence_token,
            tx.owner_id,
            "audit anchor unavailable",
            self.t0 + timedelta(seconds=1),
        )
        self.assertEqual(aborted.status, "ABORTED")
        self.assertEqual(aborted.version, 2)
        self.assertEqual(self.resources.pool_state("refund-usd-minor")["reserved_units"], 0)
        self.assertEqual(self.resources.reservation(tx.exact_reservation_id)["status"], "RELEASED")
        fence = self.conn.execute(
            "SELECT * FROM fence_resources_v07 WHERE resource_key=?",
            (tx.resource_key,),
        ).fetchone()
        self.assertIsNone(fence["current_token"])
        self.assertEqual(self.identities.get(self.identity.identity_digest)["status"], "BOUND")
        self.assertEqual(self.replay.get(self.replay_nonce)["status"], "PENDING")

    def test_executing_can_enter_reconciliation_required_with_fenced_version(self):
        tx = self.prepare()
        running = self.coordinator.transition(tx.transaction_id, tx.fence_token, tx.owner_id, "EXECUTING", now=self.t0 + timedelta(seconds=1))
        unknown = self.coordinator.transition(
            tx.transaction_id,
            running.fence_token,
            running.owner_id,
            "RECONCILIATION_REQUIRED",
            {"provider_outcome": "unknown"},
            self.t0 + timedelta(seconds=2),
        )
        self.assertEqual(unknown.status, "RECONCILIATION_REQUIRED")
        self.assertEqual(unknown.version, 3)
        self.assertEqual(self.identities.get(self.identity.identity_digest)["status"], "RECONCILIATION_REQUIRED")

    def test_reconciliation_takeover_requires_released_or_expired_execution_fence(self):
        tx = self.prepare()
        self.coordinator.transition(tx.transaction_id, tx.fence_token, tx.owner_id, "EXECUTING", now=self.t0 + timedelta(seconds=1))
        unknown = self.coordinator.transition(tx.transaction_id, tx.fence_token, tx.owner_id, "RECONCILIATION_REQUIRED", now=self.t0 + timedelta(seconds=2))
        with self.assertRaises(HardeningError) as cm:
            self.coordinator.takeover_for_reconciliation(
                unknown.transaction_id,
                "kernel:B:reconcile",
                30,
                self.t0 + timedelta(seconds=3),
            )
        self.assertEqual(cm.exception.code, "CFHS_FENCE_BUSY")

    def test_reconciliation_takeover_uses_higher_epoch_and_old_owner_becomes_stale(self):
        tx = self.prepare()
        self.coordinator.transition(tx.transaction_id, tx.fence_token, tx.owner_id, "EXECUTING", now=self.t0 + timedelta(seconds=1))
        unknown = self.coordinator.transition(tx.transaction_id, tx.fence_token, tx.owner_id, "RECONCILIATION_REQUIRED", now=self.t0 + timedelta(seconds=2))
        self.coordinator.release_epoch(unknown.transaction_id, unknown.fence_token, unknown.owner_id, self.t0 + timedelta(seconds=3))
        reconcile = self.coordinator.takeover_for_reconciliation(
            unknown.transaction_id,
            "kernel:B:reconcile",
            30,
            self.t0 + timedelta(seconds=4),
        )
        self.assertEqual(reconcile.status, "RECONCILING")
        self.assertEqual(reconcile.fence_token, 2)
        self.assertEqual(reconcile.owner_id, "kernel:B:reconcile")
        self.assertGreater(reconcile.version, unknown.version)
        with self.assertRaises(HardeningError) as cm:
            self.coordinator.transition(
                tx.transaction_id,
                tx.fence_token,
                tx.owner_id,
                "COMMITTED",
                now=self.t0 + timedelta(seconds=5),
            )
        self.assertEqual(cm.exception.code, "CFHS_STALE_FENCE")

    def test_reconciler_can_commit_business_state_under_new_epoch(self):
        tx = self.prepare()
        self.coordinator.transition(tx.transaction_id, tx.fence_token, tx.owner_id, "EXECUTING", now=self.t0 + timedelta(seconds=1))
        unknown = self.coordinator.transition(tx.transaction_id, tx.fence_token, tx.owner_id, "RECONCILIATION_REQUIRED", now=self.t0 + timedelta(seconds=2))
        self.coordinator.release_epoch(unknown.transaction_id, unknown.fence_token, unknown.owner_id, self.t0 + timedelta(seconds=3))
        reconcile = self.coordinator.takeover_for_reconciliation(
            unknown.transaction_id,
            "kernel:B:reconcile",
            30,
            self.t0 + timedelta(seconds=4),
        )
        committed = self.coordinator.transition(
            reconcile.transaction_id,
            reconcile.fence_token,
            reconcile.owner_id,
            "COMMITTED",
            {"provider_lookup": "SUCCEEDED"},
            self.t0 + timedelta(seconds=5),
        )
        self.assertEqual(committed.status, "COMMITTED")
        self.assertEqual(self.identities.get(self.identity.identity_digest)["status"], "COMMITTED")
        journal = self.coordinator.journal(tx.transaction_id)
        self.assertEqual(journal[-1]["to_status"], "COMMITTED")
        self.assertEqual(journal[-1]["fence_token"], 2)

    def test_transaction_binding_change_is_rejected(self):
        self.prepare()
        with self.assertRaises(HardeningError) as cm:
            self.coordinator.prepare(
                semantic_intent_digest=self.intent_digest,
                replay_nonce=self.replay_nonce,
                identity_digest=self.identity.identity_digest,
                provider_id="sandbox-payments",
                resource_key=self.identity.resource_key(),
                owner_id="kernel:A",
                fence_ttl_seconds=30,
                exact_pool_id="refund-usd-minor",
                exact_units=2000,
                now=self.t0,
            )
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")


if __name__ == "__main__":
    unittest.main()
