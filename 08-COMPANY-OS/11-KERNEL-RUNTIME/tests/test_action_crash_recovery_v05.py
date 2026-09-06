import sqlite3
import tempfile
import unittest
from pathlib import Path

from kernel.action_safety import (
    ActionIntent,
    CompensationRegistry,
    MultiPartyApprovalLedger,
    ReplayNonceRegistry,
    ResourceRequest,
    ResourceReservationLedger,
    SQLiteActionAuditSink,
    digest,
)
from kernel.action_safety_runtime import CrashSafeConsequentialActionCoordinator
from kernel.hardening import HardeningError


class RuntimeFailPrepareAudit(SQLiteActionAuditSink):
    def prepare(self, intent):
        raise RuntimeError("storage unavailable before audit prepare")


class CrashRecoveryV05Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "crash.db"
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.replay = ReplayNonceRegistry(self.conn)
        self.resources = ResourceReservationLedger(self.conn)
        self.approvals = MultiPartyApprovalLedger(self.conn)
        self.compensation = CompensationRegistry(self.conn)
        self.audit = SQLiteActionAuditSink(self.conn)
        self.resources.configure_pool("money", 1000)
        self.coordinator = CrashSafeConsequentialActionCoordinator(
            self.conn, self.replay, self.resources, self.approvals, self.compensation, self.audit
        )

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def make_intent(self, nonce="crash-nonce-001", amount=100, side="S3"):
        args = {"amount": amount}
        intent = ActionIntent.create(
            actor_id="agent:ops",
            process_id="proc:ops",
            action="payments.refund",
            resource="/dev/payments/primary",
            side_effect_class=side,
            purpose="crash-test",
            arguments=args,
            replay_nonce=nonce,
            required_approvals=0,
            resource_requests=[ResourceRequest("money", amount)],
        )
        return intent, args

    def mark_executing(self, intent):
        self.coordinator.intents.set_status(
            intent.intent_id,
            "EXECUTING",
            self.coordinator.recovery._now(self.conn),
        )

    def stage_prepared(self, intent):
        self.coordinator.intents.register(intent)
        self.mark_executing(intent)
        self.replay.reserve(intent.replay_nonce, intent.intent_digest())
        reservations = self.resources.reserve_many(intent.intent_id, intent.resource_requests)
        audit_id = self.audit.prepare(intent)
        return reservations, audit_id

    def test_unexpected_storage_exception_before_invoke_is_cleaned_up(self):
        bad = CrashSafeConsequentialActionCoordinator(
            self.conn,
            self.replay,
            self.resources,
            self.approvals,
            self.compensation,
            RuntimeFailPrepareAudit(self.conn),
        )
        intent, args = self.make_intent(nonce="crash-runtime-prep")
        called = {"invoke": False}

        with self.assertRaises(HardeningError) as cm:
            bad.execute(
                intent,
                args,
                lambda i, a: {"decision": "ALLOW"},
                lambda a: called.__setitem__("invoke", True),
            )

        self.assertEqual(cm.exception.code, "CFHS_PREEXECUTION_FAILED")
        self.assertFalse(called["invoke"])
        self.assertEqual(self.resources.pool_state("money")["reserved"], 0)
        self.assertEqual(self.resources.pool_state("money")["used"], 0)
        self.assertEqual(self.replay.get(intent.replay_nonce)["status"], "FAILED")

    def test_crash_after_reservation_before_audit_releases_resources(self):
        intent, _ = self.make_intent(nonce="crash-before-audit")
        self.coordinator.intents.register(intent)
        self.mark_executing(intent)
        self.replay.reserve(intent.replay_nonce, intent.intent_digest())
        self.resources.reserve_many(intent.intent_id, intent.resource_requests)

        result = self.coordinator.recovery.reconcile_intent(intent.intent_id)

        self.assertEqual(result["recovery"], "RELEASED_PREEXECUTION")
        self.assertEqual(self.resources.pool_state("money")["reserved"], 0)
        self.assertEqual(self.resources.pool_state("money")["used"], 0)
        self.assertEqual(self.replay.get(intent.replay_nonce)["status"], "FAILED")

    def test_crash_after_audit_prepare_before_execution_start_is_safe(self):
        intent, _ = self.make_intent(nonce="crash-after-prepare")
        self.stage_prepared(intent)

        result = self.coordinator.recovery.reconcile_intent(intent.intent_id)

        self.assertEqual(result["recovery"], "RELEASED_PREEXECUTION")
        self.assertEqual(self.resources.pool_state("money")["used"], 0)
        self.assertEqual(self.resources.pool_state("money")["reserved"], 0)
        audit = self.conn.execute(
            "SELECT status,failure_code FROM action_commit_audit WHERE intent_id=?",
            (intent.intent_id,),
        ).fetchone()
        self.assertEqual(audit["status"], "FAILED")
        self.assertEqual(audit["failure_code"], "CFHS_PREEXECUTION_CRASH")

    def test_crash_after_execution_start_is_unknown_and_conservatively_accounted(self):
        intent, _ = self.make_intent(nonce="crash-after-start", amount=90)
        self.stage_prepared(intent)
        self.coordinator.intents.mark_execution_started(intent.intent_id, self.coordinator.recovery._now(self.conn))

        result = self.coordinator.recovery.reconcile_intent(intent.intent_id)

        self.assertEqual(result["recovery"], "UNKNOWN_SIDE_EFFECT")
        self.assertEqual(self.resources.pool_state("money")["used"], 90)
        self.assertEqual(self.resources.pool_state("money")["reserved"], 0)
        self.assertEqual(self.replay.get(intent.replay_nonce)["status"], "UNKNOWN_SIDE_EFFECT")

    def test_crash_after_audit_commit_recovers_resource_and_replay_commit(self):
        intent, _ = self.make_intent(nonce="crash-after-audit-commit", amount=75)
        _, audit_id = self.stage_prepared(intent)
        self.coordinator.intents.mark_execution_started(intent.intent_id, self.coordinator.recovery._now(self.conn))
        result_digest = digest({"provider": "succeeded"})
        self.audit.commit(audit_id, result_digest)

        result = self.coordinator.recovery.reconcile_intent(intent.intent_id)

        self.assertEqual(result["recovery"], "COMMITTED_FROM_AUDIT")
        self.assertEqual(self.resources.pool_state("money")["used"], 75)
        self.assertEqual(self.resources.pool_state("money")["reserved"], 0)
        replay = self.replay.get(intent.replay_nonce)
        self.assertEqual(replay["status"], "COMMITTED")
        self.assertEqual(replay["result_digest"], result_digest)

    def test_crash_after_resource_commit_before_replay_commit_recovers_replay(self):
        intent, _ = self.make_intent(nonce="crash-after-resource-commit", amount=65)
        reservations, audit_id = self.stage_prepared(intent)
        self.coordinator.intents.mark_execution_started(intent.intent_id, self.coordinator.recovery._now(self.conn))
        result_digest = digest({"provider": "succeeded"})
        self.audit.commit(audit_id, result_digest)
        self.resources.commit_many([r["reservation_id"] for r in reservations])

        result = self.coordinator.recovery.reconcile_intent(intent.intent_id)

        self.assertEqual(result["recovery"], "COMMITTED_FROM_AUDIT")
        self.assertEqual(self.resources.pool_state("money")["used"], 65)
        self.assertEqual(self.replay.get(intent.replay_nonce)["status"], "COMMITTED")

    def test_reconcile_all_recovers_multiple_active_intents(self):
        safe, _ = self.make_intent(nonce="crash-batch-safe", amount=20)
        unknown, _ = self.make_intent(nonce="crash-batch-unknown", amount=30)
        self.stage_prepared(safe)
        self.stage_prepared(unknown)
        self.coordinator.intents.mark_execution_started(unknown.intent_id, self.coordinator.recovery._now(self.conn))

        result = self.coordinator.recovery.reconcile_all()

        self.assertEqual(result["count"], 2)
        states = {r["intent_id"]: r["recovery"] for r in result["results"]}
        self.assertEqual(states[safe.intent_id], "RELEASED_PREEXECUTION")
        self.assertEqual(states[unknown.intent_id], "UNKNOWN_SIDE_EFFECT")
        self.assertEqual(self.resources.pool_state("money")["used"], 30)


if __name__ == "__main__":
    unittest.main()
