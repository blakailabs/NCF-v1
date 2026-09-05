import sqlite3
import tempfile
import unittest
from pathlib import Path

from kernel.action_safety import (
    ActionIntent,
    CompensationRegistry,
    ConsequentialActionCoordinator,
    MultiPartyApprovalLedger,
    ReplayNonceRegistry,
    ResourceRequest,
    ResourceReservationLedger,
    SQLiteActionAuditSink,
)
from kernel.hardening import HardeningError


class FailingPrepareAudit(SQLiteActionAuditSink):
    def prepare(self, intent):
        raise HardeningError("CFHS_INTERNAL", "audit unavailable")


class FailingCommitAudit(SQLiteActionAuditSink):
    def commit(self, audit_id, result_digest):
        raise RuntimeError("audit commit unavailable")


class ActionSafetyV05Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "action.db"
        self.conn = sqlite3.connect(self.db)
        self.conn.row_factory = sqlite3.Row
        self.replay = ReplayNonceRegistry(self.conn)
        self.resources = ResourceReservationLedger(self.conn)
        self.approvals = MultiPartyApprovalLedger(self.conn)
        self.compensation = CompensationRegistry(self.conn)
        self.audit = SQLiteActionAuditSink(self.conn)
        self.coordinator = ConsequentialActionCoordinator(self.replay, self.resources, self.approvals, self.compensation, self.audit)
        self.resources.configure_pool("refund-budget", 1000)
        self.resources.configure_pool("message-budget", 10)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    @staticmethod
    def allow(_intent, _arguments):
        return {"decision": "ALLOW"}

    def intent(self, side="S2", nonce="nonce-action-001", amount=100, required=None):
        args = {"amount": amount}
        return ActionIntent.create(
            actor_id="agent:ops",
            process_id="proc:ops",
            action="payments.refund" if side != "S1" else "crm.note.update",
            resource="/dev/payments/primary" if side != "S1" else "/dev/crm/primary",
            side_effect_class=side,
            purpose="customer correction",
            arguments=args,
            replay_nonce=nonce,
            required_approvals=required,
            evidence_refs=["ticket:123"],
            resource_requests=[ResourceRequest("refund-budget", amount)] if side != "S1" else [],
        ), args

    def test_semantic_digest_survives_new_ephemeral_intent(self):
        first, args = self.intent(nonce="nonce-stable-001")
        second = ActionIntent.create(
            actor_id=first.actor_id,
            process_id=first.process_id,
            action=first.action,
            resource=first.resource,
            side_effect_class=first.side_effect_class,
            purpose=first.purpose,
            arguments=args,
            replay_nonce=first.replay_nonce,
            required_approvals=first.required_approvals,
            evidence_refs=list(first.evidence_refs),
            resource_requests=list(first.resource_requests),
        )
        self.assertNotEqual(first.intent_id, second.intent_id)
        self.assertEqual(first.intent_digest(), second.intent_digest())

    def test_same_nonce_different_action_conflicts(self):
        first, _ = self.intent(nonce="nonce-conflict-01")
        self.replay.reserve(first.replay_nonce, first.intent_digest())
        second, _ = self.intent(nonce="nonce-conflict-01", amount=200)
        with self.assertRaises(HardeningError) as cm:
            self.replay.check(second.replay_nonce, second.intent_digest())
        self.assertEqual(cm.exception.code, "CFHS_IDEMPOTENCY_CONFLICT")

    def test_resource_reservation_is_all_or_nothing(self):
        with self.assertRaises(HardeningError):
            self.resources.reserve_many(
                "intent-x",
                [ResourceRequest("refund-budget", 100), ResourceRequest("message-budget", 20)],
            )
        self.assertEqual(self.resources.pool_state("refund-budget")["reserved"], 0)
        self.assertEqual(self.resources.pool_state("message-budget")["reserved"], 0)

    def test_pool_limit_cannot_drop_below_used_plus_reserved(self):
        reservations = self.resources.reserve_many("intent-x", [ResourceRequest("refund-budget", 100)])
        with self.assertRaises(HardeningError):
            self.resources.configure_pool("refund-budget", 50)
        self.resources.release_many([reservations[0]["reservation_id"]])

    def test_multi_party_approval_requires_distinct_eligible_non_requesters(self):
        intent, _ = self.intent(side="S3", nonce="nonce-approve-01", amount=100)
        req = self.approvals.create(
            intent.intent_digest(),
            "agent:ops",
            required_count=2,
            eligible_approvers=["human:a", "human:b", "human:c"],
        )
        with self.assertRaises(HardeningError):
            self.approvals.approve(req["request_id"], "agent:ops")
        with self.assertRaises(HardeningError):
            self.approvals.approve(req["request_id"], "human:not-eligible")
        self.assertEqual(self.approvals.approve(req["request_id"], "human:a")["status"], "PENDING")
        self.assertEqual(self.approvals.approve(req["request_id"], "human:b")["status"], "APPROVED")
        self.approvals.require_satisfied(req["request_id"], intent.intent_digest(), 2)

    def test_approval_request_with_too_few_required_signers_does_not_satisfy_s3(self):
        intent, _ = self.intent(side="S3", nonce="nonce-approve-02", amount=100)
        req = self.approvals.create(intent.intent_digest(), "agent:ops", required_count=1, eligible_approvers=["human:a", "human:b"])
        self.approvals.approve(req["request_id"], "human:a")
        with self.assertRaises(HardeningError):
            self.approvals.require_satisfied(req["request_id"], intent.intent_digest(), intent.required_approvals)

    def test_s2_happy_path_commits_resources_audit_and_replay(self):
        intent, args = self.intent(nonce="nonce-happy-s2", amount=100)
        self.compensation.declare(intent.intent_digest(), "payments.refund.reverse", "/dev/payments/primary")
        result = self.coordinator.execute(
            intent,
            args,
            self.allow,
            lambda a: {"refunded": a["amount"]},
            lambda a, cause: {"reversed": a["amount"]},
        )
        self.assertEqual(result["status"], "COMMITTED")
        self.assertEqual(self.resources.pool_state("refund-budget")["used"], 100)
        self.assertEqual(self.resources.pool_state("refund-budget")["reserved"], 0)
        self.assertEqual(self.replay.get(intent.replay_nonce)["status"], "COMMITTED")

    def test_committed_replay_does_not_invoke_or_require_new_ephemeral_intent(self):
        intent, args = self.intent(nonce="nonce-replay-s2", amount=50)
        self.compensation.declare(intent.intent_digest(), "payments.refund.reverse", "/dev/payments/primary")
        count = {"invoke": 0}
        def invoke(a):
            count["invoke"] += 1
            return {"ok": a["amount"]}
        self.coordinator.execute(intent, args, self.allow, invoke, lambda a, cause: {"reversed": True})
        retry = ActionIntent.create(
            actor_id=intent.actor_id,
            process_id=intent.process_id,
            action=intent.action,
            resource=intent.resource,
            side_effect_class=intent.side_effect_class,
            purpose=intent.purpose,
            arguments=args,
            replay_nonce=intent.replay_nonce,
            evidence_refs=list(intent.evidence_refs),
            resource_requests=list(intent.resource_requests),
        )
        result = self.coordinator.execute(retry, args, self.allow, invoke, lambda a, cause: {"reversed": True})
        self.assertEqual(result["status"], "REPLAYED")
        self.assertEqual(count["invoke"], 1)

    def test_s2_invocation_failure_is_compensated_and_resource_released(self):
        intent, args = self.intent(nonce="nonce-compensate-ok", amount=80)
        self.compensation.declare(intent.intent_digest(), "payments.refund.reverse", "/dev/payments/primary")
        with self.assertRaises(HardeningError) as cm:
            self.coordinator.execute(
                intent,
                args,
                self.allow,
                lambda a: (_ for _ in ()).throw(RuntimeError("provider timeout after submit")),
                lambda a, cause: {"reversed": a["amount"]},
            )
        self.assertEqual(cm.exception.code, "CFHS_DEVICE_FAILED")
        self.assertEqual(self.resources.pool_state("refund-budget")["used"], 0)
        self.assertEqual(self.resources.pool_state("refund-budget")["reserved"], 0)
        self.assertEqual(self.replay.get(intent.replay_nonce)["status"], "FAILED")

    def test_s2_compensation_failure_marks_unknown_and_commits_conservative_resource(self):
        intent, args = self.intent(nonce="nonce-compensate-bad", amount=70)
        self.compensation.declare(intent.intent_digest(), "payments.refund.reverse", "/dev/payments/primary")
        with self.assertRaises(HardeningError) as cm:
            self.coordinator.execute(
                intent,
                args,
                self.allow,
                lambda a: (_ for _ in ()).throw(RuntimeError("provider uncertain")),
                lambda a, cause: (_ for _ in ()).throw(RuntimeError("reverse failed")),
            )
        self.assertEqual(cm.exception.code, "CFHS_COMPENSATION_FAILED")
        self.assertEqual(self.resources.pool_state("refund-budget")["used"], 70)
        self.assertEqual(self.replay.get(intent.replay_nonce)["status"], "UNKNOWN_SIDE_EFFECT")

    def test_s3_invocation_failure_is_unknown_and_conservatively_accounted(self):
        intent, args = self.intent(side="S3", nonce="nonce-s3-unknown", amount=60)
        req = self.approvals.create(intent.intent_digest(), "agent:ops", 2, eligible_approvers=["human:a", "human:b"])
        self.approvals.approve(req["request_id"], "human:a")
        self.approvals.approve(req["request_id"], "human:b")
        intent = intent.with_approval(req["request_id"])
        with self.assertRaises(HardeningError) as cm:
            self.coordinator.execute(intent, args, self.allow, lambda a: (_ for _ in ()).throw(RuntimeError("network lost after submit")))
        self.assertEqual(cm.exception.code, "CFHS_UNKNOWN_SIDE_EFFECT")
        self.assertEqual(self.resources.pool_state("refund-budget")["used"], 60)
        self.assertEqual(self.replay.get(intent.replay_nonce)["status"], "UNKNOWN_SIDE_EFFECT")

    def test_audit_prepare_failure_prevents_invoke_and_cleans_reservations(self):
        intent, args = self.intent(side="S0", nonce="nonce-audit-prepare", amount=30)
        called = {"invoke": False}
        coordinator = ConsequentialActionCoordinator(
            self.replay,
            self.resources,
            self.approvals,
            self.compensation,
            FailingPrepareAudit(self.conn),
        )
        with self.assertRaises(HardeningError):
            coordinator.execute(intent, args, self.allow, lambda a: called.__setitem__("invoke", True))
        self.assertFalse(called["invoke"])
        self.assertEqual(self.resources.pool_state("refund-budget")["reserved"], 0)
        self.assertEqual(self.replay.get(intent.replay_nonce)["status"], "FAILED")

    def test_audit_commit_failure_on_s2_compensates_and_releases_resources(self):
        intent, args = self.intent(nonce="nonce-audit-commit", amount=40)
        self.compensation.declare(intent.intent_digest(), "payments.refund.reverse", "/dev/payments/primary")
        coordinator = ConsequentialActionCoordinator(
            self.replay,
            self.resources,
            self.approvals,
            self.compensation,
            FailingCommitAudit(self.conn),
        )
        with self.assertRaises(HardeningError) as cm:
            coordinator.execute(intent, args, self.allow, lambda a: {"ok": True}, lambda a, cause: {"reversed": True})
        self.assertEqual(cm.exception.code, "CFHS_AUDIT_COMMIT_FAILED")
        self.assertEqual(self.resources.pool_state("refund-budget")["used"], 0)
        self.assertEqual(self.replay.get(intent.replay_nonce)["status"], "FAILED")

    def test_s2_requires_compensation_plan(self):
        intent, args = self.intent(nonce="nonce-no-plan", amount=10)
        with self.assertRaises(HardeningError) as cm:
            self.coordinator.execute(intent, args, self.allow, lambda a: {"ok": True}, lambda a, cause: {"reversed": True})
        self.assertEqual(cm.exception.code, "CFHS_POLICY_DENIED")

    def test_s1_requires_compensation_callback(self):
        intent, args = self.intent(side="S1", nonce="nonce-s1-no-comp", amount=1)
        with self.assertRaises(HardeningError) as cm:
            self.coordinator.execute(intent, args, self.allow, lambda a: {"ok": True})
        self.assertEqual(cm.exception.code, "CFHS_POLICY_DENIED")


if __name__ == "__main__":
    unittest.main()
