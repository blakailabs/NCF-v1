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
)
from kernel.action_safety_runtime import CrashSafeConsequentialActionCoordinator
from kernel.hardening import HardeningError
from kernel.runtime import CompanyKernel, RequestContext
from kernel.server_v02 import HardenedKernel
from kernel.server_v05 import TrustKernelV05

ROOT = Path(__file__).resolve().parents[1]


class FailOnceCommitResources(ResourceReservationLedger):
    def __init__(self, conn):
        super().__init__(conn)
        self.fail_once = True

    def commit_many(self, reservation_ids):
        if self.fail_once:
            self.fail_once = False
            raise RuntimeError("simulated resource commit outage")
        return super().commit_many(reservation_ids)


class ActionReconciliationV05Tests(unittest.TestCase):
    def test_pending_intent_survives_restart_without_recovery_side_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            config = ROOT / "examples/kernel.config.json"
            policies = ROOT / "examples/policies"

            core = CompanyKernel.from_file(state, config)
            hardened = HardenedKernel(core, str(policies), set(), False)
            kernel = TrustKernelV05(hardened)
            bootstrap = RequestContext("human:owner", "kernel:bootstrap", "trace:bootstrap")
            agent_process = core.spawn_process(bootstrap, "ops", "agent:ops")
            agent = RequestContext("agent:ops", agent_process["process_id"], "trace:agent")

            created = kernel.create_action_intent(
                agent,
                "payments-primary",
                "payments.refund",
                {"amount": 25},
                "pending-restart-001",
                "pending approval",
                [],
                [],
            )
            intent_id = created["intent"]["intent_id"]
            core.store.conn.close()

            core2 = CompanyKernel.from_file(state, config)
            hardened2 = HardenedKernel(core2, str(policies), set(), False)
            kernel2 = TrustKernelV05(hardened2)
            try:
                self.assertEqual(kernel2.startup_recovery["count"], 0)
                loaded = kernel2._load_intent(intent_id)
                self.assertEqual(loaded.replay_nonce, "pending-restart-001")
                row = core2.store.one("SELECT status FROM action_intent_index WHERE intent_id=?", (intent_id,))
                self.assertEqual(row["status"], "PENDING")
            finally:
                core2.store.conn.close()

    def test_post_audit_resource_commit_failure_is_reconciled_and_retry_does_not_reinvoke(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = sqlite3.connect(Path(tmp) / "reconcile.db")
            conn.row_factory = sqlite3.Row
            try:
                replay = ReplayNonceRegistry(conn)
                resources = FailOnceCommitResources(conn)
                approvals = MultiPartyApprovalLedger(conn)
                compensation = CompensationRegistry(conn)
                audit = SQLiteActionAuditSink(conn)
                coordinator = CrashSafeConsequentialActionCoordinator(
                    conn, replay, resources, approvals, compensation, audit
                )
                resources.configure_pool("money", 1000)

                args = {"amount": 45}
                intent = ActionIntent.create(
                    actor_id="agent:ops",
                    process_id="proc:ops",
                    action="payments.refund",
                    resource="/dev/payments/primary",
                    side_effect_class="S0",
                    purpose="bookkeeping recovery test",
                    arguments=args,
                    replay_nonce="resource-reconcile-001",
                    resource_requests=[ResourceRequest("money", 45)],
                )
                calls = {"invoke": 0}

                def invoke(_arguments):
                    calls["invoke"] += 1
                    return {"ok": True}

                with self.assertRaises(HardeningError) as cm:
                    coordinator.execute(intent, args, lambda i, a: {"decision": "ALLOW"}, invoke)
                self.assertEqual(cm.exception.code, "CFHS_RESOURCE_COMMIT_FAILED")

                # The wrapper uses the committed audit record to finish local bookkeeping.
                self.assertEqual(resources.pool_state("money")["used"], 45)
                self.assertEqual(resources.pool_state("money")["reserved"], 0)
                self.assertEqual(replay.get(intent.replay_nonce)["status"], "COMMITTED")

                retry = ActionIntent.create(
                    actor_id=intent.actor_id,
                    process_id=intent.process_id,
                    action=intent.action,
                    resource=intent.resource,
                    side_effect_class=intent.side_effect_class,
                    purpose=intent.purpose,
                    arguments=args,
                    replay_nonce=intent.replay_nonce,
                    resource_requests=list(intent.resource_requests),
                )
                result = coordinator.execute(retry, args, lambda i, a: {"decision": "ALLOW"}, invoke)
                self.assertEqual(result["status"], "REPLAYED")
                self.assertEqual(calls["invoke"], 1)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
