import tempfile
import unittest
from pathlib import Path

from kernel.hardening import HardeningError
from kernel.runtime import CompanyKernel, RequestContext
from kernel.server_v02 import HardenedKernel
from kernel.server_v05 import TrustKernelV05

ROOT = Path(__file__).resolve().parents[1]


class ServerV05IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.tmp.name) / "state"
        self.config = ROOT / "examples/kernel.config.json"
        self.policies = ROOT / "examples/policies"
        self.core = CompanyKernel.from_file(self.state_dir, self.config)
        self.hardened = HardenedKernel(self.core, str(self.policies), set(), False)
        self.kernel = TrustKernelV05(self.hardened)

        bootstrap = RequestContext("human:owner", "kernel:bootstrap", "trace:bootstrap")
        owner = self.core.spawn_process(bootstrap, "owner", "human:owner")
        agent = self.core.spawn_process(bootstrap, "ops", "agent:ops")
        risk = self.core.spawn_process(bootstrap, "risk", "human:risk")
        finance = self.core.spawn_process(bootstrap, "finance", "human:finance")

        self.owner = RequestContext("human:owner", owner["process_id"], "trace:owner")
        self.agent = RequestContext("agent:ops", agent["process_id"], "trace:agent")
        self.risk = RequestContext("human:risk", risk["process_id"], "trace:risk")
        self.finance = RequestContext("human:finance", finance["process_id"], "trace:finance")

        self.kernel.configure_action_resource_pool(self.owner, "refund-budget", 1000)

    def tearDown(self):
        try:
            self.core.store.conn.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def _refund_intent(self, nonce="v05-refund-001", amount=100):
        return self.kernel.create_action_intent(
            self.agent,
            "payments-primary",
            "payments.refund",
            {"amount": amount},
            nonce,
            "approved customer refund",
            ["ticket:refund-123"],
            [{"pool_id": "refund-budget", "amount": amount}],
        )

    def test_full_s3_two_party_approval_and_simulated_execution(self):
        created = self._refund_intent()
        intent_id = created["intent"]["intent_id"]
        self.assertEqual(created["intent"]["side_effect_class"], "S3")
        self.assertEqual(created["intent"]["required_approvals"], 2)

        request = self.kernel.request_action_approval(
            self.agent,
            intent_id,
            ["human:risk", "human:finance"],
        )
        self.assertEqual(self.kernel.approve_action(self.risk, request["request_id"])["status"], "PENDING")
        self.assertEqual(self.kernel.approve_action(self.finance, request["request_id"])["status"], "APPROVED")

        result = self.kernel.execute_simulated_action(
            self.agent,
            intent_id,
            "payments-primary",
            {"amount": 100},
            request["request_id"],
        )

        self.assertEqual(result["status"], "COMMITTED")
        self.assertTrue(result["result"]["simulation"])
        self.assertEqual(self.kernel.action_resources.pool_state("refund-budget")["used"], 100)
        replay = self.kernel.action_replay.get(created["intent"]["replay_nonce"])
        self.assertEqual(replay["status"], "COMMITTED")

    def test_s3_cannot_execute_without_required_approvals(self):
        created = self._refund_intent(nonce="v05-refund-no-approval")
        with self.assertRaises(HardeningError) as cm:
            self.kernel.execute_simulated_action(
                self.agent,
                created["intent"]["intent_id"],
                "payments-primary",
                {"amount": 100},
            )
        self.assertEqual(cm.exception.code, "CFHS_ELEVATION_REQUIRED")
        self.assertEqual(self.kernel.action_resources.pool_state("refund-budget")["used"], 0)

    def test_ineligible_principal_cannot_approve(self):
        created = self._refund_intent(nonce="v05-refund-bad-approver")
        request = self.kernel.request_action_approval(
            self.agent,
            created["intent"]["intent_id"],
            ["human:risk", "human:finance"],
        )
        with self.assertRaises(HardeningError):
            self.kernel.approve_action(self.owner, request["request_id"])

    def test_s2_requires_declared_compensation_then_can_execute(self):
        created = self.kernel.create_action_intent(
            self.agent,
            "mail-primary",
            "mail.send",
            {"to": "example.invalid", "resource_amount": 1},
            "v05-mail-001",
            "simulated notice",
            ["ticket:mail-1"],
            [],
        )
        intent_id = created["intent"]["intent_id"]
        self.assertEqual(created["intent"]["side_effect_class"], "S2")

        with self.assertRaises(HardeningError) as cm:
            self.kernel.execute_simulated_action(
                self.agent,
                intent_id,
                "mail-primary",
                {"to": "example.invalid", "resource_amount": 1},
            )
        self.assertEqual(cm.exception.code, "CFHS_POLICY_DENIED")

        self.kernel.declare_compensation(
            self.agent,
            intent_id,
            "mail.send.compensate",
            "/dev/mail/primary",
        )
        result = self.kernel.execute_simulated_action(
            self.agent,
            intent_id,
            "mail-primary",
            {"to": "example.invalid", "resource_amount": 1},
        )
        self.assertEqual(result["status"], "COMMITTED")

    def test_s2_provider_failure_runs_simulated_compensation(self):
        created = self.kernel.create_action_intent(
            self.agent,
            "mail-primary",
            "mail.send",
            {"to": "example.invalid", "resource_amount": 1},
            "v05-mail-failure",
            "simulated failure notice",
            [],
            [],
        )
        intent_id = created["intent"]["intent_id"]
        self.kernel.declare_compensation(self.agent, intent_id, "mail.send.compensate", "/dev/mail/primary")

        with self.assertRaises(HardeningError) as cm:
            self.kernel.execute_simulated_action(
                self.agent,
                intent_id,
                "mail-primary",
                {"to": "example.invalid", "resource_amount": 1},
                simulation_mode="provider_failure",
            )
        self.assertEqual(cm.exception.code, "CFHS_DEVICE_FAILED")
        self.assertEqual(self.kernel.action_replay.get("v05-mail-failure")["status"], "FAILED")

    def test_restart_recovery_marks_started_uncommitted_s3_unknown(self):
        created = self._refund_intent(nonce="v05-restart-unknown", amount=55)
        intent = self.kernel._load_intent(created["intent"]["intent_id"])
        self.kernel.action_coordinator.intents.set_status(
            intent.intent_id,
            "EXECUTING",
            self.kernel.action_coordinator.recovery._now(self.core.store.conn),
        )
        self.kernel.action_replay.reserve(intent.replay_nonce, intent.intent_digest())
        self.kernel.action_resources.reserve_many(intent.intent_id, intent.resource_requests)
        self.kernel.action_audit.prepare(intent)
        self.kernel.action_coordinator.intents.mark_execution_started(
            intent.intent_id,
            self.kernel.action_coordinator.recovery._now(self.core.store.conn),
        )
        self.core.store.conn.close()

        core2 = CompanyKernel.from_file(self.state_dir, self.config)
        hardened2 = HardenedKernel(core2, str(self.policies), set(), False)
        kernel2 = TrustKernelV05(hardened2)
        try:
            self.assertEqual(kernel2.startup_recovery["count"], 1)
            self.assertEqual(kernel2.startup_recovery["results"][0]["recovery"], "UNKNOWN_SIDE_EFFECT")
            self.assertEqual(kernel2.action_resources.pool_state("refund-budget")["used"], 55)
            self.assertEqual(kernel2.action_replay.get("v05-restart-unknown")["status"], "UNKNOWN_SIDE_EFFECT")
        finally:
            core2.store.conn.close()


if __name__ == "__main__":
    unittest.main()
