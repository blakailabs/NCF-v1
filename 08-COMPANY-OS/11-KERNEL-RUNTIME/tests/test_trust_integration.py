import tempfile
import unittest
from pathlib import Path

from kernel.hardening import HardeningError
from kernel.runtime import CompanyKernel, RequestContext
from kernel.server_v02 import HardenedKernel
from kernel.server_v03 import TrustKernel
from kernel.trust import PolicyPackageSigner

ROOT = Path(__file__).resolve().parents[1]


class TrustKernelIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        core = CompanyKernel.from_file(self.tmp.name, ROOT / "examples/kernel.config.json")
        hardened = HardenedKernel(core, str(ROOT / "examples/policies"), {"127.0.0.1"}, True)
        self.tk = TrustKernel(hardened, {"root-1": b"test-signing-key"})

        bootstrap = RequestContext("human:owner", "kernel:bootstrap", "trace:bootstrap")
        owner_proc = core.spawn_process(bootstrap, "owner-console", "human:owner")
        self.owner = RequestContext("human:owner", owner_proc["process_id"], "trace:owner")

        agent_proc = core.spawn_process(self.owner, "ops-agent", "agent:ops")
        self.agent = RequestContext("agent:ops", agent_proc["process_id"], "trace:agent")

    def tearDown(self):
        self.tmp.cleanup()

    def test_bounded_child_cannot_regain_broader_amount_authority(self):
        child = self.tk.spawn_bounded_process(
            self.owner,
            "refund-specialist",
            "agent:ops",
            [
                {
                    "action": "payments.refund",
                    "resource": "/dev/payments/primary",
                    "conditions": {"max_amount": 100},
                }
            ],
        )
        child_ctx = RequestContext("agent:ops", child["process_id"], "trace:child")
        allowed = self.tk.authorize(child_ctx, "payments.refund", "/dev/payments/primary", {"amount": 80})
        denied = self.tk.authorize(child_ctx, "payments.refund", "/dev/payments/primary", {"amount": 150})
        self.assertEqual(allowed["decision"], "ALLOW")
        self.assertEqual(denied["decision"], "DENY")
        self.assertIn("process-capability-bound", denied["matched_policies"])

    def test_child_cannot_receive_capability_delegate_does_not_have(self):
        with self.assertRaises(HardeningError):
            self.tk.spawn_bounded_process(
                self.owner,
                "bad-delegate",
                "agent:ops",
                [{"action": "code.deploy", "resource": "/dev/code/prod"}],
            )

    def test_signed_policy_can_tighten_runtime_authority(self):
        package = {
            "id": "refund-trust-policy",
            "version": "0.3.0",
            "policies": [
                {
                    "id": "refund-over-50",
                    "effect": "ELEVATION_REQUIRED",
                    "principal": "agent:*",
                    "action": "payments.refund",
                    "resource": "/dev/payments/*",
                    "conditions": {"amount_gt": 50},
                }
            ],
        }
        envelope = PolicyPackageSigner.sign(package, "root-1", b"test-signing-key")
        self.tk.install_signed_policy_packages(self.owner, [envelope])
        decision = self.tk.authorize(self.agent, "payments.refund", "/dev/payments/primary", {"amount": 75})
        self.assertEqual(decision["decision"], "ELEVATION_REQUIRED")
        self.assertTrue(any("refund-trust-policy@0.3.0:refund-over-50" in p for p in decision["matched_policies"]))

    def test_event_bus_is_authorized_and_durable(self):
        created = self.tk.publish_event(self.agent, "company.customer.created", {"customer_id": "c-100"})
        message = self.tk.poll_event(self.agent, ["company.customer.created"])
        self.assertEqual(message.id, created["event_id"])
        self.tk.ack_event(self.agent, message.id)
        self.assertIsNone(self.tk.poll_event(self.agent, ["company.customer.created"]))

    def test_audit_anchor_records_current_hash_head(self):
        self.tk.authorize(self.agent, "github.repo.read", "/dev/github/readonly", {"external": True, "classification": "PUBLIC"})
        anchor = self.tk.anchor_audit(self.owner, {"reason": "integration-test"})
        self.assertTrue(anchor["audit_head_hash"])
        self.assertTrue(self.tk.anchors.verify()["valid"])


if __name__ == "__main__":
    unittest.main()
