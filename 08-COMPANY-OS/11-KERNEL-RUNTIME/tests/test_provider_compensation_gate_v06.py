import tempfile
import unittest
from pathlib import Path

from kernel.hardening import HardeningError
from kernel.provider_compensation_hardening import TrustKernelV06FinalGate
from kernel.runtime import CompanyKernel, RequestContext
from kernel.server_v02 import HardenedKernel

ROOT = Path(__file__).resolve().parents[1]


class RejectingAnchor:
    def anchor(self, head_hash, metadata=None):
        raise RuntimeError("compensation authorization anchor unavailable")


class ProviderCompensationGateV06Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "state"
        self.config = ROOT / "examples/kernel.config.json"
        self.policies = ROOT / "examples/policies"
        self.core = CompanyKernel.from_file(self.state, self.config)
        self.hardened = HardenedKernel(self.core, str(self.policies), set(), False)
        self.kernel = TrustKernelV06FinalGate(self.hardened)

        bootstrap = RequestContext("human:owner", "kernel:bootstrap", "trace:bootstrap")
        owner = self.core.spawn_process(bootstrap, "owner", "human:owner")
        agent = self.core.spawn_process(bootstrap, "ops", "agent:ops")
        risk = self.core.spawn_process(bootstrap, "risk", "human:risk")
        finance = self.core.spawn_process(bootstrap, "finance", "human:finance")
        self.owner = RequestContext("human:owner", owner["process_id"], "trace:owner")
        self.agent = RequestContext("agent:ops", agent["process_id"], "trace:agent")
        self.risk = RequestContext("human:risk", risk["process_id"], "trace:risk")
        self.finance = RequestContext("human:finance", finance["process_id"], "trace:finance")
        self.owner_session = self.hardened.sessions.issue("human:owner", 3600)
        self.risk_session = self.hardened.sessions.issue("human:risk", 3600)
        self.finance_session = self.hardened.sessions.issue("human:finance", 3600)
        self.kernel.configure_exact_resource_pool(
            self.owner,
            "refund-usd-minor",
            100_000,
            "currency_minor",
            {"currency": "USD", "minor_exponent": 2},
        )

    def tearDown(self):
        try:
            self.core.store.conn.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def committed_refund(self, nonce="comp-gate-original", amount="25.00"):
        created = self.kernel.create_provider_intent(
            self.agent,
            "payments-primary",
            "payments.refund",
            {"amount": amount},
            nonce,
            "sandbox refund requiring compensation test",
            ["ticket:comp-gate"],
        )
        intent_id = created["intent"]["intent_id"]
        request = self.kernel.request_action_approval(
            self.agent, intent_id, ["human:risk", "human:finance"]
        )
        self.kernel.approve_action_with_session(
            self.risk, self.risk_session["bearer_token"], request["request_id"]
        )
        self.kernel.approve_action_with_session(
            self.finance, self.finance_session["bearer_token"], request["request_id"]
        )
        self.kernel.prepare_provider_action(
            self.agent, intent_id, {"amount": amount}, request["request_id"]
        )
        result = self.kernel.execute_provider_action(
            self.agent, intent_id, {"amount": amount}, request["request_id"]
        )
        self.assertEqual(result["status"], "COMMITTED")
        return created

    def request_compensation(self, intent_id, amount="25.00", required_count=None):
        return self.kernel.request_provider_compensation_approval(
            self.owner,
            intent_id,
            {"amount": amount},
            ["human:risk", "human:finance"],
            required_count,
        )

    def approve_compensation(self, request_id):
        first = self.kernel.approve_action_with_session(
            self.risk, self.risk_session["bearer_token"], request_id
        )
        second = self.kernel.approve_action_with_session(
            self.finance, self.finance_session["bearer_token"], request_id
        )
        return first, second

    def test_agent_without_reverse_authority_cannot_open_compensation_workflow(self):
        created = self.committed_refund("comp-agent-denied")
        with self.assertRaises(HardeningError) as cm:
            self.kernel.request_provider_compensation_approval(
                self.agent,
                created["intent"]["intent_id"],
                {"amount": "25.00"},
                ["human:risk", "human:finance"],
            )
        self.assertEqual(cm.exception.code, "CFHS_POLICY_DENIED")
        count = self.core.store.one("SELECT COUNT(*) AS n FROM provider_compensation_intents_v06")["n"]
        self.assertEqual(count, 0)

    def test_s3_compensation_approval_floor_cannot_be_lowered(self):
        created = self.committed_refund("comp-floor")
        workflow = self.request_compensation(created["intent"]["intent_id"], required_count=0)
        self.assertEqual(workflow["compensation_intent"]["required_approvals"], 2)
        self.assertEqual(workflow["approval_request"]["required_count"], 2)

    def test_compensation_cannot_execute_before_independent_approvals(self):
        created = self.committed_refund("comp-no-approval")
        workflow = self.request_compensation(created["intent"]["intent_id"])
        with self.assertRaises(HardeningError) as cm:
            self.kernel.compensate_provider_action(
                self.owner,
                created["intent"]["intent_id"],
                {"amount": "25.00"},
                compensation_intent_id=workflow["compensation_intent"]["compensation_intent_id"],
                compensation_approval_request_id=workflow["approval_request"]["request_id"],
            )
        self.assertEqual(cm.exception.code, "CFHS_ELEVATION_REQUIRED")
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["used_units"], 2500)

    def test_raw_approvals_without_session_provenance_do_not_release_compensation(self):
        created = self.committed_refund("comp-unproven")
        workflow = self.request_compensation(created["intent"]["intent_id"])
        request_id = workflow["approval_request"]["request_id"]
        self.kernel.action_approvals.approve(request_id, "human:risk")
        self.kernel.action_approvals.approve(request_id, "human:finance")
        with self.assertRaises(HardeningError) as cm:
            self.kernel.compensate_provider_action(
                self.owner,
                created["intent"]["intent_id"],
                {"amount": "25.00"},
                compensation_intent_id=workflow["compensation_intent"]["compensation_intent_id"],
                compensation_approval_request_id=request_id,
            )
        self.assertEqual(cm.exception.code, "CFHS_ELEVATION_REQUIRED")

    def test_approved_compensation_arguments_are_immutable(self):
        created = self.committed_refund("comp-args")
        workflow = self.request_compensation(created["intent"]["intent_id"], "25.00")
        self.approve_compensation(workflow["approval_request"]["request_id"])
        with self.assertRaises(HardeningError) as cm:
            self.kernel.compensate_provider_action(
                self.owner,
                created["intent"]["intent_id"],
                {"amount": "20.00"},
                compensation_intent_id=workflow["compensation_intent"]["compensation_intent_id"],
                compensation_approval_request_id=workflow["approval_request"]["request_id"],
            )
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["used_units"], 2500)

    def test_compensation_authorization_anchor_failure_blocks_provider_reversal(self):
        created = self.committed_refund("comp-anchor-fail")
        workflow = self.request_compensation(created["intent"]["intent_id"])
        self.approve_compensation(workflow["approval_request"]["request_id"])
        self.kernel.provider_authorizations.anchor_provider = RejectingAnchor()
        with self.assertRaises(HardeningError) as cm:
            self.kernel.compensate_provider_action(
                self.owner,
                created["intent"]["intent_id"],
                {"amount": "25.00"},
                compensation_intent_id=workflow["compensation_intent"]["compensation_intent_id"],
                compensation_approval_request_id=workflow["approval_request"]["request_id"],
            )
        self.assertEqual(cm.exception.code, "CFHS_AUDIT_ANCHOR_FAILED")
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["used_units"], 2500)
        state = self.kernel.provider_actions.state(created["intent_digest"])
        provider = self.kernel.providers["sandbox-payments"]
        self.assertEqual(provider.lookup(state["idempotency_key"]).status, "SUCCEEDED")
        comp = self.kernel.compensation_intents.get(workflow["compensation_intent"]["compensation_intent_id"])
        self.assertEqual(comp["status"], "PENDING")

    def test_fully_governed_s3_compensation_reverses_provider_and_exact_usage(self):
        created = self.committed_refund("comp-success")
        workflow = self.request_compensation(created["intent"]["intent_id"])
        request_id = workflow["approval_request"]["request_id"]
        first, second = self.approve_compensation(request_id)
        self.assertEqual(first["status"], "PENDING")
        self.assertEqual(second["status"], "APPROVED")

        result = self.kernel.compensate_provider_action(
            self.owner,
            created["intent"]["intent_id"],
            {"amount": "25.00"},
            compensation_intent_id=workflow["compensation_intent"]["compensation_intent_id"],
            compensation_approval_request_id=request_id,
        )
        self.assertEqual(result["status"], "COMPENSATED")
        self.assertTrue(result["compensation_authorization_evidence_digest"])
        self.assertTrue(result["compensation_authorization_anchor_head"])
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["used_units"], 0)
        self.assertEqual(self.kernel.provider_replay.get("comp-success")["status"], "COMPENSATED")
        comp = self.kernel.compensation_intents.get(workflow["compensation_intent"]["compensation_intent_id"])
        self.assertEqual(comp["status"], "COMPENSATED")
        evidence = self.kernel.provider_authorizations.get(comp["compensation_intent_digest"])
        self.assertEqual(evidence["approval_request_id"], request_id)
        self.assertIsNotNone(self.kernel.provider_authorizations.receipt(comp["compensation_intent_digest"]))

    def test_repeat_same_compensation_request_reuses_intent_and_approval_request(self):
        created = self.committed_refund("comp-repeat")
        first = self.request_compensation(created["intent"]["intent_id"])
        second = self.request_compensation(created["intent"]["intent_id"])
        self.assertFalse(first["replayed_request"])
        self.assertTrue(second["replayed_request"])
        self.assertEqual(
            first["compensation_intent"]["compensation_intent_id"],
            second["compensation_intent"]["compensation_intent_id"],
        )
        self.assertEqual(
            first["approval_request"]["request_id"],
            second["approval_request"]["request_id"],
        )


if __name__ == "__main__":
    unittest.main()
