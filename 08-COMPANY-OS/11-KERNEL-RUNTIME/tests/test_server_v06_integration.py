import tempfile
import unittest
from pathlib import Path

from kernel.hardening import HardeningError
from kernel.runtime import CompanyKernel, RequestContext
from kernel.server_v02 import HardenedKernel
from kernel.server_v06 import TrustKernelV06

ROOT = Path(__file__).resolve().parents[1]


class RejectingAnchor:
    def anchor(self, head_hash, metadata=None):
        raise RuntimeError("simulated external anchor outage")


class ServerV06IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.tmp.name) / "state"
        self.config = ROOT / "examples/kernel.config.json"
        self.policies = ROOT / "examples/policies"
        self.core = CompanyKernel.from_file(self.state_dir, self.config)
        self.hardened = HardenedKernel(self.core, str(self.policies), set(), False)
        self.kernel = TrustKernelV06(self.hardened)

        bootstrap = RequestContext("human:owner", "kernel:bootstrap", "trace:bootstrap")
        owner_process = self.core.spawn_process(bootstrap, "owner", "human:owner")
        agent_process = self.core.spawn_process(bootstrap, "ops", "agent:ops")
        risk_process = self.core.spawn_process(bootstrap, "risk", "human:risk")
        finance_process = self.core.spawn_process(bootstrap, "finance", "human:finance")

        self.owner = RequestContext("human:owner", owner_process["process_id"], "trace:owner")
        self.agent = RequestContext("agent:ops", agent_process["process_id"], "trace:agent")
        self.risk = RequestContext("human:risk", risk_process["process_id"], "trace:risk")
        self.finance = RequestContext("human:finance", finance_process["process_id"], "trace:finance")

        self.owner_session = self.hardened.sessions.issue("human:owner", 3600)
        self.agent_session = self.hardened.sessions.issue("agent:ops", 3600)
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

    def create_refund(self, nonce="v06-refund-001", amount="10.25"):
        return self.kernel.create_provider_intent(
            self.agent,
            "payments-primary",
            "payments.refund",
            {"amount": amount},
            nonce,
            "sandbox refund",
            ["ticket:refund-v06"],
        )

    def approve_refund(self, intent_id):
        request = self.kernel.request_action_approval(
            self.agent,
            intent_id,
            ["human:risk", "human:finance"],
        )
        risk = self.kernel.approve_action_with_session(
            self.risk,
            self.risk_session["bearer_token"],
            request["request_id"],
        )
        finance = self.kernel.approve_action_with_session(
            self.finance,
            self.finance_session["bearer_token"],
            request["request_id"],
        )
        return request, risk, finance

    def prepare_refund(self, created, request):
        return self.kernel.prepare_provider_action(
            self.agent,
            created["intent"]["intent_id"],
            {"amount": created["exact_resource"]["units"] / 100 if False else "10.25"},
            request["request_id"],
        )

    def test_full_s3_provider_flow_uses_exact_units_session_provenance_and_anchors(self):
        created = self.create_refund()
        intent_id = created["intent"]["intent_id"]
        self.assertEqual(created["exact_resource"]["units"], 1025)
        self.assertEqual(created["intent"]["resource_requests"], [])
        self.assertEqual(created["required_approvals"], 2)
        request, risk, finance = self.approve_refund(intent_id)
        self.assertEqual(risk["authentication_class"], "kernel_session")
        self.assertEqual(finance["status"], "APPROVED")
        complete = self.kernel.approval_provenance.require_complete(request["request_id"])
        self.assertEqual(complete["provenance_count"], 2)

        prepared = self.kernel.prepare_provider_action(
            self.agent,
            intent_id,
            {"amount": "10.25"},
            request["request_id"],
        )
        self.assertEqual(prepared["status"], "PREPARED")
        self.assertEqual(prepared["exact_units"], 1025)
        receipts = self.kernel.provider_audit.receipts(prepared["audit_id"])
        self.assertEqual([r["transition_status"] for r in receipts], ["PREPARED"])

        result = self.kernel.execute_provider_action(
            self.agent,
            intent_id,
            {"amount": "10.25"},
            request["request_id"],
        )
        self.assertEqual(result["status"], "COMMITTED")
        self.assertTrue(result["provider_action_id"])
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["used_units"], 1025)
        state = self.kernel.provider_actions.state(created["intent_digest"])
        self.assertEqual(state["status"], "COMMITTED")
        receipts = self.kernel.provider_audit.receipts(state["audit_id"])
        self.assertEqual(
            [r["transition_status"] for r in receipts],
            ["PREPARED", "PROVIDER_CONFIRMED", "COMMITTED"],
        )
        self.assertTrue(self.hardened.audit_chain.verify()["valid"])
        self.assertTrue(self.kernel.anchors.verify()["valid"])

    def test_provider_replay_does_not_double_consume_or_double_execute(self):
        created = self.create_refund("v06-replay-001")
        request, _, _ = self.approve_refund(created["intent"]["intent_id"])
        self.kernel.prepare_provider_action(
            self.agent, created["intent"]["intent_id"], {"amount": "10.25"}, request["request_id"]
        )
        first = self.kernel.execute_provider_action(
            self.agent, created["intent"]["intent_id"], {"amount": "10.25"}, request["request_id"]
        )
        second = self.kernel.execute_provider_action(
            self.agent, created["intent"]["intent_id"], {"amount": "10.25"}, request["request_id"]
        )
        self.assertEqual(first["provider_action_id"], second["provider_action_id"])
        self.assertEqual(second["status"], "REPLAYED")
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["used_units"], 1025)

    def test_unproven_counted_approval_blocks_provider_prepare(self):
        created = self.create_refund("v06-unproven-001")
        intent_id = created["intent"]["intent_id"]
        request = self.kernel.request_action_approval(
            self.agent, intent_id, ["human:risk", "human:finance"]
        )
        # v0.5 ledger records approvals, but v0.6 refuses to count them without
        # authenticated session provenance.
        self.kernel.action_approvals.approve(request["request_id"], "human:risk")
        self.kernel.action_approvals.approve(request["request_id"], "human:finance")
        with self.assertRaises(HardeningError) as cm:
            self.kernel.prepare_provider_action(
                self.agent, intent_id, {"amount": "10.25"}, request["request_id"]
            )
        self.assertEqual(cm.exception.code, "CFHS_ELEVATION_REQUIRED")
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["reserved_units"], 0)

    def test_wrong_bearer_cannot_supply_another_approvers_provenance(self):
        created = self.create_refund("v06-wrong-session")
        request = self.kernel.request_action_approval(
            self.agent,
            created["intent"]["intent_id"],
            ["human:risk", "human:finance"],
        )
        with self.assertRaises(HardeningError):
            self.kernel.approve_action_with_session(
                self.risk,
                self.finance_session["bearer_token"],
                request["request_id"],
            )

    def test_provider_timeout_after_commit_requires_reconciliation_and_blocks_retry(self):
        created = self.create_refund("v06-timeout-001", "20.00")
        intent_id = created["intent"]["intent_id"]
        request, _, _ = self.approve_refund(intent_id)
        self.kernel.prepare_provider_action(
            self.agent, intent_id, {"amount": "20.00"}, request["request_id"]
        )
        timed_out = self.kernel.execute_provider_action(
            self.agent,
            intent_id,
            {"amount": "20.00"},
            request["request_id"],
            "commit_then_timeout",
        )
        self.assertEqual(timed_out["status"], "RECONCILIATION_REQUIRED")
        self.assertTrue(timed_out["reconciliation_case_id"])
        pool = self.kernel.exact_resources.pool_state("refund-usd-minor")
        self.assertEqual(pool["reserved_units"], 2000)
        self.assertEqual(pool["used_units"], 0)

        with self.assertRaises(HardeningError) as cm:
            self.kernel.execute_provider_action(
                self.agent, intent_id, {"amount": "20.00"}, request["request_id"]
            )
        self.assertEqual(cm.exception.code, "CFHS_UNKNOWN_SIDE_EFFECT")

        reconciled = self.kernel.reconcile_provider_action(self.owner, intent_id)
        self.assertEqual(reconciled["status"], "COMMITTED_RECONCILED")
        pool = self.kernel.exact_resources.pool_state("refund-usd-minor")
        self.assertEqual(pool["reserved_units"], 0)
        self.assertEqual(pool["used_units"], 2000)

    def test_provider_definite_failure_releases_exact_reservation(self):
        created = self.create_refund("v06-definite-failure", "15.00")
        intent_id = created["intent"]["intent_id"]
        request, _, _ = self.approve_refund(intent_id)
        self.kernel.prepare_provider_action(
            self.agent, intent_id, {"amount": "15.00"}, request["request_id"]
        )
        result = self.kernel.execute_provider_action(
            self.agent,
            intent_id,
            {"amount": "15.00"},
            request["request_id"],
            "fail_before_commit",
        )
        self.assertEqual(result["status"], "FAILED_NOT_EXECUTED")
        pool = self.kernel.exact_resources.pool_state("refund-usd-minor")
        self.assertEqual(pool["reserved_units"], 0)
        self.assertEqual(pool["used_units"], 0)

    def test_anchor_failure_before_provider_call_fails_closed_and_releases_reservation(self):
        created = self.create_refund("v06-anchor-failure", "12.00")
        intent_id = created["intent"]["intent_id"]
        request, _, _ = self.approve_refund(intent_id)
        self.kernel.provider_audit.anchor_provider = RejectingAnchor()
        with self.assertRaises(HardeningError) as cm:
            self.kernel.prepare_provider_action(
                self.agent, intent_id, {"amount": "12.00"}, request["request_id"]
            )
        self.assertEqual(cm.exception.code, "CFHS_AUDIT_ANCHOR_FAILED")
        pool = self.kernel.exact_resources.pool_state("refund-usd-minor")
        self.assertEqual(pool["reserved_units"], 0)
        self.assertEqual(pool["used_units"], 0)
        provider = self.kernel.providers["sandbox-payments"]
        binding = self.kernel._provider_binding(intent_id)
        # No provider action state exists because PREPARE never completed.
        self.assertIsNone(self.core.store.one(
            "SELECT 1 FROM provider_action_state_v06 WHERE intent_digest=?",
            (binding["intent_digest"],),
        ))
        self.assertEqual(self.core.store.one("SELECT COUNT(*) AS n FROM sandbox_provider_actions")["n"], 0)

    def test_committed_provider_action_requires_separate_authority_to_compensate(self):
        created = self.create_refund("v06-compensation", "25.00")
        intent_id = created["intent"]["intent_id"]
        request, _, _ = self.approve_refund(intent_id)
        self.kernel.prepare_provider_action(
            self.agent, intent_id, {"amount": "25.00"}, request["request_id"]
        )
        committed = self.kernel.execute_provider_action(
            self.agent, intent_id, {"amount": "25.00"}, request["request_id"]
        )
        self.assertEqual(committed["status"], "COMMITTED")
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["used_units"], 2500)

        with self.assertRaises(HardeningError) as cm:
            self.kernel.compensate_provider_action(self.agent, intent_id, {"amount": "25.00"})
        self.assertEqual(cm.exception.code, "CFHS_POLICY_DENIED")
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["used_units"], 2500)

        compensated = self.kernel.compensate_provider_action(
            self.owner, intent_id, {"amount": "25.00"}
        )
        self.assertEqual(compensated["status"], "COMPENSATED")
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["used_units"], 0)
        provider = self.kernel.providers["sandbox-payments"]
        state = self.kernel.provider_actions.state(created["intent_digest"])
        original_key = state["idempotency_key"]
        self.assertEqual(provider.lookup(original_key).status, "COMPENSATED")

    def test_sub_minor_currency_precision_is_rejected_before_intent_persistence(self):
        with self.assertRaises(HardeningError):
            self.create_refund("v06-precision", "10.001")
        self.assertIsNone(
            self.core.store.one(
                "SELECT 1 FROM provider_intent_bindings_v06 WHERE intent_id IN (SELECT intent_id FROM action_intent_index WHERE replay_nonce=?)",
                ("v06-precision",),
            )
        )

    def test_verified_external_identity_flows_into_approval_provenance(self):
        created = self.create_refund("v06-oidc-provenance")
        intent_id = created["intent"]["intent_id"]
        self.kernel.session_identity_provenance.bind_verified_identity(
            self.risk_session["session_id"],
            "human:risk",
            "oidc:workforce",
            "https://id.example.test",
            "risk-subject",
            {"amr": ["mfa"]},
        )
        request = self.kernel.request_action_approval(
            self.agent, intent_id, ["human:risk", "human:finance"]
        )
        risk = self.kernel.approve_action_with_session(
            self.risk, self.risk_session["bearer_token"], request["request_id"]
        )
        self.kernel.approve_action_with_session(
            self.finance, self.finance_session["bearer_token"], request["request_id"]
        )
        self.assertEqual(risk["authentication_class"], "verified_external_identity")
        provenance = self.kernel.approval_provenance.get(request["request_id"], "human:risk")
        self.assertEqual(provenance["external_provider_id"], "oidc:workforce")
        self.assertTrue(provenance["external_identity_digest"])


if __name__ == "__main__":
    unittest.main()
