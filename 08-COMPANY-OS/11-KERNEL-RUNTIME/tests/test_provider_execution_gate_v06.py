import json
import tempfile
import unittest
from pathlib import Path

from kernel.hardening import HardeningError
from kernel.provider_execution_gate import TrustKernelV06ExecutionGate
from kernel.runtime import CompanyKernel, RequestContext
from kernel.server_v02 import HardenedKernel

ROOT = Path(__file__).resolve().parents[1]


class RejectingAnchor:
    def anchor(self, head_hash, metadata=None):
        raise RuntimeError("authorization anchor unavailable")


class ProviderExecutionGateV06Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "state"
        self.config = ROOT / "examples/kernel.config.json"
        self.policies = ROOT / "examples/policies"
        self.core = CompanyKernel.from_file(self.state, self.config)
        self.hardened = HardenedKernel(self.core, str(self.policies), set(), False)
        self.kernel = TrustKernelV06ExecutionGate(self.hardened)

        bootstrap = RequestContext("human:owner", "kernel:bootstrap", "trace:bootstrap")
        owner = self.core.spawn_process(bootstrap, "owner", "human:owner")
        agent = self.core.spawn_process(bootstrap, "ops", "agent:ops")
        risk = self.core.spawn_process(bootstrap, "risk", "human:risk")
        finance = self.core.spawn_process(bootstrap, "finance", "human:finance")
        self.owner = RequestContext("human:owner", owner["process_id"], "trace:owner")
        self.agent = RequestContext("agent:ops", agent["process_id"], "trace:agent")
        self.risk = RequestContext("human:risk", risk["process_id"], "trace:risk")
        self.finance = RequestContext("human:finance", finance["process_id"], "trace:finance")
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

    def create(self, nonce="gate-replay-001", amount="10.00", purpose="sandbox refund"):
        return self.kernel.create_provider_intent(
            self.agent,
            "payments-primary",
            "payments.refund",
            {"amount": amount},
            nonce,
            purpose,
            ["ticket:gate"],
        )

    def approvals(self, intent_id):
        request = self.kernel.request_action_approval(
            self.agent, intent_id, ["human:risk", "human:finance"]
        )
        self.kernel.approve_action_with_session(
            self.risk, self.risk_session["bearer_token"], request["request_id"]
        )
        self.kernel.approve_action_with_session(
            self.finance, self.finance_session["bearer_token"], request["request_id"]
        )
        return request

    def test_same_replay_nonce_same_semantics_reuses_original_intent(self):
        first = self.create("gate-same-001", "10.00")
        second = self.create("gate-same-001", "10.00")
        self.assertFalse(first["replayed_intent"])
        self.assertTrue(second["replayed_intent"])
        self.assertEqual(first["intent"]["intent_id"], second["intent"]["intent_id"])
        self.assertEqual(first["intent_digest"], second["intent_digest"])
        count = self.core.store.one(
            "SELECT COUNT(*) AS n FROM provider_intent_bindings_v06 WHERE intent_digest=?",
            (first["intent_digest"],),
        )["n"]
        self.assertEqual(count, 1)

    def test_same_replay_nonce_different_amount_is_rejected_before_second_intent_persists(self):
        first = self.create("gate-conflict-001", "10.00")
        with self.assertRaises(HardeningError) as cm:
            self.create("gate-conflict-001", "11.00")
        self.assertEqual(cm.exception.code, "CFHS_IDEMPOTENCY_CONFLICT")
        rows = self.core.store.conn.execute(
            "SELECT intent_id,intent_digest FROM provider_intent_bindings_v06"
        ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["intent_digest"], first["intent_digest"])

    def test_same_replay_nonce_different_purpose_is_rejected(self):
        self.create("gate-purpose-001", "10.00", "purpose A")
        with self.assertRaises(HardeningError):
            self.create("gate-purpose-001", "10.00", "purpose B")

    def test_authorization_anchor_failure_happens_before_exact_reservation_and_provider_prepare(self):
        created = self.create("gate-auth-anchor-fail", "12.00")
        request = self.approvals(created["intent"]["intent_id"])
        self.kernel.provider_authorizations.anchor_provider = RejectingAnchor()
        with self.assertRaises(HardeningError) as cm:
            self.kernel.prepare_provider_action(
                self.agent,
                created["intent"]["intent_id"],
                {"amount": "12.00"},
                request["request_id"],
            )
        self.assertEqual(cm.exception.code, "CFHS_AUDIT_ANCHOR_FAILED")
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["reserved_units"], 0)
        self.assertIsNone(
            self.core.store.one(
                "SELECT 1 FROM provider_action_state_v06 WHERE intent_digest=?",
                (created["intent_digest"],),
            )
        )
        replay = self.kernel.provider_replay.get(created["intent"]["replay_nonce"])
        self.assertEqual(replay["status"], "PENDING")

    def test_authorization_checkpoint_precedes_provider_prepare_checkpoint(self):
        created = self.create("gate-order-001", "9.00")
        request = self.approvals(created["intent"]["intent_id"])
        self.kernel.prepare_provider_action(
            self.agent,
            created["intent"]["intent_id"],
            {"amount": "9.00"},
            request["request_id"],
        )
        records = [json.loads(x) for x in (self.state / "audit-chain.jsonl").read_text().splitlines() if x.strip()]
        kinds = [r.get("kind") for r in records]
        auth_index = kinds.index("provider.authorization.v06")
        provider_index = kinds.index("provider.action.transition.v06")
        self.assertLess(auth_index, provider_index)
        self.assertEqual(records[provider_index]["transition_status"], "PREPARED")

    def test_different_approval_provenance_cannot_replace_release_evidence(self):
        created = self.create("gate-auth-immutable", "13.00")
        intent_id = created["intent"]["intent_id"]
        first_request = self.approvals(intent_id)
        self.kernel.prepare_provider_action(
            self.agent, intent_id, {"amount": "13.00"}, first_request["request_id"]
        )

        second_request = self.approvals(intent_id)
        with self.assertRaises(HardeningError) as cm:
            self.kernel.prepare_provider_action(
                self.agent, intent_id, {"amount": "13.00"}, second_request["request_id"]
            )
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")

    def test_replay_state_tracks_timeout_reconciliation_to_commit(self):
        created = self.create("gate-reconcile-001", "20.00")
        intent_id = created["intent"]["intent_id"]
        request = self.approvals(intent_id)
        self.kernel.prepare_provider_action(
            self.agent, intent_id, {"amount": "20.00"}, request["request_id"]
        )
        self.assertEqual(self.kernel.provider_replay.get("gate-reconcile-001")["status"], "PREPARED")
        result = self.kernel.execute_provider_action(
            self.agent,
            intent_id,
            {"amount": "20.00"},
            request["request_id"],
            "commit_then_timeout",
        )
        self.assertEqual(result["status"], "RECONCILIATION_REQUIRED")
        replay = self.kernel.provider_replay.get("gate-reconcile-001")
        self.assertEqual(replay["status"], "RECONCILIATION_REQUIRED")
        self.assertEqual(replay["reconciliation_case_id"], result["reconciliation_case_id"])

        resolved = self.kernel.reconcile_provider_action(self.owner, intent_id)
        self.assertEqual(resolved["status"], "COMMITTED_RECONCILED")
        replay = self.kernel.provider_replay.get("gate-reconcile-001")
        self.assertEqual(replay["status"], "COMMITTED")
        self.assertTrue(replay["provider_action_id"])

    def test_replay_state_tracks_commit_then_compensation(self):
        created = self.create("gate-compensate-001", "25.00")
        intent_id = created["intent"]["intent_id"]
        request = self.approvals(intent_id)
        self.kernel.prepare_provider_action(
            self.agent, intent_id, {"amount": "25.00"}, request["request_id"]
        )
        committed = self.kernel.execute_provider_action(
            self.agent, intent_id, {"amount": "25.00"}, request["request_id"]
        )
        self.assertEqual(committed["status"], "COMMITTED")
        self.assertEqual(self.kernel.provider_replay.get("gate-compensate-001")["status"], "COMMITTED")
        compensated = self.kernel.compensate_provider_action(
            self.owner, intent_id, {"amount": "25.00"}
        )
        self.assertEqual(compensated["status"], "COMPENSATED")
        self.assertEqual(self.kernel.provider_replay.get("gate-compensate-001")["status"], "COMPENSATED")

    def test_status_exposes_replay_and_anchored_authorization_evidence(self):
        created = self.create("gate-status-001", "5.00")
        intent_id = created["intent"]["intent_id"]
        request = self.approvals(intent_id)
        self.kernel.prepare_provider_action(
            self.agent, intent_id, {"amount": "5.00"}, request["request_id"]
        )
        status = self.kernel.provider_action_status(self.agent, intent_id)
        self.assertEqual(status["kernel_replay"]["status"], "PREPARED")
        self.assertIsNotNone(status["authorization_evidence"])
        self.assertIsNotNone(status["authorization_anchor"])
        self.assertEqual(
            status["authorization_evidence"]["approval_request_id"],
            request["request_id"],
        )


if __name__ == "__main__":
    unittest.main()
