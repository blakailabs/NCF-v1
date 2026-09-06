import tempfile
import unittest
from pathlib import Path

from kernel.distributed_compensation_hardening import TrustKernelV07DistributedCompensationFinalGate
from kernel.hardening import HardeningError
from kernel.live_adapter_safety import ProviderOutcomeUnknown
from kernel.runtime import CompanyKernel, RequestContext
from kernel.server_v02 import HardenedKernel

ROOT = Path(__file__).resolve().parents[1]


class RejectingAnchor:
    def anchor(self, head_hash, metadata=None):
        raise RuntimeError("distributed compensation authorization anchor unavailable")


class DistributedCompensationV07Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "state"
        self.config = ROOT / "examples/kernel.config.json"
        self.policies = ROOT / "examples/policies"
        self.core = CompanyKernel.from_file(self.state, self.config)
        self.hardened = HardenedKernel(self.core, str(self.policies), set(), False)
        self.kernel = TrustKernelV07DistributedCompensationFinalGate(
            self.hardened,
            kernel_instance_id="kernel:A",
        )

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

    @staticmethod
    def args(amount="25.00", charge_id="charge-comp-123", refund_reference="case-comp-456"):
        return {
            "provider_account_id": "acct-sandbox",
            "charge_id": charge_id,
            "refund_reference": refund_reference,
            "amount": amount,
        }

    def committed_refund(self, nonce="dist-comp-original", amount="25.00"):
        arguments = self.args(amount)
        created = self.kernel.create_provider_intent(
            self.agent,
            "payments-primary",
            "payments.refund",
            arguments,
            nonce,
            "distributed compensation source refund",
            ["ticket:dist-comp"],
        )
        intent_id = created["intent"]["intent_id"]
        request = self.kernel.request_action_approval(
            self.agent,
            intent_id,
            ["human:risk", "human:finance"],
        )
        self.kernel.approve_action_with_session(
            self.risk, self.risk_session["bearer_token"], request["request_id"]
        )
        self.kernel.approve_action_with_session(
            self.finance, self.finance_session["bearer_token"], request["request_id"]
        )
        prepared = self.kernel.prepare_provider_action(
            self.agent, intent_id, arguments, request["request_id"]
        )
        committed = self.kernel.execute_provider_action(
            self.agent, intent_id, arguments, request["request_id"]
        )
        self.assertEqual(committed["status"], "COMMITTED")
        self.assertEqual(committed["distributed_transaction"]["status"], "COMMITTED")
        return created, arguments, prepared, committed

    def compensation_workflow(self, intent_id, arguments):
        workflow = self.kernel.request_provider_compensation_approval(
            self.owner,
            intent_id,
            arguments,
            ["human:risk", "human:finance"],
        )
        request_id = workflow["approval_request"]["request_id"]
        self.kernel.approve_action_with_session(
            self.risk, self.risk_session["bearer_token"], request_id
        )
        self.kernel.approve_action_with_session(
            self.finance, self.finance_session["bearer_token"], request_id
        )
        return workflow

    def compensate(self, created, arguments, workflow, mode="success"):
        return self.kernel.compensate_provider_action(
            self.owner,
            created["intent"]["intent_id"],
            arguments,
            mode,
            compensation_intent_id=workflow["compensation_intent"]["compensation_intent_id"],
            compensation_approval_request_id=workflow["approval_request"]["request_id"],
        )

    def test_distributed_compensation_still_requires_independent_approvals(self):
        created, arguments, _prepared, _committed = self.committed_refund("dist-comp-no-approval")
        workflow = self.kernel.request_provider_compensation_approval(
            self.owner,
            created["intent"]["intent_id"],
            arguments,
            ["human:risk", "human:finance"],
        )
        with self.assertRaises(HardeningError) as cm:
            self.compensate(created, arguments, workflow)
        self.assertEqual(cm.exception.code, "CFHS_ELEVATION_REQUIRED")
        tx = self.kernel.distributed_state.find_for_intent(created["intent_digest"])
        self.assertEqual(tx.status, "COMMITTED")
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["used_units"], 2500)

    def test_compensation_authorization_anchor_failure_creates_no_compensation_epoch(self):
        created, arguments, _prepared, committed = self.committed_refund("dist-comp-anchor-fail")
        workflow = self.compensation_workflow(created["intent"]["intent_id"], arguments)
        self.kernel.provider_authorizations.anchor_provider = RejectingAnchor()
        with self.assertRaises(HardeningError) as cm:
            self.compensate(created, arguments, workflow)
        self.assertEqual(cm.exception.code, "CFHS_AUDIT_ANCHOR_FAILED")
        tx = self.kernel.distributed_state.find_for_intent(created["intent_digest"])
        self.assertEqual(tx.status, "COMMITTED")
        self.assertEqual(tx.fence_token, committed["distributed_transaction"]["fence_token"])
        self.assertIsNone(self.kernel.distributed_compensations.find_for_original(created["intent_digest"]))

    def test_successful_compensation_uses_higher_fence_and_converges_all_state(self):
        created, arguments, _prepared, committed = self.committed_refund("dist-comp-success")
        workflow = self.compensation_workflow(created["intent"]["intent_id"], arguments)
        result = self.compensate(created, arguments, workflow)
        self.assertEqual(result["status"], "COMPENSATED")
        self.assertGreater(
            result["distributed_transaction"]["fence_token"],
            committed["distributed_transaction"]["fence_token"],
        )
        self.assertEqual(result["distributed_transaction"]["status"], "COMPENSATED")
        self.assertEqual(self.kernel.provider_replay.get("dist-comp-success")["status"], "COMPENSATED")
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["used_units"], 0)
        business = self.kernel.business_identities.get(created["business_identity"]["identity_digest"])
        self.assertEqual(business["status"], "COMPENSATED")
        distributed = self.kernel.distributed_compensations.get(
            workflow["compensation_intent"]["compensation_intent_id"]
        )
        self.assertEqual(distributed.status, "COMPENSATED")
        self.assertEqual(distributed.compensation_action_id, result["provider_action_id"])

    def test_definite_compensation_failure_returns_transaction_to_committed_and_releases_fence(self):
        created, arguments, _prepared, _committed = self.committed_refund("dist-comp-definite-fail")
        workflow = self.compensation_workflow(created["intent"]["intent_id"], arguments)
        result = self.compensate(created, arguments, workflow, "fail_before_commit")
        self.assertEqual(result["status"], "COMPENSATION_FAILED_NOT_EXECUTED")
        self.assertEqual(result["distributed_transaction"]["status"], "COMMITTED")
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["used_units"], 2500)
        fence = self.core.store.one(
            "SELECT current_token FROM fence_resources_v07 WHERE resource_key=?",
            (result["distributed_transaction"]["resource_key"],),
        )
        self.assertIsNone(fence["current_token"])
        distributed = self.kernel.distributed_compensations.get(
            workflow["compensation_intent"]["compensation_intent_id"]
        )
        self.assertEqual(distributed.status, "FAILED_NOT_EXECUTED")

    def test_retry_after_definite_failure_reuses_compensation_identity_and_higher_fence(self):
        created, arguments, _prepared, _committed = self.committed_refund("dist-comp-definite-retry")
        workflow = self.compensation_workflow(created["intent"]["intent_id"], arguments)
        first = self.compensate(created, arguments, workflow, "fail_before_commit")
        first_binding = self.kernel.distributed_compensations.get(
            workflow["compensation_intent"]["compensation_intent_id"]
        )
        second = self.compensate(created, arguments, workflow, "success")
        second_binding = self.kernel.distributed_compensations.get(
            workflow["compensation_intent"]["compensation_intent_id"]
        )
        self.assertEqual(second["status"], "COMPENSATED")
        self.assertEqual(
            first_binding.compensation_identity_digest,
            second_binding.compensation_identity_digest,
        )
        self.assertGreater(
            second["distributed_transaction"]["fence_token"],
            first["distributed_transaction"]["fence_token"],
        )
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["used_units"], 0)

    def test_compensation_commit_then_timeout_does_not_reverse_local_accounting_early(self):
        created, arguments, _prepared, committed = self.committed_refund("dist-comp-timeout", "30.00")
        workflow = self.compensation_workflow(created["intent"]["intent_id"], arguments)
        result = self.compensate(created, arguments, workflow, "commit_then_timeout")
        self.assertEqual(result["status"], "COMPENSATION_RECONCILIATION_REQUIRED")
        self.assertEqual(result["distributed_transaction"]["status"], "COMPENSATION_RECONCILIATION_REQUIRED")
        self.assertGreater(
            result["distributed_transaction"]["fence_token"],
            committed["distributed_transaction"]["fence_token"],
        )
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["used_units"], 3000)
        self.assertEqual(self.kernel.provider_replay.get("dist-comp-timeout")["status"], "COMMITTED")
        distributed = self.kernel.distributed_compensations.get(
            workflow["compensation_intent"]["compensation_intent_id"]
        )
        self.assertEqual(distributed.status, "RECONCILIATION_REQUIRED")
        self.assertTrue(distributed.reconciliation_case_id)

    def test_compensation_reconciliation_confirms_persisted_reversal_under_new_epoch(self):
        created, arguments, _prepared, _committed = self.committed_refund("dist-comp-reconcile", "30.00")
        workflow = self.compensation_workflow(created["intent"]["intent_id"], arguments)
        timed_out = self.compensate(created, arguments, workflow, "commit_then_timeout")
        resolved = self.kernel.reconcile_provider_compensation(
            self.owner,
            created["intent"]["intent_id"],
            workflow["compensation_intent"]["compensation_intent_id"],
        )
        self.assertEqual(resolved["status"], "COMPENSATED_RECONCILED")
        self.assertGreater(
            resolved["distributed_transaction"]["fence_token"],
            timed_out["distributed_transaction"]["fence_token"],
        )
        self.assertEqual(resolved["distributed_transaction"]["status"], "COMPENSATED")
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["used_units"], 0)
        self.assertEqual(self.kernel.provider_replay.get("dist-comp-reconcile")["status"], "COMPENSATED")
        business = self.kernel.business_identities.get(created["business_identity"]["identity_digest"])
        self.assertEqual(business["status"], "COMPENSATED")

    def test_unknown_compensation_with_no_provider_record_reconciles_to_not_executed(self):
        created, arguments, _prepared, _committed = self.committed_refund("dist-comp-not-executed")
        workflow = self.compensation_workflow(created["intent"]["intent_id"], arguments)
        provider = self.kernel.providers["sandbox-payments"]
        original_compensate = provider.compensate

        def unknown_without_persistence(*_args, **_kwargs):
            raise ProviderOutcomeUnknown("transport failed before observable persistence", provider.provider_id, "unknown-key")

        provider.compensate = unknown_without_persistence
        try:
            uncertain = self.compensate(created, arguments, workflow, "success")
        finally:
            provider.compensate = original_compensate
        self.assertEqual(uncertain["status"], "COMPENSATION_RECONCILIATION_REQUIRED")
        resolved = self.kernel.reconcile_provider_compensation(
            self.owner,
            created["intent"]["intent_id"],
            workflow["compensation_intent"]["compensation_intent_id"],
        )
        self.assertEqual(resolved["status"], "COMPENSATION_FAILED_NOT_EXECUTED_RECONCILED")
        self.assertEqual(resolved["distributed_transaction"]["status"], "COMMITTED")
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["used_units"], 2500)
        self.assertEqual(self.kernel.provider_replay.get("dist-comp-not-executed")["status"], "COMMITTED")

    def test_reconciliation_case_can_reopen_for_later_uncertain_retry_and_preserve_attempt_history(self):
        created, arguments, _prepared, _committed = self.committed_refund("dist-comp-reopen")
        workflow = self.compensation_workflow(created["intent"]["intent_id"], arguments)
        provider = self.kernel.providers["sandbox-payments"]
        original_compensate = provider.compensate

        def unknown_without_persistence(*_args, **_kwargs):
            raise ProviderOutcomeUnknown("first attempt unknown without persistence", provider.provider_id, "unknown-key")

        provider.compensate = unknown_without_persistence
        try:
            first_uncertain = self.compensate(created, arguments, workflow, "success")
        finally:
            provider.compensate = original_compensate
        first_resolved = self.kernel.reconcile_provider_compensation(
            self.owner,
            created["intent"]["intent_id"],
            workflow["compensation_intent"]["compensation_intent_id"],
        )
        self.assertEqual(first_resolved["status"], "COMPENSATION_FAILED_NOT_EXECUTED_RECONCILED")

        second_uncertain = self.compensate(created, arguments, workflow, "commit_then_timeout")
        self.assertEqual(second_uncertain["status"], "COMPENSATION_RECONCILIATION_REQUIRED")
        self.assertEqual(
            second_uncertain["compensation_reconciliation_case_id"],
            first_uncertain["compensation_reconciliation_case_id"],
        )
        history = self.kernel.distributed_compensations.reconciliation_history(
            second_uncertain["compensation_reconciliation_case_id"]
        )
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["status"], "CONFIRMED_NOT_EXECUTED")
        self.assertEqual(history[1]["status"], "OPEN")
        second_resolved = self.kernel.reconcile_provider_compensation(
            self.owner,
            created["intent"]["intent_id"],
            workflow["compensation_intent"]["compensation_intent_id"],
        )
        self.assertEqual(second_resolved["status"], "COMPENSATED_RECONCILED")
        history = self.kernel.distributed_compensations.reconciliation_history(
            second_uncertain["compensation_reconciliation_case_id"]
        )
        self.assertEqual([row["status"] for row in history], ["CONFIRMED_NOT_EXECUTED", "CONFIRMED_COMPENSATED"])

    def test_compensation_arguments_cannot_change_after_approval(self):
        created, arguments, _prepared, _committed = self.committed_refund("dist-comp-immutable")
        workflow = self.compensation_workflow(created["intent"]["intent_id"], arguments)
        altered = dict(arguments)
        altered["amount"] = "20.00"
        with self.assertRaises(HardeningError) as cm:
            self.compensate(created, altered, workflow)
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")
        self.assertEqual(self.kernel.exact_resources.pool_state("refund-usd-minor")["used_units"], 2500)

    def test_status_exposes_distributed_compensation_and_reconciliation(self):
        created, arguments, _prepared, _committed = self.committed_refund("dist-comp-status")
        workflow = self.compensation_workflow(created["intent"]["intent_id"], arguments)
        uncertain = self.compensate(created, arguments, workflow, "commit_then_timeout")
        status = self.kernel.provider_action_status(self.owner, created["intent"]["intent_id"])
        self.assertEqual(
            status["distributed_compensation"]["compensation_intent_id"],
            workflow["compensation_intent"]["compensation_intent_id"],
        )
        self.assertEqual(status["distributed_compensation"]["status"], "RECONCILIATION_REQUIRED")
        self.assertEqual(
            status["distributed_compensation_reconciliation"]["case_id"],
            uncertain["compensation_reconciliation_case_id"],
        )


if __name__ == "__main__":
    unittest.main()
