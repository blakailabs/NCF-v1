import json
import tempfile
import unittest
from pathlib import Path

from kernel.distributed_provider_gate import TrustKernelV07DistributedProviderGate
from kernel.hardening import HardeningError
from kernel.provider_release_gate import TrustKernelV06ReleaseGate
from kernel.runtime import CompanyKernel, RequestContext
from kernel.server_v02 import HardenedKernel

ROOT = Path(__file__).resolve().parents[1]


class RejectingAnchor:
    def anchor(self, head_hash, metadata=None):
        raise RuntimeError("simulated distributed prepare anchor outage")


class DistributedProviderGateV07Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "state"
        self.config = ROOT / "examples/kernel.config.json"
        self.policies = ROOT / "examples/policies"

        self.core_a, self.hardened_a, self.kernel_a = self._kernel("kernel:A")
        bootstrap = RequestContext("human:owner", "kernel:bootstrap", "trace:bootstrap")
        owner = self.core_a.spawn_process(bootstrap, "owner", "human:owner")
        agent = self.core_a.spawn_process(bootstrap, "ops", "agent:ops")
        risk = self.core_a.spawn_process(bootstrap, "risk", "human:risk")
        finance = self.core_a.spawn_process(bootstrap, "finance", "human:finance")
        self.owner = RequestContext("human:owner", owner["process_id"], "trace:owner")
        self.agent = RequestContext("agent:ops", agent["process_id"], "trace:agent")
        self.risk = RequestContext("human:risk", risk["process_id"], "trace:risk")
        self.finance = RequestContext("human:finance", finance["process_id"], "trace:finance")
        self.risk_session = self.hardened_a.sessions.issue("human:risk", 3600)
        self.finance_session = self.hardened_a.sessions.issue("human:finance", 3600)
        self.kernel_a.configure_exact_resource_pool(
            self.owner,
            "refund-usd-minor",
            100_000,
            "currency_minor",
            {"currency": "USD", "minor_exponent": 2},
        )
        self._extra_cores = []

    def tearDown(self):
        for core in self._extra_cores:
            try:
                core.store.conn.close()
            except Exception:
                pass
        try:
            self.core_a.store.conn.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def _kernel(self, instance_id):
        core = CompanyKernel.from_file(self.state, self.config)
        hardened = HardenedKernel(core, str(self.policies), set(), False)
        kernel = TrustKernelV07DistributedProviderGate(
            hardened,
            kernel_instance_id=instance_id,
        )
        return core, hardened, kernel

    def kernel_b(self):
        core, hardened, kernel = self._kernel("kernel:B")
        self._extra_cores.append(core)
        return core, hardened, kernel

    @staticmethod
    def args(amount="10.00", charge_id="charge-123", refund_reference="case-456"):
        return {
            "provider_account_id": "acct-sandbox",
            "charge_id": charge_id,
            "refund_reference": refund_reference,
            "amount": amount,
        }

    def create(self, nonce="distributed-refund-001", amount="10.00", charge_id="charge-123", refund_reference="case-456"):
        arguments = self.args(amount, charge_id, refund_reference)
        created = self.kernel_a.create_provider_intent(
            self.agent,
            "payments-primary",
            "payments.refund",
            arguments,
            nonce,
            "distributed sandbox refund",
            ["ticket:v07"],
        )
        return created, arguments

    def approve(self, intent_id):
        request = self.kernel_a.request_action_approval(
            self.agent,
            intent_id,
            ["human:risk", "human:finance"],
        )
        self.kernel_a.approve_action_with_session(
            self.risk,
            self.risk_session["bearer_token"],
            request["request_id"],
        )
        self.kernel_a.approve_action_with_session(
            self.finance,
            self.finance_session["bearer_token"],
            request["request_id"],
        )
        return request

    def prepare(self, created, arguments, request, kernel=None):
        target = kernel or self.kernel_a
        return target.prepare_provider_action(
            self.agent,
            created["intent"]["intent_id"],
            arguments,
            request["request_id"],
        )

    def expire_current_fence(self, resource_key):
        self.core_a.store.conn.execute(
            "UPDATE fence_resources_v07 SET expires_at='2000-01-01T00:00:00+00:00' WHERE resource_key=?",
            (resource_key,),
        )
        self.core_a.store.conn.commit()

    def test_create_binds_business_identity_without_raw_values(self):
        created, _arguments = self.create("distributed-identity-001")
        identity = created["business_identity"]
        self.assertEqual(identity["contract_id"], "payments.refund.target")
        row = dict(self.core_a.store.conn.execute("SELECT * FROM provider_business_identity_v07").fetchone())
        serialized = json.dumps(row, sort_keys=True)
        self.assertNotIn("acct-sandbox", serialized)
        self.assertNotIn("charge-123", serialized)
        self.assertNotIn("case-456", serialized)

    def test_same_business_identity_different_nonce_is_rejected_before_second_intent(self):
        self.create("distributed-business-first", "10.00")
        with self.assertRaises(HardeningError) as cm:
            self.create("distributed-business-second", "11.00")
        self.assertEqual(cm.exception.code, "CFHS_BUSINESS_IDENTITY_CONFLICT")
        count = self.core_a.store.one("SELECT COUNT(*) AS n FROM provider_intent_bindings_v06")["n"]
        self.assertEqual(count, 1)

    def test_same_semantic_retry_reuses_original_intent_and_identity(self):
        first, args = self.create("distributed-retry-001")
        second = self.kernel_a.create_provider_intent(
            self.agent,
            "payments-primary",
            "payments.refund",
            args,
            "distributed-retry-001",
            "distributed sandbox refund",
            ["ticket:v07"],
        )
        self.assertTrue(second["replayed_intent"])
        self.assertEqual(first["intent"]["intent_id"], second["intent"]["intent_id"])
        self.assertEqual(first["business_identity"]["identity_digest"], second["business_identity"]["identity_digest"])

    def test_prepare_acquires_execution_fence_before_provider_prepare(self):
        created, arguments = self.create("distributed-prepare-001")
        request = self.approve(created["intent"]["intent_id"])
        prepared = self.prepare(created, arguments, request)
        permit = prepared["distributed_permit"]
        self.assertEqual(permit["fence"]["owner_id"], "kernel:A")
        self.assertEqual(permit["fence"]["fence_token"], 1)
        history = self.kernel_a.distributed_permits.history(created["intent_digest"])
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["purpose"], "EXECUTE")
        self.assertEqual(history[0]["status"], "ACTIVE")

    def test_prepare_failure_releases_fence_and_keeps_business_bound(self):
        created, arguments = self.create("distributed-prepare-anchor-fail")
        request = self.approve(created["intent"]["intent_id"])
        self.kernel_a.provider_authorizations.anchor_provider = RejectingAnchor()
        with self.assertRaises(HardeningError) as cm:
            self.prepare(created, arguments, request)
        self.assertEqual(cm.exception.code, "CFHS_AUDIT_ANCHOR_FAILED")
        business = self.kernel_a.business_identities.get(created["business_identity"]["identity_digest"])
        self.assertEqual(business["status"], "BOUND")
        history = self.kernel_a.distributed_permits.history(created["intent_digest"])
        self.assertEqual(history[-1]["status"], "RELEASED")

    def test_competing_kernel_cannot_prepare_while_execution_fence_is_active(self):
        created, arguments = self.create("distributed-contention-001")
        request = self.approve(created["intent"]["intent_id"])
        self.prepare(created, arguments, request)
        _core_b, _hardened_b, kernel_b = self.kernel_b()
        with self.assertRaises(HardeningError) as cm:
            self.prepare(created, arguments, request, kernel_b)
        self.assertEqual(cm.exception.code, "CFHS_FENCE_BUSY")

    def test_expired_execution_fence_allows_takeover_with_higher_token(self):
        created, arguments = self.create("distributed-takeover-001")
        request = self.approve(created["intent"]["intent_id"])
        first = self.prepare(created, arguments, request)
        resource_key = first["distributed_permit"]["fence"]["resource_key"]
        self.expire_current_fence(resource_key)
        _core_b, _hardened_b, kernel_b = self.kernel_b()
        second = self.prepare(created, arguments, request, kernel_b)
        self.assertEqual(first["distributed_permit"]["fence"]["fence_token"], 1)
        self.assertEqual(second["distributed_permit"]["fence"]["fence_token"], 2)
        self.assertEqual(second["distributed_permit"]["fence"]["owner_id"], "kernel:B")
        history = kernel_b.distributed_permits.history(created["intent_digest"])
        self.assertEqual([x["status"] for x in history], ["STALE", "ACTIVE"])

    def test_stale_kernel_cannot_execute_after_takeover(self):
        created, arguments = self.create("distributed-stale-executor")
        request = self.approve(created["intent"]["intent_id"])
        first = self.prepare(created, arguments, request)
        self.expire_current_fence(first["distributed_permit"]["fence"]["resource_key"])
        _core_b, _hardened_b, kernel_b = self.kernel_b()
        self.prepare(created, arguments, request, kernel_b)
        with self.assertRaises(HardeningError) as cm:
            self.kernel_a.execute_provider_action(
                self.agent,
                created["intent"]["intent_id"],
                arguments,
                request["request_id"],
            )
        self.assertEqual(cm.exception.code, "CFHS_STALE_FENCE")
        provider_count = self.core_a.store.one("SELECT COUNT(*) AS n FROM sandbox_provider_actions")["n"]
        self.assertEqual(provider_count, 0)

    def test_takeover_kernel_executes_and_commits_business_state(self):
        created, arguments = self.create("distributed-takeover-execute")
        request = self.approve(created["intent"]["intent_id"])
        first = self.prepare(created, arguments, request)
        self.expire_current_fence(first["distributed_permit"]["fence"]["resource_key"])
        _core_b, _hardened_b, kernel_b = self.kernel_b()
        second = self.prepare(created, arguments, request, kernel_b)
        result = kernel_b.execute_provider_action(
            self.agent,
            created["intent"]["intent_id"],
            arguments,
            request["request_id"],
        )
        self.assertEqual(result["status"], "COMMITTED")
        self.assertEqual(result["distributed_permit"]["fence"]["fence_token"], 2)
        business = kernel_b.business_identities.get(created["business_identity"]["identity_digest"])
        self.assertEqual(business["status"], "COMMITTED")
        self.assertEqual(kernel_b.exact_resources.pool_state("refund-usd-minor")["used_units"], 1000)
        self.assertEqual(kernel_b.distributed_permits.history(created["intent_digest"])[-1]["status"], "RELEASED")

    def test_provider_gateway_rejects_old_fence_after_new_epoch_observed(self):
        created, arguments = self.create("distributed-provider-fence")
        request = self.approve(created["intent"]["intent_id"])
        first = self.prepare(created, arguments, request)
        resource_key = first["distributed_permit"]["fence"]["resource_key"]
        self.expire_current_fence(resource_key)
        _core_b, _hardened_b, kernel_b = self.kernel_b()
        second = self.prepare(created, arguments, request, kernel_b)
        kernel_b.provider_fence_guard.accept("sandbox-payments", resource_key, 2)
        with self.assertRaises(HardeningError) as cm:
            self.kernel_a.provider_fence_guard.accept("sandbox-payments", resource_key, 1)
        self.assertEqual(cm.exception.code, "CFHS_STALE_FENCE")
        self.assertEqual(second["distributed_permit"]["fence"]["fence_token"], 2)

    def test_timeout_releases_execution_fence_and_enters_business_reconciliation(self):
        created, arguments = self.create("distributed-timeout-001", "20.00")
        request = self.approve(created["intent"]["intent_id"])
        prepared = self.prepare(created, arguments, request)
        result = self.kernel_a.execute_provider_action(
            self.agent,
            created["intent"]["intent_id"],
            arguments,
            request["request_id"],
            "commit_then_timeout",
        )
        self.assertEqual(result["status"], "RECONCILIATION_REQUIRED")
        business = self.kernel_a.business_identities.get(created["business_identity"]["identity_digest"])
        self.assertEqual(business["status"], "RECONCILIATION_REQUIRED")
        history = self.kernel_a.distributed_permits.history(created["intent_digest"])
        self.assertEqual(history[-1]["status"], "RELEASED")
        self.assertEqual(history[-1]["fence_token"], prepared["distributed_permit"]["fence"]["fence_token"])

    def test_reconciliation_uses_new_higher_fence_and_commits_provider_truth(self):
        created, arguments = self.create("distributed-reconcile-001", "20.00")
        request = self.approve(created["intent"]["intent_id"])
        prepared = self.prepare(created, arguments, request)
        self.kernel_a.execute_provider_action(
            self.agent,
            created["intent"]["intent_id"],
            arguments,
            request["request_id"],
            "commit_then_timeout",
        )
        reconciled = self.kernel_a.reconcile_provider_action(
            self.owner,
            created["intent"]["intent_id"],
        )
        self.assertEqual(reconciled["status"], "COMMITTED_RECONCILED")
        execution_token = prepared["distributed_permit"]["fence"]["fence_token"]
        reconcile_token = reconciled["distributed_reconciliation_permit"]["fence"]["fence_token"]
        self.assertGreater(reconcile_token, execution_token)
        business = self.kernel_a.business_identities.get(created["business_identity"]["identity_digest"])
        self.assertEqual(business["status"], "COMMITTED")
        self.assertEqual(self.kernel_a.exact_resources.pool_state("refund-usd-minor")["used_units"], 2000)
        history = self.kernel_a.distributed_permits.history(created["intent_digest"])
        self.assertEqual([x["purpose"] for x in history], ["EXECUTE", "RECONCILE"])
        self.assertEqual([x["status"] for x in history], ["RELEASED", "RELEASED"])

    def test_active_reconciliation_fence_blocks_competing_reconciler(self):
        created, arguments = self.create("distributed-reconcile-contention", "20.00")
        request = self.approve(created["intent"]["intent_id"])
        self.prepare(created, arguments, request)
        self.kernel_a.execute_provider_action(
            self.agent,
            created["intent"]["intent_id"],
            arguments,
            request["request_id"],
            "commit_then_timeout",
        )
        business = self.kernel_a._business_row(created["intent"]["intent_id"])
        lease = self.kernel_a.distributed_fences.acquire(
            business["resource_key"],
            "kernel:A:reconcile",
            30,
        )
        _core_b, _hardened_b, kernel_b = self.kernel_b()
        with self.assertRaises(HardeningError) as cm:
            kernel_b.reconcile_provider_action(self.owner, created["intent"]["intent_id"])
        self.assertEqual(cm.exception.code, "CFHS_FENCE_BUSY")
        self.kernel_a.distributed_fences.release(lease)

    def test_execute_without_distributed_prepare_is_blocked(self):
        created, arguments = self.create("distributed-bypass-prepare")
        request = self.approve(created["intent"]["intent_id"])
        TrustKernelV06ReleaseGate.prepare_provider_action(
            self.kernel_a,
            self.agent,
            created["intent"]["intent_id"],
            arguments,
            request["request_id"],
        )
        with self.assertRaises(HardeningError) as cm:
            self.kernel_a.execute_provider_action(
                self.agent,
                created["intent"]["intent_id"],
                arguments,
                request["request_id"],
            )
        self.assertEqual(cm.exception.code, "CFHS_DISTRIBUTED_PERMIT_REQUIRED")
        self.assertEqual(self.core_a.store.one("SELECT COUNT(*) AS n FROM sandbox_provider_actions")["n"], 0)

    def test_altered_arguments_are_rejected_before_fence_acquisition(self):
        created, arguments = self.create("distributed-altered-args")
        request = self.approve(created["intent"]["intent_id"])
        altered = dict(arguments)
        altered["amount"] = "11.00"
        with self.assertRaises(HardeningError) as cm:
            self.prepare(created, altered, request)
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")
        count = self.core_a.store.one("SELECT COUNT(*) AS n FROM distributed_provider_permits_v07")["n"]
        self.assertEqual(count, 0)

    def test_v07_compensation_is_blocked_until_distributed_compensation_is_integrated(self):
        created, arguments = self.create("distributed-compensation-block")
        request = self.approve(created["intent"]["intent_id"])
        self.prepare(created, arguments, request)
        self.kernel_a.execute_provider_action(
            self.agent,
            created["intent"]["intent_id"],
            arguments,
            request["request_id"],
        )
        with self.assertRaises(HardeningError) as cm:
            self.kernel_a.request_provider_compensation_approval(
                self.owner,
                created["intent"]["intent_id"],
                arguments,
                ["human:risk", "human:finance"],
            )
        self.assertEqual(cm.exception.code, "CFHS_DISTRIBUTED_SAFETY_REQUIRED")

    def test_status_exposes_business_identity_and_permit_history(self):
        created, arguments = self.create("distributed-status-001")
        request = self.approve(created["intent"]["intent_id"])
        self.prepare(created, arguments, request)
        status = self.kernel_a.provider_action_status(self.agent, created["intent"]["intent_id"])
        self.assertEqual(status["business_identity"]["identity_digest"], created["business_identity"]["identity_digest"])
        self.assertEqual(status["business_identity"]["state"]["status"], "BOUND")
        self.assertEqual(len(status["distributed_permit_history"]), 1)
        self.assertEqual(status["distributed_permit_history"][0]["status"], "ACTIVE")


if __name__ == "__main__":
    unittest.main()
