import tempfile
import unittest
from pathlib import Path

from kernel.hardening import HardeningError
from kernel.provider_release_gate import TrustKernelV06ReleaseGate
from kernel.runtime import CompanyKernel, RequestContext
from kernel.server_v02 import HardenedKernel
from kernel.transactional_provider_gate import TrustKernelV07TransactionalProviderGate

ROOT = Path(__file__).resolve().parents[1]


class RejectingAnchor:
    def anchor(self, head_hash, metadata=None):
        raise RuntimeError("simulated anchor outage")


class TransactionalProviderGateV07Tests(unittest.TestCase):
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
        self.extra_cores = []

    def tearDown(self):
        for core in self.extra_cores:
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
        kernel = TrustKernelV07TransactionalProviderGate(hardened, kernel_instance_id=instance_id)
        return core, hardened, kernel

    def kernel_b(self):
        core, hardened, kernel = self._kernel("kernel:B")
        self.extra_cores.append(core)
        return core, hardened, kernel

    @staticmethod
    def args(amount="10.00", charge_id="charge-123", refund_reference="case-456"):
        return {
            "provider_account_id": "acct-sandbox",
            "charge_id": charge_id,
            "refund_reference": refund_reference,
            "amount": amount,
        }

    def create(self, nonce="tx-gate-001", amount="10.00"):
        arguments = self.args(amount)
        created = self.kernel_a.create_provider_intent(
            self.agent,
            "payments-primary",
            "payments.refund",
            arguments,
            nonce,
            "transactional sandbox refund",
            ["ticket:tx-gate"],
        )
        return created, arguments

    def approve(self, intent_id):
        request = self.kernel_a.request_action_approval(
            self.agent,
            intent_id,
            ["human:risk", "human:finance"],
        )
        self.kernel_a.approve_action_with_session(
            self.risk, self.risk_session["bearer_token"], request["request_id"]
        )
        self.kernel_a.approve_action_with_session(
            self.finance, self.finance_session["bearer_token"], request["request_id"]
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

    def expire_transaction_fence(self, tx):
        self.core_a.store.conn.execute(
            "UPDATE fence_resources_v07 SET expires_at='2000-01-01T00:00:00+00:00' WHERE resource_key=?",
            (tx["resource_key"],),
        )
        self.core_a.store.conn.commit()

    def test_prepare_uses_same_exact_reservation_in_transaction_and_v06_provider_state(self):
        created, arguments = self.create("tx-same-reservation")
        request = self.approve(created["intent"]["intent_id"])
        prepared = self.prepare(created, arguments, request)
        tx = prepared["distributed_transaction"]
        self.assertEqual(prepared["exact_reservation_id"], tx["exact_reservation_id"])
        self.assertEqual(prepared["exact_units"], tx["exact_units"])
        self.assertEqual(self.kernel_a.exact_resources.pool_state("refund-usd-minor")["reserved_units"], 1000)
        reservations = self.core_a.store.conn.execute(
            "SELECT COUNT(*) AS n FROM exact_resource_reservations_v06 WHERE intent_digest=? AND status='RESERVED'",
            (created["intent_digest"],),
        ).fetchone()["n"]
        self.assertEqual(reservations, 1)

    def test_authorization_anchor_failure_creates_no_transaction_or_exact_reservation(self):
        created, arguments = self.create("tx-auth-anchor-fail")
        request = self.approve(created["intent"]["intent_id"])
        self.kernel_a.provider_authorizations.anchor_provider = RejectingAnchor()
        with self.assertRaises(HardeningError) as cm:
            self.prepare(created, arguments, request)
        self.assertEqual(cm.exception.code, "CFHS_AUDIT_ANCHOR_FAILED")
        self.assertIsNone(self.kernel_a.distributed_state.find_for_intent(created["intent_digest"]))
        self.assertEqual(self.kernel_a.exact_resources.pool_state("refund-usd-minor")["reserved_units"], 0)
        business = self.kernel_a._business_row(created["intent"]["intent_id"])
        fence = self.core_a.store.one(
            "SELECT current_token FROM fence_resources_v07 WHERE resource_key=?",
            (business["resource_key"],),
        )
        self.assertTrue(fence is None or fence["current_token"] is None)

    def test_provider_prepare_failure_aborts_transaction_and_retry_uses_higher_epoch(self):
        created, arguments = self.create("tx-prepare-retry")
        request = self.approve(created["intent"]["intent_id"])
        original_anchor = self.kernel_a.provider_audit.anchor_provider
        self.kernel_a.provider_audit.anchor_provider = RejectingAnchor()
        with self.assertRaises(HardeningError):
            self.prepare(created, arguments, request)
        aborted = self.kernel_a.distributed_state.find_for_intent(created["intent_digest"])
        self.assertEqual(aborted.status, "ABORTED")
        self.assertEqual(aborted.fence_token, 1)
        self.assertEqual(self.kernel_a.exact_resources.pool_state("refund-usd-minor")["reserved_units"], 0)

        self.kernel_a.provider_audit.anchor_provider = original_anchor
        retried = self.prepare(created, arguments, request)
        self.assertEqual(retried["distributed_transaction"]["transaction_id"], aborted.transaction_id)
        self.assertEqual(retried["distributed_transaction"]["fence_token"], 2)
        self.assertEqual(self.kernel_a.exact_resources.pool_state("refund-usd-minor")["reserved_units"], 1000)
        journal = self.kernel_a.distributed_state.journal(aborted.transaction_id)
        self.assertEqual([x["to_status"] for x in journal], ["PREPARED", "ABORTED", "PREPARED"])

    def test_prepared_takeover_reuses_transaction_and_exact_reservation(self):
        created, arguments = self.create("tx-prepared-takeover")
        request = self.approve(created["intent"]["intent_id"])
        first = self.prepare(created, arguments, request)
        self.expire_transaction_fence(first["distributed_transaction"])
        _core_b, _hard_b, kernel_b = self.kernel_b()
        second = self.prepare(created, arguments, request, kernel_b)
        self.assertEqual(
            second["distributed_transaction"]["transaction_id"],
            first["distributed_transaction"]["transaction_id"],
        )
        self.assertEqual(second["distributed_transaction"]["fence_token"], 2)
        self.assertEqual(second["exact_reservation_id"], first["exact_reservation_id"])
        self.assertEqual(kernel_b.exact_resources.pool_state("refund-usd-minor")["reserved_units"], 1000)

    def test_stale_kernel_cannot_execute_transaction_after_takeover(self):
        created, arguments = self.create("tx-stale-execute")
        request = self.approve(created["intent"]["intent_id"])
        first = self.prepare(created, arguments, request)
        self.expire_transaction_fence(first["distributed_transaction"])
        _core_b, _hard_b, kernel_b = self.kernel_b()
        self.prepare(created, arguments, request, kernel_b)
        with self.assertRaises(HardeningError) as cm:
            self.kernel_a.execute_provider_action(
                self.agent, created["intent"]["intent_id"], arguments, request["request_id"]
            )
        self.assertEqual(cm.exception.code, "CFHS_STALE_FENCE")
        self.assertEqual(self.core_a.store.one("SELECT COUNT(*) AS n FROM sandbox_provider_actions")["n"], 0)

    def test_takeover_kernel_executes_and_commits_same_transaction(self):
        created, arguments = self.create("tx-takeover-commit")
        request = self.approve(created["intent"]["intent_id"])
        first = self.prepare(created, arguments, request)
        self.expire_transaction_fence(first["distributed_transaction"])
        _core_b, _hard_b, kernel_b = self.kernel_b()
        second = self.prepare(created, arguments, request, kernel_b)
        result = kernel_b.execute_provider_action(
            self.agent, created["intent"]["intent_id"], arguments, request["request_id"]
        )
        self.assertEqual(result["status"], "COMMITTED")
        self.assertEqual(result["distributed_transaction"]["status"], "COMMITTED")
        self.assertEqual(
            result["distributed_transaction"]["transaction_id"],
            second["distributed_transaction"]["transaction_id"],
        )
        self.assertEqual(kernel_b.exact_resources.pool_state("refund-usd-minor")["used_units"], 1000)
        business = kernel_b.business_identities.get(created["business_identity"]["identity_digest"])
        self.assertEqual(business["status"], "COMMITTED")

    def test_timeout_enters_reconciliation_on_same_transaction_and_releases_epoch(self):
        created, arguments = self.create("tx-timeout", "20.00")
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
        tx = result["distributed_transaction"]
        self.assertEqual(tx["transaction_id"], prepared["distributed_transaction"]["transaction_id"])
        self.assertEqual(tx["status"], "RECONCILIATION_REQUIRED")
        fence = self.core_a.store.one(
            "SELECT current_token FROM fence_resources_v07 WHERE resource_key=?",
            (tx["resource_key"],),
        )
        self.assertIsNone(fence["current_token"])

    def test_reconciliation_reuses_transaction_id_with_higher_epoch(self):
        created, arguments = self.create("tx-reconcile", "20.00")
        request = self.approve(created["intent"]["intent_id"])
        prepared = self.prepare(created, arguments, request)
        timed_out = self.kernel_a.execute_provider_action(
            self.agent,
            created["intent"]["intent_id"],
            arguments,
            request["request_id"],
            "commit_then_timeout",
        )
        resolved = self.kernel_a.reconcile_provider_action(self.owner, created["intent"]["intent_id"])
        self.assertEqual(resolved["status"], "COMMITTED_RECONCILED")
        self.assertEqual(
            resolved["distributed_transaction"]["transaction_id"],
            prepared["distributed_transaction"]["transaction_id"],
        )
        self.assertGreater(
            resolved["distributed_transaction"]["fence_token"],
            timed_out["distributed_transaction"]["fence_token"],
        )
        self.assertEqual(resolved["distributed_transaction"]["status"], "COMMITTED")
        journal = self.kernel_a.distributed_state.journal(resolved["distributed_transaction"]["transaction_id"])
        self.assertIn("RECONCILING", [x["to_status"] for x in journal])
        self.assertEqual(journal[-1]["to_status"], "COMMITTED")

    def test_nontransactional_prepare_cannot_bypass_transactional_execute(self):
        created, arguments = self.create("tx-bypass")
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
                self.agent, created["intent"]["intent_id"], arguments, request["request_id"]
            )
        self.assertEqual(cm.exception.code, "CFHS_DISTRIBUTED_PERMIT_REQUIRED")
        self.assertEqual(self.core_a.store.one("SELECT COUNT(*) AS n FROM sandbox_provider_actions")["n"], 0)

    def test_status_exposes_transaction_and_versioned_journal(self):
        created, arguments = self.create("tx-status")
        request = self.approve(created["intent"]["intent_id"])
        prepared = self.prepare(created, arguments, request)
        status = self.kernel_a.provider_action_status(self.agent, created["intent"]["intent_id"])
        self.assertEqual(
            status["distributed_transaction"]["transaction_id"],
            prepared["distributed_transaction"]["transaction_id"],
        )
        self.assertEqual(status["distributed_transaction"]["status"], "PREPARED")
        self.assertEqual(len(status["distributed_transaction_journal"]), 1)
        self.assertEqual(status["distributed_transaction_journal"][0]["to_status"], "PREPARED")

    def test_compensation_remains_blocked_on_transactional_gate(self):
        created, arguments = self.create("tx-compensation-block")
        request = self.approve(created["intent"]["intent_id"])
        self.prepare(created, arguments, request)
        self.kernel_a.execute_provider_action(
            self.agent, created["intent"]["intent_id"], arguments, request["request_id"]
        )
        with self.assertRaises(HardeningError) as cm:
            self.kernel_a.request_provider_compensation_approval(
                self.owner,
                created["intent"]["intent_id"],
                arguments,
                ["human:risk", "human:finance"],
            )
        self.assertEqual(cm.exception.code, "CFHS_DISTRIBUTED_SAFETY_REQUIRED")


if __name__ == "__main__":
    unittest.main()
