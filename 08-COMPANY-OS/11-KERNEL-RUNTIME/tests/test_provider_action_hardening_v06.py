import sqlite3
import tempfile
import unittest
from pathlib import Path

from kernel.action_safety import ActionIntent
from kernel.exact_units import ExactResourceLedger, ExactUnitPolicy
from kernel.live_adapter_safety import (
    ProviderBoundCompensationRegistry,
    ProviderReconciliationLedger,
    SQLiteSandboxProvider,
)
from kernel.provider_action_hardening import ResilientProviderActionCoordinator
from kernel.provider_action_runtime import ProviderActionAudit


class FailOnceProviderConfirmedAudit(ProviderActionAudit):
    def __init__(self, conn):
        super().__init__(conn)
        self.failed = False

    def set_status(self, audit_id, status, provider_action_id=None, result=None, details=None):
        if status == "PROVIDER_CONFIRMED" and not self.failed:
            self.failed = True
            raise RuntimeError("simulated audit persistence failure after provider success")
        return super().set_status(audit_id, status, provider_action_id, result, details)


class FailOnceExactCommitLedger(ExactResourceLedger):
    def __init__(self, conn):
        super().__init__(conn)
        self.failed = False

    def transition(self, reservation_id, target, compensation_ref=None):
        if target == "COMMITTED" and not self.failed:
            self.failed = True
            raise RuntimeError("simulated exact-resource commit failure")
        return super().transition(reservation_id, target, compensation_ref)


class PersistThenUnexpectedErrorProvider(SQLiteSandboxProvider):
    def execute(self, operation, arguments, idempotency_key, mode="success"):
        super().execute(operation, arguments, idempotency_key, "success")
        raise RuntimeError("unexpected transport wrapper error after provider persistence")


class UnexpectedPrePersistErrorProvider(SQLiteSandboxProvider):
    def execute(self, operation, arguments, idempotency_key, mode="success"):
        raise RuntimeError("unexpected provider client failure before persistence")


class ProviderActionHardeningV06Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = sqlite3.connect(Path(self.tmp.name) / "provider-hardening.db")
        self.conn.row_factory = sqlite3.Row

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def components(self, provider_cls=SQLiteSandboxProvider, exact_cls=ExactResourceLedger, audit_cls=ProviderActionAudit):
        exact = exact_cls(self.conn)
        exact.configure_pool("money", 100_000, "currency_minor", {"currency": "USD", "minor_exponent": 2})
        reconciliation = ProviderReconciliationLedger(self.conn)
        bindings = ProviderBoundCompensationRegistry(self.conn)
        audit = audit_cls(self.conn)
        coordinator = ResilientProviderActionCoordinator(self.conn, exact, reconciliation, bindings, audit)
        provider = provider_cls(self.conn, "sandbox-payments")
        return exact, reconciliation, bindings, audit, coordinator, provider

    def intent(self, nonce="provider-hardening-001", amount="10.00"):
        args = {"amount": amount}
        intent = ActionIntent.create(
            actor_id="agent:ops",
            process_id="proc:ops",
            action="payments.refund",
            resource="/dev/payments/primary",
            side_effect_class="S3",
            purpose="provider hardening test",
            arguments=args,
            replay_nonce=nonce,
            required_approvals=0,
        )
        return intent, args

    def prepare(self, coordinator, provider, intent, args):
        return coordinator.prepare(
            intent,
            "payments-primary",
            provider,
            args,
            ExactUnitPolicy("money", "amount", "currency_minor", 2, "USD"),
            lambda _i, _a: {"decision": "ALLOW"},
        )

    def test_audit_failure_after_provider_success_opens_reconciliation_not_retry(self):
        exact, _, _, _, coordinator, provider = self.components(audit_cls=FailOnceProviderConfirmedAudit)
        intent, args = self.intent("provider-audit-fail")
        self.prepare(coordinator, provider, intent, args)
        result = coordinator.execute_prepared(intent, provider, args)
        self.assertEqual(result.status, "RECONCILIATION_REQUIRED")
        self.assertIsNotNone(provider.lookup(result.provider_idempotency_key))
        self.assertEqual(exact.pool_state("money")["reserved_units"], 1000)

        with self.assertRaises(Exception):
            coordinator.execute_prepared(intent, provider, args)

        resolved = coordinator.reconcile(intent.intent_digest(), provider)
        self.assertEqual(resolved.status, "COMMITTED_RECONCILED")
        self.assertEqual(exact.pool_state("money")["used_units"], 1000)
        self.assertEqual(exact.pool_state("money")["reserved_units"], 0)

    def test_exact_resource_commit_failure_after_provider_success_reconciles(self):
        exact, _, _, _, coordinator, provider = self.components(exact_cls=FailOnceExactCommitLedger)
        intent, args = self.intent("provider-resource-fail", "12.50")
        self.prepare(coordinator, provider, intent, args)
        result = coordinator.execute_prepared(intent, provider, args)
        self.assertEqual(result.status, "RECONCILIATION_REQUIRED")
        self.assertEqual(exact.pool_state("money")["reserved_units"], 1250)
        resolved = coordinator.reconcile(intent.intent_digest(), provider)
        self.assertEqual(resolved.status, "COMMITTED_RECONCILED")
        self.assertEqual(exact.pool_state("money")["used_units"], 1250)

    def test_unexpected_exception_after_provider_persistence_reconciles_from_lookup(self):
        exact, _, _, _, coordinator, provider = self.components(provider_cls=PersistThenUnexpectedErrorProvider)
        intent, args = self.intent("provider-generic-after", "8.00")
        self.prepare(coordinator, provider, intent, args)
        result = coordinator.execute_prepared(intent, provider, args)
        self.assertEqual(result.status, "RECONCILIATION_REQUIRED")
        receipt = provider.lookup(result.provider_idempotency_key)
        self.assertIsNotNone(receipt)
        resolved = coordinator.reconcile(intent.intent_digest(), provider)
        self.assertEqual(resolved.status, "COMMITTED_RECONCILED")
        self.assertEqual(exact.pool_state("money")["used_units"], 800)

    def test_unexpected_exception_before_provider_persistence_reconciles_to_not_executed(self):
        exact, _, _, _, coordinator, provider = self.components(provider_cls=UnexpectedPrePersistErrorProvider)
        intent, args = self.intent("provider-generic-before", "6.00")
        self.prepare(coordinator, provider, intent, args)
        result = coordinator.execute_prepared(intent, provider, args)
        self.assertEqual(result.status, "RECONCILIATION_REQUIRED")
        self.assertIsNone(provider.lookup(result.provider_idempotency_key))
        resolved = coordinator.reconcile(intent.intent_digest(), provider)
        self.assertEqual(resolved.status, "FAILED_NOT_EXECUTED_RECONCILED")
        self.assertEqual(exact.pool_state("money")["used_units"], 0)
        self.assertEqual(exact.pool_state("money")["reserved_units"], 0)

    def test_open_reconciliation_blocks_second_provider_execute(self):
        _, _, _, _, coordinator, provider = self.components(provider_cls=PersistThenUnexpectedErrorProvider)
        intent, args = self.intent("provider-retry-block", "7.00")
        self.prepare(coordinator, provider, intent, args)
        first = coordinator.execute_prepared(intent, provider, args)
        self.assertEqual(first.status, "RECONCILIATION_REQUIRED")
        with self.assertRaises(Exception) as cm:
            coordinator.execute_prepared(intent, provider, args)
        self.assertEqual(getattr(cm.exception, "code", None), "CFHS_UNKNOWN_SIDE_EFFECT")
        actions = self.conn.execute(
            "SELECT COUNT(*) AS n FROM sandbox_provider_actions WHERE provider_id=?",
            (provider.provider_id,),
        ).fetchone()["n"]
        self.assertEqual(actions, 1)


if __name__ == "__main__":
    unittest.main()
