import sqlite3
import tempfile
import unittest
from pathlib import Path

from kernel.hardening import HardeningError
from kernel.live_adapter_safety import (
    ExactResourceLedger,
    ExactUnitPolicy,
    ProviderBoundCompensationRegistry,
    ProviderDefiniteFailure,
    ProviderOutcomeUnknown,
    ProviderReconciliationLedger,
    SQLiteSandboxProvider,
    compensation_idempotency_key,
    provider_idempotency_key,
)


class LiveAdapterSafetyV06Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "v06.db"
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_currency_minor_units_are_exact(self):
        policy = ExactUnitPolicy("refund-usd", "amount", "currency_minor", 2, "USD")
        self.assertEqual(policy.to_units({"amount": "10.25"}), 1025)
        self.assertEqual(policy.to_units({"amount": 10.25}), 1025)
        self.assertEqual(policy.to_units({"amount": "0.01"}), 1)

    def test_currency_rejects_sub_minor_precision(self):
        policy = ExactUnitPolicy("refund-usd", "amount", "currency_minor", 2, "USD")
        with self.assertRaises(HardeningError):
            policy.to_units({"amount": "10.001"})

    def test_currency_rejects_non_finite_zero_and_negative(self):
        policy = ExactUnitPolicy("refund-usd", "amount", "currency_minor", 2, "USD")
        for value in ["NaN", "Infinity", "-Infinity", "0", "-1.00"]:
            with self.subTest(value=value):
                with self.assertRaises(HardeningError):
                    policy.to_units({"amount": value})

    def test_count_requires_whole_positive_units(self):
        policy = ExactUnitPolicy("messages", "count", "count")
        self.assertEqual(policy.to_units({"count": "3"}), 3)
        for value in [3.5, "1.1", 0, -1, True, "NaN"]:
            with self.subTest(value=value):
                with self.assertRaises(HardeningError):
                    policy.to_units({"count": value})

    def test_exact_resource_reserve_commit_release(self):
        ledger = ExactResourceLedger(self.conn)
        ledger.configure_pool("refund-usd", 10_000, "currency_minor", {"currency": "USD", "minor_exponent": 2})
        first = ledger.reserve("intent-a", "refund-usd", 2500)
        state = ledger.pool_state("refund-usd")
        self.assertEqual(state["reserved_units"], 2500)
        self.assertEqual(state["used_units"], 0)
        ledger.transition(first["reservation_id"], "COMMITTED")
        state = ledger.pool_state("refund-usd")
        self.assertEqual(state["reserved_units"], 0)
        self.assertEqual(state["used_units"], 2500)

        second = ledger.reserve("intent-b", "refund-usd", 1000)
        ledger.transition(second["reservation_id"], "RELEASED")
        state = ledger.pool_state("refund-usd")
        self.assertEqual(state["used_units"], 2500)
        self.assertEqual(state["reserved_units"], 0)

    def test_exact_resource_limit_and_unit_definition_are_immutable(self):
        ledger = ExactResourceLedger(self.conn)
        ledger.configure_pool("refund-usd", 1000, "currency_minor", {"currency": "USD", "minor_exponent": 2})
        ledger.reserve("intent-a", "refund-usd", 900)
        with self.assertRaises(HardeningError):
            ledger.reserve("intent-b", "refund-usd", 101)
        with self.assertRaises(HardeningError):
            ledger.configure_pool("refund-usd", 1000, "count", {})
        with self.assertRaises(HardeningError):
            ledger.configure_pool("refund-usd", 800, "currency_minor", {"currency": "USD", "minor_exponent": 2})

    def test_provider_same_key_same_request_is_idempotent(self):
        provider = SQLiteSandboxProvider(self.conn, "sandbox-payments")
        key = provider_idempotency_key("intent-digest-1", provider.provider_id, "payments.refund")
        first = provider.execute("payments.refund", {"amount_minor": 1250}, key)
        second = provider.execute("payments.refund", {"amount_minor": 1250}, key)
        self.assertEqual(first.provider_action_id, second.provider_action_id)
        self.assertEqual(first.request_digest, second.request_digest)

    def test_provider_same_key_different_request_conflicts(self):
        provider = SQLiteSandboxProvider(self.conn, "sandbox-payments")
        key = provider_idempotency_key("intent-digest-2", provider.provider_id, "payments.refund")
        provider.execute("payments.refund", {"amount_minor": 1250}, key)
        with self.assertRaises(HardeningError) as cm:
            provider.execute("payments.refund", {"amount_minor": 1300}, key)
        self.assertEqual(cm.exception.code, "CFHS_IDEMPOTENCY_CONFLICT")

    def test_provider_definite_failure_creates_no_provider_record(self):
        provider = SQLiteSandboxProvider(self.conn, "sandbox-payments")
        key = provider_idempotency_key("intent-digest-3", provider.provider_id, "payments.refund")
        with self.assertRaises(ProviderDefiniteFailure):
            provider.execute("payments.refund", {"amount_minor": 1250}, key, "fail_before_commit")
        self.assertIsNone(provider.lookup(key))

    def test_provider_timeout_after_commit_is_reconcilable(self):
        provider = SQLiteSandboxProvider(self.conn, "sandbox-payments")
        key = provider_idempotency_key("intent-digest-4", provider.provider_id, "payments.refund")
        with self.assertRaises(ProviderOutcomeUnknown):
            provider.execute("payments.refund", {"amount_minor": 1250}, key, "commit_then_timeout")
        receipt = provider.lookup(key)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt.status, "SUCCEEDED")

    def test_provider_idempotency_survives_restart(self):
        provider = SQLiteSandboxProvider(self.conn, "sandbox-payments")
        key = provider_idempotency_key("intent-digest-5", provider.provider_id, "payments.refund")
        first = provider.execute("payments.refund", {"amount_minor": 1250}, key)
        self.conn.close()
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        provider2 = SQLiteSandboxProvider(self.conn, "sandbox-payments")
        second = provider2.execute("payments.refund", {"amount_minor": 1250}, key)
        self.assertEqual(first.provider_action_id, second.provider_action_id)

    def test_provider_compensation_is_idempotent_and_updates_original(self):
        provider = SQLiteSandboxProvider(self.conn, "sandbox-payments")
        intent_digest = "intent-digest-6"
        key = provider_idempotency_key(intent_digest, provider.provider_id, "payments.refund")
        original = provider.execute("payments.refund", {"amount_minor": 1250}, key)
        comp_key = compensation_idempotency_key(intent_digest, original.provider_action_id, "payments.refund.reverse")
        first = provider.compensate(original.provider_action_id, "payments.refund.reverse", {"amount_minor": 1250}, comp_key)
        second = provider.compensate(original.provider_action_id, "payments.refund.reverse", {"amount_minor": 1250}, comp_key)
        self.assertEqual(first.provider_action_id, second.provider_action_id)
        self.assertEqual(provider.lookup(key).status, "COMPENSATED")

    def test_provider_compensation_requires_original_action(self):
        provider = SQLiteSandboxProvider(self.conn, "sandbox-payments")
        with self.assertRaises(ProviderDefiniteFailure):
            provider.compensate("missing", "payments.refund.reverse", {"amount_minor": 1250}, "comp-key-1")

    def test_provider_compensation_key_conflict_is_rejected(self):
        provider = SQLiteSandboxProvider(self.conn, "sandbox-payments")
        intent_digest = "intent-digest-7"
        key = provider_idempotency_key(intent_digest, provider.provider_id, "payments.refund")
        original = provider.execute("payments.refund", {"amount_minor": 1250}, key)
        comp_key = compensation_idempotency_key(intent_digest, original.provider_action_id, "payments.refund.reverse")
        provider.compensate(original.provider_action_id, "payments.refund.reverse", {"amount_minor": 1250}, comp_key)
        with self.assertRaises(HardeningError):
            provider.compensate(original.provider_action_id, "payments.refund.reverse", {"amount_minor": 1300}, comp_key)

    def test_provider_bound_compensation_is_one_binding_per_intent(self):
        registry = ProviderBoundCompensationRegistry(self.conn)
        registry.bind(
            "intent-digest-8",
            "sandbox-payments",
            "payments-primary",
            "payments.refund",
            "payments-primary",
            "payments.refund.reverse",
            "payments.refund.reverse",
        )
        with self.assertRaises(HardeningError):
            registry.bind(
                "intent-digest-8",
                "sandbox-payments",
                "payments-primary",
                "payments.refund",
                "other-device",
                "other.reverse",
                "other.reverse",
            )

    def test_reconciliation_confirms_committed_after_timeout(self):
        provider = SQLiteSandboxProvider(self.conn, "sandbox-payments")
        ledger = ProviderReconciliationLedger(self.conn)
        intent_digest = "intent-digest-9"
        key = provider_idempotency_key(intent_digest, provider.provider_id, "payments.refund")
        with self.assertRaises(ProviderOutcomeUnknown):
            provider.execute("payments.refund", {"amount_minor": 1250}, key, "commit_then_timeout")
        case = ledger.open_case(intent_digest, provider.provider_id, key, {"reason": "transport_timeout"})
        resolved = ledger.reconcile(case["case_id"], provider)
        self.assertEqual(resolved["status"], "CONFIRMED_COMMITTED")
        self.assertTrue(resolved["provider_action_id"])

    def test_reconciliation_confirms_not_executed_after_definite_failure(self):
        provider = SQLiteSandboxProvider(self.conn, "sandbox-payments")
        ledger = ProviderReconciliationLedger(self.conn)
        intent_digest = "intent-digest-10"
        key = provider_idempotency_key(intent_digest, provider.provider_id, "payments.refund")
        with self.assertRaises(ProviderDefiniteFailure):
            provider.execute("payments.refund", {"amount_minor": 1250}, key, "fail_before_commit")
        case = ledger.open_case(intent_digest, provider.provider_id, key)
        resolved = ledger.reconcile(case["case_id"], provider)
        self.assertEqual(resolved["status"], "CONFIRMED_NOT_EXECUTED")

    def test_reconciliation_confirms_compensated(self):
        provider = SQLiteSandboxProvider(self.conn, "sandbox-payments")
        ledger = ProviderReconciliationLedger(self.conn)
        intent_digest = "intent-digest-11"
        key = provider_idempotency_key(intent_digest, provider.provider_id, "payments.refund")
        original = provider.execute("payments.refund", {"amount_minor": 1250}, key)
        comp_key = compensation_idempotency_key(intent_digest, original.provider_action_id, "payments.refund.reverse")
        provider.compensate(original.provider_action_id, "payments.refund.reverse", {"amount_minor": 1250}, comp_key)
        case = ledger.open_case(intent_digest, provider.provider_id, key)
        resolved = ledger.reconcile(case["case_id"], provider)
        self.assertEqual(resolved["status"], "COMPENSATED")

    def test_reconciliation_rejects_wrong_provider_and_cross_intent_key(self):
        provider = SQLiteSandboxProvider(self.conn, "sandbox-payments")
        other = SQLiteSandboxProvider(self.conn, "sandbox-other")
        ledger = ProviderReconciliationLedger(self.conn)
        key = provider_idempotency_key("intent-digest-12", provider.provider_id, "payments.refund")
        case = ledger.open_case("intent-digest-12", provider.provider_id, key)
        with self.assertRaises(HardeningError):
            ledger.reconcile(case["case_id"], other)
        with self.assertRaises(HardeningError):
            ledger.open_case("different-intent", provider.provider_id, key)


if __name__ == "__main__":
    unittest.main()
