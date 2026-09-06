import tempfile
import unittest
from pathlib import Path

from kernel.exact_authority import TrustKernelV07ExactAuthorityFinalGate
from kernel.hardening import HardeningError
from kernel.runtime import CompanyKernel, RequestContext
from kernel.server_v02 import HardenedKernel

ROOT = Path(__file__).resolve().parents[1]


class ExactAuthorityV07Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "state"
        self.config = ROOT / "examples/kernel.config.json"
        self.policies = ROOT / "examples/policies"
        self.core = CompanyKernel.from_file(self.state, self.config)
        self.hardened = HardenedKernel(self.core, str(self.policies), set(), False)
        self.kernel = TrustKernelV07ExactAuthorityFinalGate(
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
        self.resource = "/dev/payments/primary"

    def tearDown(self):
        try:
            self.core.store.conn.close()
        except Exception:
            pass
        self.tmp.cleanup()

    @staticmethod
    def exact_scope(max_units=30000, currency="USD", exponent=2):
        return {
            "exact_authority": {
                "argument": "amount",
                "unit_kind": "currency_minor",
                "currency": currency,
                "minor_exponent": exponent,
                "max_units": max_units,
            }
        }

    def approve_exact_elevation(self, max_units=30000, currency="USD", exponent=2):
        requested = self.kernel.request_elevation(
            self.agent,
            "payments.refund",
            self.resource,
            self.exact_scope(max_units, currency, exponent),
            "test exact financial authority",
        )
        self.kernel.approve_elevation(self.owner, requested["elevation_id"], 600)
        return requested

    def test_exact_threshold_allows_250_dollars_as_25000_minor_units(self):
        decision = self.kernel.authorize(
            self.agent,
            "payments.refund",
            self.resource,
            {"amount": "250.00"},
        )
        self.assertEqual(decision["decision"], "ALLOW")
        self.assertEqual(decision["exact_authority"]["requested_units"], 25000)
        self.assertEqual(decision["exact_authority"]["max_units"], 25000)
        self.assertEqual(decision["exact_authority"]["currency"], "USD")

    def test_one_cent_over_exact_threshold_requires_elevation(self):
        decision = self.kernel.authorize(
            self.agent,
            "payments.refund",
            self.resource,
            {"amount": "250.01"},
        )
        self.assertEqual(decision["decision"], "ELEVATION_REQUIRED")
        self.assertEqual(decision["exact_authority"]["requested_units"], 25001)

    def test_sub_minor_precision_is_rejected_not_rounded(self):
        with self.assertRaises(HardeningError) as cm:
            self.kernel.authorize(
                self.agent,
                "payments.refund",
                self.resource,
                {"amount": "250.001"},
            )
        self.assertEqual(cm.exception.code, "CFHS_INVALID_REQUEST")

    def test_non_finite_financial_authority_value_is_rejected(self):
        with self.assertRaises(HardeningError) as cm:
            self.kernel.authorize(
                self.agent,
                "payments.refund",
                self.resource,
                {"amount": "NaN"},
            )
        self.assertEqual(cm.exception.code, "CFHS_INVALID_REQUEST")

    def test_legacy_float_elevation_does_not_bypass_exact_authority(self):
        requested = self.kernel.request_elevation(
            self.agent,
            "payments.refund",
            self.resource,
            {"max_amount": 300},
            "legacy float elevation must not satisfy exact authority",
        )
        self.kernel.approve_elevation(self.owner, requested["elevation_id"], 600)
        decision = self.kernel.authorize(
            self.agent,
            "payments.refund",
            self.resource,
            {"amount": "275.00"},
        )
        self.assertEqual(decision["decision"], "ELEVATION_REQUIRED")
        self.assertNotIn("elevation_id", decision["exact_authority"])

    def test_matching_exact_elevation_allows_amount_above_standing_limit(self):
        requested = self.approve_exact_elevation(30000)
        decision = self.kernel.authorize(
            self.agent,
            "payments.refund",
            self.resource,
            {"amount": "275.00"},
        )
        self.assertEqual(decision["decision"], "ALLOW")
        self.assertEqual(decision["exact_authority"]["requested_units"], 27500)
        self.assertEqual(decision["exact_authority"]["elevation_id"], requested["elevation_id"])
        self.assertIn("exact-authority-v07", decision["matched_policies"])

    def test_mismatched_currency_or_insufficient_exact_elevation_is_rejected(self):
        self.approve_exact_elevation(50000, currency="EUR")
        self.approve_exact_elevation(27000, currency="USD")
        decision = self.kernel.authorize(
            self.agent,
            "payments.refund",
            self.resource,
            {"amount": "275.00"},
        )
        self.assertEqual(decision["decision"], "ELEVATION_REQUIRED")

    def test_provider_prepare_uses_exact_authority_and_succeeds_after_exact_elevation(self):
        arguments = {
            "provider_account_id": "acct-sandbox",
            "charge_id": "charge-exact-authority",
            "refund_reference": "case-exact-authority",
            "amount": "275.00",
        }
        created = self.kernel.create_provider_intent(
            self.agent,
            "payments-primary",
            "payments.refund",
            arguments,
            "exact-auth-provider-001",
            "exact authority provider flow",
            ["ticket:exact-authority"],
        )
        request = self.kernel.request_action_approval(
            self.agent,
            created["intent"]["intent_id"],
            ["human:risk", "human:finance"],
        )
        self.kernel.approve_action_with_session(
            self.risk,
            self.risk_session["bearer_token"],
            request["request_id"],
        )
        self.kernel.approve_action_with_session(
            self.finance,
            self.finance_session["bearer_token"],
            request["request_id"],
        )
        with self.assertRaises(HardeningError) as cm:
            self.kernel.prepare_provider_action(
                self.agent,
                created["intent"]["intent_id"],
                arguments,
                request["request_id"],
            )
        self.assertEqual(cm.exception.code, "CFHS_ELEVATION_REQUIRED")
        self.approve_exact_elevation(30000)
        prepared = self.kernel.prepare_provider_action(
            self.agent,
            created["intent"]["intent_id"],
            arguments,
            request["request_id"],
        )
        self.assertEqual(prepared["exact_units"], 27500)
        self.assertEqual(prepared["distributed_transaction"]["exact_units"], 27500)


if __name__ == "__main__":
    unittest.main()
