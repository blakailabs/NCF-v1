import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kernel.hardening import HardeningError
from kernel.production_identity import TrustKernelV07ProductionIdentityFinalGate
from kernel.runtime import CompanyKernel, RequestContext
from kernel.server_v02 import HardenedKernel

ROOT = Path(__file__).resolve().parents[1]


class ProductionIdentityV07Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        config_doc = json.loads((ROOT / "examples/kernel.config.json").read_text())
        config_doc["security"]["production_identity"]["mode"] = "production"
        self.config = self.root / "kernel.production.json"
        self.config.write_text(json.dumps(config_doc, indent=2))
        self.state = self.root / "state"
        self.policies = ROOT / "examples/policies"
        self.core = CompanyKernel.from_file(self.state, self.config)
        self.hardened = HardenedKernel(self.core, str(self.policies), set(), False)
        self.kernel = TrustKernelV07ProductionIdentityFinalGate(
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

    @staticmethod
    def args(amount="25.00", charge_id="charge-prod-id", reference="case-prod-id"):
        return {
            "provider_account_id": "acct-sandbox",
            "charge_id": charge_id,
            "refund_reference": reference,
            "amount": amount,
        }

    def bind_identity(
        self,
        session,
        principal,
        *,
        provider="oidc:workforce",
        issuer="https://id.example.test",
        amr=None,
        acr="urn:mfa",
        auth_time=None,
    ):
        if auth_time is None:
            auth_time = datetime.now(timezone.utc).isoformat()
        return self.kernel.session_identity_provenance.bind_verified_identity(
            session["session_id"],
            principal,
            provider,
            issuer,
            f"subject:{principal}",
            {
                "amr": ["pwd", "mfa"] if amr is None else amr,
                "acr": acr,
                "auth_time": auth_time,
            },
        )

    def strong_humans(self):
        self.bind_identity(self.owner_session, "human:owner")
        self.bind_identity(self.risk_session, "human:risk")
        self.bind_identity(self.finance_session, "human:finance")

    def create_intent(self, nonce="prod-id-001", amount="25.00", charge_id="charge-prod-id"):
        arguments = self.args(amount, charge_id, f"case:{nonce}")
        created = self.kernel.create_provider_intent(
            self.agent,
            "payments-primary",
            "payments.refund",
            arguments,
            nonce,
            "production identity test",
            ["ticket:prod-id"],
        )
        return created, arguments

    def strong_approval_request(self, created):
        request = self.kernel.request_action_approval(
            self.agent,
            created["intent"]["intent_id"],
            ["human:risk", "human:finance"],
        )
        self.kernel.approve_action_with_session(
            self.risk, self.risk_session["bearer_token"], request["request_id"]
        )
        self.kernel.approve_action_with_session(
            self.finance, self.finance_session["bearer_token"], request["request_id"]
        )
        return request

    def committed_refund(self, nonce="prod-id-commit"):
        self.strong_humans()
        created, arguments = self.create_intent(nonce)
        request = self.strong_approval_request(created)
        self.kernel.prepare_provider_action(
            self.agent, created["intent"]["intent_id"], arguments, request["request_id"]
        )
        committed = self.kernel.execute_provider_action(
            self.agent, created["intent"]["intent_id"], arguments, request["request_id"]
        )
        self.assertEqual(committed["status"], "COMMITTED")
        return created, arguments, request

    def test_production_policy_rejects_kernel_session_only_approval(self):
        created, _arguments = self.create_intent("prod-id-kernel-session")
        request = self.kernel.request_action_approval(
            self.agent,
            created["intent"]["intent_id"],
            ["human:risk", "human:finance"],
        )
        with self.assertRaises(HardeningError) as cm:
            self.kernel.approve_action_with_session(
                self.risk, self.risk_session["bearer_token"], request["request_id"]
            )
        self.assertEqual(cm.exception.code, "CFHS_AUTHENTICATION_CLASS_REQUIRED")
        self.assertEqual(
            self.core.store.one(
                "SELECT COUNT(*) AS n FROM action_approvals WHERE request_id=?",
                (request["request_id"],),
            )["n"],
            0,
        )

    def test_verified_external_identity_without_mfa_is_rejected(self):
        self.bind_identity(self.risk_session, "human:risk", amr=["pwd"])
        created, _arguments = self.create_intent("prod-id-no-mfa")
        request = self.kernel.request_action_approval(
            self.agent,
            created["intent"]["intent_id"],
            ["human:risk", "human:finance"],
        )
        with self.assertRaises(HardeningError) as cm:
            self.kernel.approve_action_with_session(
                self.risk, self.risk_session["bearer_token"], request["request_id"]
            )
        self.assertEqual(cm.exception.code, "CFHS_MFA_REQUIRED")

    def test_wrong_provider_or_issuer_is_rejected(self):
        self.bind_identity(self.risk_session, "human:risk", provider="oidc:untrusted")
        with self.assertRaises(HardeningError) as cm:
            self.kernel.identity_assurance.require_bearer(
                self.risk_session["bearer_token"], "human:risk", "test"
            )
        self.assertEqual(cm.exception.code, "CFHS_AUTHENTICATION_CLASS_REQUIRED")

        replacement = self.hardened.sessions.issue("human:finance", 3600)
        self.bind_identity(replacement, "human:finance", issuer="https://evil.example.test")
        with self.assertRaises(HardeningError) as cm2:
            self.kernel.identity_assurance.require_bearer(
                replacement["bearer_token"], "human:finance", "test"
            )
        self.assertEqual(cm2.exception.code, "CFHS_AUTHENTICATION_CLASS_REQUIRED")

    def test_stale_authentication_requires_reauthentication(self):
        stale = (datetime.now(timezone.utc) - timedelta(seconds=901)).isoformat()
        self.bind_identity(self.risk_session, "human:risk", auth_time=stale)
        with self.assertRaises(HardeningError) as cm:
            self.kernel.identity_assurance.require_bearer(
                self.risk_session["bearer_token"], "human:risk", "approval"
            )
        self.assertEqual(cm.exception.code, "CFHS_REAUTHENTICATION_REQUIRED")

    def test_strong_mfa_approval_is_recorded_and_s3_prepare_accepts_it(self):
        self.bind_identity(self.risk_session, "human:risk")
        self.bind_identity(self.finance_session, "human:finance", acr="urn:phishing-resistant")
        created, arguments = self.create_intent("prod-id-strong")
        request = self.strong_approval_request(created)
        prepared = self.kernel.prepare_provider_action(
            self.agent,
            created["intent"]["intent_id"],
            arguments,
            request["request_id"],
        )
        self.assertEqual(prepared["status"], "PREPARED")
        strong = self.kernel.identity_assurance.require_request_provenance(
            request["request_id"], "assert-test"
        )
        self.assertEqual(len(strong["strong_approvers"]), 2)
        self.assertTrue(strong["strong_provenance_digest"])

    def test_s3_prepare_rejects_weak_provenance_injected_below_canonical_gate(self):
        created, arguments = self.create_intent("prod-id-injected-weak")
        request = self.kernel.request_action_approval(
            self.agent,
            created["intent"]["intent_id"],
            ["human:risk", "human:finance"],
        )
        self.kernel.action_approvals.approve(request["request_id"], "human:risk")
        self.kernel.approval_provenance.record(
            request["request_id"],
            "human:risk",
            self.kernel.approval_session_resolver.resolve(
                self.risk_session["bearer_token"], "human:risk"
            ),
        )
        self.kernel.action_approvals.approve(request["request_id"], "human:finance")
        self.kernel.approval_provenance.record(
            request["request_id"],
            "human:finance",
            self.kernel.approval_session_resolver.resolve(
                self.finance_session["bearer_token"], "human:finance"
            ),
        )
        with self.assertRaises(HardeningError) as cm:
            self.kernel.prepare_provider_action(
                self.agent,
                created["intent"]["intent_id"],
                arguments,
                request["request_id"],
            )
        self.assertEqual(cm.exception.code, "CFHS_AUTHENTICATION_CLASS_REQUIRED")
        self.assertIsNone(self.kernel.distributed_state.find_for_intent(created["intent_digest"]))

    def test_compensation_requester_requires_strong_identity(self):
        created, arguments, _request = self.committed_refund("prod-id-comp-request")
        weak_owner = self.hardened.sessions.issue("human:owner", 3600)
        with self.assertRaises(HardeningError) as cm:
            self.kernel.request_provider_compensation_approval_with_session(
                self.owner,
                weak_owner["bearer_token"],
                created["intent"]["intent_id"],
                arguments,
                ["human:risk", "human:finance"],
            )
        self.assertEqual(cm.exception.code, "CFHS_AUTHENTICATION_CLASS_REQUIRED")

        workflow = self.kernel.request_provider_compensation_approval_with_session(
            self.owner,
            self.owner_session["bearer_token"],
            created["intent"]["intent_id"],
            arguments,
            ["human:risk", "human:finance"],
        )
        self.assertEqual(
            workflow["requester_identity_assurance"]["authentication_class"],
            "verified_external_identity+mfa",
        )

    def test_elevation_approval_requires_mfa_and_records_identity_provenance(self):
        requested = self.core.request_elevation(
            self.agent,
            "payments.refund",
            "/dev/payments/primary",
            {
                "exact_authority": {
                    "argument": "amount",
                    "unit_kind": "currency_minor",
                    "currency": "USD",
                    "minor_exponent": 2,
                    "max_units": 30000,
                }
            },
            "production exact elevation",
        )
        with self.assertRaises(HardeningError) as cm:
            self.kernel.approve_elevation_with_session(
                self.owner,
                self.owner_session["bearer_token"],
                requested["elevation_id"],
            )
        self.assertEqual(cm.exception.code, "CFHS_AUTHENTICATION_CLASS_REQUIRED")
        self.assertEqual(
            self.core.store.one(
                "SELECT status FROM elevation_requests WHERE id=?",
                (requested["elevation_id"],),
            )["status"],
            "PENDING",
        )

        self.bind_identity(self.owner_session, "human:owner")
        approved = self.kernel.approve_elevation_with_session(
            self.owner,
            self.owner_session["bearer_token"],
            requested["elevation_id"],
        )
        self.assertEqual(approved["status"], "APPROVED")
        provenance = self.kernel.elevation_identity.get(requested["elevation_id"])
        self.assertEqual(provenance["authentication_class"], "verified_external_identity+mfa")
        self.assertTrue(provenance["assurance_digest"])

    def test_direct_core_approved_elevation_is_not_trusted_in_production(self):
        requested = self.core.request_elevation(
            self.agent,
            "payments.refund",
            "/dev/payments/primary",
            {
                "exact_authority": {
                    "argument": "amount",
                    "unit_kind": "currency_minor",
                    "currency": "USD",
                    "minor_exponent": 2,
                    "max_units": 30000,
                }
            },
            "unproven elevation",
        )
        self.core.approve_elevation(self.owner, requested["elevation_id"], 600)
        decision = self.kernel.authorize(
            self.agent,
            "payments.refund",
            "/dev/payments/primary",
            {"amount": "275.00"},
        )
        self.assertEqual(decision["decision"], "ELEVATION_REQUIRED")
        self.assertEqual(decision["identity_requirement"], "verified_external_identity+mfa")

    def test_strong_elevation_allows_exact_authority_above_standing_limit(self):
        self.bind_identity(self.owner_session, "human:owner")
        requested = self.core.request_elevation(
            self.agent,
            "payments.refund",
            "/dev/payments/primary",
            {
                "exact_authority": {
                    "argument": "amount",
                    "unit_kind": "currency_minor",
                    "currency": "USD",
                    "minor_exponent": 2,
                    "max_units": 30000,
                }
            },
            "strong production elevation",
        )
        self.kernel.approve_elevation_with_session(
            self.owner,
            self.owner_session["bearer_token"],
            requested["elevation_id"],
        )
        decision = self.kernel.authorize(
            self.agent,
            "payments.refund",
            "/dev/payments/primary",
            {"amount": "275.00"},
        )
        self.assertEqual(decision["decision"], "ALLOW")
        self.assertEqual(decision["exact_authority"]["elevation_id"], requested["elevation_id"])

    def test_identity_policy_status_exposes_no_raw_tokens(self):
        status = self.kernel.identity_policy_status()
        self.assertTrue(status["production_enforced"])
        self.assertFalse(status["raw_identity_tokens_stored"])
        self.assertEqual(status["required_human_class"], "verified_external_identity+mfa")
        self.assertTrue(status["policy_digest"])


if __name__ == "__main__":
    unittest.main()
