import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kernel.control_plane_fencing import FencedApprovalControlPlane, TrustKernelV07ControlPlaneFinalGate
from kernel.hardening import HardeningError
from kernel.runtime import CompanyKernel, RequestContext
from kernel.server_v02 import HardenedKernel

ROOT = Path(__file__).resolve().parents[1]


class ControlPlaneFencingV07Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "state"
        self.config = ROOT / "examples/kernel.config.json"
        self.policies = ROOT / "examples/policies"
        self.core = CompanyKernel.from_file(self.state, self.config)
        self.hardened = HardenedKernel(self.core, str(self.policies), set(), False)
        self.kernel = TrustKernelV07ControlPlaneFinalGate(
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
        self.t0 = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)

    def tearDown(self):
        try:
            self.core.store.conn.close()
        except Exception:
            pass
        self.tmp.cleanup()

    @staticmethod
    def args(amount="10.00", charge_id="charge-approval-1"):
        return {
            "provider_account_id": "acct-sandbox",
            "charge_id": charge_id,
            "refund_reference": "case-approval-1",
            "amount": amount,
        }

    def provider_intent(self, nonce="approval-control-001", charge_id="charge-approval-1"):
        return self.kernel.create_provider_intent(
            self.agent,
            "payments-primary",
            "payments.refund",
            self.args(charge_id=charge_id),
            nonce,
            "approval control test",
            ["ticket:approval-control"],
        )

    def approval_request(self, created):
        return self.kernel.request_action_approval(
            self.agent,
            created["intent"]["intent_id"],
            ["human:risk", "human:finance"],
        )

    def test_request_initializes_versioned_control_record(self):
        created = self.provider_intent("approval-control-init")
        request = self.approval_request(created)
        self.assertEqual(request["control_version"], 0)
        self.assertEqual(request["last_fence_token"], 0)
        state = self.kernel.approval_control.state(request["request_id"])
        self.assertEqual(state["control"]["version"], 0)
        self.assertEqual(state["journal"], [])

    def test_two_party_approval_uses_monotonic_fences_and_atomic_provenance(self):
        created = self.provider_intent("approval-control-two-party")
        request = self.approval_request(created)
        first = self.kernel.approve_action_with_session(
            self.risk,
            self.risk_session["bearer_token"],
            request["request_id"],
        )
        second = self.kernel.approve_action_with_session(
            self.finance,
            self.finance_session["bearer_token"],
            request["request_id"],
        )
        self.assertEqual(first["fence_token"], 1)
        self.assertEqual(first["control_version"], 1)
        self.assertEqual(first["status"], "PENDING")
        self.assertEqual(second["fence_token"], 2)
        self.assertEqual(second["control_version"], 2)
        self.assertEqual(second["status"], "APPROVED")
        complete = self.kernel.approval_provenance.require_complete(request["request_id"])
        self.assertEqual(complete["approval_count"], 2)
        self.assertEqual(complete["provenance_count"], 2)
        journal = self.kernel.approval_control.journal(request["request_id"])
        self.assertEqual([row["fence_token"] for row in journal], [1, 2])
        self.assertEqual([row["approval_count"] for row in journal], [1, 2])

    def test_plain_non_session_approval_is_rejected_in_canonical_v07_gate(self):
        created = self.provider_intent("approval-control-no-session")
        request = self.approval_request(created)
        with self.assertRaises(HardeningError) as cm:
            self.kernel.approve_action(self.risk, request["request_id"])
        self.assertEqual(cm.exception.code, "CFHS_UNAUTHENTICATED")
        self.assertEqual(
            self.core.store.one(
                "SELECT COUNT(*) AS n FROM action_approvals WHERE request_id=?",
                (request["request_id"],),
            )["n"],
            0,
        )

    def test_active_mutation_fence_blocks_competing_kernel_owner(self):
        created = self.provider_intent("approval-control-contention")
        request = self.approval_request(created)
        fence = self.kernel.approval_control.acquire(
            request["request_id"],
            "kernel:A:approval:human:risk",
            30,
            self.t0,
        )
        with self.assertRaises(HardeningError) as cm:
            self.kernel.approval_control.acquire(
                request["request_id"],
                "kernel:B:approval:human:finance",
                30,
                self.t0 + timedelta(seconds=1),
            )
        self.assertEqual(cm.exception.code, "CFHS_FENCE_BUSY")
        self.kernel.approval_control.release(fence, self.t0 + timedelta(seconds=2))

    def test_expired_mutation_fence_takeover_makes_old_owner_stale(self):
        created = self.provider_intent("approval-control-takeover")
        request = self.approval_request(created)
        old = self.kernel.approval_control.acquire(
            request["request_id"],
            "kernel:A:approval:human:risk",
            10,
            self.t0,
        )
        new = self.kernel.approval_control.acquire(
            request["request_id"],
            "kernel:B:approval:human:risk",
            30,
            self.t0 + timedelta(seconds=11),
        )
        self.assertEqual(old.fence_token, 1)
        self.assertEqual(new.fence_token, 2)
        evidence = self.kernel.approval_session_resolver.resolve(
            self.risk_session["bearer_token"],
            "human:risk",
        )
        with self.assertRaises(HardeningError) as cm:
            self.kernel.approval_control.approve_with_provenance(
                old,
                "human:risk",
                evidence,
                self.t0 + timedelta(seconds=12),
            )
        self.assertEqual(cm.exception.code, "CFHS_STALE_FENCE")
        result = self.kernel.approval_control.approve_with_provenance(
            new,
            "human:risk",
            evidence,
            self.t0 + timedelta(seconds=12),
        )
        self.assertEqual(result["fence_token"], 2)
        self.assertEqual(result["approval_count"], 1)

    def test_duplicate_same_session_approval_is_idempotent_but_versioned(self):
        created = self.provider_intent("approval-control-replay")
        request = self.approval_request(created)
        first = self.kernel.approve_action_with_session(
            self.risk,
            self.risk_session["bearer_token"],
            request["request_id"],
        )
        second = self.kernel.approve_action_with_session(
            self.risk,
            self.risk_session["bearer_token"],
            request["request_id"],
        )
        self.assertEqual(first["approval_count"], 1)
        self.assertEqual(second["approval_count"], 1)
        self.assertEqual(second["mutation"], "APPROVAL_REPLAY")
        self.assertEqual(second["control_version"], 2)
        self.assertEqual(second["fence_token"], 2)
        self.assertEqual(
            self.core.store.one(
                "SELECT COUNT(*) AS n FROM action_approvals WHERE request_id=? AND approver_id='human:risk'",
                (request["request_id"],),
            )["n"],
            1,
        )
        self.assertEqual(
            self.core.store.one(
                "SELECT COUNT(*) AS n FROM action_approval_provenance_v06 WHERE request_id=? AND approver_id='human:risk'",
                (request["request_id"],),
            )["n"],
            1,
        )

    def test_same_approver_cannot_replace_provenance_with_new_session(self):
        created = self.provider_intent("approval-control-provenance-immutable")
        request = self.approval_request(created)
        self.kernel.approve_action_with_session(
            self.risk,
            self.risk_session["bearer_token"],
            request["request_id"],
        )
        replacement = self.hardened.sessions.issue("human:risk", 3600)
        with self.assertRaises(HardeningError) as cm:
            self.kernel.approve_action_with_session(
                self.risk,
                replacement["bearer_token"],
                request["request_id"],
            )
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")
        control = self.kernel.approval_control.state(request["request_id"])["control"]
        self.assertIsNone(control["current_token"])
        self.assertEqual(control["version"], 1)

    def test_compensation_approval_uses_same_fenced_control_plane(self):
        created = self.provider_intent("approval-control-comp", "charge-approval-comp")
        request = self.approval_request(created)
        self.kernel.approve_action_with_session(self.risk, self.risk_session["bearer_token"], request["request_id"])
        self.kernel.approve_action_with_session(self.finance, self.finance_session["bearer_token"], request["request_id"])
        args = self.args(charge_id="charge-approval-comp")
        self.kernel.prepare_provider_action(self.agent, created["intent"]["intent_id"], args, request["request_id"])
        self.kernel.execute_provider_action(self.agent, created["intent"]["intent_id"], args, request["request_id"])

        workflow = self.kernel.request_provider_compensation_approval(
            self.owner,
            created["intent"]["intent_id"],
            args,
            ["human:risk", "human:finance"],
        )
        comp_request = workflow["approval_request"]["request_id"]
        first = self.kernel.approve_action_with_session(
            self.risk,
            self.risk_session["bearer_token"],
            comp_request,
        )
        second = self.kernel.approve_action_with_session(
            self.finance,
            self.finance_session["bearer_token"],
            comp_request,
        )
        self.assertEqual(first["fence_token"], 1)
        self.assertEqual(second["fence_token"], 2)
        self.assertEqual(second["status"], "APPROVED")
        complete = self.kernel.approval_provenance.require_complete(comp_request)
        self.assertEqual(complete["provenance_count"], 2)
        self.assertEqual(len(self.kernel.approval_control.journal(comp_request)), 2)

    def test_requester_and_ineligible_approver_rejections_leave_no_mutation(self):
        created = self.provider_intent("approval-control-ineligible")
        request = self.kernel.request_action_approval(
            self.agent,
            created["intent"]["intent_id"],
            ["human:risk", "human:finance"],
        )
        with self.assertRaises(HardeningError):
            self.kernel.approve_action_with_session(
                self.owner,
                self.hardened.sessions.issue("human:owner", 3600)["bearer_token"],
                request["request_id"],
            )
        self.assertEqual(
            self.core.store.one(
                "SELECT COUNT(*) AS n FROM action_approvals WHERE request_id=?",
                (request["request_id"],),
            )["n"],
            0,
        )
        state = self.kernel.approval_control.state(request["request_id"])
        self.assertEqual(state["control"]["version"], 0)
        self.assertEqual(state["journal"], [])


if __name__ == "__main__":
    unittest.main()
