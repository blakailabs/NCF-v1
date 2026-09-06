import tempfile
import unittest
from pathlib import Path

from kernel.hardening import HardeningError
from kernel.provider_release_gate import TrustKernelV06ReleaseGate
from kernel.runtime import CompanyKernel, RequestContext
from kernel.server_v02 import HardenedKernel
from kernel.server_v06 import TrustKernelV06

ROOT = Path(__file__).resolve().parents[1]


class ProviderReplayRestartV06Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "state"
        self.config = ROOT / "examples/kernel.config.json"
        self.policies = ROOT / "examples/policies"

    def tearDown(self):
        self.tmp.cleanup()

    def kernel(self):
        core = CompanyKernel.from_file(self.state, self.config)
        hardened = HardenedKernel(core, str(self.policies), set(), False)
        gate = TrustKernelV06ReleaseGate(hardened)
        return core, hardened, gate

    @staticmethod
    def contexts(core):
        bootstrap = RequestContext("human:owner", "kernel:bootstrap", "trace:bootstrap")
        owner = core.spawn_process(bootstrap, "owner", "human:owner")
        agent = core.spawn_process(bootstrap, "ops", "agent:ops")
        risk = core.spawn_process(bootstrap, "risk", "human:risk")
        return (
            RequestContext("human:owner", owner["process_id"], "trace:owner"),
            RequestContext("agent:ops", agent["process_id"], "trace:agent"),
            RequestContext("human:risk", risk["process_id"], "trace:risk"),
        )

    def test_reservation_only_survives_restart_then_attaches_when_creation_retries(self):
        core, _hardened, gate = self.kernel()
        _owner, agent, _risk = self.contexts(core)
        probe, _profile, _policy, _units = gate._probe_provider_intent(
            agent,
            "payments-primary",
            "payments.refund",
            {"amount": "10.00"},
            "restart-reserved-only",
            "sandbox refund",
            ["ticket:restart"],
            None,
        )
        gate.provider_replay.reserve("restart-reserved-only", probe.intent_digest())
        core.store.conn.close()

        core2, _hardened2, gate2 = self.kernel()
        try:
            self.assertEqual(gate2.startup_provider_replay_recovery["recovered_count"], 0)
            self.assertEqual(gate2.startup_provider_replay_recovery["pending_count"], 1)
            # Recreate the originating process identity in the durable process table
            # by using the original process id from the semantic probe.
            agent2 = RequestContext("agent:ops", probe.process_id, "trace:agent-retry")
            created = gate2.create_provider_intent(
                agent2,
                "payments-primary",
                "payments.refund",
                {"amount": "10.00"},
                "restart-reserved-only",
                "sandbox refund",
                ["ticket:restart"],
            )
            replay = gate2.provider_replay.get("restart-reserved-only")
            self.assertEqual(replay["status"], "PENDING")
            self.assertEqual(replay["intent_id"], created["intent"]["intent_id"])
        finally:
            core2.store.conn.close()

    def test_restart_attaches_intent_persisted_before_replay_attachment(self):
        core, _hardened, gate = self.kernel()
        _owner, agent, _risk = self.contexts(core)
        args = {"amount": "11.00"}
        probe, _profile, _policy, _units = gate._probe_provider_intent(
            agent,
            "payments-primary",
            "payments.refund",
            args,
            "restart-after-intent",
            "sandbox refund",
            ["ticket:restart-intent"],
            None,
        )
        gate.provider_replay.reserve("restart-after-intent", probe.intent_digest())
        created = TrustKernelV06.create_provider_intent(
            gate,
            agent,
            "payments-primary",
            "payments.refund",
            args,
            "restart-after-intent",
            "sandbox refund",
            ["ticket:restart-intent"],
            None,
        )
        self.assertIsNone(gate.provider_replay.get("restart-after-intent")["intent_id"])
        core.store.conn.close()

        core2, _hardened2, gate2 = self.kernel()
        try:
            recovery = gate2.startup_provider_replay_recovery
            self.assertEqual(recovery["recovered_count"], 1)
            replay = gate2.provider_replay.get("restart-after-intent")
            self.assertEqual(replay["status"], "PENDING")
            self.assertEqual(replay["intent_id"], created["intent"]["intent_id"])
            agent2 = RequestContext("agent:ops", probe.process_id, "trace:retry")
            replayed = gate2.create_provider_intent(
                agent2,
                "payments-primary",
                "payments.refund",
                args,
                "restart-after-intent",
                "sandbox refund",
                ["ticket:restart-intent"],
            )
            self.assertTrue(replayed["replayed_intent"])
            self.assertEqual(replayed["intent"]["intent_id"], created["intent"]["intent_id"])
        finally:
            core2.store.conn.close()

    def test_different_semantics_cannot_take_over_unattached_reserved_nonce(self):
        core, _hardened, gate = self.kernel()
        try:
            _owner, agent, _risk = self.contexts(core)
            probe, _profile, _policy, _units = gate._probe_provider_intent(
                agent,
                "payments-primary",
                "payments.refund",
                {"amount": "10.00"},
                "reserved-conflict",
                "sandbox refund",
                [],
                None,
            )
            gate.provider_replay.reserve("reserved-conflict", probe.intent_digest())
            with self.assertRaises(HardeningError) as cm:
                gate.create_provider_intent(
                    agent,
                    "payments-primary",
                    "payments.refund",
                    {"amount": "12.00"},
                    "reserved-conflict",
                    "sandbox refund",
                    [],
                )
            self.assertEqual(cm.exception.code, "CFHS_IDEMPOTENCY_CONFLICT")
            self.assertIsNone(
                core.store.one(
                    "SELECT 1 FROM action_intent_index WHERE replay_nonce=?",
                    ("reserved-conflict",),
                )
            )
        finally:
            core.store.conn.close()

    def test_ordinary_pre_persistence_authorization_failure_releases_unattached_nonce(self):
        core, _hardened, gate = self.kernel()
        try:
            _owner, _agent, risk = self.contexts(core)
            with self.assertRaises(HardeningError) as cm:
                gate.create_provider_intent(
                    risk,
                    "payments-primary",
                    "payments.refund",
                    {"amount": "10.00"},
                    "denied-cleanup",
                    "unauthorized intent",
                    [],
                )
            self.assertEqual(cm.exception.code, "CFHS_POLICY_DENIED")
            self.assertIsNone(gate.provider_replay.get("denied-cleanup"))
            self.assertIsNone(
                core.store.one(
                    "SELECT 1 FROM action_intent_index WHERE replay_nonce=?",
                    ("denied-cleanup",),
                )
            )
        finally:
            core.store.conn.close()


if __name__ == "__main__":
    unittest.main()
