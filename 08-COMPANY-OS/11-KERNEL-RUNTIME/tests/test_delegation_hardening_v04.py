import json
import tempfile
import unittest
from pathlib import Path

from kernel.delegation_hardening import RecursiveDelegationVerifier
from kernel.hardening import HardeningError
from kernel.runtime import CompanyKernel, RequestContext
from kernel.server_v02 import HardenedKernel
from kernel.server_v03 import TrustKernel

ROOT = Path(__file__).resolve().parents[1]


class DelegationHardeningV04Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        core = CompanyKernel.from_file(self.tmp.name, ROOT / "examples/kernel.config.json")
        hardened = HardenedKernel(core, str(ROOT / "examples/policies"), {"127.0.0.1"}, True)
        self.tk = TrustKernel(hardened)
        bootstrap = RequestContext("human:owner", "kernel:bootstrap", "trace:bootstrap")
        owner = core.spawn_process(bootstrap, "owner-root", "human:owner")
        self.owner = RequestContext("human:owner", owner["process_id"], "trace:owner")
        self.verifier = RecursiveDelegationVerifier(core.store.conn)

    def tearDown(self):
        self.tmp.cleanup()

    def test_recursive_delegation_chain_verifies(self):
        child = self.tk.spawn_bounded_process(
            self.owner,
            "refund-parent",
            "agent:ops",
            [{"action": "payments.refund", "resource": "/dev/payments/primary", "conditions": {"max_amount": 100}}],
        )
        child_ctx = RequestContext("agent:ops", child["process_id"], "trace:child")
        grandchild = self.tk.spawn_bounded_process(
            child_ctx,
            "refund-child",
            "agent:ops",
            [{"action": "payments.refund", "resource": "/dev/payments/primary", "conditions": {"max_amount": 50}}],
        )
        result = self.verifier.verify_chain(grandchild["process_id"])
        self.assertTrue(result["valid"])
        self.assertEqual(result["depth"], 2)
        self.assertEqual(result["chain"][-1]["process_id"], grandchild["process_id"])

    def test_tampered_delegation_digest_is_rejected(self):
        child = self.tk.spawn_bounded_process(
            self.owner,
            "refund-parent",
            "agent:ops",
            [{"action": "payments.refund", "resource": "/dev/payments/primary", "conditions": {"max_amount": 100}}],
        )
        self.tk.core.store.execute(
            "UPDATE delegation_proofs SET proof_digest='tampered' WHERE child_process_id=?",
            (child["process_id"],),
        )
        with self.assertRaises(HardeningError) as cm:
            self.verifier.verify_chain(child["process_id"])
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")

    def test_process_bounds_tampering_is_rejected(self):
        child = self.tk.spawn_bounded_process(
            self.owner,
            "refund-parent",
            "agent:ops",
            [{"action": "payments.refund", "resource": "/dev/payments/primary", "conditions": {"max_amount": 100}}],
        )
        row = self.tk.core.store.one("SELECT metadata_json FROM processes WHERE id=?", (child["process_id"],))
        metadata = json.loads(row["metadata_json"])
        metadata["capability_bounds"][0]["conditions"]["max_amount"] = 999
        self.tk.core.store.execute(
            "UPDATE processes SET metadata_json=? WHERE id=?",
            (json.dumps(metadata, sort_keys=True), child["process_id"]),
        )
        with self.assertRaises(HardeningError):
            self.verifier.verify_chain(child["process_id"])


if __name__ == "__main__":
    unittest.main()
