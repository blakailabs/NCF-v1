import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from kernel.hardening import HardeningError
from kernel.recoverable_anchor_consumers import (
    RecoverableAnchoredProviderActionAudit,
    RecoverableAnchoredProviderAuthorizationEvidenceLedger,
    TrustKernelV07RecoverableAnchorFinalGate,
)
from kernel.remote_anchor_config import reference_quorum_anchor_status
from kernel.runtime import CompanyKernel
from kernel.server_v02 import HardenedKernel
from kernel.server_v07 import _build_remote_anchor

ROOT = Path(__file__).resolve().parents[1]


class ServerV07AnchorWiringTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.core = CompanyKernel.from_file(
            self.root / "state",
            ROOT / "examples/kernel.config.json",
        )
        self.hardened = HardenedKernel(
            self.core,
            str(ROOT / "examples/policies"),
            set(),
            False,
        )

    def tearDown(self):
        try:
            self.core.store.conn.close()
        except Exception:
            pass
        self.tmp.cleanup()

    @staticmethod
    def args(**overrides):
        values = {
            "remote_anchor_endpoint": [],
            "remote_anchor_receipt_key_env": [],
            "remote_anchor_quorum": 0,
            "remote_anchor_request_key_id": None,
            "remote_anchor_request_key_env": None,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_default_server_anchor_configuration_stays_local_reference(self):
        anchor = _build_remote_anchor(self.args(), self.core.store.conn)
        self.assertIsNone(anchor)
        status = reference_quorum_anchor_status(anchor)
        self.assertEqual(status["mode"], "local_reference")
        self.assertFalse(status["authenticated_quorum_configured"])
        self.assertFalse(status["reference_crypto_production_ready"])

    def test_partial_remote_anchor_flags_without_endpoints_fail_closed(self):
        with self.assertRaises(HardeningError) as cm:
            _build_remote_anchor(
                self.args(
                    remote_anchor_quorum=2,
                    remote_anchor_request_key_id="request-key-v1",
                    remote_anchor_request_key_env="ANCHOR_REQUEST_KEY",
                ),
                self.core.store.conn,
            )
        self.assertEqual(cm.exception.code, "CFHS_INVALID_POLICY")

    def test_legacy_single_remote_endpoint_is_not_accepted_as_hardened_mode(self):
        env = {
            "ANCHOR_REQUEST_KEY": "reference-request-key",
            "ANCHOR_A_KEY": "reference-a-key",
        }
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(HardeningError) as cm:
                _build_remote_anchor(
                    self.args(
                        remote_anchor_endpoint=["anchor-a=https://anchor-a.example.test/v1/anchor"],
                        remote_anchor_receipt_key_env=["anchor-a:a-key-v1:ANCHOR_A_KEY"],
                        remote_anchor_quorum=1,
                        remote_anchor_request_key_id="request-key-v1",
                        remote_anchor_request_key_env="ANCHOR_REQUEST_KEY",
                    ),
                    self.core.store.conn,
                )
        self.assertEqual(cm.exception.code, "CFHS_INVALID_POLICY")

    def test_valid_two_endpoint_runtime_config_builds_authenticated_quorum_reference(self):
        env = {
            "ANCHOR_REQUEST_KEY": "reference-request-key",
            "ANCHOR_A_KEY": "reference-a-key",
            "ANCHOR_B_KEY": "reference-b-key",
        }
        with patch.dict(os.environ, env, clear=False):
            anchor = _build_remote_anchor(
                self.args(
                    remote_anchor_endpoint=[
                        "anchor-a=https://anchor-a.example.test/v1/anchor",
                        "anchor-b=https://anchor-b.example.test/v1/anchor",
                    ],
                    remote_anchor_receipt_key_env=[
                        "anchor-a:a-key-v1:ANCHOR_A_KEY",
                        "anchor-b:b-key-v1:ANCHOR_B_KEY",
                    ],
                    remote_anchor_quorum=2,
                    remote_anchor_request_key_id="request-key-v1",
                    remote_anchor_request_key_env="ANCHOR_REQUEST_KEY",
                ),
                self.core.store.conn,
            )
        status = reference_quorum_anchor_status(anchor)
        self.assertEqual(status["mode"], "authenticated_quorum_reference")
        self.assertEqual(status["required_quorum"], 2)
        self.assertEqual(status["endpoint_ids"], ["anchor-a", "anchor-b"])
        self.assertFalse(status["reference_crypto_production_ready"])

    def test_canonical_gate_installs_recoverable_consumers(self):
        kernel = TrustKernelV07RecoverableAnchorFinalGate(
            self.hardened,
            kernel_instance_id="kernel:server-wiring-test",
        )
        self.assertIsInstance(kernel.provider_audit, RecoverableAnchoredProviderActionAudit)
        self.assertIs(kernel.provider_actions.audit, kernel.provider_audit)
        self.assertIsInstance(
            kernel.provider_authorizations,
            RecoverableAnchoredProviderAuthorizationEvidenceLedger,
        )
        status = kernel.anchor_recovery_status()
        self.assertTrue(status["same_head_retry"])
        self.assertEqual(status["pending_provider_action_checkpoints"], 0)
        self.assertEqual(status["pending_authorization_checkpoints"], 0)


if __name__ == "__main__":
    unittest.main()
