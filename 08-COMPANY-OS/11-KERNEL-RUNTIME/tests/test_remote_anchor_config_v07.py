import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from kernel.hardening import HardeningError
from kernel.remote_anchor_config import build_reference_quorum_anchor, reference_quorum_anchor_status


class RemoteAnchorConfigV07Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = sqlite3.connect(Path(self.tmp.name) / "config.db")
        self.conn.row_factory = sqlite3.Row
        self.env = {
            "ANCHOR_REQUEST_KEY": "request-reference-secret",
            "ANCHOR_A_RECEIPT_KEY": "anchor-a-reference-secret",
            "ANCHOR_B_RECEIPT_KEY": "anchor-b-reference-secret",
        }
        self.endpoints = [
            "anchor-a=https://anchor-a.example.test/v1/anchor",
            "anchor-b=https://anchor-b.example.test/v1/anchor",
        ]
        self.keys = [
            "anchor-a:anchor-a-key-v1:ANCHOR_A_RECEIPT_KEY",
            "anchor-b:anchor-b-key-v1:ANCHOR_B_RECEIPT_KEY",
        ]

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def build(self, **overrides):
        args = {
            "endpoint_specs": self.endpoints,
            "receipt_key_specs": self.keys,
            "quorum": 2,
            "request_key_id": "request-key-v1",
            "request_key_env": "ANCHOR_REQUEST_KEY",
        }
        args.update(overrides)
        with patch.dict(os.environ, self.env, clear=False):
            return build_reference_quorum_anchor(self.conn, **args)

    def test_hardened_runtime_requires_at_least_two_remote_endpoints(self):
        with self.assertRaises(HardeningError) as cm:
            self.build(endpoint_specs=[self.endpoints[0]], receipt_key_specs=[self.keys[0]], quorum=1)
        self.assertEqual(cm.exception.code, "CFHS_INVALID_POLICY")

    def test_hardened_runtime_requires_quorum_of_at_least_two(self):
        with self.assertRaises(HardeningError) as cm:
            self.build(quorum=1)
        self.assertEqual(cm.exception.code, "CFHS_INVALID_POLICY")

    def test_every_endpoint_requires_exact_receipt_verification_key_binding(self):
        with self.assertRaises(HardeningError) as cm:
            self.build(receipt_key_specs=[self.keys[0]])
        self.assertEqual(cm.exception.code, "CFHS_INVALID_POLICY")
        self.assertEqual(cm.exception.details["endpoint_ids"], ["anchor-a", "anchor-b"])

    def test_runtime_key_material_must_exist_outside_repository(self):
        with patch.dict(os.environ, self.env, clear=False):
            os.environ.pop("ANCHOR_REQUEST_KEY", None)
            with self.assertRaises(HardeningError) as cm:
                build_reference_quorum_anchor(
                    self.conn,
                    endpoint_specs=self.endpoints,
                    receipt_key_specs=self.keys,
                    quorum=2,
                    request_key_id="request-key-v1",
                    request_key_env="ANCHOR_REQUEST_KEY",
                )
        self.assertEqual(cm.exception.code, "CFHS_SECRET_DENIED")

    def test_valid_reference_quorum_config_builds_without_network_access(self):
        provider = self.build()
        status = reference_quorum_anchor_status(provider)
        self.assertTrue(status["authenticated_quorum_configured"])
        self.assertEqual(status["endpoint_ids"], ["anchor-a", "anchor-b"])
        self.assertEqual(status["required_quorum"], 2)
        self.assertFalse(status["reference_crypto_production_ready"])

    def test_non_https_anchor_endpoint_is_rejected(self):
        bad = [
            "anchor-a=http://anchor-a.example.test/v1/anchor",
            self.endpoints[1],
        ]
        with self.assertRaises(HardeningError) as cm:
            self.build(endpoint_specs=bad)
        self.assertEqual(cm.exception.code, "CFHS_INVALID_REQUEST")


if __name__ == "__main__":
    unittest.main()
