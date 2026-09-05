import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from kernel.hardening import HardeningError, SessionManager
from kernel.identity_hardening import OIDCIdentityBroker, OIDCProviderConfig, StaticVerifiedClaimsProvider
from kernel.remote_anchor import HTTPSAuditAnchorProvider


class FakeHTTPResponse:
    def __init__(self, body, url="https://anchor.example/v1/anchors"):
        self.body = json.dumps(body).encode("utf-8")
        self.status = 201
        self._url = url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, _n=-1):
        return self.body

    def geturl(self):
        return self._url


class IdentityAndAnchorV04Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "identity.db"
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.sessions = SessionManager(self.conn)
        self.broker = OIDCIdentityBroker(self.conn, self.sessions)
        self.config = OIDCProviderConfig("workforce-idp", "https://id.example", "company-kernel", 600)
        self.broker.map_subject(self.config, "subject-123", "human:owner")

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def _claims(self, nonce):
        return {
            "iss": "https://id.example",
            "aud": "company-kernel",
            "sub": "subject-123",
            "nonce": nonce,
            "exp": (datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp(),
        }

    def test_oidc_login_creates_kernel_session_and_consumes_nonce(self):
        login = self.broker.begin_login(self.config)
        result = self.broker.complete_login(
            self.config,
            StaticVerifiedClaimsProvider(self._claims(login["nonce"])),
            "verified-token-placeholder",
            login["nonce"],
            300,
        )
        self.assertEqual(self.sessions.authenticate(result["bearer_token"]), "human:owner")
        with self.assertRaises(HardeningError):
            self.broker.complete_login(
                self.config,
                StaticVerifiedClaimsProvider(self._claims(login["nonce"])),
                "verified-token-placeholder",
                login["nonce"],
                300,
            )

    def test_oidc_wrong_audience_does_not_consume_nonce(self):
        login = self.broker.begin_login(self.config)
        claims = self._claims(login["nonce"])
        claims["aud"] = "wrong-audience"
        with self.assertRaises(HardeningError):
            self.broker.complete_login(self.config, StaticVerifiedClaimsProvider(claims), "x", login["nonce"])
        good = self.broker.complete_login(
            self.config,
            StaticVerifiedClaimsProvider(self._claims(login["nonce"])),
            "y",
            login["nonce"],
        )
        self.assertEqual(good["principal_id"], "human:owner")

    def test_disabled_oidc_mapping_is_denied(self):
        login = self.broker.begin_login(self.config)
        self.broker.disable_subject(self.config, "subject-123")
        with self.assertRaises(HardeningError) as cm:
            self.broker.complete_login(
                self.config,
                StaticVerifiedClaimsProvider(self._claims(login["nonce"])),
                "x",
                login["nonce"],
            )
        self.assertEqual(cm.exception.code, "CFHS_POLICY_DENIED")

    @patch("urllib.request.urlopen")
    def test_remote_anchor_requires_matching_receipt(self, urlopen):
        head = "a" * 64
        urlopen.return_value = FakeHTTPResponse(
            {"receipt_id": "r-1", "audit_head_hash": head, "anchored_at": "2026-09-05T00:00:00Z"}
        )
        adapter = HTTPSAuditAnchorProvider("https://anchor.example/v1/anchors")
        result = adapter.anchor(head, {"node": "kernel-a"})
        self.assertEqual(result["receipt_id"], "r-1")
        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.full_url, "https://anchor.example/v1/anchors")

    @patch("urllib.request.urlopen")
    def test_remote_anchor_rejects_mismatched_head(self, urlopen):
        urlopen.return_value = FakeHTTPResponse({"receipt_id": "r-2", "audit_head_hash": "wrong"})
        adapter = HTTPSAuditAnchorProvider("https://anchor.example/v1/anchors")
        with self.assertRaises(HardeningError) as cm:
            adapter.anchor("b" * 64)
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")

    @patch("urllib.request.urlopen")
    def test_remote_anchor_rejects_cross_origin_redirect(self, urlopen):
        head = "c" * 64
        urlopen.return_value = FakeHTTPResponse(
            {"receipt_id": "r-3", "audit_head_hash": head},
            url="https://attacker.example/steal",
        )
        adapter = HTTPSAuditAnchorProvider("https://anchor.example/v1/anchors")
        with self.assertRaises(HardeningError):
            adapter.anchor(head)


if __name__ == "__main__":
    unittest.main()
