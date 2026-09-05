import base64
import json
import unittest
from unittest.mock import patch

from kernel.hardening import HardeningError
from kernel.vault_providers import HTTPSVaultProvider


class FakeVaultResponse:
    def __init__(self, payload, url="https://vault.example/v1/resolve/vault%3A%2F%2Fteam%2Fkey"):
        self.payload = json.dumps(payload).encode("utf-8")
        self._url = url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, _n=-1):
        return self.payload

    def geturl(self):
        return self._url


class HTTPSVaultProviderTests(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_resolves_secret_without_returning_bootstrap_credential(self, urlopen):
        secret = b"test-secret-value"
        urlopen.return_value = FakeVaultResponse(
            {"provider_ref": "vault://team/key", "value_base64": base64.b64encode(secret).decode("ascii")}
        )
        provider = HTTPSVaultProvider("https://vault.example/v1", b"runtime-bootstrap-token")
        value = provider.resolve("vault://team/key")
        self.assertEqual(value, secret)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.get_header("Authorization"), "Bearer runtime-bootstrap-token")
        self.assertNotIn("runtime-bootstrap-token", value.decode("utf-8"))

    @patch("urllib.request.urlopen")
    def test_rejects_reference_mismatch(self, urlopen):
        urlopen.return_value = FakeVaultResponse(
            {"provider_ref": "vault://other/key", "value_base64": base64.b64encode(b"x").decode("ascii")}
        )
        provider = HTTPSVaultProvider("https://vault.example/v1", b"runtime-bootstrap-token")
        with self.assertRaises(HardeningError) as cm:
            provider.resolve("vault://team/key")
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")

    @patch("urllib.request.urlopen")
    def test_rejects_cross_origin_redirect(self, urlopen):
        urlopen.return_value = FakeVaultResponse(
            {"provider_ref": "vault://team/key", "value_base64": base64.b64encode(b"x").decode("ascii")},
            url="https://attacker.example/steal",
        )
        provider = HTTPSVaultProvider("https://vault.example/v1", b"runtime-bootstrap-token")
        with self.assertRaises(HardeningError):
            provider.resolve("vault://team/key")

    def test_bootstrap_credential_can_be_cleared(self):
        provider = HTTPSVaultProvider("https://vault.example/v1", b"runtime-bootstrap-token")
        provider.clear_bootstrap_credential()
        self.assertEqual(provider.bootstrap_bearer, b"")


if __name__ == "__main__":
    unittest.main()
