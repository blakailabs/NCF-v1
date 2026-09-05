import json
import unittest
from unittest.mock import patch

from kernel.providers.github_readonly import GitHubReadOnlyAdapter
from kernel.trust import MemoryVaultProvider, VaultSecretBroker


class FakeResponse:
    def __init__(self, body, status=200):
        self.body = json.dumps(body).encode("utf-8")
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, _n=-1):
        return self.body


class GitHubReadOnlyTests(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_repository_get_is_read_only(self, urlopen):
        urlopen.return_value = FakeResponse({"full_name": "blakailabs/Company-Operating-System", "private": False})
        adapter = GitHubReadOnlyAdapter()
        result = adapter.get_repository("blakailabs", "Company-Operating-System")
        self.assertEqual(result["full_name"], "blakailabs/Company-Operating-System")
        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, "https://api.github.com/repos/blakailabs/Company-Operating-System")

    @patch("urllib.request.urlopen")
    def test_optional_token_only_enters_adapter_header(self, urlopen):
        urlopen.return_value = FakeResponse([])
        broker = VaultSecretBroker(MemoryVaultProvider({"vault://github/readonly": b"test-token-value"}))
        lease = broker.lease("vault://github/readonly", "github-readonly", 30)
        adapter = GitHubReadOnlyAdapter(broker)
        result = adapter.list_branches("blakailabs", "Company-Operating-System", lease["lease_id"])
        self.assertEqual(result, [])
        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-token-value")
        self.assertNotIn("test-token-value", json.dumps(result))
        self.assertNotIn("test-token-value", json.dumps(lease))

    def test_adapter_exposes_no_write_api(self):
        adapter = GitHubReadOnlyAdapter()
        for name in ["post", "put", "patch", "delete", "create_issue", "merge", "write_file"]:
            self.assertFalse(hasattr(adapter, name), name)


if __name__ == "__main__":
    unittest.main()
