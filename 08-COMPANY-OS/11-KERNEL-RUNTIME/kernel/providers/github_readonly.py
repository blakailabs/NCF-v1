from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from ..hardening import HardeningError
from ..trust import VaultSecretBroker


class GitHubReadOnlyAdapter:
    """Strictly read-only GitHub API adapter.

    The adapter exposes only GET operations. An optional token can be supplied only
    through an audience-bound VaultSecretBroker lease; the token is never returned
    in results or logs.
    """

    API_ORIGIN = "https://api.github.com"
    AUDIENCE = "github-readonly"

    def __init__(self, secret_broker: VaultSecretBroker | None = None, max_bytes: int = 1_048_576, timeout_seconds: float = 5.0):
        self.secret_broker = secret_broker
        self.max_bytes = max_bytes
        self.timeout_seconds = timeout_seconds

    def _headers(self, lease_id: str | None = None) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "Company-Operating-System-GitHub-ReadOnly/0.3",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if lease_id:
            if not self.secret_broker:
                raise HardeningError("CFHS_SECRET_DENIED", "No secret broker configured for authenticated GitHub access")
            token = self.secret_broker.resolve_for_adapter(lease_id, self.AUDIENCE).decode("utf-8")
            headers["Authorization"] = "Bearer " + token
        return headers

    def _get(self, path: str, lease_id: str | None = None) -> Any:
        if not path.startswith("/") or ".." in path:
            raise HardeningError("CFHS_INVALID_REQUEST", "Invalid GitHub API path")
        url = self.API_ORIGIN + path
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or parsed.netloc != "api.github.com":
            raise HardeningError("CFHS_DEVICE_DENIED", "GitHub adapter is pinned to api.github.com")
        request = urllib.request.Request(url, method="GET", headers=self._headers(lease_id))
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read(self.max_bytes + 1)
                if len(raw) > self.max_bytes:
                    raise HardeningError("CFHS_RESOURCE_EXHAUSTED", "GitHub response exceeded byte ceiling")
                return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise HardeningError("CFHS_DEVICE_FAILED", f"GitHub returned HTTP {e.code}", {"status": e.code}) from e
        except urllib.error.URLError as e:
            raise HardeningError("CFHS_DEVICE_UNAVAILABLE", "GitHub API unavailable") from e

    def get_repository(self, owner: str, repo: str, lease_id: str | None = None) -> dict[str, Any]:
        owner_q = urllib.parse.quote(owner, safe="")
        repo_q = urllib.parse.quote(repo, safe="")
        result = self._get(f"/repos/{owner_q}/{repo_q}", lease_id)
        if not isinstance(result, dict):
            raise HardeningError("CFHS_DEVICE_FAILED", "Unexpected GitHub repository response")
        return result

    def list_branches(self, owner: str, repo: str, lease_id: str | None = None) -> list[dict[str, Any]]:
        owner_q = urllib.parse.quote(owner, safe="")
        repo_q = urllib.parse.quote(repo, safe="")
        result = self._get(f"/repos/{owner_q}/{repo_q}/branches?per_page=100", lease_id)
        if not isinstance(result, list):
            raise HardeningError("CFHS_DEVICE_FAILED", "Unexpected GitHub branches response")
        return result

    def get_contents(self, owner: str, repo: str, path: str, ref: str | None = None, lease_id: str | None = None) -> Any:
        owner_q = urllib.parse.quote(owner, safe="")
        repo_q = urllib.parse.quote(repo, safe="")
        clean = path.lstrip("/")
        if ".." in clean.split("/"):
            raise HardeningError("CFHS_INVALID_REQUEST", "Invalid repository content path")
        path_q = "/".join(urllib.parse.quote(part, safe="") for part in clean.split("/") if part)
        api_path = f"/repos/{owner_q}/{repo_q}/contents/{path_q}"
        if ref:
            api_path += "?ref=" + urllib.parse.quote(ref, safe="")
        return self._get(api_path, lease_id)

    # Deliberately no POST, PUT, PATCH, DELETE, merge, issue-create, or file-write methods.
