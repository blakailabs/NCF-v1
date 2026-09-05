from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request

from .hardening import HardeningError


class HTTPSVaultProvider:
    """Provider-neutral HTTPS vault adapter for kernel-space secret resolution.

    The bootstrap credential must be injected at runtime from outside the
    repository. Secret values returned by this provider are intended only for
    VaultSecretBroker/adapter boundaries and must never be logged.
    """

    def __init__(
        self,
        endpoint: str,
        bootstrap_bearer: bytes,
        timeout_seconds: float = 5.0,
        max_response_bytes: int = 65536,
    ):
        parsed = urllib.parse.urlparse(endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise HardeningError("CFHS_INVALID_REQUEST", "Vault endpoint must be a credential-free HTTPS URL")
        if parsed.query or parsed.fragment:
            raise HardeningError("CFHS_INVALID_REQUEST", "Vault endpoint may not contain query or fragment")
        if not bootstrap_bearer:
            raise HardeningError("CFHS_SECRET_DENIED", "Vault bootstrap credential is required at runtime")
        self.endpoint = endpoint.rstrip("/")
        self.origin = f"https://{parsed.hostname}" + (f":{parsed.port}" if parsed.port else "")
        self.bootstrap_bearer = bytes(bootstrap_bearer)
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes

    def resolve(self, provider_ref: str) -> bytes:
        if not provider_ref or len(provider_ref) > 2048:
            raise HardeningError("CFHS_INVALID_REQUEST", "Vault provider reference is invalid")
        encoded_ref = urllib.parse.quote(provider_ref, safe="")
        url = self.endpoint + "/resolve/" + encoded_ref
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Accept": "application/json",
                "Authorization": "Bearer " + self.bootstrap_bearer.decode("utf-8"),
                "User-Agent": "Company-Operating-System-Vault/0.4",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                final = urllib.parse.urlparse(response.geturl())
                final_origin = f"{final.scheme}://{final.hostname}" + (f":{final.port}" if final.port else "")
                if final_origin != self.origin:
                    raise HardeningError("CFHS_DEVICE_DENIED", "Vault redirect escaped configured origin")
                raw = response.read(self.max_response_bytes + 1)
                if len(raw) > self.max_response_bytes:
                    raise HardeningError("CFHS_RESOURCE_EXHAUSTED", "Vault response exceeded byte ceiling")
                payload = json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code in {401, 403, 404}:
                raise HardeningError("CFHS_SECRET_DENIED", "Vault denied or could not resolve secret reference") from e
            raise HardeningError("CFHS_DEVICE_FAILED", f"Vault returned HTTP {e.code}", {"status": e.code}) from e
        except urllib.error.URLError as e:
            raise HardeningError("CFHS_DEVICE_UNAVAILABLE", "Vault provider unavailable") from e

        if not isinstance(payload, dict) or payload.get("provider_ref") != provider_ref:
            raise HardeningError("CFHS_CONFLICT", "Vault response did not confirm requested provider reference")
        value_b64 = payload.get("value_base64")
        if not isinstance(value_b64, str):
            raise HardeningError("CFHS_DEVICE_FAILED", "Vault response omitted encoded secret value")
        try:
            return base64.b64decode(value_b64, validate=True)
        except Exception as e:
            raise HardeningError("CFHS_DEVICE_FAILED", "Vault secret value encoding is invalid") from e

    def clear_bootstrap_credential(self) -> None:
        # Best-effort reference behavior. Production implementations should use
        # protected memory/credential handles instead of long-lived Python bytes.
        self.bootstrap_bearer = b""
