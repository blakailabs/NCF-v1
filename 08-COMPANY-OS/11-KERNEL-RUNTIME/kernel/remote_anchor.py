from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .hardening import HardeningError
from .trust import VaultSecretBroker


class HTTPSAuditAnchorProvider:
    """Remote append-only audit-anchor client contract.

    This adapter writes only audit checkpoints to one configured HTTPS origin. It
    is not a general-purpose HTTP client and cannot be used for business actions.
    """

    AUDIENCE = "audit-anchor"

    def __init__(
        self,
        endpoint: str,
        secret_broker: VaultSecretBroker | None = None,
        token_lease_id: str | None = None,
        timeout_seconds: float = 5.0,
        max_response_bytes: int = 65536,
    ):
        parsed = urllib.parse.urlparse(endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise HardeningError("CFHS_INVALID_REQUEST", "Audit anchor endpoint must be a credential-free HTTPS URL")
        if parsed.query or parsed.fragment:
            raise HardeningError("CFHS_INVALID_REQUEST", "Audit anchor endpoint may not contain query or fragment")
        self.endpoint = endpoint.rstrip("/")
        self.origin = f"https://{parsed.hostname}" + (f":{parsed.port}" if parsed.port else "")
        self.secret_broker = secret_broker
        self.token_lease_id = token_lease_id
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Company-Operating-System-Audit-Anchor/0.4",
        }
        if self.token_lease_id:
            if not self.secret_broker:
                raise HardeningError("CFHS_SECRET_DENIED", "Audit anchor token lease requires a secret broker")
            token = self.secret_broker.resolve_for_adapter(self.token_lease_id, self.AUDIENCE).decode("utf-8")
            headers["Authorization"] = "Bearer " + token
        return headers

    def anchor(self, head_hash: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        if not head_hash or len(head_hash) < 16:
            raise HardeningError("CFHS_INVALID_REQUEST", "Audit head hash is required")
        payload = json.dumps({"audit_head_hash": head_hash, "metadata": metadata or {}}, sort_keys=True).encode("utf-8")
        request = urllib.request.Request(self.endpoint, data=payload, method="POST", headers=self._headers())
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                final = urllib.parse.urlparse(response.geturl())
                final_origin = f"{final.scheme}://{final.hostname}" + (f":{final.port}" if final.port else "")
                if final_origin != self.origin:
                    raise HardeningError("CFHS_DEVICE_DENIED", "Audit anchor redirect escaped configured origin")
                raw = response.read(self.max_response_bytes + 1)
                if len(raw) > self.max_response_bytes:
                    raise HardeningError("CFHS_RESOURCE_EXHAUSTED", "Audit anchor response exceeded byte ceiling")
                receipt = json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise HardeningError("CFHS_DEVICE_FAILED", f"Audit anchor returned HTTP {e.code}", {"status": e.code}) from e
        except urllib.error.URLError as e:
            raise HardeningError("CFHS_DEVICE_UNAVAILABLE", "Audit anchor unavailable") from e

        if not isinstance(receipt, dict):
            raise HardeningError("CFHS_DEVICE_FAILED", "Audit anchor receipt must be an object")
        if receipt.get("audit_head_hash") != head_hash:
            raise HardeningError("CFHS_CONFLICT", "Audit anchor receipt does not confirm requested head hash")
        if not receipt.get("receipt_id"):
            raise HardeningError("CFHS_DEVICE_FAILED", "Audit anchor receipt id missing")
        return {
            "receipt_id": receipt["receipt_id"],
            "audit_head_hash": head_hash,
            "anchored_at": receipt.get("anchored_at"),
            "provider_receipt": receipt,
        }
