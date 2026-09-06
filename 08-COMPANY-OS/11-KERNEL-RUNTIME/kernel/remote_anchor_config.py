from __future__ import annotations

import os
import sqlite3
from typing import Any

from .hardening import HardeningError
from .remote_anchor import HTTPSAuditAnchorProvider
from .remote_anchor_hardening import (
    AnchorEndpointBinding,
    AnchorRequestAuthenticator,
    QuorumAuditAnchorProvider,
    SignedAnchorReceiptVerifier,
)


def _endpoint_spec(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise HardeningError(
            "CFHS_INVALID_POLICY",
            "Remote anchor endpoint must use ENDPOINT_ID=https://host/path",
        )
    endpoint_id, url = value.split("=", 1)
    endpoint_id = endpoint_id.strip()
    url = url.strip()
    if not endpoint_id or not url:
        raise HardeningError("CFHS_INVALID_POLICY", "Remote anchor endpoint id/url is empty")
    return endpoint_id, url


def _receipt_key_spec(value: str) -> tuple[str, str, str]:
    parts = value.split(":", 2)
    if len(parts) != 3 or not all(part.strip() for part in parts):
        raise HardeningError(
            "CFHS_INVALID_POLICY",
            "Remote anchor receipt key must use ENDPOINT_ID:KEY_ID:ENV_VAR",
        )
    return parts[0].strip(), parts[1].strip(), parts[2].strip()


def _env_bytes(name: str) -> bytes:
    value = os.environ.get(name)
    if not value:
        raise HardeningError(
            "CFHS_SECRET_DENIED",
            "Required remote-anchor runtime key environment variable is unavailable",
            {"env_name": name},
        )
    return value.encode("utf-8")


def build_reference_quorum_anchor(
    conn: sqlite3.Connection,
    *,
    endpoint_specs: list[str],
    receipt_key_specs: list[str],
    quorum: int,
    request_key_id: str,
    request_key_env: str,
) -> QuorumAuditAnchorProvider:
    """Build the v0.7 dependency-free authenticated quorum reference adapter.

    Runtime key material is read only from named environment variables. This
    reference path is deliberately not labeled production cryptography; a real
    deployment should replace HMAC with asymmetric/mTLS/HSM-backed trust.
    """

    endpoints = dict(_endpoint_spec(item) for item in endpoint_specs)
    if len(endpoints) < 2:
        raise HardeningError("CFHS_INVALID_POLICY", "Hardened remote anchoring requires at least two endpoints")
    if isinstance(quorum, bool) or not isinstance(quorum, int) or quorum < 2 or quorum > len(endpoints):
        raise HardeningError("CFHS_INVALID_POLICY", "Remote anchor quorum must be at least two and no greater than endpoint count")
    keys: dict[str, tuple[str, bytes]] = {}
    for item in receipt_key_specs:
        endpoint_id, key_id, env_name = _receipt_key_spec(item)
        if endpoint_id in keys:
            raise HardeningError("CFHS_INVALID_POLICY", "Duplicate remote anchor receipt key binding")
        keys[endpoint_id] = (key_id, _env_bytes(env_name))
    if set(keys) != set(endpoints):
        raise HardeningError(
            "CFHS_INVALID_POLICY",
            "Every remote anchor endpoint must have exactly one receipt verification key",
            {
                "endpoint_ids": sorted(endpoints),
                "receipt_key_endpoint_ids": sorted(keys),
            },
        )
    request_key_id = request_key_id.strip()
    request_key_env = request_key_env.strip()
    if not request_key_id or not request_key_env:
        raise HardeningError("CFHS_INVALID_POLICY", "Remote anchor request key id/env are required")
    request_auth = AnchorRequestAuthenticator(request_key_id, _env_bytes(request_key_env))
    bindings = []
    for endpoint_id, url in sorted(endpoints.items()):
        key_id, key = keys[endpoint_id]
        provider = HTTPSAuditAnchorProvider(url)
        verifier = SignedAnchorReceiptVerifier(endpoint_id, {key_id: key})
        bindings.append(AnchorEndpointBinding(endpoint_id, provider, verifier))
    return QuorumAuditAnchorProvider(conn, bindings, quorum, request_auth)


def reference_quorum_anchor_status(provider: Any | None) -> dict[str, Any]:
    if not isinstance(provider, QuorumAuditAnchorProvider):
        return {
            "mode": "local_reference",
            "authenticated_quorum_configured": False,
            "reference_crypto_production_ready": False,
        }
    return {
        "mode": "authenticated_quorum_reference",
        "authenticated_quorum_configured": True,
        "endpoint_ids": [binding.endpoint_id for binding in provider.endpoints],
        "required_quorum": provider.quorum,
        "request_authentication": "HMAC-SHA256-REFERENCE",
        "receipt_authentication": "HMAC-SHA256-REFERENCE",
        "reference_crypto_production_ready": False,
    }
