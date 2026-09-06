from __future__ import annotations

from typing import Any

from .hardening import HardeningError
from .remote_anchor_hardening import SQLiteSignedAnchorEndpoint
from .trust import sha256_hex


class StrictSQLiteSignedAnchorEndpoint(SQLiteSignedAnchorEndpoint):
    """Reference endpoint that independently recomputes the signed request binding."""

    RESERVED = {
        "anchor_request_id",
        "anchor_request_digest",
        "anchor_request_auth",
    }

    def anchor(self, head_hash: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        envelope = dict(metadata or {})
        request_id = str(envelope.get("anchor_request_id", ""))
        request_digest = str(envelope.get("anchor_request_digest", ""))
        if not request_id or not request_digest:
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Authenticated anchor request identity is required")
        business_metadata = {k: v for k, v in envelope.items() if k not in self.RESERVED}
        metadata_digest = sha256_hex(business_metadata)
        expected_digest = sha256_hex(
            {
                "contract": "audit-anchor-quorum/v0.7",
                "audit_head_hash": head_hash,
                "metadata_digest": metadata_digest,
            }
        )
        expected_id = "anchorq_" + expected_digest[:32]
        if request_digest != expected_digest or request_id != expected_id:
            raise HardeningError(
                "CFHS_AUDIT_ANCHOR_FAILED",
                "Anchor request digest/id does not match received head and metadata",
            )
        return super().anchor(head_hash, envelope)
