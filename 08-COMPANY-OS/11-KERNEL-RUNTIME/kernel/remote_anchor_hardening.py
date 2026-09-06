from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from .hardening import HardeningError
from .trust import canonical_json, sha256_hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


REQUEST_AUTH_ALG = "HMAC-SHA256-REFERENCE"
RECEIPT_AUTH_ALG = "HMAC-SHA256-REFERENCE"


class ReconcilableAnchorEndpoint(Protocol):
    def anchor(self, head_hash: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]: ...


@dataclass(frozen=True)
class AnchorEndpointBinding:
    endpoint_id: str
    provider: ReconcilableAnchorEndpoint
    verifier: "SignedAnchorReceiptVerifier"


class AnchorRequestAuthenticator:
    """Dependency-free reference request authenticator.

    HMAC is used only to exercise the authenticated-request contract. A real
    deployment should replace this boundary with asymmetric workload identity,
    mTLS and/or HSM/KMS-backed request signing.
    """

    def __init__(self, key_id: str, key: bytes):
        if not key_id or not key:
            raise HardeningError("CFHS_INVALID_POLICY", "Anchor request authentication key is required")
        self.key_id = key_id
        self.key = bytes(key)

    def sign(self, request_id: str, request_digest: str) -> dict[str, str]:
        payload = {"request_id": request_id, "request_digest": request_digest}
        signature = hmac.new(self.key, canonical_json(payload), hashlib.sha256).hexdigest()
        return {
            "algorithm": REQUEST_AUTH_ALG,
            "key_id": self.key_id,
            "value": signature,
        }

    @staticmethod
    def verify(
        auth: dict[str, Any],
        request_id: str,
        request_digest: str,
        trusted_keys: dict[str, bytes],
    ) -> None:
        if auth.get("algorithm") != REQUEST_AUTH_ALG:
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Unsupported anchor request authentication algorithm")
        key_id = str(auth.get("key_id", ""))
        key = trusted_keys.get(key_id)
        if not key:
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Anchor request signing key is not trusted")
        expected = hmac.new(
            key,
            canonical_json({"request_id": request_id, "request_digest": request_digest}),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(str(auth.get("value", "")), expected):
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Anchor request authentication failed")


class SignedAnchorReceiptVerifier:
    """Verifies an endpoint-bound authenticated anchor receipt."""

    def __init__(self, endpoint_id: str, trusted_keys: dict[str, bytes]):
        if not endpoint_id or not trusted_keys:
            raise HardeningError("CFHS_INVALID_POLICY", "Anchor endpoint verifier requires endpoint and trusted key")
        self.endpoint_id = endpoint_id
        self.trusted_keys = dict(trusted_keys)

    @staticmethod
    def _signed_payload(receipt: dict[str, Any]) -> dict[str, Any]:
        payload = dict(receipt)
        payload.pop("signature", None)
        return payload

    def verify(
        self,
        receipt: dict[str, Any],
        request_id: str,
        request_digest: str,
        head_hash: str,
    ) -> dict[str, Any]:
        if receipt.get("endpoint_id") != self.endpoint_id:
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Anchor receipt endpoint identity mismatch")
        if receipt.get("anchor_request_id") != request_id:
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Anchor receipt request id mismatch")
        if receipt.get("anchor_request_digest") != request_digest:
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Anchor receipt request digest mismatch")
        if receipt.get("audit_head_hash") != head_hash:
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Anchor receipt audit head mismatch")
        if not receipt.get("receipt_id") or not receipt.get("anchored_at"):
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Anchor receipt is missing required identity/time fields")
        signature = receipt.get("signature") or {}
        if signature.get("algorithm") != RECEIPT_AUTH_ALG:
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Unsupported anchor receipt signature algorithm")
        key_id = str(signature.get("key_id", ""))
        key = self.trusted_keys.get(key_id)
        if not key:
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Anchor receipt signing key is not trusted")
        expected = hmac.new(key, canonical_json(self._signed_payload(receipt)), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(signature.get("value", "")), expected):
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Anchor receipt signature verification failed")
        return {
            "endpoint_id": self.endpoint_id,
            "receipt_id": receipt["receipt_id"],
            "audit_head_hash": head_hash,
            "anchor_request_id": request_id,
            "anchor_request_digest": request_digest,
            "anchored_at": receipt["anchored_at"],
            "receipt_digest": sha256_hex(receipt),
            "signing_key_id": key_id,
        }


class SQLiteSignedAnchorEndpoint:
    """Reference/test anchor endpoint with durable idempotency and signed receipts."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        endpoint_id: str,
        receipt_key_id: str,
        receipt_key: bytes,
        trusted_request_keys: dict[str, bytes],
    ):
        self.conn = conn
        self.endpoint_id = endpoint_id
        self.receipt_key_id = receipt_key_id
        self.receipt_key = bytes(receipt_key)
        self.trusted_request_keys = dict(trusted_request_keys)
        self.mode = "success"
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS signed_anchor_endpoint_receipts_v07(
                endpoint_id TEXT NOT NULL,
                anchor_request_id TEXT NOT NULL,
                anchor_request_digest TEXT NOT NULL,
                audit_head_hash TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(endpoint_id,anchor_request_id)
            )
            """
        )
        self.conn.commit()

    def _existing(self, request_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM signed_anchor_endpoint_receipts_v07 WHERE endpoint_id=? AND anchor_request_id=?",
            (self.endpoint_id, request_id),
        ).fetchone()
        return json.loads(row["receipt_json"]) if row else None

    def anchor(self, head_hash: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        metadata = dict(metadata or {})
        request_id = str(metadata.get("anchor_request_id", ""))
        request_digest = str(metadata.get("anchor_request_digest", ""))
        request_auth = metadata.get("anchor_request_auth") or {}
        if not request_id or not request_digest:
            raise HardeningError("CFHS_AUDIT_ANCHOR_FAILED", "Authenticated anchor request identity is required")
        AnchorRequestAuthenticator.verify(
            request_auth,
            request_id,
            request_digest,
            self.trusted_request_keys,
        )
        existing = self._existing(request_id)
        if existing:
            if existing.get("anchor_request_digest") != request_digest or existing.get("audit_head_hash") != head_hash:
                raise HardeningError("CFHS_IDEMPOTENCY_CONFLICT", "Anchor request id was reused with different content")
            return existing
        if self.mode == "unavailable":
            raise HardeningError("CFHS_DEVICE_UNAVAILABLE", f"Reference anchor endpoint unavailable: {self.endpoint_id}")

        effective_head = "0" * len(head_hash) if self.mode == "wrong_head" else head_hash
        receipt = {
            "receipt_id": f"{self.endpoint_id}:" + request_id,
            "endpoint_id": self.endpoint_id,
            "anchor_request_id": request_id,
            "anchor_request_digest": request_digest,
            "audit_head_hash": effective_head,
            "anchored_at": utcnow().isoformat(),
        }
        signature_value = hmac.new(
            self.receipt_key,
            canonical_json(receipt),
            hashlib.sha256,
        ).hexdigest()
        if self.mode == "bad_signature":
            signature_value = "0" * 64
        receipt["signature"] = {
            "algorithm": RECEIPT_AUTH_ALG,
            "key_id": self.receipt_key_id,
            "value": signature_value,
        }
        self.conn.execute(
            "INSERT INTO signed_anchor_endpoint_receipts_v07(endpoint_id,anchor_request_id,anchor_request_digest,audit_head_hash,receipt_json,created_at) VALUES(?,?,?,?,?,?)",
            (
                self.endpoint_id,
                request_id,
                request_digest,
                effective_head,
                json.dumps(receipt, sort_keys=True),
                utcnow().isoformat(),
            ),
        )
        self.conn.commit()
        return receipt

    def lookup_anchor(self, request_id: str) -> dict[str, Any] | None:
        return self._existing(request_id)


class QuorumAuditAnchorProvider:
    """Durable authenticated N-of-M anchor provider compatible with v0.6 consumers.

    Partial verified receipts are retained when quorum is unavailable. Repeating
    the same semantic anchor request reuses the deterministic request id and
    attempts only missing endpoints. Production deployments should replace the
    reference HMAC authenticators with asymmetric/mTLS/HSM-backed trust.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        endpoints: list[AnchorEndpointBinding],
        quorum: int,
        request_authenticator: AnchorRequestAuthenticator,
    ):
        if not endpoints:
            raise HardeningError("CFHS_INVALID_POLICY", "At least one audit anchor endpoint is required")
        endpoint_ids = [x.endpoint_id for x in endpoints]
        if len(endpoint_ids) != len(set(endpoint_ids)):
            raise HardeningError("CFHS_INVALID_POLICY", "Audit anchor endpoint ids must be unique")
        if isinstance(quorum, bool) or not isinstance(quorum, int) or quorum < 1 or quorum > len(endpoints):
            raise HardeningError("CFHS_INVALID_POLICY", "Audit anchor quorum is invalid")
        for binding in endpoints:
            if binding.verifier.endpoint_id != binding.endpoint_id:
                raise HardeningError("CFHS_INVALID_POLICY", "Anchor endpoint verifier binding mismatch")
        self.conn = conn
        self.endpoints = list(endpoints)
        self.quorum = quorum
        self.request_authenticator = request_authenticator
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS quorum_anchor_requests_v07(
                anchor_request_id TEXT PRIMARY KEY,
                anchor_request_digest TEXT NOT NULL UNIQUE,
                audit_head_hash TEXT NOT NULL,
                metadata_digest TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                required_quorum INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS quorum_anchor_receipts_v07(
                anchor_request_id TEXT NOT NULL,
                endpoint_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                receipt_digest TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                verified_at TEXT NOT NULL,
                PRIMARY KEY(anchor_request_id,endpoint_id),
                UNIQUE(endpoint_id,receipt_id)
            );
            """
        )
        self.conn.commit()

    @staticmethod
    def _request(head_hash: str, metadata: dict[str, Any]) -> tuple[str, str, str]:
        metadata_digest = sha256_hex(metadata)
        request_digest = sha256_hex(
            {
                "contract": "audit-anchor-quorum/v0.7",
                "audit_head_hash": head_hash,
                "metadata_digest": metadata_digest,
            }
        )
        return "anchorq_" + request_digest[:32], request_digest, metadata_digest

    def _ensure_request(self, head_hash: str, metadata: dict[str, Any]) -> dict[str, Any]:
        request_id, request_digest, metadata_digest = self._request(head_hash, metadata)
        existing = self.conn.execute(
            "SELECT * FROM quorum_anchor_requests_v07 WHERE anchor_request_id=?",
            (request_id,),
        ).fetchone()
        if existing:
            if (
                existing["anchor_request_digest"] != request_digest
                or existing["audit_head_hash"] != head_hash
                or existing["metadata_digest"] != metadata_digest
                or int(existing["required_quorum"]) != self.quorum
            ):
                raise HardeningError("CFHS_IDEMPOTENCY_CONFLICT", "Durable audit anchor request binding changed")
            return dict(existing)
        now = utcnow().isoformat()
        self.conn.execute(
            """
            INSERT INTO quorum_anchor_requests_v07(
                anchor_request_id,anchor_request_digest,audit_head_hash,metadata_digest,
                metadata_json,required_quorum,status,created_at,updated_at
            ) VALUES(?,?,?,?,?,?,'PENDING',?,?)
            """,
            (
                request_id,
                request_digest,
                head_hash,
                metadata_digest,
                json.dumps(metadata, sort_keys=True),
                self.quorum,
                now,
                now,
            ),
        )
        self.conn.commit()
        return dict(
            self.conn.execute(
                "SELECT * FROM quorum_anchor_requests_v07 WHERE anchor_request_id=?",
                (request_id,),
            ).fetchone()
        )

    def _verified_receipts(self, request_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM quorum_anchor_receipts_v07 WHERE anchor_request_id=? ORDER BY endpoint_id",
            (request_id,),
        ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["receipt"] = json.loads(item.pop("receipt_json"))
            out.append(item)
        return out

    @staticmethod
    def _provider_receipt(raw: dict[str, Any]) -> dict[str, Any]:
        nested = raw.get("provider_receipt")
        return dict(nested) if isinstance(nested, dict) else dict(raw)

    def _persist_verified(self, request_id: str, endpoint_id: str, verified: dict[str, Any], receipt: dict[str, Any]) -> None:
        existing = self.conn.execute(
            "SELECT * FROM quorum_anchor_receipts_v07 WHERE anchor_request_id=? AND endpoint_id=?",
            (request_id, endpoint_id),
        ).fetchone()
        if existing:
            if existing["receipt_digest"] != verified["receipt_digest"]:
                raise HardeningError("CFHS_CONFLICT", "Anchor endpoint returned conflicting receipt for same request")
            return
        self.conn.execute(
            """
            INSERT INTO quorum_anchor_receipts_v07(
                anchor_request_id,endpoint_id,receipt_id,receipt_digest,receipt_json,verified_at
            ) VALUES(?,?,?,?,?,?)
            """,
            (
                request_id,
                endpoint_id,
                verified["receipt_id"],
                verified["receipt_digest"],
                json.dumps(receipt, sort_keys=True),
                utcnow().isoformat(),
            ),
        )
        self.conn.commit()

    def _aggregate(self, request: dict[str, Any]) -> dict[str, Any]:
        receipts = self._verified_receipts(request["anchor_request_id"])
        confirmed = [x["endpoint_id"] for x in receipts]
        receipt_set_digest = sha256_hex(
            [{"endpoint_id": x["endpoint_id"], "receipt_digest": x["receipt_digest"]} for x in receipts]
        )
        return {
            "receipt_id": request["anchor_request_id"],
            "anchor_request_id": request["anchor_request_id"],
            "anchor_request_digest": request["anchor_request_digest"],
            "audit_head_hash": request["audit_head_hash"],
            "required_quorum": int(request["required_quorum"]),
            "confirmed_count": len(receipts),
            "confirmed_endpoint_ids": confirmed,
            "receipt_set_digest": receipt_set_digest,
            "anchored_at": max((x["verified_at"] for x in receipts), default=None),
            "quorum_confirmed": len(receipts) >= int(request["required_quorum"]),
            "reference_authentication": REQUEST_AUTH_ALG,
        }

    def anchor(self, head_hash: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        if not head_hash or len(head_hash) < 16:
            raise HardeningError("CFHS_INVALID_REQUEST", "Audit head hash is required")
        metadata = dict(metadata or {})
        request = self._ensure_request(head_hash, metadata)
        existing_receipts = {x["endpoint_id"] for x in self._verified_receipts(request["anchor_request_id"])}
        errors: dict[str, str] = {}
        request_auth = self.request_authenticator.sign(
            request["anchor_request_id"],
            request["anchor_request_digest"],
        )
        endpoint_metadata = {
            **metadata,
            "anchor_request_id": request["anchor_request_id"],
            "anchor_request_digest": request["anchor_request_digest"],
            "anchor_request_auth": request_auth,
        }
        for binding in self.endpoints:
            if binding.endpoint_id in existing_receipts:
                continue
            try:
                raw = binding.provider.anchor(head_hash, endpoint_metadata)
                receipt = self._provider_receipt(raw)
                verified = binding.verifier.verify(
                    receipt,
                    request["anchor_request_id"],
                    request["anchor_request_digest"],
                    head_hash,
                )
                self._persist_verified(request["anchor_request_id"], binding.endpoint_id, verified, receipt)
            except Exception as exc:
                errors[binding.endpoint_id] = str(exc)

        aggregate = self._aggregate(request)
        status = "CONFIRMED" if aggregate["quorum_confirmed"] else "PARTIAL"
        self.conn.execute(
            "UPDATE quorum_anchor_requests_v07 SET status=?,updated_at=? WHERE anchor_request_id=?",
            (status, utcnow().isoformat(), request["anchor_request_id"]),
        )
        self.conn.commit()
        if not aggregate["quorum_confirmed"]:
            raise HardeningError(
                "CFHS_AUDIT_ANCHOR_FAILED",
                "Audit anchor quorum was not reached",
                {
                    "anchor_request_id": request["anchor_request_id"],
                    "required_quorum": self.quorum,
                    "confirmed_count": aggregate["confirmed_count"],
                    "confirmed_endpoint_ids": aggregate["confirmed_endpoint_ids"],
                    "endpoint_errors": errors,
                },
            )
        return aggregate

    def request_status(self, request_id: str) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM quorum_anchor_requests_v07 WHERE anchor_request_id=?",
            (request_id,),
        ).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Audit anchor request not found")
        result = dict(row)
        result["metadata"] = json.loads(result.pop("metadata_json"))
        result["receipts"] = self._verified_receipts(request_id)
        result["aggregate"] = self._aggregate(dict(row))
        return result

    def reconcile(self, request_id: str) -> dict[str, Any]:
        state = self.request_status(request_id)
        if state["aggregate"]["quorum_confirmed"]:
            return state["aggregate"]
        request = state
        metadata = request["metadata"]
        head_hash = request["audit_head_hash"]
        request_digest = request["anchor_request_digest"]
        request_auth = self.request_authenticator.sign(request_id, request_digest)
        endpoint_metadata = {
            **metadata,
            "anchor_request_id": request_id,
            "anchor_request_digest": request_digest,
            "anchor_request_auth": request_auth,
        }
        have = {x["endpoint_id"] for x in state["receipts"]}
        for binding in self.endpoints:
            if binding.endpoint_id in have:
                continue
            try:
                lookup = getattr(binding.provider, "lookup_anchor", None)
                raw = lookup(request_id) if callable(lookup) else None
                if raw is None:
                    raw = binding.provider.anchor(head_hash, endpoint_metadata)
                receipt = self._provider_receipt(raw)
                verified = binding.verifier.verify(receipt, request_id, request_digest, head_hash)
                self._persist_verified(request_id, binding.endpoint_id, verified, receipt)
            except Exception:
                continue
        aggregate = self._aggregate(
            dict(
                self.conn.execute(
                    "SELECT * FROM quorum_anchor_requests_v07 WHERE anchor_request_id=?",
                    (request_id,),
                ).fetchone()
            )
        )
        status = "CONFIRMED" if aggregate["quorum_confirmed"] else "PARTIAL"
        self.conn.execute(
            "UPDATE quorum_anchor_requests_v07 SET status=?,updated_at=? WHERE anchor_request_id=?",
            (status, utcnow().isoformat(), request_id),
        )
        self.conn.commit()
        if not aggregate["quorum_confirmed"]:
            raise HardeningError(
                "CFHS_AUDIT_ANCHOR_FAILED",
                "Audit anchor reconciliation did not reach quorum",
                {
                    "anchor_request_id": request_id,
                    "confirmed_count": aggregate["confirmed_count"],
                    "required_quorum": self.quorum,
                },
            )
        return aggregate
