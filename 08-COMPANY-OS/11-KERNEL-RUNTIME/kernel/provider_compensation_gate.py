from __future__ import annotations

import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .action_safety import digest as action_digest
from .hardening import HardeningError
from .trust import sha256_hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ProviderCompensationIntent:
    compensation_intent_id: str
    original_intent_digest: str
    requester_id: str
    requester_process_id: str
    provider_id: str
    provider_action_id: str
    device_id: str
    operation: str
    resource: str
    side_effect_class: str
    arguments_digest: str
    required_approvals: int
    created_at: str

    def envelope(self) -> dict[str, Any]:
        return {
            "original_intent_digest": self.original_intent_digest,
            "requester_id": self.requester_id,
            "requester_process_id": self.requester_process_id,
            "provider_id": self.provider_id,
            "provider_action_id": self.provider_action_id,
            "device_id": self.device_id,
            "operation": self.operation,
            "resource": self.resource,
            "side_effect_class": self.side_effect_class,
            "arguments_digest": self.arguments_digest,
            "required_approvals": self.required_approvals,
        }

    def semantic_digest(self) -> str:
        return sha256_hex(self.envelope())


class ProviderCompensationIntentLedger:
    """Creates one immutable, separately approved compensation intent per original action."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_compensation_intents_v06(
                compensation_intent_id TEXT PRIMARY KEY,
                compensation_intent_digest TEXT NOT NULL UNIQUE,
                original_intent_digest TEXT NOT NULL,
                requester_id TEXT NOT NULL,
                requester_process_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                provider_action_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                resource TEXT NOT NULL,
                side_effect_class TEXT NOT NULL,
                arguments_digest TEXT NOT NULL,
                required_approvals INTEGER NOT NULL,
                approval_request_id TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(original_intent_digest,status) WHERE status IN ('PENDING','APPROVED')
            )
            """
        )
        self.conn.commit()

    def create(
        self,
        original_intent_digest: str,
        requester_id: str,
        requester_process_id: str,
        provider_id: str,
        provider_action_id: str,
        device_id: str,
        operation: str,
        resource: str,
        side_effect_class: str,
        arguments: dict[str, Any],
        required_approvals: int,
    ) -> dict[str, Any]:
        if required_approvals < 1:
            raise HardeningError("CFHS_INVALID_POLICY", "Consequential compensation requires at least one approval")
        intent = ProviderCompensationIntent(
            compensation_intent_id="compintent_" + secrets.token_hex(10),
            original_intent_digest=original_intent_digest,
            requester_id=requester_id,
            requester_process_id=requester_process_id,
            provider_id=provider_id,
            provider_action_id=provider_action_id,
            device_id=device_id,
            operation=operation,
            resource=resource,
            side_effect_class=side_effect_class,
            arguments_digest=action_digest(arguments),
            required_approvals=int(required_approvals),
            created_at=utcnow().isoformat(),
        )
        semantic = intent.semantic_digest()
        existing = self.conn.execute(
            "SELECT * FROM provider_compensation_intents_v06 WHERE original_intent_digest=? AND status IN ('PENDING','APPROVED')",
            (original_intent_digest,),
        ).fetchone()
        if existing:
            if existing["compensation_intent_digest"] != semantic:
                raise HardeningError("CFHS_CONFLICT", "A different active compensation intent already exists")
            return dict(existing)
        self.conn.execute(
            """
            INSERT INTO provider_compensation_intents_v06(
                compensation_intent_id,compensation_intent_digest,original_intent_digest,requester_id,
                requester_process_id,provider_id,provider_action_id,device_id,operation,resource,
                side_effect_class,arguments_digest,required_approvals,status,created_at,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'PENDING',?,?)
            """,
            (
                intent.compensation_intent_id,
                semantic,
                original_intent_digest,
                requester_id,
                requester_process_id,
                provider_id,
                provider_action_id,
                device_id,
                operation,
                resource,
                side_effect_class,
                intent.arguments_digest,
                intent.required_approvals,
                intent.created_at,
                intent.created_at,
            ),
        )
        self.conn.commit()
        return self.get(intent.compensation_intent_id)

    def attach_approval(self, compensation_intent_id: str, request_id: str) -> dict[str, Any]:
        row = self.get(compensation_intent_id)
        if row["status"] not in {"PENDING", "APPROVED"}:
            raise HardeningError("CFHS_CONFLICT", "Compensation intent cannot accept an approval request")
        if row["approval_request_id"] and row["approval_request_id"] != request_id:
            raise HardeningError("CFHS_CONFLICT", "Compensation intent is already bound to another approval request")
        self.conn.execute(
            "UPDATE provider_compensation_intents_v06 SET approval_request_id=?,updated_at=? WHERE compensation_intent_id=?",
            (request_id, utcnow().isoformat(), compensation_intent_id),
        )
        self.conn.commit()
        return self.get(compensation_intent_id)

    def mark(self, compensation_intent_id: str, status: str) -> dict[str, Any]:
        if status not in {"PENDING", "APPROVED", "COMPENSATED", "FAILED"}:
            raise HardeningError("CFHS_INVALID_REQUEST", "Unsupported compensation intent state")
        self.conn.execute(
            "UPDATE provider_compensation_intents_v06 SET status=?,updated_at=? WHERE compensation_intent_id=?",
            (status, utcnow().isoformat(), compensation_intent_id),
        )
        self.conn.commit()
        return self.get(compensation_intent_id)

    def get(self, compensation_intent_id: str) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM provider_compensation_intents_v06 WHERE compensation_intent_id=?",
            (compensation_intent_id,),
        ).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Provider compensation intent not found")
        return dict(row)

    def require_arguments(self, compensation_intent_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
        row = self.get(compensation_intent_id)
        if row["arguments_digest"] != action_digest(arguments):
            raise HardeningError("CFHS_CONFLICT", "Compensation arguments differ from approved compensation intent")
        return row
