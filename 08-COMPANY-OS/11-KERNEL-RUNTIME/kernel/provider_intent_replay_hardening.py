from __future__ import annotations

from typing import Any

from .hardening import HardeningError
from .provider_execution_gate import TrustKernelV06ExecutionGate
from .runtime import RequestContext
from .server_v06 import TrustKernelV06


class TrustKernelV06ReplaySafeGate(TrustKernelV06ExecutionGate):
    """Reserves semantic replay identity before intent persistence and repairs crash gaps."""

    def __init__(self, hardened, trusted_policy_keys=None, provider_anchor=None):
        super().__init__(hardened, trusted_policy_keys or {}, provider_anchor)
        self.startup_provider_replay_recovery = self.recover_unattached_provider_replays()

    def _durable_matches(self, replay_nonce: str, intent_digest: str) -> list[str]:
        rows = self.core.store.conn.execute(
            """
            SELECT i.intent_id
              FROM action_intent_index i
              JOIN provider_intent_bindings_v06 b ON b.intent_id=i.intent_id
             WHERE i.replay_nonce=? AND i.intent_digest=? AND b.intent_digest=?
             ORDER BY i.created_at,i.intent_id
            """,
            (replay_nonce, intent_digest, intent_digest),
        ).fetchall()
        return [r["intent_id"] for r in rows]

    def recover_unattached_provider_replays(self) -> dict[str, Any]:
        rows = self.core.store.conn.execute(
            "SELECT replay_nonce,intent_digest FROM provider_replay_v06 WHERE status='RESERVED' AND intent_id IS NULL ORDER BY created_at,replay_nonce"
        ).fetchall()
        recovered: list[dict[str, Any]] = []
        pending: list[dict[str, Any]] = []
        for row in rows:
            matches = self._durable_matches(row["replay_nonce"], row["intent_digest"])
            if len(matches) > 1:
                raise HardeningError(
                    "CFHS_CONFLICT",
                    "Multiple durable provider intents match one unattached replay reservation",
                    {"replay_nonce": row["replay_nonce"], "intent_ids": matches},
                )
            if len(matches) == 1:
                attached = self.provider_replay.attach_intent(
                    row["replay_nonce"], row["intent_digest"], matches[0]
                )
                recovered.append(
                    {
                        "replay_nonce": row["replay_nonce"],
                        "intent_digest": row["intent_digest"],
                        "intent_id": matches[0],
                        "status": attached["status"],
                    }
                )
            else:
                pending.append(
                    {
                        "replay_nonce": row["replay_nonce"],
                        "intent_digest": row["intent_digest"],
                        "status": "RESERVED_NO_DURABLE_INTENT",
                    }
                )
        return {"recovered": recovered, "pending": pending, "recovered_count": len(recovered), "pending_count": len(pending)}

    def _release_unattached_if_safe(self, replay_nonce: str, intent_digest: str) -> bool:
        matches = self._durable_matches(replay_nonce, intent_digest)
        if matches:
            return False
        cur = self.core.store.conn.execute(
            "DELETE FROM provider_replay_v06 WHERE replay_nonce=? AND intent_digest=? AND intent_id IS NULL AND status='RESERVED'",
            (replay_nonce, intent_digest),
        )
        self.core.store.conn.commit()
        return cur.rowcount == 1

    def create_provider_intent(
        self,
        ctx: RequestContext,
        device_id: str,
        operation_name: str,
        arguments: dict[str, Any],
        replay_nonce: str,
        purpose: str,
        evidence_refs: list[str] | None = None,
        required_approvals: int | None = None,
    ) -> dict[str, Any]:
        probe, _profile, _policy, _units = self._probe_provider_intent(
            ctx,
            device_id,
            operation_name,
            arguments,
            replay_nonce,
            purpose,
            evidence_refs,
            required_approvals,
        )
        semantic_digest = probe.intent_digest()
        reserved = self.provider_replay.reserve(replay_nonce, semantic_digest)
        if reserved.get("intent_id"):
            return self._existing_intent_response(reserved["intent_id"], arguments)

        matches = self._durable_matches(replay_nonce, semantic_digest)
        if len(matches) > 1:
            raise HardeningError(
                "CFHS_CONFLICT",
                "Multiple durable provider intents match one replay reservation",
                {"replay_nonce": replay_nonce, "intent_ids": matches},
            )
        if len(matches) == 1:
            self.provider_replay.attach_intent(replay_nonce, semantic_digest, matches[0])
            return self._existing_intent_response(matches[0], arguments)

        try:
            # Bypass TrustKernelV06ExecutionGate.create_provider_intent because the
            # replay nonce is already safely RESERVED before persistence.
            created = TrustKernelV06.create_provider_intent(
                self,
                ctx,
                device_id,
                operation_name,
                arguments,
                replay_nonce,
                purpose,
                evidence_refs,
                required_approvals,
            )
        except Exception:
            # Ordinary caught failure with no durable intent may safely release the
            # reservation. A process crash never reaches this handler, preserving
            # the reservation for startup recovery.
            self._release_unattached_if_safe(replay_nonce, semantic_digest)
            raise

        if created["intent_digest"] != semantic_digest:
            raise HardeningError("CFHS_CONFLICT", "Provider intent semantic digest changed during durable creation")
        self.provider_replay.attach_intent(
            replay_nonce,
            semantic_digest,
            created["intent"]["intent_id"],
        )
        created["replayed_intent"] = False
        return created
