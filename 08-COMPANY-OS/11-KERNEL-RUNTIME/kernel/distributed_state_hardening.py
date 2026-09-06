from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from typing import Any

from .distributed_state import DistributedStateTransaction, SQLiteFencedStateCoordinator, utcnow
from .hardening import HardeningError


class RecoverableSQLiteFencedStateCoordinator(SQLiteFencedStateCoordinator):
    """Adds restart/retry semantics required by the provider integration layer.

    Safe PREPARE aborts retain durable history but can be re-prepared under a
    strictly newer fencing epoch. PREPARED work whose owner died can likewise
    be taken over only after the old fence is no longer active.
    """

    def _reprepare_aborted(
        self,
        existing: DistributedStateTransaction,
        *,
        owner_id: str,
        fence_ttl_seconds: int,
        exact_units: int,
        now: datetime,
    ) -> DistributedStateTransaction:
        ttl = self._positive_int(fence_ttl_seconds, "Fence TTL", 86400)
        units = self._positive_int(exact_units, "Exact units", 9_223_372_036_854_775_807)
        now_text = now.isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM distributed_state_transactions_v07 WHERE transaction_id=?",
                (existing.transaction_id,),
            ).fetchone()
            if not row or row["status"] != "ABORTED":
                raise HardeningError("CFHS_CONFLICT", "Distributed transaction is no longer safely retryable")
            business = self.conn.execute(
                "SELECT * FROM business_identity_bindings_v07 WHERE identity_digest=?",
                (row["identity_digest"],),
            ).fetchone()
            if not business or business["status"] != "BOUND":
                raise HardeningError("CFHS_CONFLICT", "Retryable transaction requires BOUND business identity")
            replay = self.conn.execute(
                "SELECT * FROM provider_replay_v06 WHERE replay_nonce=?",
                (row["replay_nonce"],),
            ).fetchone()
            if not replay or replay["intent_digest"] != row["semantic_intent_digest"] or replay["status"] not in {"PENDING", "PREPARED"}:
                raise HardeningError("CFHS_CONFLICT", "Retryable transaction requires compatible semantic replay state")
            fence = self.conn.execute(
                "SELECT * FROM fence_resources_v07 WHERE resource_key=?",
                (row["resource_key"],),
            ).fetchone()
            if fence and fence["current_token"] is not None and not self._expired(fence["expires_at"], now):
                raise HardeningError("CFHS_FENCE_BUSY", "Business resource already has an active owner")
            if not fence:
                raise HardeningError("CFHS_CONFLICT", "Fence resource disappeared before retry")
            next_token = int(fence["last_token"]) + 1
            lease_id = "flease_" + secrets.token_hex(12)
            expires_at = (now + timedelta(seconds=ttl)).isoformat()

            pool = self.conn.execute(
                "SELECT * FROM exact_resource_pools_v06 WHERE pool_id=?",
                (row["exact_pool_id"],),
            ).fetchone()
            if not pool:
                raise HardeningError("CFHS_NOT_FOUND", "Exact resource pool not found")
            available = int(pool["hard_limit_units"]) - int(pool["used_units"]) - int(pool["reserved_units"])
            if units > available:
                raise HardeningError(
                    "CFHS_RESOURCE_EXHAUSTED",
                    "Retry exact reservation exceeds available units",
                    {"requested_units": units, "available_units": available},
                )
            reservation_id = "xresv_" + secrets.token_hex(10)
            self.conn.execute(
                "UPDATE exact_resource_pools_v06 SET reserved_units=reserved_units+?,updated_at=? WHERE pool_id=?",
                (units, now_text, row["exact_pool_id"]),
            )
            self.conn.execute(
                """
                INSERT INTO exact_resource_reservations_v06(
                    reservation_id,intent_digest,pool_id,units,status,created_at,updated_at
                ) VALUES(?,?,?,?, 'RESERVED', ?, ?)
                """,
                (reservation_id, row["semantic_intent_digest"], row["exact_pool_id"], units, now_text, now_text),
            )
            self.conn.execute(
                """
                UPDATE fence_resources_v07
                   SET last_token=?,current_token=?,owner_id=?,lease_id=?,acquired_at=?,expires_at=?,updated_at=?
                 WHERE resource_key=?
                """,
                (next_token, next_token, owner_id, lease_id, now_text, expires_at, now_text, row["resource_key"]),
            )
            version = int(row["version"]) + 1
            self.conn.execute(
                """
                UPDATE distributed_state_transactions_v07
                   SET owner_id=?,lease_id=?,fence_token=?,fence_expires_at=?,exact_units=?,
                       exact_reservation_id=?,purpose='EXECUTE',status='PREPARED',version=?,details_digest=NULL,updated_at=?
                 WHERE transaction_id=?
                """,
                (owner_id, lease_id, next_token, expires_at, units, reservation_id, version, now_text, row["transaction_id"]),
            )
            self._journal(row["transaction_id"], version, next_token, owner_id, "ABORTED", "PREPARED", {"retry": True})
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self.get(existing.transaction_id)

    def prepare(self, **kwargs: Any) -> DistributedStateTransaction:
        semantic_intent_digest = kwargs.get("semantic_intent_digest")
        existing = self.find_for_intent(str(semantic_intent_digest)) if semantic_intent_digest else None
        if existing and existing.status == "ABORTED":
            immutable = {
                "replay_nonce": kwargs.get("replay_nonce"),
                "identity_digest": kwargs.get("identity_digest"),
                "provider_id": kwargs.get("provider_id"),
                "resource_key": kwargs.get("resource_key"),
                "exact_pool_id": kwargs.get("exact_pool_id"),
                "exact_units": kwargs.get("exact_units"),
            }
            for key, value in immutable.items():
                if getattr(existing, key) != value:
                    raise HardeningError("CFHS_CONFLICT", f"Retry changed distributed transaction binding: {key}")
            return self._reprepare_aborted(
                existing,
                owner_id=str(kwargs["owner_id"]),
                fence_ttl_seconds=int(kwargs["fence_ttl_seconds"]),
                exact_units=int(kwargs["exact_units"]),
                now=kwargs.get("now") or utcnow(),
            )
        return super().prepare(**kwargs)

    def takeover_prepared(
        self,
        transaction_id: str,
        new_owner_id: str,
        fence_ttl_seconds: int,
        now: datetime | None = None,
    ) -> DistributedStateTransaction:
        ttl = self._positive_int(fence_ttl_seconds, "Fence TTL", 86400)
        current_time = now or utcnow()
        now_text = current_time.isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute(
                "SELECT * FROM distributed_state_transactions_v07 WHERE transaction_id=?",
                (transaction_id,),
            ).fetchone()
            if not row or row["status"] != "PREPARED":
                raise HardeningError("CFHS_CONFLICT", "Only PREPARED work can be taken over before execution")
            fence = self.conn.execute(
                "SELECT * FROM fence_resources_v07 WHERE resource_key=?",
                (row["resource_key"],),
            ).fetchone()
            if not fence:
                raise HardeningError("CFHS_CONFLICT", "Fence resource disappeared before takeover")
            if fence["current_token"] is not None and not self._expired(fence["expires_at"], current_time):
                raise HardeningError("CFHS_FENCE_BUSY", "Existing PREPARED owner is still active")
            next_token = int(fence["last_token"]) + 1
            lease_id = "flease_" + secrets.token_hex(12)
            expires_at = (current_time + timedelta(seconds=ttl)).isoformat()
            self.conn.execute(
                """
                UPDATE fence_resources_v07
                   SET last_token=?,current_token=?,owner_id=?,lease_id=?,acquired_at=?,expires_at=?,updated_at=?
                 WHERE resource_key=?
                """,
                (next_token, next_token, new_owner_id, lease_id, now_text, expires_at, now_text, row["resource_key"]),
            )
            version = int(row["version"]) + 1
            self.conn.execute(
                """
                UPDATE distributed_state_transactions_v07
                   SET owner_id=?,lease_id=?,fence_token=?,fence_expires_at=?,version=?,updated_at=?
                 WHERE transaction_id=?
                """,
                (new_owner_id, lease_id, next_token, expires_at, version, now_text, transaction_id),
            )
            self._journal(transaction_id, version, next_token, new_owner_id, "PREPARED", "PREPARED", {"takeover": True})
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self.get(transaction_id)
