from __future__ import annotations

import json
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Any

from .action_safety import digest as action_digest
from .distributed_safety import (
    BusinessIdentityContract,
    BusinessIdentityLedger,
    BusinessObjectIdentity,
    DistributedActionGuard,
    DistributedActionPermit,
    FenceLease,
    ProviderFenceGuard,
    SQLiteFenceStore,
)
from .hardening import HardeningError
from .provider_release_gate import TrustKernelV06ReleaseGate
from .runtime import RequestContext


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DistributedProviderPermitLedger:
    """Durable history of provider execution/reconciliation fence epochs."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS distributed_provider_permits_v07(
                permit_id TEXT PRIMARY KEY,
                intent_digest TEXT NOT NULL,
                identity_digest TEXT NOT NULL,
                contract_id TEXT NOT NULL,
                contract_version INTEGER NOT NULL,
                operation TEXT NOT NULL,
                component_digest TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                resource_key TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                lease_id TEXT NOT NULL,
                fence_token INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                purpose TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(intent_digest,fence_token)
            )
            """
        )
        self.conn.commit()

    @staticmethod
    def _permit(row: sqlite3.Row) -> DistributedActionPermit:
        identity = BusinessObjectIdentity(
            contract_id=row["contract_id"],
            contract_version=int(row["contract_version"]),
            operation=row["operation"],
            identity_digest=row["identity_digest"],
            component_digest=row["component_digest"],
        )
        lease = FenceLease(
            resource_key=row["resource_key"],
            owner_id=row["owner_id"],
            lease_id=row["lease_id"],
            fence_token=int(row["fence_token"]),
            expires_at=row["expires_at"],
        )
        return DistributedActionPermit(identity, row["intent_digest"], row["provider_id"], lease)

    def record(self, permit: DistributedActionPermit, purpose: str) -> dict[str, Any]:
        if purpose not in {"EXECUTE", "RECONCILE"}:
            raise HardeningError("CFHS_INVALID_REQUEST", "Unsupported distributed permit purpose")
        now = utcnow().isoformat()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            self.conn.execute(
                "UPDATE distributed_provider_permits_v07 SET status='STALE',updated_at=? WHERE intent_digest=? AND status='ACTIVE'",
                (now, permit.semantic_intent_digest),
            )
            self.conn.execute(
                """
                INSERT INTO distributed_provider_permits_v07(
                    permit_id,intent_digest,identity_digest,contract_id,contract_version,operation,
                    component_digest,provider_id,resource_key,owner_id,lease_id,fence_token,
                    expires_at,purpose,status,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'ACTIVE',?,?)
                """,
                (
                    "dpermit_" + secrets.token_hex(10),
                    permit.semantic_intent_digest,
                    permit.identity.identity_digest,
                    permit.identity.contract_id,
                    permit.identity.contract_version,
                    permit.identity.operation,
                    permit.identity.component_digest,
                    permit.provider_id,
                    permit.lease.resource_key,
                    permit.lease.owner_id,
                    permit.lease.lease_id,
                    permit.lease.fence_token,
                    permit.lease.expires_at,
                    purpose,
                    now,
                    now,
                ),
            )
            self.conn.commit()
        except sqlite3.IntegrityError as exc:
            self.conn.rollback()
            existing = self.conn.execute(
                "SELECT * FROM distributed_provider_permits_v07 WHERE intent_digest=? AND fence_token=?",
                (permit.semantic_intent_digest, permit.lease.fence_token),
            ).fetchone()
            if existing and (
                existing["identity_digest"] == permit.identity.identity_digest
                and existing["owner_id"] == permit.lease.owner_id
                and existing["lease_id"] == permit.lease.lease_id
                and existing["purpose"] == purpose
            ):
                return dict(existing)
            raise HardeningError("CFHS_CONFLICT", "Distributed permit epoch already has another binding") from exc
        return self.latest(permit.semantic_intent_digest)

    def latest(self, intent_digest: str) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM distributed_provider_permits_v07 WHERE intent_digest=? ORDER BY fence_token DESC LIMIT 1",
            (intent_digest,),
        ).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Distributed provider permit not found")
        return dict(row)

    def latest_active(self, intent_digest: str) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM distributed_provider_permits_v07 WHERE intent_digest=? AND status='ACTIVE' ORDER BY fence_token DESC LIMIT 1",
            (intent_digest,),
        ).fetchone()
        if not row:
            raise HardeningError("CFHS_DISTRIBUTED_PERMIT_REQUIRED", "No active distributed provider permit exists")
        return dict(row)

    def load_active(self, intent_digest: str) -> DistributedActionPermit:
        row = self.conn.execute(
            "SELECT * FROM distributed_provider_permits_v07 WHERE intent_digest=? AND status='ACTIVE' ORDER BY fence_token DESC LIMIT 1",
            (intent_digest,),
        ).fetchone()
        if not row:
            raise HardeningError("CFHS_DISTRIBUTED_PERMIT_REQUIRED", "No active distributed provider permit exists")
        return self._permit(row)

    def mark(self, intent_digest: str, fence_token: int, status: str) -> dict[str, Any]:
        if status not in {"ACTIVE", "RELEASED", "STALE"}:
            raise HardeningError("CFHS_INVALID_REQUEST", "Unsupported distributed permit state")
        self.conn.execute(
            "UPDATE distributed_provider_permits_v07 SET status=?,updated_at=? WHERE intent_digest=? AND fence_token=?",
            (status, utcnow().isoformat(), intent_digest, fence_token),
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT * FROM distributed_provider_permits_v07 WHERE intent_digest=? AND fence_token=?",
            (intent_digest, fence_token),
        ).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Distributed provider permit history row not found")
        return dict(row)

    def history(self, intent_digest: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM distributed_provider_permits_v07 WHERE intent_digest=? ORDER BY fence_token",
            (intent_digest,),
        ).fetchall()
        return [dict(row) for row in rows]


class TrustKernelV07DistributedProviderGate(TrustKernelV06ReleaseGate):
    """v0.7 gate requiring current business identity + fencing for provider side effects."""

    def __init__(
        self,
        hardened,
        trusted_policy_keys=None,
        provider_anchor=None,
        kernel_instance_id: str = "kernel:reference-v07",
    ):
        if not kernel_instance_id:
            raise HardeningError("CFHS_INVALID_REQUEST", "Distributed kernel instance id is required")
        super().__init__(hardened, trusted_policy_keys or {}, provider_anchor)
        conn = self.core.store.conn
        self.kernel_instance_id = kernel_instance_id
        self.business_identities = BusinessIdentityLedger(conn)
        self.distributed_fences = SQLiteFenceStore(conn)
        self.provider_fence_guard = ProviderFenceGuard(conn)
        self.distributed_guard = DistributedActionGuard(self.business_identities, self.distributed_fences)
        self.distributed_permits = DistributedProviderPermitLedger(conn)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_business_identity_v07(
                intent_id TEXT PRIMARY KEY,
                intent_digest TEXT NOT NULL UNIQUE,
                identity_digest TEXT NOT NULL,
                contract_id TEXT NOT NULL,
                contract_version INTEGER NOT NULL,
                operation TEXT NOT NULL,
                component_digest TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                resource_key TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()

    @staticmethod
    def _distributed_profile(profile: dict[str, Any], operation_name: str) -> tuple[BusinessIdentityContract, int]:
        distributed = profile.get("distributed_safety")
        if not isinstance(distributed, dict):
            raise HardeningError("CFHS_INVALID_POLICY", "v0.7 provider operation lacks distributed-safety policy")
        identity = distributed.get("business_identity")
        if not isinstance(identity, dict):
            raise HardeningError("CFHS_INVALID_POLICY", "v0.7 provider operation lacks business-identity contract")
        fields = identity.get("fields")
        if not isinstance(fields, list) or not fields or not all(isinstance(x, str) and x for x in fields):
            raise HardeningError("CFHS_INVALID_POLICY", "Business-identity contract fields must be a non-empty string list")
        contract = BusinessIdentityContract(
            contract_id=str(identity.get("contract_id", "")),
            contract_version=int(identity.get("contract_version", 0)),
            operation=operation_name,
            fields=tuple(fields),
        )
        ttl = distributed.get("fence_ttl_seconds", 30)
        if isinstance(ttl, bool) or not isinstance(ttl, int):
            raise HardeningError("CFHS_INVALID_POLICY", "Distributed fence TTL must be an integer")
        SQLiteFenceStore._ttl(ttl)
        return contract, ttl

    def _business_row(self, intent_id: str) -> dict[str, Any]:
        row = self.core.store.one("SELECT * FROM provider_business_identity_v07 WHERE intent_id=?", (intent_id,))
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Provider business-identity binding not found")
        return dict(row)

    def _attach_business_mapping(
        self,
        intent_id: str,
        intent_digest: str,
        identity: BusinessObjectIdentity,
        provider_id: str,
    ) -> dict[str, Any]:
        now = utcnow().isoformat()
        existing = self.core.store.one("SELECT * FROM provider_business_identity_v07 WHERE intent_id=?", (intent_id,))
        if existing:
            result = dict(existing)
            expected = {
                "intent_digest": intent_digest,
                "identity_digest": identity.identity_digest,
                "contract_id": identity.contract_id,
                "contract_version": identity.contract_version,
                "operation": identity.operation,
                "component_digest": identity.component_digest,
                "provider_id": provider_id,
                "resource_key": identity.resource_key(),
            }
            for key, value in expected.items():
                if result[key] != value:
                    raise HardeningError("CFHS_BUSINESS_IDENTITY_CONFLICT", "Durable provider business identity changed after creation")
            return result
        try:
            self.core.store.conn.execute(
                """
                INSERT INTO provider_business_identity_v07(
                    intent_id,intent_digest,identity_digest,contract_id,contract_version,operation,
                    component_digest,provider_id,resource_key,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    intent_id,
                    intent_digest,
                    identity.identity_digest,
                    identity.contract_id,
                    identity.contract_version,
                    identity.operation,
                    identity.component_digest,
                    provider_id,
                    identity.resource_key(),
                    now,
                ),
            )
            self.core.store.conn.commit()
        except sqlite3.IntegrityError as exc:
            self.core.store.conn.rollback()
            raise HardeningError("CFHS_BUSINESS_IDENTITY_CONFLICT", "Provider intent is already bound to another business identity") from exc
        return self._business_row(intent_id)

    def _release_new_identity_if_safe(self, identity_digest: str, semantic_digest: str, was_new: bool) -> None:
        if not was_new:
            return
        durable = self.core.store.one("SELECT 1 FROM action_intent_index WHERE intent_digest=?", (semantic_digest,))
        if durable:
            return
        self.core.store.conn.execute(
            "DELETE FROM business_identity_bindings_v07 WHERE identity_digest=? AND semantic_intent_digest=? AND status='BOUND'",
            (identity_digest, semantic_digest),
        )
        self.core.store.conn.commit()

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
        decision = self.authorize(ctx, "kernel.action.intent.create", "/run/actions/intents", {})
        if decision.get("decision") != "ALLOW":
            raise HardeningError("CFHS_POLICY_DENIED", "Provider-intent creation denied", decision)
        probe, profile, _exact_policy, _exact_units = self._probe_provider_intent(
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
        contract, _ttl = self._distributed_profile(profile, operation_name)
        identity = contract.derive(arguments)
        prior = self.core.store.one(
            "SELECT * FROM business_identity_bindings_v07 WHERE identity_digest=?",
            (identity.identity_digest,),
        )
        self.business_identities.bind(identity, profile["provider_id"], semantic_digest)
        try:
            created = super().create_provider_intent(
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
            self._release_new_identity_if_safe(identity.identity_digest, semantic_digest, prior is None)
            raise
        self._attach_business_mapping(
            created["intent"]["intent_id"],
            created["intent_digest"],
            identity,
            profile["provider_id"],
        )
        result = dict(created)
        result["business_identity"] = {
            "identity_digest": identity.identity_digest,
            "contract_id": identity.contract_id,
            "contract_version": identity.contract_version,
            "operation": identity.operation,
            "resource_key": identity.resource_key(),
        }
        return result

    def _ensure_business_binding(self, intent_id: str, arguments: dict[str, Any]) -> tuple[dict[str, Any], BusinessObjectIdentity, int]:
        intent, binding, _operation, profile = self._bound_provider_context(intent_id)
        if action_digest(arguments) != intent.arguments_digest:
            raise HardeningError("CFHS_CONFLICT", "Provider action arguments differ from the immutable semantic intent")
        contract, ttl = self._distributed_profile(profile, intent.action)
        identity = contract.derive(arguments)
        self.business_identities.bind(identity, binding["provider_id"], intent.intent_digest())
        row = self._attach_business_mapping(intent_id, intent.intent_digest(), identity, binding["provider_id"])
        return row, identity, ttl

    def _acquire_permit(
        self,
        intent_id: str,
        arguments: dict[str, Any],
        purpose: str,
        owner_id: str,
    ) -> DistributedActionPermit:
        intent = self._load_intent(intent_id)
        row, identity, ttl = self._ensure_business_binding(intent_id, arguments)
        try:
            active = self.distributed_permits.load_active(intent.intent_digest())
        except HardeningError as exc:
            if exc.code != "CFHS_DISTRIBUTED_PERMIT_REQUIRED":
                raise
            active = None
        if active and active.lease.owner_id == owner_id and active.identity.identity_digest == identity.identity_digest:
            try:
                self.distributed_guard.assert_current(active)
                return active
            except HardeningError as exc:
                if exc.code != "CFHS_STALE_FENCE":
                    raise
                self.distributed_permits.mark(intent.intent_digest(), active.lease.fence_token, "STALE")
        permit = self.distributed_guard.prepare(
            BusinessIdentityContract(identity.contract_id, identity.contract_version, identity.operation, self._distributed_profile(self._bound_provider_context(intent_id)[3], identity.operation)[0].fields),
            arguments,
            intent.intent_digest(),
            row["provider_id"],
            owner_id,
            ttl,
        )
        self.distributed_permits.record(permit, purpose)
        return permit

    def _release_permit(self, permit: DistributedActionPermit) -> None:
        try:
            self.distributed_fences.release(permit.lease)
            self.distributed_permits.mark(permit.semantic_intent_digest, permit.lease.fence_token, "RELEASED")
        except HardeningError as exc:
            if exc.code != "CFHS_STALE_FENCE":
                raise
            self.distributed_permits.mark(permit.semantic_intent_digest, permit.lease.fence_token, "STALE")

    def _require_execution_permit(self, intent_id: str, arguments: dict[str, Any]) -> DistributedActionPermit:
        intent = self._load_intent(intent_id)
        self._ensure_business_binding(intent_id, arguments)
        permit = self.distributed_permits.load_active(intent.intent_digest())
        if permit.lease.owner_id != self.kernel_instance_id:
            raise HardeningError(
                "CFHS_STALE_FENCE",
                "Provider execution permit belongs to another kernel instance",
                {"owner_id": permit.lease.owner_id, "kernel_instance_id": self.kernel_instance_id},
            )
        self.distributed_guard.assert_current(permit)
        return permit

    def prepare_provider_action(
        self,
        ctx: RequestContext,
        intent_id: str,
        arguments: dict[str, Any],
        approval_request_id: str | None = None,
    ) -> dict[str, Any]:
        intent = self._load_intent(intent_id)
        replay = self.provider_replay.require_intent(intent.replay_nonce, intent.intent_digest())
        if replay["status"] == "COMMITTED":
            return super().prepare_provider_action(ctx, intent_id, arguments, approval_request_id)
        if replay["status"] == "RECONCILIATION_REQUIRED":
            raise HardeningError("CFHS_UNKNOWN_SIDE_EFFECT", "Reconciliation is required before provider preparation")
        permit = self._acquire_permit(intent_id, arguments, "EXECUTE", self.kernel_instance_id)
        try:
            prepared = super().prepare_provider_action(ctx, intent_id, arguments, approval_request_id)
        except Exception:
            self._release_permit(permit)
            raise
        self.hardened._chain(
            ctx,
            "provider.distributed.prepared.v07",
            {
                "intent_id": intent_id,
                "intent_digest": intent.intent_digest(),
                "identity_digest": permit.identity.identity_digest,
                "kernel_instance_id": self.kernel_instance_id,
                "fence_token": permit.lease.fence_token,
                "fence_expires_at": permit.lease.expires_at,
                "provider_id": permit.provider_id,
            },
        )
        result = dict(prepared)
        result["distributed_permit"] = permit.envelope()
        return result

    def execute_provider_action(
        self,
        ctx: RequestContext,
        intent_id: str,
        arguments: dict[str, Any],
        approval_request_id: str | None = None,
        sandbox_mode: str = "success",
    ) -> dict[str, Any]:
        intent = self._load_intent(intent_id)
        replay = self.provider_replay.require_intent(intent.replay_nonce, intent.intent_digest())
        if replay["status"] == "COMMITTED":
            result = super().execute_provider_action(ctx, intent_id, arguments, approval_request_id, sandbox_mode)
            result["distributed_replay"] = True
            return result
        if replay["status"] != "PREPARED":
            raise HardeningError("CFHS_CONFLICT", f"Distributed provider action cannot execute from replay state {replay['status']}")
        authorization = self.provider_authorizations.get(intent.intent_digest())
        if authorization.get("approval_request_id") != approval_request_id:
            raise HardeningError("CFHS_ELEVATION_REQUIRED", "Execution approval request differs from prepared release evidence")
        permit = self._require_execution_permit(intent_id, arguments)
        self.provider_fence_guard.accept(permit.provider_id, permit.lease.resource_key, permit.lease.fence_token)
        identity_state = self.business_identities.get(permit.identity.identity_digest)
        if identity_state["status"] == "BOUND":
            self.distributed_guard.transition(permit, "EXECUTING")
        elif identity_state["status"] != "EXECUTING":
            raise HardeningError("CFHS_CONFLICT", f"Business action cannot execute from {identity_state['status']}")
        self.hardened._chain(
            ctx,
            "provider.distributed.fence.accepted.v07",
            {
                "intent_id": intent_id,
                "identity_digest": permit.identity.identity_digest,
                "provider_id": permit.provider_id,
                "kernel_instance_id": self.kernel_instance_id,
                "fence_token": permit.lease.fence_token,
            },
        )
        result = super().execute_provider_action(ctx, intent_id, arguments, approval_request_id, sandbox_mode)
        status = result["status"]
        if status in {"COMMITTED", "REPLAYED"}:
            self.distributed_guard.transition(permit, "COMMITTED")
            self._release_permit(permit)
        elif status == "FAILED_NOT_EXECUTED":
            self.distributed_guard.transition(permit, "FAILED_NOT_EXECUTED")
            self._release_permit(permit)
        elif status == "RECONCILIATION_REQUIRED":
            self.distributed_guard.transition(permit, "RECONCILIATION_REQUIRED")
            self._release_permit(permit)
        result["distributed_permit"] = permit.envelope()
        return result

    def reconcile_provider_action(self, ctx: RequestContext, intent_id: str) -> dict[str, Any]:
        intent = self._load_intent(intent_id)
        replay = self.provider_replay.require_intent(intent.replay_nonce, intent.intent_digest())
        if replay["status"] != "RECONCILIATION_REQUIRED":
            raise HardeningError("CFHS_CONFLICT", "Provider replay state does not require reconciliation")
        business = self._business_row(intent_id)
        identity_state = self.business_identities.get(business["identity_digest"])
        if identity_state["status"] != "RECONCILIATION_REQUIRED":
            raise HardeningError("CFHS_CONFLICT", "Business-object state does not require reconciliation")
        provider_state = self.provider_actions.state(intent.intent_digest())
        stored_arguments = json.loads(self.core.store.one("SELECT envelope_json FROM action_intent_index WHERE intent_id=?", (intent_id,))["envelope_json"])
        del stored_arguments  # action intents intentionally do not persist raw provider arguments
        profile = self._bound_provider_context(intent_id)[3]
        _contract, ttl = self._distributed_profile(profile, intent.action)
        identity = BusinessObjectIdentity(
            contract_id=business["contract_id"],
            contract_version=int(business["contract_version"]),
            operation=business["operation"],
            identity_digest=business["identity_digest"],
            component_digest=business["component_digest"],
        )
        lease = self.distributed_fences.acquire(
            business["resource_key"],
            f"{self.kernel_instance_id}:reconcile",
            ttl,
        )
        permit = DistributedActionPermit(identity, intent.intent_digest(), business["provider_id"], lease)
        self.distributed_permits.record(permit, "RECONCILE")
        try:
            self.provider_fence_guard.accept(permit.provider_id, permit.lease.resource_key, permit.lease.fence_token)
            self.hardened._chain(
                ctx,
                "provider.distributed.reconciliation.fence.v07",
                {
                    "intent_id": intent_id,
                    "identity_digest": permit.identity.identity_digest,
                    "provider_id": permit.provider_id,
                    "kernel_instance_id": self.kernel_instance_id,
                    "fence_token": permit.lease.fence_token,
                    "reconciliation_case_id": provider_state.get("reconciliation_case_id"),
                },
            )
            result = super().reconcile_provider_action(ctx, intent_id)
            if result["status"] == "COMMITTED_RECONCILED":
                self.distributed_guard.transition(permit, "COMMITTED")
            elif result["status"] == "FAILED_NOT_EXECUTED_RECONCILED":
                self.distributed_guard.transition(permit, "FAILED_NOT_EXECUTED")
            elif result["status"] == "COMPENSATED_RECONCILED":
                self.distributed_guard.transition(permit, "COMPENSATED")
            result["distributed_reconciliation_permit"] = permit.envelope()
            return result
        finally:
            self._release_permit(permit)

    def request_provider_compensation_approval(self, *args, **kwargs):
        raise HardeningError(
            "CFHS_DISTRIBUTED_SAFETY_REQUIRED",
            "v0.7 blocks provider compensation until compensation fencing/reconciliation is integrated",
        )

    def compensate_provider_action(self, *args, **kwargs):
        raise HardeningError(
            "CFHS_DISTRIBUTED_SAFETY_REQUIRED",
            "v0.7 blocks provider compensation until compensation fencing/reconciliation is integrated",
        )

    def provider_action_status(self, ctx: RequestContext, intent_id: str) -> dict[str, Any]:
        result = super().provider_action_status(ctx, intent_id)
        try:
            business = self._business_row(intent_id)
            result["business_identity"] = {
                **business,
                "state": self.business_identities.get(business["identity_digest"]),
            }
            result["distributed_permit_history"] = self.distributed_permits.history(business["intent_digest"])
        except HardeningError:
            result["business_identity"] = None
            result["distributed_permit_history"] = []
        return result
