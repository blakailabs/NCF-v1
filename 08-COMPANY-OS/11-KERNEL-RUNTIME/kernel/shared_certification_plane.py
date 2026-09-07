from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from .ha_certification_runtime import HACertificationRecord, _parse_time
from .hardening import HardeningError
from .shared_state_backend import SharedBackendCapabilities, SharedFence, SharedObject, certify_backend
from .trust import sha256_hex


PLANE_CONTRACT = "ha-shared-certification-plane/v0.8"


@dataclass(frozen=True)
class CertificationPlaneReadiness:
    production_ready: bool
    missing_requirements: tuple[str, ...]
    backend_capabilities: SharedBackendCapabilities
    reference_adapter_only: bool

    def envelope(self) -> dict[str, Any]:
        return {
            "production_ready": self.production_ready,
            "missing_requirements": list(self.missing_requirements),
            "backend_capabilities": self.backend_capabilities.envelope(),
            "reference_adapter_only": self.reference_adapter_only,
        }


class CertificationPlaneBackend(Protocol):
    def capabilities(self) -> SharedBackendCapabilities: ...
    def authoritative_now(self) -> datetime: ...
    def read(self, object_key: str) -> SharedObject | None: ...
    def put_if_absent(self, object_key: str, value: dict[str, Any]) -> SharedObject: ...
    def acquire_fence(self, resource_key: str, owner_id: str, ttl_seconds: int, now: datetime | None = None) -> SharedFence: ...
    def assert_fence(self, fence: SharedFence, now: datetime | None = None) -> None: ...
    def release_fence(self, fence: SharedFence, now: datetime | None = None) -> None: ...
    def stream_version(self, stream_key: str) -> int: ...
    def fenced_compare_and_swap_with_event(
        self,
        *,
        fence: SharedFence,
        object_key: str,
        expected_object_version: int,
        value: dict[str, Any],
        stream_key: str,
        expected_stream_version: int,
        event: dict[str, Any],
        now: datetime | None = None,
    ) -> tuple[SharedObject, dict[str, Any]]: ...


@dataclass(frozen=True)
class SharedCertificationPlaneState:
    object_key: str
    version: int
    backend_id: str
    cluster_id: str | None
    topology_epoch: int
    active_certification: dict[str, Any] | None
    handoff: dict[str, Any] | None
    bootstrap_closed: bool
    seen_evidence_nonces: dict[str, str]
    last_invalidation: dict[str, Any] | None

    def envelope(self) -> dict[str, Any]:
        return asdict(self)


class SharedStateCertificationPlane:
    """Provider-neutral state machine implemented over the shared backend contract.

    This class proves the state-transition contract using shared objects, fences,
    CAS and an ordered journal. It is deliberately a reference adapter and never
    self-certifies as production deployment infrastructure.
    """

    reference_adapter_only = True

    def __init__(self, backend: CertificationPlaneBackend, *, fence_ttl_seconds: int = 30):
        if isinstance(fence_ttl_seconds, bool) or not isinstance(fence_ttl_seconds, int) or not 1 <= fence_ttl_seconds <= 300:
            raise HardeningError("CFHS_INVALID_POLICY", "Certification-plane fence TTL must be 1..300 seconds")
        self.backend = backend
        self.backend_id = backend.capabilities().backend_id
        self.fence_ttl_seconds = fence_ttl_seconds

    @staticmethod
    def state_key(backend_id: str) -> str:
        return "/_cfhs/ha/certification/plane/" + sha256_hex(backend_id)[:32]

    @staticmethod
    def fence_key(backend_id: str) -> str:
        return "/_cfhs/ha/certification/plane-fence/" + sha256_hex(backend_id)[:32]

    @staticmethod
    def stream_key(backend_id: str) -> str:
        return "ha-certification-plane:" + sha256_hex(backend_id)[:32]

    def readiness(self) -> CertificationPlaneReadiness:
        caps = self.backend.capabilities()
        backend_result = certify_backend(caps)
        missing = list(backend_result.missing_requirements)
        if self.reference_adapter_only:
            missing.append("production_certification_plane_adapter_attestation")
        return CertificationPlaneReadiness(False if missing else True, tuple(missing), caps, self.reference_adapter_only)

    def _now(self) -> datetime:
        now = self.backend.authoritative_now()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise HardeningError("CFHS_HA_CERTIFICATION_DENIED", "Certification plane requires timezone-aware backend-authoritative time")
        return now.astimezone(timezone.utc)

    def _empty_value(self) -> dict[str, Any]:
        return {
            "contract": PLANE_CONTRACT,
            "backend_id": self.backend_id,
            "cluster_id": None,
            "topology_epoch": 0,
            "active_certification": None,
            "handoff": None,
            "bootstrap_closed": False,
            "seen_evidence_nonces": {},
            "last_invalidation": None,
        }

    def current(self) -> SharedCertificationPlaneState:
        obj = self.backend.read(self.state_key(self.backend_id))
        if obj is None:
            value = self._empty_value()
            return SharedCertificationPlaneState(
                object_key=self.state_key(self.backend_id),
                version=0,
                backend_id=self.backend_id,
                cluster_id=None,
                topology_epoch=0,
                active_certification=None,
                handoff=None,
                bootstrap_closed=False,
                seen_evidence_nonces={},
                last_invalidation=None,
            )
        value = obj.value
        if value.get("contract") != PLANE_CONTRACT or value.get("backend_id") != self.backend_id:
            raise HardeningError("CFHS_HA_CERTIFICATION_CONFLICT", "Shared certification-plane state identity/contract mismatch")
        return SharedCertificationPlaneState(
            object_key=obj.object_key,
            version=obj.version,
            backend_id=value["backend_id"],
            cluster_id=value.get("cluster_id"),
            topology_epoch=int(value.get("topology_epoch", 0)),
            active_certification=value.get("active_certification"),
            handoff=value.get("handoff"),
            bootstrap_closed=bool(value.get("bootstrap_closed")),
            seen_evidence_nonces=dict(value.get("seen_evidence_nonces") or {}),
            last_invalidation=value.get("last_invalidation"),
        )

    def acquire_writer_fence(self, owner_id: str) -> SharedFence:
        if not owner_id:
            raise HardeningError("CFHS_INVALID_REQUEST", "Certification-plane writer owner is required")
        return self.backend.acquire_fence(
            self.fence_key(self.backend_id),
            owner_id,
            self.fence_ttl_seconds,
            now=self._now(),
        )

    def _ensure_object(self) -> SharedObject:
        existing = self.backend.read(self.state_key(self.backend_id))
        if existing is not None:
            return existing
        return self.backend.put_if_absent(self.state_key(self.backend_id), self._empty_value())

    def _mutate(self, owner_id: str, event_type: str, transform, *, fence: SharedFence | None = None) -> SharedCertificationPlaneState:
        own_fence = fence is None
        active_fence = fence or self.acquire_writer_fence(owner_id)
        now = self._now()
        try:
            self.backend.assert_fence(active_fence, now=now)
            obj = self._ensure_object()
            current_value = dict(obj.value)
            next_value = transform(current_value, now)
            if next_value == current_value:
                return self.current()
            stream_key = self.stream_key(self.backend_id)
            stream_version = self.backend.stream_version(stream_key)
            event = {
                "type": event_type,
                "backend_id": self.backend_id,
                "state_before_digest": sha256_hex(current_value),
                "state_after_digest": sha256_hex(next_value),
                "at": now.isoformat(),
            }
            self.backend.fenced_compare_and_swap_with_event(
                fence=active_fence,
                object_key=obj.object_key,
                expected_object_version=obj.version,
                value=next_value,
                stream_key=stream_key,
                expected_stream_version=stream_version,
                event=event,
                now=now,
            )
            return self.current()
        finally:
            if own_fence:
                try:
                    self.backend.release_fence(active_fence, now=self._now())
                except HardeningError:
                    pass

    @staticmethod
    def _record_value(record: HACertificationRecord) -> dict[str, Any]:
        return record.envelope()

    def prepare_handoff(
        self,
        *,
        cluster_id: str,
        topology_epoch: int,
        handoff_digest: str,
        bootstrap_state_digest: str,
        control_state_digest: str,
        owner_id: str,
        fence: SharedFence | None = None,
    ) -> SharedCertificationPlaneState:
        if not cluster_id or not handoff_digest or not bootstrap_state_digest or not control_state_digest:
            raise HardeningError("CFHS_INVALID_REQUEST", "Shared handoff binding is incomplete")
        if isinstance(topology_epoch, bool) or not isinstance(topology_epoch, int) or topology_epoch < 1:
            raise HardeningError("CFHS_INVALID_REQUEST", "Shared handoff topology epoch must be positive")

        def transform(value, now):
            if value.get("bootstrap_closed"):
                raise HardeningError("CFHS_HA_BOOTSTRAP_CLOSED", "First-bootstrap authority is already closed in shared certification plane")
            existing_cluster = value.get("cluster_id")
            current_epoch = int(value.get("topology_epoch", 0))
            if existing_cluster and existing_cluster != cluster_id:
                raise HardeningError("CFHS_CLUSTER_IDENTITY_CONFLICT", "Shared certification-plane cluster identity changed")
            if topology_epoch < current_epoch:
                raise HardeningError("CFHS_TOPOLOGY_ROLLBACK", "Shared certification-plane topology epoch cannot move backward")
            existing = value.get("handoff")
            desired = {
                "status": "PREPARED",
                "cluster_id": cluster_id,
                "topology_epoch": topology_epoch,
                "handoff_digest": handoff_digest,
                "bootstrap_state_digest": bootstrap_state_digest,
                "control_state_digest": control_state_digest,
            }
            if existing:
                comparable = {k: existing.get(k) for k in desired if k != "status"}
                expected = {k: desired[k] for k in desired if k != "status"}
                if comparable != expected:
                    raise HardeningError("CFHS_HA_HANDOFF_CONFLICT", "Shared certification-plane handoff binding changed")
                return value
            next_value = dict(value)
            next_value["cluster_id"] = cluster_id
            next_value["topology_epoch"] = max(current_epoch, topology_epoch)
            next_value["handoff"] = desired
            return next_value

        return self._mutate(owner_id, "HANDOFF_PREPARED", transform, fence=fence)

    def activate(
        self,
        record: HACertificationRecord,
        *,
        owner_id: str,
        handoff_digest: str | None = None,
        fence: SharedFence | None = None,
    ) -> SharedCertificationPlaneState:
        if record.backend_id != self.backend_id:
            raise HardeningError("CFHS_HA_CERTIFICATION_CONFLICT", "Certification record targets a different backend")

        def transform(value, now):
            existing_cluster = value.get("cluster_id")
            current_epoch = int(value.get("topology_epoch", 0))
            if existing_cluster and existing_cluster != record.cluster_id:
                raise HardeningError("CFHS_CLUSTER_IDENTITY_CONFLICT", "Shared certification-plane cluster identity changed")
            if record.topology_epoch < current_epoch:
                raise HardeningError("CFHS_TOPOLOGY_ROLLBACK", "Shared certification-plane topology epoch cannot move backward")
            seen = dict(value.get("seen_evidence_nonces") or {})
            previous_digest = seen.get(record.evidence_nonce)
            if previous_digest and previous_digest != record.evidence_digest:
                raise HardeningError("CFHS_EVIDENCE_REPLAY", "Shared certification-plane evidence nonce was reused for different evidence")
            active = value.get("active_certification")
            if active and int(active["topology_epoch"]) == record.topology_epoch:
                if active.get("evidence_digest") == record.evidence_digest and active.get("evidence_nonce") == record.evidence_nonce:
                    return value
                raise HardeningError("CFHS_HA_CERTIFICATION_CONFLICT", "Same topology epoch is already bound to different certification evidence")
            handoff = value.get("handoff")
            if not value.get("bootstrap_closed"):
                if not handoff or handoff.get("status") not in {"PREPARED", "ACTIVATED"}:
                    raise HardeningError("CFHS_HA_HANDOFF_INCOMPLETE", "Initial shared certification activation requires prepared handoff")
                if handoff_digest != handoff.get("handoff_digest"):
                    raise HardeningError("CFHS_HA_HANDOFF_CONFLICT", "Activation handoff digest mismatch")
                if int(handoff.get("topology_epoch", 0)) != record.topology_epoch:
                    raise HardeningError("CFHS_HA_HANDOFF_CONFLICT", "Activation topology does not match prepared handoff")
            next_value = dict(value)
            next_value["cluster_id"] = record.cluster_id
            next_value["topology_epoch"] = record.topology_epoch
            next_value["active_certification"] = self._record_value(record)
            seen[record.evidence_nonce] = record.evidence_digest
            next_value["seen_evidence_nonces"] = seen
            if handoff and not value.get("bootstrap_closed"):
                next_handoff = dict(handoff)
                next_handoff["status"] = "ACTIVATED"
                next_handoff["certification_id"] = record.certification_id
                next_value["handoff"] = next_handoff
            return next_value

        return self._mutate(owner_id, "CERTIFICATION_ACTIVATED", transform, fence=fence)

    def close_handoff(
        self,
        *,
        cluster_id: str,
        topology_epoch: int,
        handoff_digest: str,
        certification_id: str,
        owner_id: str,
        fence: SharedFence | None = None,
    ) -> SharedCertificationPlaneState:
        def transform(value, now):
            if value.get("cluster_id") != cluster_id:
                raise HardeningError("CFHS_CLUSTER_IDENTITY_CONFLICT", "Shared handoff closure cluster mismatch")
            if topology_epoch < int(value.get("topology_epoch", 0)):
                raise HardeningError("CFHS_TOPOLOGY_ROLLBACK", "Shared handoff closure topology rollback")
            handoff = value.get("handoff")
            active = value.get("active_certification")
            if not handoff or handoff.get("handoff_digest") != handoff_digest:
                raise HardeningError("CFHS_HA_HANDOFF_CONFLICT", "Shared handoff closure binding mismatch")
            if value.get("bootstrap_closed"):
                if handoff.get("status") == "CLOSED" and handoff.get("certification_id") == certification_id:
                    return value
                raise HardeningError("CFHS_HA_HANDOFF_CONFLICT", "Shared bootstrap closure is bound to another certificate")
            if handoff.get("status") != "ACTIVATED" or not active or active.get("certification_id") != certification_id:
                raise HardeningError("CFHS_HA_HANDOFF_INCOMPLETE", "Shared handoff cannot close before matching certification activation")
            if now >= _parse_time(active["valid_until"]):
                raise HardeningError("CFHS_HA_CERTIFICATION_EXPIRED", "Shared handoff certificate expired before closure")
            next_value = dict(value)
            next_handoff = dict(handoff)
            next_handoff["status"] = "CLOSED"
            next_handoff["closed_at"] = now.isoformat()
            next_value["handoff"] = next_handoff
            next_value["bootstrap_closed"] = True
            return next_value

        return self._mutate(owner_id, "HANDOFF_CLOSED", transform, fence=fence)

    def invalidate(self, reason: str, *, owner_id: str, fence: SharedFence | None = None) -> SharedCertificationPlaneState:
        if not reason:
            raise HardeningError("CFHS_INVALID_REQUEST", "Certification invalidation reason is required")

        def transform(value, now):
            active = value.get("active_certification")
            if not active:
                return value
            next_value = dict(value)
            next_value["active_certification"] = None
            next_value["last_invalidation"] = {
                "certification_id": active.get("certification_id"),
                "reason": reason,
                "invalidated_at": now.isoformat(),
            }
            return next_value

        return self._mutate(owner_id, "CERTIFICATION_INVALIDATED", transform, fence=fence)

    def require_active(self) -> dict[str, Any]:
        state = self.current()
        if not state.bootstrap_closed:
            raise HardeningError("CFHS_HA_HANDOFF_INCOMPLETE", "Shared certification plane has not permanently closed first-bootstrap authority")
        active = state.active_certification
        if not active:
            raise HardeningError("CFHS_HA_CERTIFICATION_REQUIRED", "Shared certification plane has no active certification")
        now = self._now()
        if now >= _parse_time(active["valid_until"]):
            raise HardeningError("CFHS_HA_CERTIFICATION_EXPIRED", "Shared certification-plane certificate expired")
        return dict(active)
