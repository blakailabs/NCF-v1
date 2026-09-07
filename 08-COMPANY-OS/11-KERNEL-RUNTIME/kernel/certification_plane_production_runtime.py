from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .certification_plane_attestation import (
    CertificationPlaneAdapterAttestation,
    CertificationPlaneAdapterReadiness,
    CertificationPlaneDeploymentIdentity,
)
from .certification_plane_enrollment import (
    AdapterEnrollmentRecord,
    EnrolledCertificationPlaneRuntime,
    SharedAdapterEnrollmentRegistry,
)
from .certification_plane_enrollment_authority import (
    AdapterEnrollmentAuthorization,
    AdapterEnrollmentAuthorizationVerifier,
    AdapterEnrollmentAuthorityTrustStore,
    ProductionAdapterEnrollmentAuthorityGate,
)
from .hardening import HardeningError
from .shared_state_backend import SharedFence, SharedObject
from .trust import sha256_hex


ACTIVATION_CONTRACT = "ha-certification-plane-production-activation/v0.8"


@dataclass(frozen=True)
class ProductionEnrollmentActivationRecord:
    object_key: str
    version: int
    deployment_id: str
    deployment_digest: str
    enrollment_generation: int
    authorization_digest: str
    authority_id: str
    authority_class: str
    authority_generation: int
    key_id: str
    status: str
    activated_at: str

    def envelope(self) -> dict[str, Any]:
        return asdict(self)


class SharedProductionEnrollmentActivationRegistry:
    """Shared proof that runtime enrollment passed the independent authority gate.

    Direct writes to SharedAdapterEnrollmentRegistry do not create this receipt,
    so they cannot unlock the production runtime facade.
    """

    def __init__(self, enrollment_registry: SharedAdapterEnrollmentRegistry, *, fence_ttl_seconds: int = 30):
        if isinstance(fence_ttl_seconds, bool) or not isinstance(fence_ttl_seconds, int) or not 1 <= fence_ttl_seconds <= 300:
            raise HardeningError("CFHS_INVALID_POLICY", "Production activation fence TTL must be 1..300 seconds")
        self.enrollment_registry = enrollment_registry
        self.backend = enrollment_registry.backend
        self.fence_ttl_seconds = fence_ttl_seconds

    @staticmethod
    def object_key(deployment_id: str) -> str:
        return "/_cfhs/ha/certification/production-activation/" + sha256_hex(deployment_id)[:32]

    @staticmethod
    def fence_key(deployment_id: str) -> str:
        return "/_cfhs/ha/certification/production-activation-fence/" + sha256_hex(deployment_id)[:32]

    @staticmethod
    def stream_key(deployment_id: str) -> str:
        return "ha-certification-production-activation:" + sha256_hex(deployment_id)[:32]

    def _now(self) -> datetime:
        now = self.backend.authoritative_now()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise HardeningError("CFHS_HA_PRODUCTION_RUNTIME_DENIED", "Production activation requires timezone-aware backend-authoritative time")
        return now.astimezone(timezone.utc)

    @staticmethod
    def _record(obj: SharedObject) -> ProductionEnrollmentActivationRecord:
        value = obj.value
        if value.get("contract") != ACTIVATION_CONTRACT:
            raise HardeningError("CFHS_HA_PRODUCTION_RUNTIME_CONFLICT", "Production activation contract mismatch")
        if value.get("status") != "ACTIVE":
            raise HardeningError("CFHS_HA_PRODUCTION_RUNTIME_DENIED", "Production activation is not ACTIVE")
        return ProductionEnrollmentActivationRecord(
            object_key=obj.object_key,
            version=obj.version,
            deployment_id=value["deployment_id"],
            deployment_digest=value["deployment_digest"],
            enrollment_generation=int(value["enrollment_generation"]),
            authorization_digest=value["authorization_digest"],
            authority_id=value["authority_id"],
            authority_class=value["authority_class"],
            authority_generation=int(value["authority_generation"]),
            key_id=value["key_id"],
            status=value["status"],
            activated_at=value["activated_at"],
        )

    def get(self, deployment_id: str) -> ProductionEnrollmentActivationRecord | None:
        obj = self.backend.read(self.object_key(deployment_id))
        if obj is None:
            return None
        return self._record(obj)

    def _fence(self, deployment_id: str, owner_id: str) -> SharedFence:
        if not owner_id:
            raise HardeningError("CFHS_INVALID_REQUEST", "Production activation owner is required")
        return self.backend.acquire_fence(
            self.fence_key(deployment_id),
            owner_id,
            self.fence_ttl_seconds,
            now=self._now(),
        )

    def record_authorized_activation(
        self,
        enrollment: AdapterEnrollmentRecord,
        authorization: AdapterEnrollmentAuthorization,
        *,
        owner_id: str,
    ) -> ProductionEnrollmentActivationRecord:
        if enrollment.deployment_id != authorization.deployment_id:
            raise HardeningError("CFHS_HA_PRODUCTION_RUNTIME_CONFLICT", "Activation authorization targets a different deployment")
        if enrollment.deployment_digest != authorization.deployment_digest:
            raise HardeningError("CFHS_HA_PRODUCTION_RUNTIME_CONFLICT", "Activation authorization deployment digest mismatch")
        if enrollment.generation != authorization.enrollment_generation:
            raise HardeningError("CFHS_HA_PRODUCTION_RUNTIME_CONFLICT", "Activation authorization enrollment generation mismatch")
        now = self._now()
        desired = {
            "contract": ACTIVATION_CONTRACT,
            "deployment_id": enrollment.deployment_id,
            "deployment_digest": enrollment.deployment_digest,
            "enrollment_generation": enrollment.generation,
            "authorization_digest": authorization.digest(),
            "authority_id": authorization.authority_id,
            "authority_class": authorization.authority_class,
            "authority_generation": authorization.authority_generation,
            "key_id": authorization.key_id,
            "status": "ACTIVE",
            "activated_at": now.isoformat(),
        }
        fence = self._fence(enrollment.deployment_id, owner_id)
        try:
            self.backend.assert_fence(fence, now=now)
            key = self.object_key(enrollment.deployment_id)
            current = self.backend.read(key)
            if current is None:
                pending = {
                    "contract": ACTIVATION_CONTRACT,
                    "deployment_id": enrollment.deployment_id,
                    "status": "PENDING",
                }
                current = self.backend.put_if_absent(key, pending)
            if current.value == desired:
                return self._record(current)
            if current.value.get("contract") != ACTIVATION_CONTRACT or current.value.get("deployment_id") != enrollment.deployment_id:
                raise HardeningError("CFHS_HA_PRODUCTION_RUNTIME_CONFLICT", "Production activation identity changed")
            if current.value.get("status") == "ACTIVE":
                prior_generation = int(current.value["enrollment_generation"])
                if enrollment.generation < prior_generation:
                    raise HardeningError("CFHS_AUTHORITY_ROLLBACK", "Production activation enrollment generation cannot move backward")
                if enrollment.generation == prior_generation:
                    raise HardeningError("CFHS_HA_PRODUCTION_RUNTIME_CONFLICT", "Production activation generation is already bound to different authority state")
                prior_authority_generation = int(current.value["authority_generation"])
                if authorization.authority_generation < prior_authority_generation:
                    raise HardeningError("CFHS_AUTHORITY_ROLLBACK", "Production activation authority generation cannot move backward")
            stream_key = self.stream_key(enrollment.deployment_id)
            self.backend.fenced_compare_and_swap_with_event(
                fence=fence,
                object_key=key,
                expected_object_version=current.version,
                value=desired,
                stream_key=stream_key,
                expected_stream_version=self.backend.stream_version(stream_key),
                event={
                    "type": "PRODUCTION_ADAPTER_ACTIVATED",
                    "deployment_id": enrollment.deployment_id,
                    "deployment_digest": enrollment.deployment_digest,
                    "enrollment_generation": enrollment.generation,
                    "authorization_digest": authorization.digest(),
                    "authority_id": authorization.authority_id,
                    "authority_generation": authorization.authority_generation,
                    "at": now.isoformat(),
                },
                now=now,
            )
            updated = self.backend.read(key)
            if updated is None:
                raise HardeningError("CFHS_HA_PRODUCTION_RUNTIME_DENIED", "Production activation receipt was not persisted")
            return self._record(updated)
        finally:
            try:
                self.backend.release_fence(fence, now=self._now())
            except HardeningError:
                pass

    def require_matches(self, enrollment: AdapterEnrollmentRecord) -> ProductionEnrollmentActivationRecord:
        activation = self.get(enrollment.deployment_id)
        if activation is None:
            raise HardeningError("CFHS_HA_PRODUCTION_ACTIVATION_REQUIRED", "No external-authority production activation receipt exists")
        if activation.deployment_digest != enrollment.deployment_digest or activation.enrollment_generation != enrollment.generation:
            raise HardeningError("CFHS_HA_PRODUCTION_ACTIVATION_STALE", "Production activation receipt does not match current enrollment")
        return activation


class ProductionCertificationPlaneRuntime:
    """Runtime facade requiring enrollment AND external-authority activation receipt."""

    def __init__(
        self,
        enrolled_runtime: EnrolledCertificationPlaneRuntime,
        activation_registry: SharedProductionEnrollmentActivationRegistry,
        deployment_resolver: Callable[[], CertificationPlaneDeploymentIdentity],
    ):
        self.enrolled_runtime = enrolled_runtime
        self.activation_registry = activation_registry
        self.deployment_resolver = deployment_resolver

    def _guard(self) -> ProductionEnrollmentActivationRecord:
        current = self.deployment_resolver()
        enrollment = self.activation_registry.enrollment_registry.require_active(current)
        return self.activation_registry.require_matches(enrollment)

    def current(self):
        self._guard(); return self.enrolled_runtime.current()
    def require_active(self):
        self._guard(); return self.enrolled_runtime.require_active()
    def acquire_writer_fence(self, owner_id: str):
        self._guard(); return self.enrolled_runtime.acquire_writer_fence(owner_id)
    def prepare_handoff(self, **kwargs):
        self._guard(); return self.enrolled_runtime.prepare_handoff(**kwargs)
    def activate(self, *args, **kwargs):
        self._guard(); return self.enrolled_runtime.activate(*args, **kwargs)
    def close_handoff(self, **kwargs):
        self._guard(); return self.enrolled_runtime.close_handoff(**kwargs)
    def invalidate(self, *args, **kwargs):
        self._guard(); return self.enrolled_runtime.invalidate(*args, **kwargs)


class ProductionCertificationPlaneRuntimeWiring:
    """One entry point for authority-controlled enrollment and production runtime.

    This is a contract/wiring layer only. It does not provide a production
    authority, production trust store, credentials, or a real HA backend.
    """

    def __init__(
        self,
        enrolled_runtime: EnrolledCertificationPlaneRuntime,
        enrollment_registry: SharedAdapterEnrollmentRegistry,
        activation_registry: SharedProductionEnrollmentActivationRegistry,
        authority_gate: ProductionAdapterEnrollmentAuthorityGate,
        deployment_resolver: Callable[[], CertificationPlaneDeploymentIdentity],
    ):
        self.enrolled_runtime = enrolled_runtime
        self.enrollment_registry = enrollment_registry
        self.activation_registry = activation_registry
        self.authority_gate = authority_gate
        self.deployment_resolver = deployment_resolver

    def authorize_activate_runtime(
        self,
        readiness: CertificationPlaneAdapterReadiness,
        deployment: CertificationPlaneDeploymentIdentity,
        attestation: CertificationPlaneAdapterAttestation,
        authorization: AdapterEnrollmentAuthorization,
        verifier: AdapterEnrollmentAuthorizationVerifier,
        trust_store: AdapterEnrollmentAuthorityTrustStore,
        *,
        owner_id: str,
        now: datetime,
    ) -> ProductionCertificationPlaneRuntime:
        enrollment = self.authority_gate.authorize_and_enroll(
            self.enrollment_registry,
            readiness,
            deployment,
            attestation,
            authorization,
            verifier,
            trust_store,
            owner_id=owner_id,
            now=now,
        )
        self.activation_registry.record_authorized_activation(
            enrollment,
            authorization,
            owner_id=owner_id + ":activation",
        )
        runtime = ProductionCertificationPlaneRuntime(
            self.enrolled_runtime,
            self.activation_registry,
            self.deployment_resolver,
        )
        runtime._guard()
        return runtime
