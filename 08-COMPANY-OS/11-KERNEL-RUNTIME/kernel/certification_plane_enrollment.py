from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .certification_plane_attestation import (
    CertificationPlaneAdapterAttestation,
    CertificationPlaneAdapterReadiness,
    CertificationPlaneDeploymentIdentity,
    _parse_time,
)
from .hardening import HardeningError
from .shared_certification_plane import SharedStateCertificationPlane
from .shared_state_backend import SharedFence, SharedObject
from .trust import sha256_hex


ENROLLMENT_CONTRACT = "ha-certification-plane-enrollment/v0.8"


@dataclass(frozen=True)
class AdapterEnrollmentRecord:
    object_key: str
    version: int
    deployment_id: str
    deployment_digest: str
    attestation_digest: str
    verifier_receipt_digest: str
    trust_store_id: str
    generation: int
    status: str
    enrolled_at: str
    valid_until: str
    revoked_at: str | None
    revocation_reason: str | None

    def envelope(self) -> dict[str, Any]:
        return asdict(self)


class SharedAdapterEnrollmentRegistry:
    """Shared, fenced adapter-enrollment lifecycle over the HA backend contract.

    Enrollment is authorization to use a previously verified adapter deployment,
    not a substitute for attestation. Runtime callers must still re-resolve the
    current deployment identity and match it to this durable record.
    """

    def __init__(self, plane: SharedStateCertificationPlane, *, fence_ttl_seconds: int = 30):
        if isinstance(fence_ttl_seconds, bool) or not isinstance(fence_ttl_seconds, int) or not 1 <= fence_ttl_seconds <= 300:
            raise HardeningError("CFHS_INVALID_POLICY", "Adapter-enrollment fence TTL must be 1..300 seconds")
        self.plane = plane
        self.backend = plane.backend
        self.backend_id = plane.backend_id
        self.fence_ttl_seconds = fence_ttl_seconds

    @staticmethod
    def object_key(deployment_id: str) -> str:
        return "/_cfhs/ha/certification/enrollment/" + sha256_hex(deployment_id)[:32]

    @staticmethod
    def fence_key(deployment_id: str) -> str:
        return "/_cfhs/ha/certification/enrollment-fence/" + sha256_hex(deployment_id)[:32]

    @staticmethod
    def stream_key(deployment_id: str) -> str:
        return "ha-certification-enrollment:" + sha256_hex(deployment_id)[:32]

    def _now(self) -> datetime:
        now = self.backend.authoritative_now()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Adapter enrollment requires timezone-aware backend-authoritative time")
        return now.astimezone(timezone.utc)

    @staticmethod
    def _record(obj: SharedObject) -> AdapterEnrollmentRecord:
        value = obj.value
        if value.get("contract") != ENROLLMENT_CONTRACT:
            raise HardeningError("CFHS_HA_ENROLLMENT_CONFLICT", "Adapter enrollment contract mismatch")
        return AdapterEnrollmentRecord(
            object_key=obj.object_key,
            version=obj.version,
            deployment_id=value["deployment_id"],
            deployment_digest=value["deployment_digest"],
            attestation_digest=value["attestation_digest"],
            verifier_receipt_digest=value["verifier_receipt_digest"],
            trust_store_id=value["trust_store_id"],
            generation=int(value["generation"]),
            status=value["status"],
            enrolled_at=value["enrolled_at"],
            valid_until=value["valid_until"],
            revoked_at=value.get("revoked_at"),
            revocation_reason=value.get("revocation_reason"),
        )

    def get(self, deployment_id: str) -> AdapterEnrollmentRecord | None:
        obj = self.backend.read(self.object_key(deployment_id))
        return self._record(obj) if obj else None

    def _fence(self, deployment_id: str, owner_id: str) -> SharedFence:
        if not owner_id:
            raise HardeningError("CFHS_INVALID_REQUEST", "Adapter-enrollment owner is required")
        return self.backend.acquire_fence(
            self.fence_key(deployment_id),
            owner_id,
            self.fence_ttl_seconds,
            now=self._now(),
        )

    def enroll(
        self,
        readiness: CertificationPlaneAdapterReadiness,
        deployment: CertificationPlaneDeploymentIdentity,
        attestation: CertificationPlaneAdapterAttestation,
        *,
        generation: int,
        owner_id: str,
    ) -> AdapterEnrollmentRecord:
        if not readiness.production_ready or readiness.missing_requirements:
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Adapter enrollment requires a production-ready adapter decision")
        if readiness.deployment_digest != deployment.digest():
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Adapter readiness does not bind the deployment being enrolled")
        if readiness.attestation_digest != attestation.digest():
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Adapter readiness does not bind the attestation being enrolled")
        if not readiness.verifier_receipt_digest or not readiness.trust_store_id:
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Adapter readiness provenance is incomplete")
        if attestation.deployment_digest != deployment.digest():
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Adapter attestation does not bind enrolled deployment")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise HardeningError("CFHS_INVALID_REQUEST", "Adapter enrollment generation must be positive")
        now = self._now()
        valid_until = _parse_time(attestation.expires_at, "adapter enrollment attestation expiry")
        if now >= valid_until:
            raise HardeningError("CFHS_HA_ENROLLMENT_EXPIRED", "Adapter attestation expired before enrollment")

        desired = {
            "contract": ENROLLMENT_CONTRACT,
            "deployment_id": deployment.deployment_id,
            "deployment_digest": deployment.digest(),
            "attestation_digest": attestation.digest(),
            "verifier_receipt_digest": readiness.verifier_receipt_digest,
            "trust_store_id": readiness.trust_store_id,
            "generation": generation,
            "status": "ACTIVE",
            "enrolled_at": now.isoformat(),
            "valid_until": valid_until.isoformat(),
            "revoked_at": None,
            "revocation_reason": None,
        }
        fence = self._fence(deployment.deployment_id, owner_id)
        try:
            self.backend.assert_fence(fence, now=now)
            key = self.object_key(deployment.deployment_id)
            current = self.backend.read(key)
            if current is None:
                created = self.backend.put_if_absent(key, desired)
                return self._record(created)
            record = self._record(current)
            if generation < record.generation:
                raise HardeningError("CFHS_AUTHORITY_ROLLBACK", "Adapter enrollment generation cannot move backward")
            if generation == record.generation:
                comparable = dict(desired)
                comparable["enrolled_at"] = record.enrolled_at
                if current.value == comparable:
                    return record
                raise HardeningError("CFHS_HA_ENROLLMENT_CONFLICT", "Adapter enrollment generation is already bound to different deployment/attestation state")

            stream_key = self.stream_key(deployment.deployment_id)
            self.backend.fenced_compare_and_swap_with_event(
                fence=fence,
                object_key=key,
                expected_object_version=current.version,
                value=desired,
                stream_key=stream_key,
                expected_stream_version=self.backend.stream_version(stream_key),
                event={
                    "type": "ADAPTER_ENROLLMENT_ROTATED",
                    "deployment_id": deployment.deployment_id,
                    "prior_generation": record.generation,
                    "generation": generation,
                    "deployment_digest": deployment.digest(),
                    "attestation_digest": attestation.digest(),
                    "at": now.isoformat(),
                },
                now=now,
            )
            updated = self.backend.read(key)
            if not updated:
                raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Adapter enrollment rotation was not persisted")
            return self._record(updated)
        finally:
            try:
                self.backend.release_fence(fence, now=self._now())
            except HardeningError:
                pass

    def revoke(self, deployment_id: str, reason: str, *, owner_id: str) -> AdapterEnrollmentRecord:
        if not reason:
            raise HardeningError("CFHS_INVALID_REQUEST", "Adapter enrollment revocation reason is required")
        fence = self._fence(deployment_id, owner_id)
        now = self._now()
        try:
            self.backend.assert_fence(fence, now=now)
            key = self.object_key(deployment_id)
            current = self.backend.read(key)
            if current is None:
                raise HardeningError("CFHS_HA_ENROLLMENT_REQUIRED", "Adapter deployment is not enrolled")
            record = self._record(current)
            if record.status == "REVOKED":
                if record.revocation_reason == reason:
                    return record
                raise HardeningError("CFHS_HA_ENROLLMENT_CONFLICT", "Adapter enrollment was already revoked for a different reason")
            next_value = dict(current.value)
            next_value["status"] = "REVOKED"
            next_value["revoked_at"] = now.isoformat()
            next_value["revocation_reason"] = reason
            stream_key = self.stream_key(deployment_id)
            self.backend.fenced_compare_and_swap_with_event(
                fence=fence,
                object_key=key,
                expected_object_version=current.version,
                value=next_value,
                stream_key=stream_key,
                expected_stream_version=self.backend.stream_version(stream_key),
                event={
                    "type": "ADAPTER_ENROLLMENT_REVOKED",
                    "deployment_id": deployment_id,
                    "generation": record.generation,
                    "reason": reason,
                    "at": now.isoformat(),
                },
                now=now,
            )
            updated = self.backend.read(key)
            if not updated:
                raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Adapter enrollment revocation was not persisted")
            return self._record(updated)
        finally:
            try:
                self.backend.release_fence(fence, now=self._now())
            except HardeningError:
                pass

    def require_active(
        self,
        current_deployment: CertificationPlaneDeploymentIdentity,
    ) -> AdapterEnrollmentRecord:
        record = self.get(current_deployment.deployment_id)
        if record is None:
            raise HardeningError("CFHS_HA_ENROLLMENT_REQUIRED", "Certification-plane adapter deployment is not enrolled")
        if record.status != "ACTIVE":
            raise HardeningError("CFHS_HA_ENROLLMENT_REVOKED", "Certification-plane adapter enrollment is revoked")
        if self._now() >= _parse_time(record.valid_until, "adapter enrollment valid_until"):
            raise HardeningError("CFHS_HA_ENROLLMENT_EXPIRED", "Certification-plane adapter enrollment expired")
        if record.deployment_digest != current_deployment.digest():
            raise HardeningError(
                "CFHS_HA_ENROLLMENT_DRIFT",
                "Running certification-plane deployment no longer matches its enrolled identity",
                {
                    "deployment_id": current_deployment.deployment_id,
                    "expected_deployment_digest": record.deployment_digest,
                    "current_deployment_digest": current_deployment.digest(),
                },
            )
        return record


class EnrolledCertificationPlaneRuntime:
    """Runtime facade that revalidates adapter enrollment on every exposed operation."""

    def __init__(
        self,
        plane: SharedStateCertificationPlane,
        registry: SharedAdapterEnrollmentRegistry,
        deployment_resolver: Callable[[], CertificationPlaneDeploymentIdentity],
    ):
        self.plane = plane
        self.registry = registry
        self.deployment_resolver = deployment_resolver

    def _guard(self) -> AdapterEnrollmentRecord:
        current = self.deployment_resolver()
        if current.backend_id != self.plane.backend_id:
            raise HardeningError("CFHS_HA_ENROLLMENT_DRIFT", "Resolved deployment targets a different certification-plane backend")
        return self.registry.require_active(current)

    def current(self):
        self._guard()
        return self.plane.current()

    def require_active(self):
        self._guard()
        return self.plane.require_active()

    def acquire_writer_fence(self, owner_id: str):
        self._guard()
        return self.plane.acquire_writer_fence(owner_id)

    def prepare_handoff(self, **kwargs):
        self._guard()
        return self.plane.prepare_handoff(**kwargs)

    def activate(self, *args, **kwargs):
        self._guard()
        return self.plane.activate(*args, **kwargs)

    def close_handoff(self, **kwargs):
        self._guard()
        return self.plane.close_handoff(**kwargs)

    def invalidate(self, *args, **kwargs):
        self._guard()
        return self.plane.invalidate(*args, **kwargs)
