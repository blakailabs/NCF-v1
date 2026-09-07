from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from .certification_plane_attestation import (
    CertificationPlaneAdapterAttestation,
    CertificationPlaneAdapterReadiness,
    CertificationPlaneDeploymentIdentity,
    _parse_time,
)
from .certification_plane_enrollment import AdapterEnrollmentRecord, SharedAdapterEnrollmentRegistry
from .hardening import HardeningError
from .trust import sha256_hex


ENROLLMENT_AUTHORITY_CONTRACT = "ha-certification-plane-enrollment-authority/v0.8"
ALLOWED_ENROLLMENT_AUTHORITY_CLASSES = {
    "independent_enrollment_authority",
    "hsm_enrollment_authority",
    "supply_chain_enrollment_authority",
}


@dataclass(frozen=True)
class AdapterEnrollmentAuthorization:
    authorization_id: str
    purpose: str
    deployment_id: str
    deployment_digest: str
    readiness_digest: str
    attestation_digest: str
    verifier_receipt_digest: str
    trust_store_id: str
    enrollment_generation: int
    authority_id: str
    authority_class: str
    key_id: str
    authority_generation: int
    authorization_nonce: str
    issued_at: str
    expires_at: str

    def envelope(self) -> dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return sha256_hex({"contract": ENROLLMENT_AUTHORITY_CONTRACT, **self.envelope()})


@dataclass(frozen=True)
class VerifiedAdapterEnrollmentAuthorization:
    authorization_digest: str
    deployment_digest: str
    authority_id: str
    authority_class: str
    key_id: str
    authority_generation: int
    enrollment_generation: int
    verified_at: str
    verifier_receipt_digest: str


@dataclass(frozen=True)
class EnrollmentAuthorityTrustReadiness:
    production_ready: bool
    trust_store_id: str
    reason: str | None = None


class AdapterEnrollmentAuthorizationVerifier(Protocol):
    def verify(
        self,
        authorization: AdapterEnrollmentAuthorization,
        deployment: CertificationPlaneDeploymentIdentity,
    ) -> VerifiedAdapterEnrollmentAuthorization: ...


class AdapterEnrollmentAuthorityTrustStore(Protocol):
    def readiness(self) -> EnrollmentAuthorityTrustReadiness: ...

    def accept(
        self,
        authorization: AdapterEnrollmentAuthorization,
        verified: VerifiedAdapterEnrollmentAuthorization,
    ) -> None: ...


class ReferenceAdapterEnrollmentAuthorityTrustStore:
    """Reference replay/rollback ledger. It can never authorize production enrollment."""

    def __init__(self, trust_store_id: str = "reference-adapter-enrollment-authority-v08"):
        self.trust_store_id = trust_store_id
        self.authorities: dict[str, dict[str, Any]] = {}
        self.nonces: dict[str, str] = {}

    def readiness(self) -> EnrollmentAuthorityTrustReadiness:
        return EnrollmentAuthorityTrustReadiness(
            production_ready=False,
            trust_store_id=self.trust_store_id,
            reason="reference_enrollment_authority_not_production_durable",
        )

    def accept(self, authorization, verified) -> None:
        digest = authorization.digest()
        nonce_key = f"{authorization.authority_id}:{authorization.authorization_nonce}"
        previous_nonce = self.nonces.get(nonce_key)
        if previous_nonce and previous_nonce != digest:
            raise HardeningError("CFHS_EVIDENCE_REPLAY", "Enrollment authorization nonce was reused for different content")
        previous = self.authorities.get(authorization.authority_id)
        if previous:
            generation = int(previous["authority_generation"])
            if authorization.authority_generation < generation:
                raise HardeningError("CFHS_AUTHORITY_ROLLBACK", "Enrollment authority generation cannot move backward")
            if authorization.authority_generation == generation and previous["key_id"] != authorization.key_id:
                raise HardeningError("CFHS_AUTHORITY_CONFLICT", "Enrollment authority key changed without generation advance")
        self.authorities[authorization.authority_id] = {
            "authority_generation": authorization.authority_generation,
            "key_id": authorization.key_id,
            "authorization_digest": digest,
            "verifier_receipt_digest": verified.verifier_receipt_digest,
        }
        self.nonces[nonce_key] = digest


class ProductionAdapterEnrollmentAuthorityGate:
    """Fail-closed boundary between verified release readiness and runtime enrollment.

    The registry cannot be promoted through this gate unless an independent,
    production-ready enrollment authority authorizes the exact readiness,
    attestation and deployment digests for one monotonic enrollment generation.
    """

    def __init__(self, *, max_age_seconds: int = 300, max_lifetime_seconds: int = 900, max_future_skew_seconds: int = 60):
        if not 30 <= max_age_seconds <= 3600 or not 30 <= max_lifetime_seconds <= 3600 or not 0 <= max_future_skew_seconds <= 300:
            raise HardeningError("CFHS_INVALID_POLICY", "Enrollment authority time policy is invalid")
        self.max_age_seconds = max_age_seconds
        self.max_lifetime_seconds = max_lifetime_seconds
        self.max_future_skew_seconds = max_future_skew_seconds

    @staticmethod
    def readiness_digest(readiness: CertificationPlaneAdapterReadiness) -> str:
        return sha256_hex(readiness.envelope())

    def authorize_and_enroll(
        self,
        registry: SharedAdapterEnrollmentRegistry,
        readiness: CertificationPlaneAdapterReadiness,
        deployment: CertificationPlaneDeploymentIdentity,
        attestation: CertificationPlaneAdapterAttestation,
        authorization: AdapterEnrollmentAuthorization | None,
        verifier: AdapterEnrollmentAuthorizationVerifier | None,
        trust_store: AdapterEnrollmentAuthorityTrustStore,
        *,
        owner_id: str,
        now: datetime,
    ) -> AdapterEnrollmentRecord:
        if now.tzinfo is None:
            raise HardeningError("CFHS_INVALID_EVIDENCE", "Enrollment authorization verification time must be timezone-aware")
        now = now.astimezone(timezone.utc)
        if not readiness.production_ready or readiness.missing_requirements:
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Production enrollment requires verified production-ready adapter state")
        if readiness.deployment_digest != deployment.digest() or readiness.attestation_digest != attestation.digest():
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Production enrollment readiness bindings do not match deployment/attestation")
        store = trust_store.readiness()
        if not store.production_ready:
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Production enrollment requires a production-ready external authority trust store")
        if authorization is None or verifier is None:
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Independent production enrollment authorization and verifier are required")
        if authorization.purpose != "activate_certification_plane_adapter":
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Enrollment authorization purpose is invalid")
        bindings = (
            authorization.deployment_id == deployment.deployment_id,
            authorization.deployment_digest == deployment.digest(),
            authorization.readiness_digest == self.readiness_digest(readiness),
            authorization.attestation_digest == attestation.digest(),
            authorization.verifier_receipt_digest == readiness.verifier_receipt_digest,
            authorization.trust_store_id == readiness.trust_store_id,
        )
        if not all(bindings):
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Enrollment authorization does not bind exact verified adapter state")
        if authorization.authority_class not in ALLOWED_ENROLLMENT_AUTHORITY_CLASSES:
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Enrollment authority class is not permitted")
        if not authorization.authorization_id or not authorization.authorization_nonce or not authorization.authority_id or not authorization.key_id:
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Enrollment authorization identity is incomplete")
        if isinstance(authorization.authority_generation, bool) or not isinstance(authorization.authority_generation, int) or authorization.authority_generation < 1:
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Enrollment authority generation is invalid")
        if isinstance(authorization.enrollment_generation, bool) or not isinstance(authorization.enrollment_generation, int) or authorization.enrollment_generation < 1:
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Enrollment generation is invalid")
        issued = _parse_time(authorization.issued_at, "enrollment authorization issued_at")
        expires = _parse_time(authorization.expires_at, "enrollment authorization expires_at")
        if expires <= issued or expires - issued > timedelta(seconds=self.max_lifetime_seconds):
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Enrollment authorization lifetime is invalid")
        if issued - now > timedelta(seconds=self.max_future_skew_seconds) or now - issued > timedelta(seconds=self.max_age_seconds) or now >= expires:
            raise HardeningError("CFHS_HA_ENROLLMENT_EXPIRED", "Enrollment authorization is outside its trusted time window")
        try:
            verified = verifier.verify(authorization, deployment)
        except Exception as exc:
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Independent enrollment authorization verification failed") from exc
        if (
            verified.authorization_digest != authorization.digest()
            or verified.deployment_digest != deployment.digest()
            or verified.authority_id != authorization.authority_id
            or verified.authority_class != authorization.authority_class
            or verified.key_id != authorization.key_id
            or verified.authority_generation != authorization.authority_generation
            or verified.enrollment_generation != authorization.enrollment_generation
            or not verified.verifier_receipt_digest
        ):
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Verified enrollment authorization bindings are invalid")
        verified_at = _parse_time(verified.verified_at, "enrollment authorization verified_at")
        if verified_at < issued - timedelta(seconds=self.max_future_skew_seconds) or verified_at >= expires:
            raise HardeningError("CFHS_HA_ENROLLMENT_DENIED", "Enrollment authorization verifier time is outside authorization lifetime")
        trust_store.accept(authorization, verified)
        return registry.enroll(
            readiness,
            deployment,
            attestation,
            generation=authorization.enrollment_generation,
            owner_id=owner_id,
        )
