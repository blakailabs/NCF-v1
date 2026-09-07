from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from .hardening import HardeningError
from .shared_certification_plane import SharedStateCertificationPlane
from .shared_state_backend import SharedBackendCapabilities, certify_backend
from .trust import sha256_hex


ALLOWED_ADAPTER_ATTESTATION_CLASSES = {
    "independent_release_attestation",
    "hsm_release_attestation",
    "supply_chain_release_attestation",
}


def _parse_time(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise HardeningError("CFHS_INVALID_EVIDENCE", f"{field} timestamp is invalid") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class CertificationPlaneDeploymentIdentity:
    deployment_id: str
    backend_id: str
    cluster_id: str
    adapter_name: str
    adapter_version: str
    adapter_implementation_digest: str
    backend_capabilities_digest: str
    topology_evidence_digest: str
    probe_evidence_digest: str

    def envelope(self) -> dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return sha256_hex(self.envelope())

    @classmethod
    def from_plane(
        cls,
        plane: SharedStateCertificationPlane,
        *,
        deployment_id: str,
        cluster_id: str,
        adapter_name: str,
        adapter_version: str,
        adapter_implementation_digest: str,
        topology_evidence_digest: str,
        probe_evidence_digest: str,
    ) -> "CertificationPlaneDeploymentIdentity":
        caps = plane.backend.capabilities()
        required = {
            "deployment_id": deployment_id,
            "cluster_id": cluster_id,
            "adapter_name": adapter_name,
            "adapter_version": adapter_version,
            "adapter_implementation_digest": adapter_implementation_digest,
            "topology_evidence_digest": topology_evidence_digest,
            "probe_evidence_digest": probe_evidence_digest,
        }
        if any(not isinstance(value, str) or not value for value in required.values()):
            raise HardeningError("CFHS_INVALID_EVIDENCE", "Certification-plane deployment identity is incomplete")
        return cls(
            deployment_id=deployment_id,
            backend_id=caps.backend_id,
            cluster_id=cluster_id,
            adapter_name=adapter_name,
            adapter_version=adapter_version,
            adapter_implementation_digest=adapter_implementation_digest,
            backend_capabilities_digest=sha256_hex(caps.envelope()),
            topology_evidence_digest=topology_evidence_digest,
            probe_evidence_digest=probe_evidence_digest,
        )


@dataclass(frozen=True)
class CertificationPlaneAdapterAttestation:
    attestation_id: str
    deployment_digest: str
    authority_id: str
    authority_class: str
    key_id: str
    authority_generation: int
    attestation_nonce: str
    issued_at: str
    expires_at: str

    def envelope(self) -> dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return sha256_hex(self.envelope())


@dataclass(frozen=True)
class VerifiedCertificationPlaneAdapterAttestation:
    attestation_digest: str
    deployment_digest: str
    authority_id: str
    authority_class: str
    key_id: str
    authority_generation: int
    verified_at: str
    verifier_receipt_digest: str

    def envelope(self) -> dict[str, Any]:
        return asdict(self)


class CertificationPlaneAdapterAttestationVerifier(Protocol):
    """Independent verifier boundary for a concrete adapter deployment.

    A production implementation should verify asymmetric/HSM-backed release or
    supply-chain evidence outside the certification-plane deployment itself.
    """

    def verify(
        self,
        attestation: CertificationPlaneAdapterAttestation,
        deployment: CertificationPlaneDeploymentIdentity,
    ) -> VerifiedCertificationPlaneAdapterAttestation: ...


@dataclass(frozen=True)
class AdapterTrustStoreReadiness:
    production_ready: bool
    trust_store_id: str
    reason: str | None = None


class AdapterAttestationTrustStore(Protocol):
    """Durable replay/rollback authority for accepted adapter attestations."""

    def readiness(self) -> AdapterTrustStoreReadiness: ...

    def accept(
        self,
        deployment: CertificationPlaneDeploymentIdentity,
        attestation: CertificationPlaneAdapterAttestation,
        verified: VerifiedCertificationPlaneAdapterAttestation,
    ) -> None: ...


@dataclass(frozen=True)
class CertificationPlaneAdapterReadiness:
    production_ready: bool
    missing_requirements: tuple[str, ...]
    deployment_digest: str
    attestation_digest: str | None
    verifier_receipt_digest: str | None
    trust_store_id: str | None

    def envelope(self) -> dict[str, Any]:
        return {
            "production_ready": self.production_ready,
            "missing_requirements": list(self.missing_requirements),
            "deployment_digest": self.deployment_digest,
            "attestation_digest": self.attestation_digest,
            "verifier_receipt_digest": self.verifier_receipt_digest,
            "trust_store_id": self.trust_store_id,
        }


class ReferenceAdapterAttestationTrustStore:
    """Reference-only lifecycle store that can never authorize production.

    It is intentionally process-local. It detects replay/rollback semantics for
    tests but reports production_ready=False so it cannot be mistaken for a
    durable external release/control-plane authority.
    """

    def __init__(self, trust_store_id: str = "reference-adapter-attestation-store-v08"):
        self.trust_store_id = trust_store_id
        self.deployments: dict[str, dict[str, Any]] = {}
        self.nonces: dict[str, str] = {}

    def readiness(self) -> AdapterTrustStoreReadiness:
        return AdapterTrustStoreReadiness(
            production_ready=False,
            trust_store_id=self.trust_store_id,
            reason="reference_trust_store_not_production_durable",
        )

    def accept(self, deployment, attestation, verified) -> None:
        deployment_digest = deployment.digest()
        attestation_digest = attestation.digest()
        nonce_key = f"{deployment.deployment_id}:{attestation.attestation_nonce}"
        previous_nonce = self.nonces.get(nonce_key)
        if previous_nonce and previous_nonce != attestation_digest:
            raise HardeningError("CFHS_EVIDENCE_REPLAY", "Adapter attestation nonce was reused for different content")

        previous = self.deployments.get(deployment.deployment_id)
        if previous:
            if previous["backend_id"] != deployment.backend_id or previous["cluster_id"] != deployment.cluster_id:
                raise HardeningError("CFHS_CLUSTER_IDENTITY_CONFLICT", "Adapter deployment backend/cluster identity changed")
            previous_generation = int(previous["authority_generation"])
            if attestation.authority_generation < previous_generation:
                raise HardeningError("CFHS_AUTHORITY_ROLLBACK", "Adapter attestation authority generation cannot move backward")
            if attestation.authority_generation == previous_generation:
                if previous["authority_id"] != attestation.authority_id or previous["key_id"] != attestation.key_id:
                    raise HardeningError("CFHS_AUTHORITY_CONFLICT", "Adapter authority/key changed without a generation advance")
                if previous["deployment_digest"] != deployment_digest:
                    raise HardeningError("CFHS_HA_CERTIFICATION_CONFLICT", "Adapter deployment changed within the same authority generation")
        self.deployments[deployment.deployment_id] = {
            "backend_id": deployment.backend_id,
            "cluster_id": deployment.cluster_id,
            "deployment_digest": deployment_digest,
            "authority_id": attestation.authority_id,
            "key_id": attestation.key_id,
            "authority_generation": attestation.authority_generation,
            "attestation_digest": attestation_digest,
            "verifier_receipt_digest": verified.verifier_receipt_digest,
        }
        self.nonces[nonce_key] = attestation_digest


class CertificationPlaneAdapterCertifier:
    """Combines semantic backend guarantees with independent adapter trust."""

    def __init__(
        self,
        *,
        expected_adapter_name: str,
        expected_adapter_implementation_digest: str,
        max_attestation_age_seconds: int = 300,
        max_attestation_lifetime_seconds: int = 900,
        max_future_skew_seconds: int = 60,
    ):
        if not expected_adapter_name or not expected_adapter_implementation_digest:
            raise HardeningError("CFHS_INVALID_POLICY", "Trusted adapter release identity is required")
        if not 30 <= max_attestation_age_seconds <= 3600:
            raise HardeningError("CFHS_INVALID_POLICY", "Adapter attestation age policy is invalid")
        if not 30 <= max_attestation_lifetime_seconds <= 3600:
            raise HardeningError("CFHS_INVALID_POLICY", "Adapter attestation lifetime policy is invalid")
        if not 0 <= max_future_skew_seconds <= 300:
            raise HardeningError("CFHS_INVALID_POLICY", "Adapter attestation future-skew policy is invalid")
        self.expected_adapter_name = expected_adapter_name
        self.expected_adapter_implementation_digest = expected_adapter_implementation_digest
        self.max_attestation_age_seconds = max_attestation_age_seconds
        self.max_attestation_lifetime_seconds = max_attestation_lifetime_seconds
        self.max_future_skew_seconds = max_future_skew_seconds

    def certify(
        self,
        plane: SharedStateCertificationPlane,
        deployment: CertificationPlaneDeploymentIdentity,
        attestation: CertificationPlaneAdapterAttestation | None,
        verifier: CertificationPlaneAdapterAttestationVerifier | None,
        trust_store: AdapterAttestationTrustStore,
        *,
        now: datetime,
    ) -> CertificationPlaneAdapterReadiness:
        if now.tzinfo is None:
            raise HardeningError("CFHS_INVALID_EVIDENCE", "Adapter certification time must be timezone-aware")
        now = now.astimezone(timezone.utc)
        missing: list[str] = []
        caps: SharedBackendCapabilities = plane.backend.capabilities()
        backend_result = certify_backend(caps)
        missing.extend(backend_result.missing_requirements)

        if deployment.backend_id != caps.backend_id:
            missing.append("deployment_backend_identity")
        state = plane.current()
        if state.cluster_id and deployment.cluster_id != state.cluster_id:
            missing.append("deployment_cluster_identity")
        if deployment.backend_capabilities_digest != sha256_hex(caps.envelope()):
            missing.append("backend_capability_binding")
        if deployment.adapter_name != self.expected_adapter_name:
            missing.append("trusted_adapter_name")
        if deployment.adapter_implementation_digest != self.expected_adapter_implementation_digest:
            missing.append("trusted_adapter_implementation_digest")
        if not deployment.topology_evidence_digest:
            missing.append("topology_evidence_binding")
        if not deployment.probe_evidence_digest:
            missing.append("probe_evidence_binding")

        store_readiness = trust_store.readiness()
        if not store_readiness.production_ready:
            missing.append("production_adapter_attestation_trust_store")

        if attestation is None:
            missing.append("adapter_attestation")
            return CertificationPlaneAdapterReadiness(False, tuple(dict.fromkeys(missing)), deployment.digest(), None, None, store_readiness.trust_store_id)
        if verifier is None:
            missing.append("adapter_attestation_verifier")
            return CertificationPlaneAdapterReadiness(False, tuple(dict.fromkeys(missing)), deployment.digest(), attestation.digest(), None, store_readiness.trust_store_id)

        if attestation.deployment_digest != deployment.digest():
            missing.append("adapter_attestation_deployment_binding")
        if not attestation.attestation_id or not attestation.attestation_nonce or not attestation.authority_id or not attestation.key_id:
            missing.append("adapter_attestation_identity")
        if attestation.authority_class not in ALLOWED_ADAPTER_ATTESTATION_CLASSES:
            missing.append("adapter_attestation_authority_class")
        if isinstance(attestation.authority_generation, bool) or not isinstance(attestation.authority_generation, int) or attestation.authority_generation < 1:
            missing.append("adapter_attestation_authority_generation")

        issued = _parse_time(attestation.issued_at, "adapter attestation issued_at")
        expires = _parse_time(attestation.expires_at, "adapter attestation expires_at")
        if expires <= issued:
            missing.append("adapter_attestation_expiry_order")
        if expires - issued > timedelta(seconds=self.max_attestation_lifetime_seconds):
            missing.append("adapter_attestation_lifetime")
        if issued - now > timedelta(seconds=self.max_future_skew_seconds):
            missing.append("adapter_attestation_future_issue")
        if now - issued > timedelta(seconds=self.max_attestation_age_seconds):
            missing.append("adapter_attestation_freshness")
        if now >= expires:
            missing.append("adapter_attestation_expired")

        verified = None
        if not missing:
            try:
                verified = verifier.verify(attestation, deployment)
            except Exception as exc:
                raise HardeningError("CFHS_HA_CERTIFICATION_DENIED", "Independent adapter attestation verification failed") from exc
            if verified.attestation_digest != attestation.digest():
                missing.append("verified_adapter_attestation_digest")
            if verified.deployment_digest != deployment.digest():
                missing.append("verified_adapter_deployment_digest")
            if (
                verified.authority_id != attestation.authority_id
                or verified.authority_class != attestation.authority_class
                or verified.key_id != attestation.key_id
                or verified.authority_generation != attestation.authority_generation
            ):
                missing.append("verified_adapter_authority_binding")
            if not verified.verifier_receipt_digest:
                missing.append("verified_adapter_receipt")
            verified_at = _parse_time(verified.verified_at, "adapter attestation verified_at")
            if verified_at < issued - timedelta(seconds=self.max_future_skew_seconds) or verified_at >= expires:
                missing.append("verified_adapter_time_binding")

        if missing:
            return CertificationPlaneAdapterReadiness(
                False,
                tuple(dict.fromkeys(missing)),
                deployment.digest(),
                attestation.digest(),
                verified.verifier_receipt_digest if verified else None,
                store_readiness.trust_store_id,
            )

        trust_store.accept(deployment, attestation, verified)  # type: ignore[arg-type]
        return CertificationPlaneAdapterReadiness(
            production_ready=True,
            missing_requirements=(),
            deployment_digest=deployment.digest(),
            attestation_digest=attestation.digest(),
            verifier_receipt_digest=verified.verifier_receipt_digest,  # type: ignore[union-attr]
            trust_store_id=store_readiness.trust_store_id,
        )
