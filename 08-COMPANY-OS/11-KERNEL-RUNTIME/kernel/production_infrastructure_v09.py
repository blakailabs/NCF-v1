from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from .hardening import HardeningError
from .trust import sha256_hex


ALLOWED_CREDENTIAL_SOURCE_CLASSES = {
    "workload_identity",
    "external_secret_manager",
    "hsm_kms_identity",
    "managed_identity",
}

REQUIRED_CAPABILITIES = (
    "serializable_transactions",
    "compare_and_swap",
    "monotonic_fencing",
    "ordered_journal",
    "synchronous_durability",
    "authoritative_shared_time",
    "distributed_quorum",
    "split_brain_protection",
)

REQUIRED_EVIDENCE_PHASES = (
    "static_deployment_identity",
    "live_capability_probes",
    "multi_client_consistency",
    "fault_partition_probes",
    "external_attestation",
    "bootstrap_certification",
    "steady_state_activation",
    "runtime_enrollment_activation",
    "restart_cross_process_recovery",
)


@dataclass(frozen=True)
class ProductionInfrastructureEvidenceBundle:
    deployment_id: str
    provider_id: str
    adapter_name: str
    adapter_version: str
    adapter_implementation_digest: str
    backend_id: str
    cluster_id: str
    capability_digest: str
    topology_evidence_digest: str
    probe_evidence_digest: str
    release_attestation_digest: str
    trust_store_id: str
    authority_id: str
    authority_class: str
    authority_generation: int
    credential_source_class: str
    observed_at: str
    valid_until: str
    evidence_nonce: str
    capability_claims: tuple[str, ...]
    evidence_phases: tuple[str, ...]

    def envelope(self) -> dict[str, Any]:
        value = asdict(self)
        value["capability_claims"] = list(self.capability_claims)
        value["evidence_phases"] = list(self.evidence_phases)
        return value

    def digest(self) -> str:
        return sha256_hex(self.envelope())


@dataclass(frozen=True)
class VerifiedProductionInfrastructureEvidence:
    deployment_digest: str
    verifier_id: str
    verifier_class: str
    verifier_receipt_digest: str
    verified_at: str
    production_trust_store_id: str

    def envelope(self) -> dict[str, Any]:
        return asdict(self)


class ProductionInfrastructureEvidenceVerifier(Protocol):
    def verify(
        self,
        evidence: ProductionInfrastructureEvidenceBundle,
    ) -> VerifiedProductionInfrastructureEvidence: ...


@dataclass(frozen=True)
class ProductionInfrastructureReadiness:
    production_ready: bool
    deployment_digest: str
    verifier_receipt_digest: str | None
    missing_requirements: tuple[str, ...]

    def envelope(self) -> dict[str, Any]:
        return {
            "production_ready": self.production_ready,
            "deployment_digest": self.deployment_digest,
            "verifier_receipt_digest": self.verifier_receipt_digest,
            "missing_requirements": list(self.missing_requirements),
        }


class ProductionInfrastructureCertifier:
    """Provider-neutral production infrastructure certification boundary.

    The certifier accepts observed evidence plus an external verifier. It never
    accepts caller-supplied `production_ready` flags, secret material, or a
    provider's self-assertion as proof of readiness.
    """

    def __init__(self, *, max_evidence_age_seconds: int = 300):
        if isinstance(max_evidence_age_seconds, bool) or not isinstance(max_evidence_age_seconds, int) or not 30 <= max_evidence_age_seconds <= 3600:
            raise HardeningError("CFHS_INVALID_POLICY", "Production infrastructure evidence age must be 30..3600 seconds")
        self.max_evidence_age_seconds = max_evidence_age_seconds

    @staticmethod
    def _parse_time(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception as exc:
            raise HardeningError("CFHS_INVALID_EVIDENCE", "Production infrastructure timestamp is invalid") from exc
        if parsed.tzinfo is None:
            raise HardeningError("CFHS_INVALID_EVIDENCE", "Production infrastructure timestamps must be timezone-aware")
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _looks_like_secret(value: str) -> bool:
        lowered = value.lower()
        return any(marker in lowered for marker in (
            "-----begin private key-----",
            "password=",
            "secret=",
            "token=",
            "api_key=",
            "apikey=",
        ))

    def _bundle_failures(self, evidence: ProductionInfrastructureEvidenceBundle, now: datetime) -> list[str]:
        failures: list[str] = []
        required_strings = {
            "deployment_id": evidence.deployment_id,
            "provider_id": evidence.provider_id,
            "adapter_name": evidence.adapter_name,
            "adapter_version": evidence.adapter_version,
            "adapter_implementation_digest": evidence.adapter_implementation_digest,
            "backend_id": evidence.backend_id,
            "cluster_id": evidence.cluster_id,
            "capability_digest": evidence.capability_digest,
            "topology_evidence_digest": evidence.topology_evidence_digest,
            "probe_evidence_digest": evidence.probe_evidence_digest,
            "release_attestation_digest": evidence.release_attestation_digest,
            "trust_store_id": evidence.trust_store_id,
            "authority_id": evidence.authority_id,
            "authority_class": evidence.authority_class,
            "evidence_nonce": evidence.evidence_nonce,
        }
        for name, value in required_strings.items():
            if not value:
                failures.append(f"missing:{name}")
            elif self._looks_like_secret(value):
                failures.append(f"secret_material_forbidden:{name}")

        if isinstance(evidence.authority_generation, bool) or not isinstance(evidence.authority_generation, int) or evidence.authority_generation < 1:
            failures.append("authority_generation_invalid")

        if evidence.credential_source_class not in ALLOWED_CREDENTIAL_SOURCE_CLASSES:
            failures.append("credential_source_class_invalid")

        if evidence.authority_id == evidence.provider_id:
            failures.append("provider_self_certification_forbidden")

        claims = set(evidence.capability_claims)
        for capability in REQUIRED_CAPABILITIES:
            if capability not in claims:
                failures.append(f"capability_missing:{capability}")

        phases = set(evidence.evidence_phases)
        for phase in REQUIRED_EVIDENCE_PHASES:
            if phase not in phases:
                failures.append(f"evidence_phase_missing:{phase}")

        observed = self._parse_time(evidence.observed_at)
        valid_until = self._parse_time(evidence.valid_until)
        age = (now - observed).total_seconds()
        if age < -60:
            failures.append("evidence_time_in_future")
        elif age > self.max_evidence_age_seconds:
            failures.append("evidence_stale")
        if valid_until <= now:
            failures.append("evidence_expired")
        if valid_until <= observed:
            failures.append("evidence_validity_window_invalid")
        return failures

    def certify(
        self,
        evidence: ProductionInfrastructureEvidenceBundle,
        verifier: ProductionInfrastructureEvidenceVerifier | None,
        *,
        now: datetime,
    ) -> ProductionInfrastructureReadiness:
        if now.tzinfo is None:
            raise HardeningError("CFHS_INVALID_EVIDENCE", "Certification time must be timezone-aware")
        current = now.astimezone(timezone.utc)
        failures = self._bundle_failures(evidence, current)
        verified: VerifiedProductionInfrastructureEvidence | None = None

        if verifier is None:
            failures.append("external_verifier_missing")
        else:
            try:
                verified = verifier.verify(evidence)
            except Exception:
                failures.append("external_verifier_failed")
            else:
                if verified.deployment_digest != evidence.digest():
                    failures.append("external_verifier_digest_mismatch")
                if not verified.verifier_id or not verified.verifier_receipt_digest or not verified.production_trust_store_id:
                    failures.append("external_verifier_incomplete")
                if verified.verifier_id in {evidence.provider_id, evidence.authority_id}:
                    failures.append("external_verifier_not_independent")
                if verified.verifier_class not in {"independent_infrastructure_attestation", "enterprise_release_authority", "external_certification_service"}:
                    failures.append("external_verifier_class_invalid")
                try:
                    verified_at = self._parse_time(verified.verified_at)
                except HardeningError:
                    failures.append("external_verifier_time_invalid")
                else:
                    verifier_age = (current - verified_at).total_seconds()
                    if verifier_age < -60:
                        failures.append("external_verifier_time_in_future")
                    elif verifier_age > self.max_evidence_age_seconds:
                        failures.append("external_verifier_stale")

        unique = tuple(dict.fromkeys(failures))
        return ProductionInfrastructureReadiness(
            production_ready=not unique,
            deployment_digest=evidence.digest(),
            verifier_receipt_digest=verified.verifier_receipt_digest if verified else None,
            missing_requirements=unique,
        )

    def require_production_ready(
        self,
        evidence: ProductionInfrastructureEvidenceBundle,
        verifier: ProductionInfrastructureEvidenceVerifier | None,
        *,
        now: datetime,
    ) -> ProductionInfrastructureReadiness:
        result = self.certify(evidence, verifier, now=now)
        if not result.production_ready:
            raise HardeningError(
                "CFHS_PRODUCTION_INFRASTRUCTURE_NOT_READY",
                "Production infrastructure evidence did not satisfy the v0.9 contract",
                result.envelope(),
            )
        return result
