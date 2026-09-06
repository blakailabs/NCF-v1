from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from .hardening import HardeningError
from .shared_state_backend import SharedBackendCapabilities, SharedFencedPersistenceBackend, certify_backend
from .trust import sha256_hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class HAMemberEvidence:
    member_id: str
    voting: bool
    healthy: bool
    failure_domain: str

    def envelope(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HAProbeEvidence:
    name: str
    passed: bool
    observed_at: str
    evidence_digest: str

    def envelope(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HADeploymentEvidence:
    backend_id: str
    cluster_id: str
    topology_epoch: int
    observed_at: str
    members: tuple[HAMemberEvidence, ...]
    consensus_protocol: str
    write_quorum: int
    read_quorum: int
    synchronous_commit: bool
    synchronous_replica_acks: int
    authoritative_time_source: str
    lease_time_source: str
    split_brain_protection: bool
    probes: tuple[HAProbeEvidence, ...]
    evidence_issuer: str
    evidence_nonce: str

    def unsigned_envelope(self) -> dict[str, Any]:
        return {
            "backend_id": self.backend_id,
            "cluster_id": self.cluster_id,
            "topology_epoch": self.topology_epoch,
            "observed_at": self.observed_at,
            "members": [member.envelope() for member in self.members],
            "consensus_protocol": self.consensus_protocol,
            "write_quorum": self.write_quorum,
            "read_quorum": self.read_quorum,
            "synchronous_commit": self.synchronous_commit,
            "synchronous_replica_acks": self.synchronous_replica_acks,
            "authoritative_time_source": self.authoritative_time_source,
            "lease_time_source": self.lease_time_source,
            "split_brain_protection": self.split_brain_protection,
            "probes": [probe.envelope() for probe in self.probes],
            "evidence_issuer": self.evidence_issuer,
            "evidence_nonce": self.evidence_nonce,
        }

    def digest(self) -> str:
        return sha256_hex(self.unsigned_envelope())


@dataclass(frozen=True)
class VerifiedDeploymentAttestation:
    issuer_id: str
    evidence_digest: str
    verification_class: str
    verified_at: str
    verifier_receipt_digest: str

    def envelope(self) -> dict[str, Any]:
        return asdict(self)


class DeploymentEvidenceVerifier(Protocol):
    def verify(self, evidence: HADeploymentEvidence) -> VerifiedDeploymentAttestation: ...


@dataclass(frozen=True)
class HAPersistenceCertification:
    backend_id: str
    capability_contract_ready: bool
    deployment_structure_ready: bool
    trusted_attestation_ready: bool
    production_ready: bool
    missing_requirements: tuple[str, ...]
    evidence_digest: str
    attestation: VerifiedDeploymentAttestation | None

    def envelope(self) -> dict[str, Any]:
        return {
            "backend_id": self.backend_id,
            "capability_contract_ready": self.capability_contract_ready,
            "deployment_structure_ready": self.deployment_structure_ready,
            "trusted_attestation_ready": self.trusted_attestation_ready,
            "production_ready": self.production_ready,
            "missing_requirements": list(self.missing_requirements),
            "evidence_digest": self.evidence_digest,
            "attestation": self.attestation.envelope() if self.attestation else None,
        }


REQUIRED_PROBES = (
    "serializable_transaction",
    "compare_and_swap",
    "monotonic_fencing",
    "ordered_journal",
    "multi_connection_visibility",
    "synchronous_durability",
    "authoritative_time",
    "quorum_loss_fail_closed",
    "stale_owner_rejected_after_takeover",
    "network_partition_single_writer",
)

ALLOWED_TIME_SOURCES = {
    "database_server",
    "consensus_service",
    "cluster_logical_clock",
}


class HAPersistenceCertifier:
    """Evidence-based production-readiness gate for shared kernel state.

    The v0.7 capability flags are necessary but not sufficient. Production
    certification additionally requires recent cluster topology evidence,
    majority/quorum structure, authoritative backend time, split-brain defense,
    behavioral probes, and independent trusted attestation.
    """

    def __init__(self, *, max_evidence_age_seconds: int = 300):
        if (
            isinstance(max_evidence_age_seconds, bool)
            or not isinstance(max_evidence_age_seconds, int)
            or max_evidence_age_seconds < 30
            or max_evidence_age_seconds > 3600
        ):
            raise HardeningError(
                "CFHS_INVALID_POLICY",
                "HA evidence maximum age must be an integer from 30 to 3600 seconds",
            )
        self.max_evidence_age_seconds = max_evidence_age_seconds

    @staticmethod
    def _parse_time(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception as exc:
            raise HardeningError("CFHS_INVALID_EVIDENCE", "HA evidence timestamp is invalid") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _majority(voters: int) -> int:
        return voters // 2 + 1

    def _structural_failures(
        self,
        capabilities: SharedBackendCapabilities,
        evidence: HADeploymentEvidence,
        now: datetime,
    ) -> list[str]:
        failures: list[str] = []
        if evidence.backend_id != capabilities.backend_id:
            failures.append("backend_identity_mismatch")
        if not evidence.cluster_id:
            failures.append("cluster_identity_missing")
        if isinstance(evidence.topology_epoch, bool) or evidence.topology_epoch < 1:
            failures.append("topology_epoch_invalid")
        if not evidence.evidence_issuer or not evidence.evidence_nonce:
            failures.append("evidence_provenance_missing")

        observed = self._parse_time(evidence.observed_at)
        age = (now - observed).total_seconds()
        if age < -60:
            failures.append("evidence_time_in_future")
        elif age > self.max_evidence_age_seconds:
            failures.append("evidence_stale")

        member_ids = [m.member_id for m in evidence.members]
        if not member_ids or any(not member_id for member_id in member_ids):
            failures.append("member_identity_missing")
        if len(member_ids) != len(set(member_ids)):
            failures.append("member_identity_duplicate")

        voters = [member for member in evidence.members if member.voting]
        healthy_voters = [member for member in voters if member.healthy]
        voter_count = len(voters)
        majority = self._majority(voter_count) if voter_count else 0
        if voter_count < 3:
            failures.append("minimum_three_voting_members_required")
        if len(healthy_voters) < majority:
            failures.append("healthy_voting_quorum_unavailable")
        failure_domains = {member.failure_domain for member in voters if member.failure_domain}
        if len(failure_domains) < 3:
            failures.append("minimum_three_failure_domains_required")

        if not evidence.consensus_protocol.strip():
            failures.append("consensus_protocol_missing")
        if evidence.write_quorum < majority:
            failures.append("write_quorum_below_majority")
        if evidence.read_quorum < 1:
            failures.append("read_quorum_invalid")
        if evidence.write_quorum + evidence.read_quorum <= voter_count:
            failures.append("read_write_quorum_intersection_not_proven")
        if not evidence.synchronous_commit:
            failures.append("synchronous_commit_disabled")
        if evidence.synchronous_replica_acks < max(1, evidence.write_quorum - 1):
            failures.append("synchronous_replica_ack_insufficient")

        if evidence.authoritative_time_source not in ALLOWED_TIME_SOURCES:
            failures.append("authoritative_time_source_invalid")
        if evidence.lease_time_source not in ALLOWED_TIME_SOURCES:
            failures.append("lease_time_source_invalid")
        if evidence.lease_time_source == "client_clock":
            failures.append("client_clock_lease_forbidden")
        if not evidence.split_brain_protection:
            failures.append("split_brain_protection_missing")

        probes = {probe.name: probe for probe in evidence.probes}
        for name in REQUIRED_PROBES:
            probe = probes.get(name)
            if not probe:
                failures.append(f"probe_missing:{name}")
                continue
            if not probe.passed:
                failures.append(f"probe_failed:{name}")
            if not probe.evidence_digest:
                failures.append(f"probe_evidence_missing:{name}")
            try:
                probe_age = (now - self._parse_time(probe.observed_at)).total_seconds()
            except HardeningError:
                failures.append(f"probe_time_invalid:{name}")
                continue
            if probe_age < -60 or probe_age > self.max_evidence_age_seconds:
                failures.append(f"probe_stale:{name}")
        return failures

    def certify(
        self,
        backend: SharedFencedPersistenceBackend,
        evidence: HADeploymentEvidence,
        verifier: DeploymentEvidenceVerifier | None,
        *,
        now: datetime | None = None,
    ) -> HAPersistenceCertification:
        capabilities = backend.capabilities()
        capability_result = certify_backend(capabilities)
        current = (now or utcnow()).astimezone(timezone.utc)
        failures = list(capability_result.missing_requirements)
        failures.extend(self._structural_failures(capabilities, evidence, current))

        attestation: VerifiedDeploymentAttestation | None = None
        if verifier is None:
            failures.append("trusted_attestation_missing")
        else:
            try:
                attestation = verifier.verify(evidence)
            except Exception:
                failures.append("trusted_attestation_failed")
            else:
                if attestation.evidence_digest != evidence.digest():
                    failures.append("trusted_attestation_digest_mismatch")
                if not attestation.issuer_id or not attestation.verifier_receipt_digest:
                    failures.append("trusted_attestation_incomplete")
                if attestation.verification_class not in {
                    "provider_control_plane",
                    "cluster_consensus_attestation",
                    "independent_observer",
                }:
                    failures.append("trusted_attestation_class_invalid")

        deduped = tuple(dict.fromkeys(failures))
        capability_ready = capability_result.production_ready
        structural_ready = not any(
            failure not in capability_result.missing_requirements
            and not failure.startswith("trusted_attestation")
            for failure in deduped
        )
        attestation_ready = attestation is not None and not any(
            failure.startswith("trusted_attestation") for failure in deduped
        )
        production_ready = capability_ready and structural_ready and attestation_ready and not deduped
        return HAPersistenceCertification(
            backend_id=capabilities.backend_id,
            capability_contract_ready=capability_ready,
            deployment_structure_ready=structural_ready,
            trusted_attestation_ready=attestation_ready,
            production_ready=production_ready,
            missing_requirements=deduped,
            evidence_digest=evidence.digest(),
            attestation=attestation,
        )

    def require_production_ready(
        self,
        backend: SharedFencedPersistenceBackend,
        evidence: HADeploymentEvidence,
        verifier: DeploymentEvidenceVerifier | None,
        *,
        now: datetime | None = None,
    ) -> HAPersistenceCertification:
        result = self.certify(backend, evidence, verifier, now=now)
        if not result.production_ready:
            raise HardeningError(
                "CFHS_HA_PERSISTENCE_NOT_READY",
                "Shared persistence backend did not satisfy production HA certification",
                result.envelope(),
            )
        return result
