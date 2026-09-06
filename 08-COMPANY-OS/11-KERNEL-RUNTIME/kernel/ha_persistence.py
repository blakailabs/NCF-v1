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
    read_consistency_mode: str
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
            "read_consistency_mode": self.read_consistency_mode,
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

ALLOWED_READ_CONSISTENCY_MODES = {
    "quorum",
    "leader_linearizable",
    "serializable_transaction",
}


class HAPersistenceCertifier:
    """Evidence-based production-readiness gate for shared kernel state.

    Capability flags are necessary but not sufficient. Production certification
    additionally requires recent topology evidence, a policy-acceptable voting
    layout, authoritative backend time, split-brain defense, behavioral probes,
    and independently verified deployment evidence.

    Minimum voter/failure-domain counts are Company OS release policy, not a
    claim that every consensus database universally requires the same topology.
    """

    def __init__(
        self,
        *,
        max_evidence_age_seconds: int = 300,
        minimum_voting_members: int = 3,
        minimum_failure_domains: int = 3,
    ):
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
        if (
            isinstance(minimum_voting_members, bool)
            or not isinstance(minimum_voting_members, int)
            or minimum_voting_members < 3
        ):
            raise HardeningError(
                "CFHS_INVALID_POLICY",
                "HA production policy requires at least three voting members",
            )
        if (
            isinstance(minimum_failure_domains, bool)
            or not isinstance(minimum_failure_domains, int)
            or minimum_failure_domains < 2
        ):
            raise HardeningError(
                "CFHS_INVALID_POLICY",
                "HA production policy requires at least two failure domains",
            )
        self.max_evidence_age_seconds = max_evidence_age_seconds
        self.minimum_voting_members = minimum_voting_members
        self.minimum_failure_domains = minimum_failure_domains

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
        if voter_count < self.minimum_voting_members:
            failures.append("minimum_voting_members_not_met")
        if len(healthy_voters) < majority:
            failures.append("healthy_voting_quorum_unavailable")
        failure_domains = {member.failure_domain for member in voters if member.failure_domain}
        if len(failure_domains) < self.minimum_failure_domains:
            failures.append("minimum_failure_domains_not_met")

        if not evidence.consensus_protocol.strip():
            failures.append("consensus_protocol_missing")
        if evidence.write_quorum < majority:
            failures.append("write_quorum_below_majority")

        if evidence.read_consistency_mode not in ALLOWED_READ_CONSISTENCY_MODES:
            failures.append("read_consistency_mode_invalid")
        elif evidence.read_consistency_mode == "quorum":
            if evidence.read_quorum < 1:
                failures.append("read_quorum_invalid")
            elif evidence.write_quorum + evidence.read_quorum <= voter_count:
                failures.append("read_write_quorum_intersection_not_proven")
        else:
            if evidence.read_quorum < 1:
                failures.append("linearizable_read_path_missing")

        if not evidence.synchronous_commit:
            failures.append("synchronous_commit_disabled")
        if evidence.synchronous_replica_acks < max(1, evidence.write_quorum - 1):
            failures.append("synchronous_replica_ack_insufficient")

        if evidence.authoritative_time_source not in ALLOWED_TIME_SOURCES:
            failures.append("authoritative_time_source_invalid")
        if evidence.lease_time_source not in ALLOWED_TIME_SOURCES:
            failures.append("lease_time_source_invalid")
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

    @staticmethod
    def _attestation_failures(
        evidence: HADeploymentEvidence,
        verifier: DeploymentEvidenceVerifier | None,
    ) -> tuple[VerifiedDeploymentAttestation | None, list[str]]:
        if verifier is None:
            return None, ["trusted_attestation_missing"]
        try:
            attestation = verifier.verify(evidence)
        except Exception:
            return None, ["trusted_attestation_failed"]

        failures: list[str] = []
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
        return attestation, failures

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
        structural_failures = self._structural_failures(capabilities, evidence, current)
        attestation, attestation_failures = self._attestation_failures(evidence, verifier)
        all_failures = tuple(
            dict.fromkeys(
                list(capability_result.missing_requirements)
                + structural_failures
                + attestation_failures
            )
        )
        capability_ready = capability_result.production_ready
        structural_ready = not structural_failures
        attestation_ready = attestation is not None and not attestation_failures
        production_ready = (
            capability_ready
            and structural_ready
            and attestation_ready
            and not all_failures
        )
        return HAPersistenceCertification(
            backend_id=capabilities.backend_id,
            capability_contract_ready=capability_ready,
            deployment_structure_ready=structural_ready,
            trusted_attestation_ready=attestation_ready,
            production_ready=production_ready,
            missing_requirements=all_failures,
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
