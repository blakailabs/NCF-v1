from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from .ha_persistence import HADeploymentEvidence, HAMemberEvidence, REQUIRED_PROBES
from .ha_probe_harness import HAProbeRunReport
from .hardening import HardeningError
from .trust import sha256_hex


def _parse_time(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise HardeningError("CFHS_INVALID_EVIDENCE", f"{field} timestamp is invalid") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


ALLOWED_TOPOLOGY_SOURCE_CLASSES = {
    "provider_control_plane",
    "cluster_consensus",
    "independent_observer",
}


@dataclass(frozen=True)
class HATopologySnapshot:
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
    source_id: str
    source_class: str
    source_receipt_digest: str

    def envelope(self) -> dict[str, Any]:
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
            "source_id": self.source_id,
            "source_class": self.source_class,
            "source_receipt_digest": self.source_receipt_digest,
        }

    def digest(self) -> str:
        return sha256_hex(self.envelope())


class HATopologyEvidenceSource(Protocol):
    def snapshot(self) -> HATopologySnapshot: ...


@dataclass(frozen=True)
class HAEvidenceAssembly:
    deployment_evidence: HADeploymentEvidence
    topology_digest: str
    topology_source_receipt_digest: str
    probe_report_digest: str
    assembly_digest: str
    certifiable_candidate: bool
    blocking_reasons: tuple[str, ...]

    def envelope(self) -> dict[str, Any]:
        return {
            "deployment_evidence_digest": self.deployment_evidence.digest(),
            "topology_digest": self.topology_digest,
            "topology_source_receipt_digest": self.topology_source_receipt_digest,
            "probe_report_digest": self.probe_report_digest,
            "assembly_digest": self.assembly_digest,
            "certifiable_candidate": self.certifiable_candidate,
            "blocking_reasons": list(self.blocking_reasons),
        }


class HAEvidenceAssembler:
    """Combines independent topology observation with active probe evidence.

    The final evidence nonce is derived from topology + source receipt + probe
    report digests. Callers do not choose it. This binds certification evidence
    to the exact observed source material used to assemble it.
    """

    def __init__(self, *, max_topology_probe_skew_seconds: int = 120):
        if (
            isinstance(max_topology_probe_skew_seconds, bool)
            or not isinstance(max_topology_probe_skew_seconds, int)
            or max_topology_probe_skew_seconds < 0
            or max_topology_probe_skew_seconds > 900
        ):
            raise HardeningError(
                "CFHS_INVALID_POLICY",
                "Topology/probe skew policy must be an integer from 0 to 900 seconds",
            )
        self.max_topology_probe_skew_seconds = max_topology_probe_skew_seconds

    def _validate_topology(self, snapshot: HATopologySnapshot) -> None:
        if not snapshot.backend_id or not snapshot.cluster_id or not snapshot.source_id:
            raise HardeningError("CFHS_INVALID_EVIDENCE", "Topology identity/source fields are required")
        if snapshot.source_class not in ALLOWED_TOPOLOGY_SOURCE_CLASSES:
            raise HardeningError("CFHS_INVALID_EVIDENCE", "Topology source class is not accepted")
        if not snapshot.source_receipt_digest:
            raise HardeningError("CFHS_INVALID_EVIDENCE", "Topology source receipt digest is required")
        if len(snapshot.source_receipt_digest) != 64:
            raise HardeningError("CFHS_INVALID_EVIDENCE", "Topology source receipt digest must be SHA-256 sized")
        if isinstance(snapshot.topology_epoch, bool) or not isinstance(snapshot.topology_epoch, int) or snapshot.topology_epoch < 1:
            raise HardeningError("CFHS_INVALID_EVIDENCE", "Topology epoch must be a positive integer")
        _parse_time(snapshot.observed_at, "topology observation")

    def _validate_report(self, snapshot: HATopologySnapshot, report: HAProbeRunReport) -> tuple[str, ...]:
        if report.backend_id != snapshot.backend_id:
            raise HardeningError(
                "CFHS_CONFLICT",
                "Probe report backend identity does not match topology snapshot",
                {"topology_backend_id": snapshot.backend_id, "probe_backend_id": report.backend_id},
            )
        if not report.report_digest or len(report.report_digest) != 64:
            raise HardeningError("CFHS_INVALID_EVIDENCE", "Probe report digest is missing or invalid")
        names = [result.name for result in report.results]
        if len(names) != len(set(names)):
            raise HardeningError("CFHS_INVALID_EVIDENCE", "Probe report contains duplicate probe identities")
        if any(name not in REQUIRED_PROBES for name in names):
            raise HardeningError("CFHS_INVALID_EVIDENCE", "Probe report contains unknown probe identity")

        topology_time = _parse_time(snapshot.observed_at, "topology observation")
        probe_start = _parse_time(report.started_at, "probe start")
        probe_end = _parse_time(report.completed_at, "probe completion")
        if probe_end < probe_start:
            raise HardeningError("CFHS_INVALID_EVIDENCE", "Probe report completion precedes start")
        skew = self.max_topology_probe_skew_seconds
        if topology_time < probe_start.replace() and (probe_start - topology_time).total_seconds() > skew:
            raise HardeningError("CFHS_EVIDENCE_WINDOW_MISMATCH", "Topology snapshot is too old relative to probe run")
        if topology_time > probe_end and (topology_time - probe_end).total_seconds() > skew:
            raise HardeningError("CFHS_EVIDENCE_WINDOW_MISMATCH", "Topology snapshot is too new relative to probe run")

        reasons: list[str] = []
        missing = sorted(set(REQUIRED_PROBES) - set(names))
        reasons.extend(f"probe_missing:{name}" for name in missing)
        reasons.extend(f"probe_blocked:{name}" for name in report.blocked())
        reasons.extend(f"probe_failed:{name}" for name in report.failed())
        return tuple(dict.fromkeys(reasons))

    def assemble(self, snapshot: HATopologySnapshot, report: HAProbeRunReport) -> HAEvidenceAssembly:
        self._validate_topology(snapshot)
        blocking = self._validate_report(snapshot, report)
        topology_digest = snapshot.digest()
        binding_digest = sha256_hex(
            {
                "contract": "ha-evidence-assembly/v0.8",
                "topology_digest": topology_digest,
                "topology_source_receipt_digest": snapshot.source_receipt_digest,
                "probe_report_digest": report.report_digest,
            }
        )
        evidence_nonce = "haevidence_" + binding_digest[:32]
        deployment = HADeploymentEvidence(
            backend_id=snapshot.backend_id,
            cluster_id=snapshot.cluster_id,
            topology_epoch=snapshot.topology_epoch,
            observed_at=snapshot.observed_at,
            members=snapshot.members,
            consensus_protocol=snapshot.consensus_protocol,
            write_quorum=snapshot.write_quorum,
            read_consistency_mode=snapshot.read_consistency_mode,
            read_quorum=snapshot.read_quorum,
            synchronous_commit=snapshot.synchronous_commit,
            synchronous_replica_acks=snapshot.synchronous_replica_acks,
            authoritative_time_source=snapshot.authoritative_time_source,
            lease_time_source=snapshot.lease_time_source,
            split_brain_protection=snapshot.split_brain_protection,
            probes=report.evidence(),
            evidence_issuer=f"assembly:{snapshot.source_class}:{snapshot.source_id}",
            evidence_nonce=evidence_nonce,
        )
        assembly_digest = sha256_hex(
            {
                "deployment_evidence_digest": deployment.digest(),
                "topology_digest": topology_digest,
                "topology_source_receipt_digest": snapshot.source_receipt_digest,
                "probe_report_digest": report.report_digest,
                "blocking_reasons": list(blocking),
            }
        )
        return HAEvidenceAssembly(
            deployment_evidence=deployment,
            topology_digest=topology_digest,
            topology_source_receipt_digest=snapshot.source_receipt_digest,
            probe_report_digest=report.report_digest,
            assembly_digest=assembly_digest,
            certifiable_candidate=not blocking,
            blocking_reasons=blocking,
        )

    def require_certifiable_candidate(
        self,
        snapshot: HATopologySnapshot,
        report: HAProbeRunReport,
    ) -> HAEvidenceAssembly:
        assembly = self.assemble(snapshot, report)
        if not assembly.certifiable_candidate:
            raise HardeningError(
                "CFHS_HA_EVIDENCE_INCOMPLETE",
                "Observed HA evidence is not complete enough for production certification",
                assembly.envelope(),
            )
        return assembly
