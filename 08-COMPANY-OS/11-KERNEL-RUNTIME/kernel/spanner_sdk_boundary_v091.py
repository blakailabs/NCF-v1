from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .hardening import HardeningError
from .spanner_backend_v091 import SpannerProductionAdapterV091


SPANNER_SDK_BOUNDARY_CONTRACT = "company-kernel-spanner-sdk-boundary/v0.9.1"


class SpannerSDKClient(Protocol):
    """Provider SDK boundary. Implementations may wrap google-cloud-spanner.

    The kernel owns semantics, evidence shape, and fail-closed policy. The SDK
    implementation owns provider calls. No credential values cross this API.
    """

    def deployment_identity(self) -> dict[str, Any]: ...
    def schema_identity(self) -> dict[str, Any]: ...
    def multi_client_visibility(self) -> dict[str, Any]: ...
    def serializability_probe(self) -> dict[str, Any]: ...
    def stale_cas_probe(self) -> dict[str, Any]: ...
    def monotonic_fencing_probe(self) -> dict[str, Any]: ...
    def ordered_journal_probe(self) -> dict[str, Any]: ...
    def atomic_fenced_cas_journal_probe(self) -> dict[str, Any]: ...
    def commit_timestamp_probe(self) -> dict[str, Any]: ...
    def durability_restart_probe(self) -> dict[str, Any]: ...
    def topology_evidence(self) -> dict[str, Any]: ...
    def fault_quorum_evidence(self) -> dict[str, Any]: ...
    def external_attestation(self) -> dict[str, Any]: ...
    def neutral_certification(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class SpannerSDKProbePolicy:
    allow_network: bool = False
    allow_mutations: bool = False
    allow_fault_injection: bool = False
    allow_external_authority: bool = False


class SpannerSDKProbeDriverV091:
    """Maps S1-S14 to a concrete SDK boundary without self-certification."""

    READ_ONLY_PHASES = {
        "S1_DEPLOYMENT_IDENTITY",
        "S2_SCHEMA_IDENTITY",
        "S11_TOPOLOGY_EVIDENCE",
    }
    MUTATING_PHASES = {
        "S3_MULTI_CLIENT_VISIBILITY",
        "S4_SERIALIZABILITY",
        "S5_STALE_CAS_REJECTION",
        "S6_MONOTONIC_FENCING",
        "S7_ORDERED_JOURNAL",
        "S8_ATOMIC_FENCED_CAS_JOURNAL",
        "S9_COMMIT_TIMESTAMP_ORDERING",
        "S10_DURABILITY_RESTART",
    }
    EXTERNAL_PHASES = {
        "S12_FAULT_QUORUM_EVIDENCE",
        "S13_EXTERNAL_ATTESTATION",
        "S14_NEUTRAL_V09_CERTIFICATION",
    }
    METHODS = {
        "S1_DEPLOYMENT_IDENTITY": "deployment_identity",
        "S2_SCHEMA_IDENTITY": "schema_identity",
        "S3_MULTI_CLIENT_VISIBILITY": "multi_client_visibility",
        "S4_SERIALIZABILITY": "serializability_probe",
        "S5_STALE_CAS_REJECTION": "stale_cas_probe",
        "S6_MONOTONIC_FENCING": "monotonic_fencing_probe",
        "S7_ORDERED_JOURNAL": "ordered_journal_probe",
        "S8_ATOMIC_FENCED_CAS_JOURNAL": "atomic_fenced_cas_journal_probe",
        "S9_COMMIT_TIMESTAMP_ORDERING": "commit_timestamp_probe",
        "S10_DURABILITY_RESTART": "durability_restart_probe",
        "S11_TOPOLOGY_EVIDENCE": "topology_evidence",
        "S12_FAULT_QUORUM_EVIDENCE": "fault_quorum_evidence",
        "S13_EXTERNAL_ATTESTATION": "external_attestation",
        "S14_NEUTRAL_V09_CERTIFICATION": "neutral_certification",
    }

    def __init__(self, client: SpannerSDKClient, policy: SpannerSDKProbePolicy | None = None):
        self.client = client
        self.policy = policy or SpannerSDKProbePolicy()

    def _blocked(self, reason: str) -> dict[str, Any]:
        return {"status": "BLOCKED", "reason": reason}

    def execute(self, phase: str, adapter: SpannerProductionAdapterV091) -> dict[str, Any]:
        if phase not in self.METHODS:
            raise HardeningError("CFHS_SPANNER_PROBE_PHASE_UNKNOWN", f"Unknown Spanner live phase: {phase}")
        if not adapter.readiness().live_integration_ready:
            return self._blocked("live_spanner_integration_not_enabled")
        if not self.policy.allow_network:
            return self._blocked("provider_network_access_not_enabled")
        if phase in self.MUTATING_PHASES and not self.policy.allow_mutations:
            return self._blocked("provider_mutations_not_enabled")
        if phase == "S12_FAULT_QUORUM_EVIDENCE" and not self.policy.allow_fault_injection:
            return self._blocked("independent_fault_control_not_enabled")
        if phase in {"S13_EXTERNAL_ATTESTATION", "S14_NEUTRAL_V09_CERTIFICATION"} and not self.policy.allow_external_authority:
            return self._blocked("external_authority_not_enabled")

        method = getattr(self.client, self.METHODS[phase])
        observed = method()
        if not isinstance(observed, dict) or not observed:
            return {"status": "FAIL", "reason": "provider_probe_returned_no_observed_evidence"}
        if "status" in observed:
            raise HardeningError("CFHS_SPANNER_PROVIDER_SELF_CERTIFICATION_DENIED", "SDK client may return observations, never PASS/FAIL/BLOCKED")
        if any(key.lower() in {"password", "token", "secret", "private_key", "credentials"} for key in observed):
            raise HardeningError("CFHS_SPANNER_EVIDENCE_SECRET_DENIED", "Observed evidence cannot contain credential material")
        return {
            "status": "PASS",
            "evidence": {
                "contract": SPANNER_SDK_BOUNDARY_CONTRACT,
                "phase": phase,
                "backend_id": adapter.backend_id,
                "cluster_id": adapter.cluster_id,
                "observed": observed,
            },
        }
