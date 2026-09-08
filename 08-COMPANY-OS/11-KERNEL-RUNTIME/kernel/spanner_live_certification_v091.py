from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .hardening import HardeningError
from .spanner_backend_v091 import SpannerProductionAdapterV091
from .trust import sha256_hex


SPANNER_LIVE_PHASES = (
    "S1_DEPLOYMENT_IDENTITY",
    "S2_SCHEMA_IDENTITY",
    "S3_MULTI_CLIENT_VISIBILITY",
    "S4_SERIALIZABILITY",
    "S5_STALE_CAS_REJECTION",
    "S6_MONOTONIC_FENCING",
    "S7_ORDERED_JOURNAL",
    "S8_ATOMIC_FENCED_CAS_JOURNAL",
    "S9_COMMIT_TIMESTAMP_ORDERING",
    "S10_DURABILITY_RESTART",
    "S11_TOPOLOGY_EVIDENCE",
    "S12_FAULT_QUORUM_EVIDENCE",
    "S13_EXTERNAL_ATTESTATION",
    "S14_NEUTRAL_V09_CERTIFICATION",
)


@dataclass(frozen=True)
class SpannerLivePhaseResult:
    phase: str
    status: str
    evidence_digest: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class SpannerLiveCertificationReport:
    deployment_digest: str
    results: tuple[SpannerLivePhaseResult, ...]

    @property
    def production_ready(self) -> bool:
        return len(self.results) == len(SPANNER_LIVE_PHASES) and all(r.status == "PASS" for r in self.results)

    def digest(self) -> str:
        return sha256_hex({
            "deployment_digest": self.deployment_digest,
            "results": [r.__dict__ for r in self.results],
        })


class SpannerLiveProbeDriver(Protocol):
    """Independent live driver. Implementations may use Google Cloud SDKs.

    The kernel orchestrator never imports credentials or provider SDKs itself.
    Each phase returns observed evidence, not a caller-selected readiness flag.
    """

    def execute(self, phase: str, adapter: SpannerProductionAdapterV091) -> dict[str, Any]: ...


class SpannerLiveCertificationOrchestrator:
    def __init__(self, adapter: SpannerProductionAdapterV091):
        self.adapter = adapter

    @staticmethod
    def _result(phase: str, payload: dict[str, Any]) -> SpannerLivePhaseResult:
        status = payload.get("status")
        if status not in {"PASS", "FAIL", "BLOCKED"}:
            raise HardeningError("CFHS_SPANNER_PROBE_INVALID", f"Invalid live probe status for {phase}")
        evidence = payload.get("evidence")
        reason = payload.get("reason")
        if status == "PASS" and (not isinstance(evidence, dict) or not evidence):
            raise HardeningError("CFHS_SPANNER_PROBE_INVALID", f"PASS requires observed evidence for {phase}")
        if status in {"FAIL", "BLOCKED"} and not reason:
            raise HardeningError("CFHS_SPANNER_PROBE_INVALID", f"{status} requires a reason for {phase}")
        return SpannerLivePhaseResult(
            phase=phase,
            status=status,
            evidence_digest=sha256_hex(evidence) if isinstance(evidence, dict) and evidence else None,
            reason=str(reason) if reason else None,
        )

    def run(self, driver: SpannerLiveProbeDriver | None) -> SpannerLiveCertificationReport:
        readiness = self.adapter.readiness()
        if not readiness.live_integration_ready:
            return SpannerLiveCertificationReport(
                deployment_digest=self.adapter.config.deployment_digest(),
                results=(SpannerLivePhaseResult(
                    phase="PRECONDITION",
                    status="BLOCKED",
                    reason="live_spanner_integration_not_enabled",
                ),),
            )
        if driver is None:
            return SpannerLiveCertificationReport(
                deployment_digest=self.adapter.config.deployment_digest(),
                results=(SpannerLivePhaseResult(
                    phase="PRECONDITION",
                    status="BLOCKED",
                    reason="independent_live_probe_driver_not_connected",
                ),),
            )

        results: list[SpannerLivePhaseResult] = []
        for phase in SPANNER_LIVE_PHASES:
            try:
                result = self._result(phase, driver.execute(phase, self.adapter))
            except HardeningError:
                raise
            except Exception as exc:
                result = SpannerLivePhaseResult(phase=phase, status="FAIL", reason=f"probe_exception:{type(exc).__name__}")
            results.append(result)
            # Fail closed and preserve the first negative boundary. Later phases
            # may depend on authority/evidence that has not been earned.
            if result.status != "PASS":
                break
        return SpannerLiveCertificationReport(self.adapter.config.deployment_digest(), tuple(results))
