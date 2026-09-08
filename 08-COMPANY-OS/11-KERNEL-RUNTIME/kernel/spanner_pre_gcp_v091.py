from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping

from .hardening import HardeningError
from .spanner_backend_v091 import SpannerDeploymentConfig, SpannerProductionAdapterV091
from .spanner_live_certification_v091 import SPANNER_LIVE_PHASES, SpannerLiveCertificationReport
from .trust import sha256_hex


PRE_GCP_CONTRACT = "company-kernel-spanner-pre-gcp/v0.9.1"
CERT_PROJECT = "cfhs-kernel-cert"
CERT_INSTANCE = "kernel-ha-cert-01"
CERT_DATABASE = "cfhs-cert"
CERT_DEPLOYMENT = "company-kernel-cert-spanner-01"
CERT_INSTANCE_CONFIG = "regional-us-central1"


@dataclass(frozen=True)
class SpannerRuntimeReferences:
    project_id: str
    instance_id: str
    database_id: str
    deployment_id: str
    instance_config: str
    workload_identity_provider: str | None
    service_account_reference: str | None
    live_enabled: bool = False

    def envelope(self) -> dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return sha256_hex({"contract": PRE_GCP_CONTRACT, **self.envelope()})

    @classmethod
    def from_environment(cls, env: Mapping[str, str]) -> "SpannerRuntimeReferences":
        live = env.get("CFHS_SPANNER_LIVE_ENABLED", "false").strip().lower()
        if live not in {"true", "false"}:
            raise HardeningError("CFHS_SPANNER_RUNTIME_CONFIG_INVALID", "Live-enabled flag must be true or false")
        refs = cls(
            project_id=env.get("CFHS_SPANNER_PROJECT_ID", CERT_PROJECT),
            instance_id=env.get("CFHS_SPANNER_INSTANCE_ID", CERT_INSTANCE),
            database_id=env.get("CFHS_SPANNER_DATABASE_ID", CERT_DATABASE),
            deployment_id=env.get("CFHS_SPANNER_DEPLOYMENT_ID", CERT_DEPLOYMENT),
            instance_config=env.get("CFHS_SPANNER_INSTANCE_CONFIG", CERT_INSTANCE_CONFIG),
            workload_identity_provider=env.get("CFHS_GCP_WORKLOAD_IDENTITY_PROVIDER"),
            service_account_reference=env.get("CFHS_GCP_SERVICE_ACCOUNT_REFERENCE"),
            live_enabled=live == "true",
        )
        refs.validate()
        return refs

    def validate(self) -> None:
        expected = {
            "project_id": CERT_PROJECT,
            "instance_id": CERT_INSTANCE,
            "database_id": CERT_DATABASE,
            "deployment_id": CERT_DEPLOYMENT,
            "instance_config": CERT_INSTANCE_CONFIG,
        }
        for field, expected_value in expected.items():
            if getattr(self, field) != expected_value:
                raise HardeningError("CFHS_SPANNER_CERT_TARGET_MISMATCH", f"Certification target mismatch: {field}")
        for name, value in {
            "workload_identity_provider": self.workload_identity_provider,
            "service_account_reference": self.service_account_reference,
        }.items():
            if value and any(marker in value.lower() for marker in ("private_key", "password=", "token=", "secret=")):
                raise HardeningError("CFHS_SPANNER_SECRET_MATERIAL_DENIED", f"Secret-like material forbidden in {name}")
        if self.service_account_reference and not self.service_account_reference.startswith("principal://"):
            raise HardeningError("CFHS_SPANNER_RUNTIME_CONFIG_INVALID", "Service account must be an external principal reference")
        if self.live_enabled and (not self.workload_identity_provider or not self.service_account_reference):
            raise HardeningError("CFHS_SPANNER_LIVE_IDENTITY_REQUIRED", "Live Spanner requires complete keyless workload identity references")

    def adapter(self) -> SpannerProductionAdapterV091:
        credential_ref = None
        if self.live_enabled:
            credential_ref = "secret://gcp/workload-identity/runtime"
        return SpannerProductionAdapterV091(SpannerDeploymentConfig(
            deployment_id=self.deployment_id,
            project_id=self.project_id,
            instance_id=self.instance_id,
            database_id=self.database_id,
            instance_config=self.instance_config,
            database_dialect="GOOGLE_STANDARD_SQL",
            credential_source_class="workload_identity",
            credential_reference=credential_ref,
            live_reads_enabled=self.live_enabled,
            live_writes_enabled=self.live_enabled,
        ))


@dataclass(frozen=True)
class SpannerCertificationArtifact:
    contract: str
    deployment_digest: str
    report_digest: str
    production_ready: bool
    phases: tuple[dict[str, Any], ...]
    artifact_digest: str

    def envelope(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "deployment_digest": self.deployment_digest,
            "report_digest": self.report_digest,
            "production_ready": self.production_ready,
            "phases": list(self.phases),
            "artifact_digest": self.artifact_digest,
        }


def build_certification_artifact(report: SpannerLiveCertificationReport) -> SpannerCertificationArtifact:
    phases = tuple({
        "phase": result.phase,
        "status": result.status,
        "evidence_digest": result.evidence_digest,
        "reason": result.reason,
    } for result in report.results)
    body = {
        "contract": PRE_GCP_CONTRACT,
        "deployment_digest": report.deployment_digest,
        "report_digest": report.digest(),
        "production_ready": report.production_ready,
        "phases": list(phases),
    }
    return SpannerCertificationArtifact(**body, artifact_digest=sha256_hex(body))


def validate_artifact(artifact: SpannerCertificationArtifact) -> None:
    body = artifact.envelope()
    supplied = body.pop("artifact_digest")
    if sha256_hex(body) != supplied:
        raise HardeningError("CFHS_SPANNER_EVIDENCE_ARTIFACT_TAMPERED", "Certification artifact digest mismatch")
    phase_names = tuple(item.get("phase") for item in artifact.phases)
    if artifact.production_ready and phase_names != SPANNER_LIVE_PHASES:
        raise HardeningError("CFHS_SPANNER_EVIDENCE_ARTIFACT_INVALID", "Production-ready artifact requires all ordered live phases")
    if artifact.production_ready and any(item.get("status") != "PASS" for item in artifact.phases):
        raise HardeningError("CFHS_SPANNER_EVIDENCE_ARTIFACT_INVALID", "Production-ready artifact cannot contain negative phase evidence")
