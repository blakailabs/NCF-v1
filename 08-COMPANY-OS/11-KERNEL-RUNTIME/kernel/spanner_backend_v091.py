from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .hardening import HardeningError
from .production_infrastructure_v09 import (
    ProductionInfrastructureEvidenceBundle,
    REQUIRED_CAPABILITIES,
    REQUIRED_EVIDENCE_PHASES,
)
from .trust import sha256_hex


SPANNER_ADAPTER_CONTRACT = "company-kernel-spanner-adapter/v0.9.1"
SPANNER_PROVIDER_ID = "google-cloud-spanner"
SPANNER_ALLOWED_DIALECTS = {"GOOGLE_STANDARD_SQL", "POSTGRESQL"}
SPANNER_ALLOWED_CREDENTIAL_SOURCE_CLASSES = {
    "workload_identity",
    "managed_identity",
    "external_secret_manager",
    "hsm_kms_identity",
}


@dataclass(frozen=True)
class SpannerDeploymentConfig:
    deployment_id: str
    project_id: str
    instance_id: str
    database_id: str
    instance_config: str
    database_dialect: str
    adapter_version: str = "0.9.1"
    credential_source_class: str = "workload_identity"
    credential_reference: str | None = None
    emulator_host: str | None = None
    live_reads_enabled: bool = False
    live_writes_enabled: bool = False

    def envelope(self) -> dict[str, Any]:
        return asdict(self)

    def deployment_digest(self) -> str:
        return sha256_hex({"contract": SPANNER_ADAPTER_CONTRACT, **self.envelope()})


@dataclass(frozen=True)
class SpannerAdapterReadiness:
    contract_ready: bool
    live_integration_ready: bool
    production_candidate: bool
    missing_requirements: tuple[str, ...]

    def envelope(self) -> dict[str, Any]:
        return {
            "contract_ready": self.contract_ready,
            "live_integration_ready": self.live_integration_ready,
            "production_candidate": self.production_candidate,
            "missing_requirements": list(self.missing_requirements),
        }


@dataclass(frozen=True)
class SpannerSchemaPlan:
    objects_table: str
    fences_table: str
    journal_table: str

    def digest(self) -> str:
        return sha256_hex(asdict(self))


class SpannerProductionAdapterV091:
    """Provider-specific contract below Production Infrastructure v0.9.

    This module deliberately does not instantiate Google credentials or make
    network calls. It defines the exact Spanner schema/identity/evidence
    contract that a later live adapter must satisfy.
    """

    def __init__(self, config: SpannerDeploymentConfig):
        self.config = config
        self._validate_config()

    def _validate_config(self) -> None:
        required = {
            "deployment_id": self.config.deployment_id,
            "project_id": self.config.project_id,
            "instance_id": self.config.instance_id,
            "database_id": self.config.database_id,
            "instance_config": self.config.instance_config,
            "adapter_version": self.config.adapter_version,
        }
        for name, value in required.items():
            if not value or not isinstance(value, str):
                raise HardeningError("CFHS_SPANNER_CONFIG_INVALID", f"Spanner {name} is required")
        if self.config.database_dialect not in SPANNER_ALLOWED_DIALECTS:
            raise HardeningError("CFHS_SPANNER_CONFIG_INVALID", "Unsupported Spanner database dialect")
        if self.config.credential_source_class not in SPANNER_ALLOWED_CREDENTIAL_SOURCE_CLASSES:
            raise HardeningError("CFHS_SPANNER_CREDENTIAL_SOURCE_DENIED", "Spanner credential source class is not allowed")
        if self.config.credential_reference and not self.config.credential_reference.startswith("secret://"):
            raise HardeningError("CFHS_SPANNER_CREDENTIAL_SOURCE_DENIED", "Spanner credentials must be referenced, never embedded")
        if self.config.emulator_host and (self.config.live_reads_enabled or self.config.live_writes_enabled):
            raise HardeningError("CFHS_SPANNER_EMULATOR_PRODUCTION_DENIED", "Spanner emulator cannot be enabled as live production infrastructure")
        if self.config.live_writes_enabled and not self.config.live_reads_enabled:
            raise HardeningError("CFHS_SPANNER_CONFIG_INVALID", "Spanner live writes require live reads to be enabled")

    @property
    def backend_id(self) -> str:
        return f"spanner://{self.config.project_id}/{self.config.instance_id}/{self.config.database_id}"

    @property
    def cluster_id(self) -> str:
        return f"spanner-instance://{self.config.project_id}/{self.config.instance_id}"

    def adapter_implementation_digest(self) -> str:
        return sha256_hex({
            "contract": SPANNER_ADAPTER_CONTRACT,
            "provider": SPANNER_PROVIDER_ID,
            "adapter_version": self.config.adapter_version,
            "schema": self.schema_plan().digest(),
        })

    def schema_plan(self) -> SpannerSchemaPlan:
        if self.config.database_dialect == "POSTGRESQL":
            # PostgreSQL-dialect DDL is kept separately because Spanner dialect
            # differences are a deployment identity property, never auto-converted.
            return SpannerSchemaPlan(
                objects_table=(
                    "CREATE TABLE cfhs_shared_objects (object_key varchar(2048) PRIMARY KEY, "
                    "version bigint NOT NULL, value_digest varchar(64) NOT NULL, value_json jsonb NOT NULL, "
                    "updated_at timestamptz NOT NULL DEFAULT spanner.commit_timestamp())"
                ),
                fences_table=(
                    "CREATE TABLE cfhs_shared_fences (resource_key varchar(2048) PRIMARY KEY, last_token bigint NOT NULL, "
                    "current_token bigint, owner_id varchar(512), lease_id varchar(512), expires_at timestamptz, "
                    "updated_at timestamptz NOT NULL DEFAULT spanner.commit_timestamp())"
                ),
                journal_table=(
                    "CREATE TABLE cfhs_shared_journal (stream_key varchar(2048) NOT NULL, version bigint NOT NULL, "
                    "event_digest varchar(64) NOT NULL, event_json jsonb NOT NULL, committed_at timestamptz NOT NULL "
                    "DEFAULT spanner.commit_timestamp(), PRIMARY KEY(stream_key, version))"
                ),
            )
        return SpannerSchemaPlan(
            objects_table=(
                "CREATE TABLE cfhs_shared_objects (object_key STRING(2048) NOT NULL, version INT64 NOT NULL, "
                "value_digest STRING(64) NOT NULL, value_json JSON NOT NULL, "
                "updated_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true)) PRIMARY KEY (object_key)"
            ),
            fences_table=(
                "CREATE TABLE cfhs_shared_fences (resource_key STRING(2048) NOT NULL, last_token INT64 NOT NULL, "
                "current_token INT64, owner_id STRING(512), lease_id STRING(512), expires_at TIMESTAMP, "
                "updated_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true)) PRIMARY KEY (resource_key)"
            ),
            journal_table=(
                "CREATE TABLE cfhs_shared_journal (stream_key STRING(2048) NOT NULL, version INT64 NOT NULL, "
                "event_digest STRING(64) NOT NULL, event_json JSON NOT NULL, "
                "committed_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true)) PRIMARY KEY (stream_key, version)"
            ),
        )

    def readiness(self) -> SpannerAdapterReadiness:
        missing: list[str] = []
        if self.config.emulator_host:
            missing.append("production_spanner_service_required")
        if not self.config.credential_reference:
            missing.append("external_credential_reference_required")
        if not self.config.live_reads_enabled:
            missing.append("live_read_probe_channel_disabled")
        if not self.config.live_writes_enabled:
            missing.append("live_write_probe_channel_disabled")
        # Even with channels enabled, live evidence must still be generated and
        # externally verified before this can become a production candidate.
        missing.append("live_spanner_evidence_not_yet_verified")
        contract_ready = not self.config.emulator_host
        live_integration_ready = bool(
            contract_ready
            and self.config.credential_reference
            and self.config.live_reads_enabled
            and self.config.live_writes_enabled
        )
        return SpannerAdapterReadiness(
            contract_ready=contract_ready,
            live_integration_ready=live_integration_ready,
            production_candidate=False,
            missing_requirements=tuple(dict.fromkeys(missing)),
        )

    def evidence_template(
        self,
        *,
        topology_evidence_digest: str,
        probe_evidence_digest: str,
        release_attestation_digest: str,
        capability_digest: str,
        trust_store_id: str,
        authority_id: str,
        authority_class: str,
        authority_generation: int,
        observed_at: str,
        valid_until: str,
        evidence_nonce: str,
    ) -> ProductionInfrastructureEvidenceBundle:
        if self.config.emulator_host:
            raise HardeningError("CFHS_SPANNER_EMULATOR_PRODUCTION_DENIED", "Spanner emulator cannot emit production evidence")
        if not self.config.live_reads_enabled or not self.config.live_writes_enabled:
            raise HardeningError("CFHS_SPANNER_LIVE_EVIDENCE_DENIED", "Live Spanner read/write probe channels must be explicitly enabled")
        return ProductionInfrastructureEvidenceBundle(
            deployment_id=self.config.deployment_id,
            provider_id=SPANNER_PROVIDER_ID,
            adapter_name="company-kernel-spanner-shared-state",
            adapter_version=self.config.adapter_version,
            adapter_implementation_digest=self.adapter_implementation_digest(),
            backend_id=self.backend_id,
            cluster_id=self.cluster_id,
            capability_digest=capability_digest,
            topology_evidence_digest=topology_evidence_digest,
            probe_evidence_digest=probe_evidence_digest,
            release_attestation_digest=release_attestation_digest,
            trust_store_id=trust_store_id,
            authority_id=authority_id,
            authority_class=authority_class,
            authority_generation=authority_generation,
            credential_source_class=self.config.credential_source_class,
            observed_at=observed_at,
            valid_until=valid_until,
            evidence_nonce=evidence_nonce,
            capability_claims=tuple(REQUIRED_CAPABILITIES),
            evidence_phases=tuple(REQUIRED_EVIDENCE_PHASES),
        )

    def production_operations_plan(self) -> dict[str, Any]:
        """Return the required live implementation semantics; no network calls."""
        return {
            "transaction_isolation": "SERIALIZABLE_EXTERNAL_CONSISTENCY_REQUIRED",
            "read": "strong read of object row",
            "put_if_absent": "read-write transaction; insert iff absent; exact digest idempotency",
            "compare_and_swap": "read-write transaction; read version; conditional version increment",
            "acquire_fence": "read-write transaction; compare expiry; increment persistent last_token",
            "assert_fence": "strong read inside mutation transaction; exact token/owner/lease + unexpired",
            "release_fence": "read-write transaction; exact token/owner/lease; clear active lease only",
            "append_event": "read-write transaction; exact stream version; insert version+1",
            "fenced_compare_and_swap_with_event": "single read-write transaction containing fence check + object CAS + journal append",
            "authoritative_time": "Spanner commit timestamp / TrueTime-backed transaction commit ordering",
            "durability": "production Spanner service only; emulator never qualifies",
        }
