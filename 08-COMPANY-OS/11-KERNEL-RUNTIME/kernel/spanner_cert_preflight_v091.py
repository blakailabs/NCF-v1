from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Any

from .hardening import HardeningError
from .spanner_pre_gcp_v091 import SpannerRuntimeReferences
from .trust import sha256_hex


SPANNER_CERT_PREFLIGHT_CONTRACT = "company-kernel-spanner-cert-preflight/v0.9.1"


@dataclass(frozen=True)
class SpannerCertificationPreflight:
    contract: str
    runtime_digest: str
    repository: str
    ref: str
    environment: str
    live_enabled: bool
    wif_configured: bool
    ready_for_cloud_connection: bool
    blockers: tuple[str, ...] | list[str]
    digest: str

    def envelope(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "runtime_digest": self.runtime_digest,
            "repository": self.repository,
            "ref": self.ref,
            "environment": self.environment,
            "live_enabled": self.live_enabled,
            "wif_configured": self.wif_configured,
            "ready_for_cloud_connection": self.ready_for_cloud_connection,
            "blockers": list(self.blockers),
            "digest": self.digest,
        }


def build_preflight(env: Mapping[str, str]) -> SpannerCertificationPreflight:
    refs = SpannerRuntimeReferences.from_environment(env)
    repo = env.get("GITHUB_REPOSITORY", "")
    ref = env.get("GITHUB_REF", "")
    environment = env.get("CFHS_ENVIRONMENT", "cert")
    if repo and repo != "blakailabs/NCF-v1":
        raise HardeningError("CFHS_SPANNER_REPOSITORY_MISMATCH", "Certification may only run from blakailabs/NCF-v1")
    if environment != "cert":
        raise HardeningError("CFHS_SPANNER_ENVIRONMENT_MISMATCH", "Spanner certification preflight requires cert environment")
    blockers: list[str] = []
    if not refs.workload_identity_provider:
        blockers.append("wif_provider_missing")
    if not refs.service_account_reference:
        blockers.append("external_principal_reference_missing")
    if not refs.live_enabled:
        blockers.append("live_integration_disabled")
    if not repo:
        blockers.append("github_repository_context_missing")
    if not ref:
        blockers.append("github_ref_context_missing")
    body = {
        "contract": SPANNER_CERT_PREFLIGHT_CONTRACT,
        "runtime_digest": refs.digest(),
        "repository": repo,
        "ref": ref,
        "environment": environment,
        "live_enabled": refs.live_enabled,
        "wif_configured": bool(refs.workload_identity_provider and refs.service_account_reference),
        "ready_for_cloud_connection": not blockers,
        "blockers": blockers,
    }
    return SpannerCertificationPreflight(**body, digest=sha256_hex(body))
