import unittest
from dataclasses import replace

from kernel.hardening import HardeningError
from kernel.spanner_live_certification_v091 import SpannerLiveCertificationOrchestrator
from kernel.spanner_pre_gcp_v091 import (
    CERT_DATABASE, CERT_DEPLOYMENT, CERT_INSTANCE, CERT_PROJECT,
    SpannerRuntimeReferences, build_certification_artifact, validate_artifact,
)


class Driver:
    def execute(self, phase, adapter):
        return {"status": "PASS", "evidence": {"phase": phase, "backend": adapter.backend_id}}


class SpannerPreGCPV091Tests(unittest.TestCase):
    def keyless_env(self, **extra):
        env = {
            "CFHS_SPANNER_PROJECT_ID": CERT_PROJECT,
            "CFHS_SPANNER_INSTANCE_ID": CERT_INSTANCE,
            "CFHS_SPANNER_DATABASE_ID": CERT_DATABASE,
            "CFHS_SPANNER_DEPLOYMENT_ID": CERT_DEPLOYMENT,
            "CFHS_GCP_WORKLOAD_IDENTITY_PROVIDER": "projects/123/locations/global/workloadIdentityPools/cfhs/providers/github",
            "CFHS_GCP_SERVICE_ACCOUNT_REFERENCE": "principal://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/cfhs/subject/repo:blakailabs/NCF-v1",
        }
        env.update(extra)
        return env

    def test_defaults_bind_fixed_certification_target(self):
        refs = SpannerRuntimeReferences.from_environment({})
        self.assertEqual((refs.project_id, refs.instance_id, refs.database_id), (CERT_PROJECT, CERT_INSTANCE, CERT_DATABASE))
        self.assertFalse(refs.live_enabled)

    def test_wrong_project_fails_closed(self):
        with self.assertRaises(HardeningError) as cm:
            SpannerRuntimeReferences.from_environment({"CFHS_SPANNER_PROJECT_ID": "some-other-project"})
        self.assertEqual(cm.exception.code, "CFHS_SPANNER_CERT_TARGET_MISMATCH")

    def test_wrong_instance_fails_closed(self):
        with self.assertRaises(HardeningError):
            SpannerRuntimeReferences.from_environment({"CFHS_SPANNER_INSTANCE_ID": "prod"})

    def test_invalid_live_flag_is_rejected(self):
        with self.assertRaises(HardeningError):
            SpannerRuntimeReferences.from_environment({"CFHS_SPANNER_LIVE_ENABLED": "yes"})

    def test_live_requires_complete_keyless_identity(self):
        with self.assertRaises(HardeningError) as cm:
            SpannerRuntimeReferences.from_environment({"CFHS_SPANNER_LIVE_ENABLED": "true"})
        self.assertEqual(cm.exception.code, "CFHS_SPANNER_LIVE_IDENTITY_REQUIRED")

    def test_plaintext_secret_like_identity_material_is_rejected(self):
        env = self.keyless_env(CFHS_GCP_SERVICE_ACCOUNT_REFERENCE="token=abc")
        with self.assertRaises(HardeningError) as cm:
            SpannerRuntimeReferences.from_environment(env)
        self.assertEqual(cm.exception.code, "CFHS_SPANNER_SECRET_MATERIAL_DENIED")

    def test_service_account_must_be_external_principal_reference(self):
        env = self.keyless_env(CFHS_GCP_SERVICE_ACCOUNT_REFERENCE="service-account@example.iam.gserviceaccount.com")
        with self.assertRaises(HardeningError):
            SpannerRuntimeReferences.from_environment(env)

    def test_disabled_runtime_cannot_become_live_adapter(self):
        adapter = SpannerRuntimeReferences.from_environment({}).adapter()
        self.assertFalse(adapter.readiness().live_integration_ready)

    def test_keyless_live_runtime_enables_probe_channels_only_explicitly(self):
        env = self.keyless_env(CFHS_SPANNER_LIVE_ENABLED="true")
        adapter = SpannerRuntimeReferences.from_environment(env).adapter()
        self.assertTrue(adapter.readiness().live_integration_ready)
        self.assertEqual(adapter.backend_id, f"spanner://{CERT_PROJECT}/{CERT_INSTANCE}/{CERT_DATABASE}")

    def test_runtime_digest_binds_wif_provider(self):
        a = SpannerRuntimeReferences.from_environment(self.keyless_env())
        b = SpannerRuntimeReferences.from_environment(self.keyless_env(CFHS_GCP_WORKLOAD_IDENTITY_PROVIDER="projects/456/locations/global/workloadIdentityPools/cfhs/providers/github"))
        self.assertNotEqual(a.digest(), b.digest())

    def test_artifact_preserves_all_observed_phase_digests(self):
        env = self.keyless_env(CFHS_SPANNER_LIVE_ENABLED="true")
        adapter = SpannerRuntimeReferences.from_environment(env).adapter()
        report = SpannerLiveCertificationOrchestrator(adapter).run(Driver())
        artifact = build_certification_artifact(report)
        self.assertTrue(artifact.production_ready)
        self.assertEqual(len(artifact.phases), 14)
        validate_artifact(artifact)

    def test_tampered_artifact_is_rejected(self):
        env = self.keyless_env(CFHS_SPANNER_LIVE_ENABLED="true")
        report = SpannerLiveCertificationOrchestrator(SpannerRuntimeReferences.from_environment(env).adapter()).run(Driver())
        artifact = build_certification_artifact(report)
        tampered = replace(artifact, production_ready=False)
        with self.assertRaises(HardeningError) as cm:
            validate_artifact(tampered)
        self.assertEqual(cm.exception.code, "CFHS_SPANNER_EVIDENCE_ARTIFACT_TAMPERED")


if __name__ == "__main__": unittest.main()
