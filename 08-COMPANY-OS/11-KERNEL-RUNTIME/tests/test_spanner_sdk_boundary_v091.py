import unittest

from kernel.hardening import HardeningError
from kernel.spanner_backend_v091 import SpannerDeploymentConfig, SpannerProductionAdapterV091
from kernel.spanner_live_certification_v091 import SPANNER_LIVE_PHASES, SpannerLiveCertificationOrchestrator
from kernel.spanner_sdk_boundary_v091 import SpannerSDKProbeDriverV091, SpannerSDKProbePolicy


class FakeClient:
    def __getattr__(self, name):
        return lambda: {"operation": name, "observed": True}


class SelfCertifyingClient(FakeClient):
    def deployment_identity(self): return {"status": "PASS", "observed": True}


class SecretClient(FakeClient):
    def deployment_identity(self): return {"token": "abc"}


class EmptyClient(FakeClient):
    def deployment_identity(self): return {}


def live_adapter():
    return SpannerProductionAdapterV091(SpannerDeploymentConfig(
        deployment_id="company-kernel-cert-spanner-01", project_id="cfhs-kernel-cert",
        instance_id="kernel-ha-cert-01", database_id="cfhs-cert",
        instance_config="regional-us-central1", database_dialect="GOOGLE_STANDARD_SQL",
        credential_reference="secret://gcp/workload-identity/runtime",
        live_reads_enabled=True, live_writes_enabled=True,
    ))


class SpannerSDKBoundaryV091Tests(unittest.TestCase):
    def test_unknown_phase_rejected(self):
        with self.assertRaises(HardeningError):
            SpannerSDKProbeDriverV091(FakeClient()).execute("S0_UNKNOWN", live_adapter())

    def test_network_disabled_by_default(self):
        result = SpannerSDKProbeDriverV091(FakeClient()).execute("S1_DEPLOYMENT_IDENTITY", live_adapter())
        self.assertEqual((result["status"], result["reason"]), ("BLOCKED", "provider_network_access_not_enabled"))

    def test_mutations_require_separate_permission(self):
        driver = SpannerSDKProbeDriverV091(FakeClient(), SpannerSDKProbePolicy(allow_network=True))
        result = driver.execute("S5_STALE_CAS_REJECTION", live_adapter())
        self.assertEqual(result["reason"], "provider_mutations_not_enabled")

    def test_fault_phase_requires_independent_fault_control(self):
        policy = SpannerSDKProbePolicy(allow_network=True, allow_mutations=True)
        result = SpannerSDKProbeDriverV091(FakeClient(), policy).execute("S12_FAULT_QUORUM_EVIDENCE", live_adapter())
        self.assertEqual(result["reason"], "independent_fault_control_not_enabled")

    def test_external_authority_phases_require_separate_permission(self):
        policy = SpannerSDKProbePolicy(allow_network=True, allow_mutations=True, allow_fault_injection=True)
        result = SpannerSDKProbeDriverV091(FakeClient(), policy).execute("S13_EXTERNAL_ATTESTATION", live_adapter())
        self.assertEqual(result["reason"], "external_authority_not_enabled")

    def test_provider_cannot_self_certify(self):
        policy = SpannerSDKProbePolicy(allow_network=True)
        with self.assertRaises(HardeningError) as cm:
            SpannerSDKProbeDriverV091(SelfCertifyingClient(), policy).execute("S1_DEPLOYMENT_IDENTITY", live_adapter())
        self.assertEqual(cm.exception.code, "CFHS_SPANNER_PROVIDER_SELF_CERTIFICATION_DENIED")

    def test_secret_material_rejected_from_evidence(self):
        policy = SpannerSDKProbePolicy(allow_network=True)
        with self.assertRaises(HardeningError) as cm:
            SpannerSDKProbeDriverV091(SecretClient(), policy).execute("S1_DEPLOYMENT_IDENTITY", live_adapter())
        self.assertEqual(cm.exception.code, "CFHS_SPANNER_EVIDENCE_SECRET_DENIED")

    def test_empty_observation_becomes_fail(self):
        policy = SpannerSDKProbePolicy(allow_network=True)
        result = SpannerSDKProbeDriverV091(EmptyClient(), policy).execute("S1_DEPLOYMENT_IDENTITY", live_adapter())
        self.assertEqual(result["status"], "FAIL")

    def test_positive_observation_is_wrapped_by_kernel(self):
        policy = SpannerSDKProbePolicy(allow_network=True)
        result = SpannerSDKProbeDriverV091(FakeClient(), policy).execute("S1_DEPLOYMENT_IDENTITY", live_adapter())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["evidence"]["backend_id"], "spanner://cfhs-kernel-cert/kernel-ha-cert-01/cfhs-cert")

    def test_disabled_adapter_blocks_even_if_driver_permissions_open(self):
        adapter = SpannerProductionAdapterV091(SpannerDeploymentConfig(
            deployment_id="d", project_id="p", instance_id="i", database_id="db",
            instance_config="regional-us-central1", database_dialect="GOOGLE_STANDARD_SQL",
        ))
        policy = SpannerSDKProbePolicy(True, True, True, True)
        result = SpannerSDKProbeDriverV091(FakeClient(), policy).execute("S1_DEPLOYMENT_IDENTITY", adapter)
        self.assertEqual(result["reason"], "live_spanner_integration_not_enabled")

    def test_full_fake_driver_maps_all_fourteen_phases(self):
        policy = SpannerSDKProbePolicy(True, True, True, True)
        report = SpannerLiveCertificationOrchestrator(live_adapter()).run(SpannerSDKProbeDriverV091(FakeClient(), policy))
        self.assertEqual(tuple(r.phase for r in report.results), SPANNER_LIVE_PHASES)
        self.assertTrue(report.production_ready)

    def test_fake_pass_is_contract_test_not_live_claim(self):
        policy = SpannerSDKProbePolicy(True, True, True, True)
        result = SpannerSDKProbeDriverV091(FakeClient(), policy).execute("S14_NEUTRAL_V09_CERTIFICATION", live_adapter())
        self.assertIn("observed", result["evidence"])
        self.assertNotIn("production_certified", result["evidence"])


if __name__ == "__main__": unittest.main()
