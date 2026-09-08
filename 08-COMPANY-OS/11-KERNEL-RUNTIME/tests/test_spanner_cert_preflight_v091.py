import unittest
from kernel.hardening import HardeningError
from kernel.spanner_cert_preflight_v091 import build_preflight

class SpannerCertPreflightTests(unittest.TestCase):
    def base(self, **extra):
        env={"GITHUB_REPOSITORY":"blakailabs/NCF-v1","GITHUB_REF":"refs/heads/feature/company-kernel-production-infrastructure-v0.9","CFHS_ENVIRONMENT":"cert"}
        env.update(extra); return env
    def test_missing_cloud_context_is_blocked_not_ready(self):
        p=build_preflight(self.base()); self.assertFalse(p.ready_for_cloud_connection); self.assertIn("wif_provider_missing",p.blockers)
    def test_wrong_repo_fails_closed(self):
        with self.assertRaises(HardeningError): build_preflight(self.base(GITHUB_REPOSITORY="other/repo"))
    def test_wrong_environment_fails_closed(self):
        with self.assertRaises(HardeningError): build_preflight(self.base(CFHS_ENVIRONMENT="prod"))
    def test_complete_keyless_context_is_ready(self):
        p=build_preflight(self.base(CFHS_SPANNER_LIVE_ENABLED="true",CFHS_GCP_WORKLOAD_IDENTITY_PROVIDER="projects/123/locations/global/workloadIdentityPools/github/providers/ncf",CFHS_GCP_SERVICE_ACCOUNT_REFERENCE="principal://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/github/subject/repo:blakailabs/NCF-v1")); self.assertTrue(p.ready_for_cloud_connection)
    def test_digest_changes_with_ref(self):
        a=build_preflight(self.base()); b=build_preflight(self.base(GITHUB_REF="refs/heads/other")); self.assertNotEqual(a.digest,b.digest)
    def test_live_disabled_remains_explicit_blocker(self):
        p=build_preflight(self.base(CFHS_GCP_WORKLOAD_IDENTITY_PROVIDER="p",CFHS_GCP_SERVICE_ACCOUNT_REFERENCE="principal://x")); self.assertIn("live_integration_disabled",p.blockers)

if __name__=="__main__": unittest.main()
