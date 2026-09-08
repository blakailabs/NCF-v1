import unittest
from datetime import datetime, timedelta, timezone

from kernel.hardening import HardeningError
from kernel.production_infrastructure_v09 import ProductionInfrastructureCertifier, VerifiedProductionInfrastructureEvidence
from kernel.spanner_backend_v091 import SpannerDeploymentConfig, SpannerProductionAdapterV091
from kernel.trust import sha256_hex


class Verifier:
    def __init__(self, now): self.now = now
    def verify(self, evidence):
        return VerifiedProductionInfrastructureEvidence(
            deployment_digest=evidence.digest(),
            verifier_id="external-spanner-certifier",
            verifier_class="independent_infrastructure_attestation",
            verifier_receipt_digest=sha256_hex({"verified": evidence.digest()}),
            verified_at=self.now.isoformat(),
            production_trust_store_id="external-spanner-trust-store",
        )


class SpannerBackendV091Tests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 9, 7, 6, 0, tzinfo=timezone.utc)

    def config(self, **kwargs):
        values = dict(
            deployment_id="company-kernel-spanner-prod-01",
            project_id="company-kernel-prod",
            instance_id="kernel-ha-01",
            database_id="cfhs",
            instance_config="nam-eur-asia1",
            database_dialect="GOOGLE_STANDARD_SQL",
            credential_source_class="workload_identity",
            credential_reference="secret://gcp/workload-identity/company-kernel-spanner",
            live_reads_enabled=False,
            live_writes_enabled=False,
        )
        values.update(kwargs)
        return SpannerDeploymentConfig(**values)

    def evidence(self, adapter):
        return adapter.evidence_template(
            topology_evidence_digest=sha256_hex({"topology": 1}),
            probe_evidence_digest=sha256_hex({"probes": 1}),
            release_attestation_digest=sha256_hex({"release": 1}),
            capability_digest=sha256_hex({"capabilities": 1}),
            trust_store_id="external-spanner-release-trust",
            authority_id="independent-spanner-enrollment-authority",
            authority_class="independent_enrollment_authority",
            authority_generation=1,
            observed_at=(self.now - timedelta(seconds=10)).isoformat(),
            valid_until=(self.now + timedelta(seconds=120)).isoformat(),
            evidence_nonce="spanner-evidence-nonce-1",
        )

    def test_default_contract_has_production_channels_disabled(self):
        adapter = SpannerProductionAdapterV091(self.config())
        readiness = adapter.readiness()
        self.assertTrue(readiness.contract_ready)
        self.assertFalse(readiness.live_integration_ready)
        self.assertFalse(readiness.production_candidate)
        self.assertIn("live_write_probe_channel_disabled", readiness.missing_requirements)

    def test_embedded_credentials_are_rejected(self):
        with self.assertRaises(HardeningError) as cm:
            SpannerProductionAdapterV091(self.config(credential_reference="plaintext-service-account-json"))
        self.assertEqual(cm.exception.code, "CFHS_SPANNER_CREDENTIAL_SOURCE_DENIED")

    def test_unapproved_credential_source_is_rejected(self):
        with self.assertRaises(HardeningError):
            SpannerProductionAdapterV091(self.config(credential_source_class="static_api_key"))

    def test_live_writes_cannot_be_enabled_without_live_reads(self):
        with self.assertRaises(HardeningError):
            SpannerProductionAdapterV091(self.config(live_reads_enabled=False, live_writes_enabled=True))

    def test_emulator_can_never_be_live_production(self):
        with self.assertRaises(HardeningError) as cm:
            SpannerProductionAdapterV091(self.config(emulator_host="localhost:9010", live_reads_enabled=True, live_writes_enabled=True))
        self.assertEqual(cm.exception.code, "CFHS_SPANNER_EMULATOR_PRODUCTION_DENIED")

    def test_emulator_readiness_is_nonproduction_even_when_disabled(self):
        adapter = SpannerProductionAdapterV091(self.config(emulator_host="localhost:9010", credential_reference=None))
        readiness = adapter.readiness()
        self.assertFalse(readiness.contract_ready)
        self.assertIn("production_spanner_service_required", readiness.missing_requirements)

    def test_google_sql_schema_uses_commit_timestamp_columns(self):
        schema = SpannerProductionAdapterV091(self.config()).schema_plan()
        self.assertIn("allow_commit_timestamp=true", schema.objects_table)
        self.assertIn("allow_commit_timestamp=true", schema.fences_table)
        self.assertIn("allow_commit_timestamp=true", schema.journal_table)

    def test_postgresql_dialect_has_separate_schema_identity(self):
        google = SpannerProductionAdapterV091(self.config())
        postgres = SpannerProductionAdapterV091(self.config(database_dialect="POSTGRESQL"))
        self.assertNotEqual(google.schema_plan().digest(), postgres.schema_plan().digest())
        self.assertNotEqual(google.adapter_implementation_digest(), postgres.adapter_implementation_digest())

    def test_backend_and_cluster_identity_bind_project_instance_database(self):
        adapter = SpannerProductionAdapterV091(self.config())
        self.assertEqual(adapter.backend_id, "spanner://company-kernel-prod/kernel-ha-01/cfhs")
        self.assertEqual(adapter.cluster_id, "spanner-instance://company-kernel-prod/kernel-ha-01")

    def test_live_evidence_requires_explicit_read_and_write_channels(self):
        adapter = SpannerProductionAdapterV091(self.config())
        with self.assertRaises(HardeningError) as cm:
            self.evidence(adapter)
        self.assertEqual(cm.exception.code, "CFHS_SPANNER_LIVE_EVIDENCE_DENIED")

    def test_emulator_cannot_emit_production_evidence(self):
        adapter = SpannerProductionAdapterV091(self.config(emulator_host="localhost:9010", credential_reference=None))
        with self.assertRaises(HardeningError) as cm:
            self.evidence(adapter)
        self.assertEqual(cm.exception.code, "CFHS_SPANNER_EMULATOR_PRODUCTION_DENIED")

    def test_live_evidence_template_binds_spanner_provider_identity(self):
        adapter = SpannerProductionAdapterV091(self.config(live_reads_enabled=True, live_writes_enabled=True))
        evidence = self.evidence(adapter)
        self.assertEqual(evidence.provider_id, "google-cloud-spanner")
        self.assertEqual(evidence.backend_id, adapter.backend_id)
        self.assertEqual(evidence.cluster_id, adapter.cluster_id)
        self.assertEqual(evidence.adapter_implementation_digest, adapter.adapter_implementation_digest())

    def test_live_template_can_pass_neutral_certifier_only_with_external_verifier(self):
        adapter = SpannerProductionAdapterV091(self.config(live_reads_enabled=True, live_writes_enabled=True))
        evidence = self.evidence(adapter)
        certifier = ProductionInfrastructureCertifier(max_evidence_age_seconds=300)
        self.assertFalse(certifier.certify(evidence, None, now=self.now).production_ready)
        self.assertTrue(certifier.certify(evidence, Verifier(self.now), now=self.now).production_ready)

    def test_operation_plan_requires_single_transaction_for_fenced_cas_and_journal(self):
        plan = SpannerProductionAdapterV091(self.config()).production_operations_plan()
        self.assertIn("single read-write transaction", plan["fenced_compare_and_swap_with_event"])
        self.assertIn("commit timestamp", plan["authoritative_time"])
        self.assertIn("emulator never qualifies", plan["durability"])


if __name__ == "__main__": unittest.main()
