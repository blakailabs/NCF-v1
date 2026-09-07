import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from kernel.production_infrastructure_v09 import (
    ProductionInfrastructureCertifier,
    ProductionInfrastructureEvidenceBundle,
    VerifiedProductionInfrastructureEvidence,
    REQUIRED_CAPABILITIES,
    REQUIRED_EVIDENCE_PHASES,
)
from kernel.hardening import HardeningError
from kernel.trust import sha256_hex


class Verifier:
    def __init__(self, now, *, verifier_id="external-certifier", verifier_class="independent_infrastructure_attestation", wrong_digest=False):
        self.now = now
        self.verifier_id = verifier_id
        self.verifier_class = verifier_class
        self.wrong_digest = wrong_digest

    def verify(self, evidence):
        return VerifiedProductionInfrastructureEvidence(
            deployment_digest=("0" * 64 if self.wrong_digest else evidence.digest()),
            verifier_id=self.verifier_id,
            verifier_class=self.verifier_class,
            verifier_receipt_digest=sha256_hex({"verified": evidence.digest()}),
            verified_at=self.now.isoformat(),
            production_trust_store_id="external-prod-trust-store",
        )


class ProductionInfrastructureV09Tests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 9, 7, 5, 0, tzinfo=timezone.utc)
        self.certifier = ProductionInfrastructureCertifier(max_evidence_age_seconds=300)

    def bundle(self):
        return ProductionInfrastructureEvidenceBundle(
            deployment_id="company-kernel-prod-01",
            provider_id="provider-a",
            adapter_name="provider-neutral-shared-state-adapter",
            adapter_version="0.9.0",
            adapter_implementation_digest=sha256_hex({"adapter": "0.9.0"}),
            backend_id="prod-backend-01",
            cluster_id="prod-cluster-01",
            capability_digest=sha256_hex({"capabilities": list(REQUIRED_CAPABILITIES)}),
            topology_evidence_digest=sha256_hex({"topology": 1}),
            probe_evidence_digest=sha256_hex({"probes": 1}),
            release_attestation_digest=sha256_hex({"release": 1}),
            trust_store_id="release-trust-store",
            authority_id="independent-enrollment-authority",
            authority_class="independent_enrollment_authority",
            authority_generation=1,
            credential_source_class="workload_identity",
            observed_at=(self.now - timedelta(seconds=10)).isoformat(),
            valid_until=(self.now + timedelta(seconds=120)).isoformat(),
            evidence_nonce="evidence-nonce-001",
            capability_claims=tuple(REQUIRED_CAPABILITIES),
            evidence_phases=tuple(REQUIRED_EVIDENCE_PHASES),
        )

    def test_valid_bundle_with_independent_verifier_is_ready(self):
        result = self.certifier.certify(self.bundle(), Verifier(self.now), now=self.now)
        self.assertTrue(result.production_ready)
        self.assertEqual(result.missing_requirements, ())

    def test_missing_external_verifier_fails_closed(self):
        result = self.certifier.certify(self.bundle(), None, now=self.now)
        self.assertFalse(result.production_ready)
        self.assertIn("external_verifier_missing", result.missing_requirements)

    def test_provider_cannot_self_certify(self):
        evidence = replace(self.bundle(), authority_id="provider-a")
        result = self.certifier.certify(evidence, Verifier(self.now), now=self.now)
        self.assertIn("provider_self_certification_forbidden", result.missing_requirements)

    def test_external_verifier_must_be_independent(self):
        result = self.certifier.certify(self.bundle(), Verifier(self.now, verifier_id="provider-a"), now=self.now)
        self.assertIn("external_verifier_not_independent", result.missing_requirements)

    def test_wrong_verifier_digest_is_rejected(self):
        result = self.certifier.certify(self.bundle(), Verifier(self.now, wrong_digest=True), now=self.now)
        self.assertIn("external_verifier_digest_mismatch", result.missing_requirements)

    def test_missing_required_capability_is_rejected(self):
        evidence = replace(self.bundle(), capability_claims=tuple(c for c in REQUIRED_CAPABILITIES if c != "split_brain_protection"))
        result = self.certifier.certify(evidence, Verifier(self.now), now=self.now)
        self.assertIn("capability_missing:split_brain_protection", result.missing_requirements)

    def test_missing_fault_partition_phase_is_rejected(self):
        evidence = replace(self.bundle(), evidence_phases=tuple(p for p in REQUIRED_EVIDENCE_PHASES if p != "fault_partition_probes"))
        result = self.certifier.certify(evidence, Verifier(self.now), now=self.now)
        self.assertIn("evidence_phase_missing:fault_partition_probes", result.missing_requirements)

    def test_stale_and_expired_evidence_is_rejected(self):
        evidence = replace(
            self.bundle(),
            observed_at=(self.now - timedelta(seconds=400)).isoformat(),
            valid_until=(self.now - timedelta(seconds=1)).isoformat(),
        )
        result = self.certifier.certify(evidence, Verifier(self.now), now=self.now)
        self.assertIn("evidence_stale", result.missing_requirements)
        self.assertIn("evidence_expired", result.missing_requirements)

    def test_invalid_credential_source_class_is_rejected(self):
        evidence = replace(self.bundle(), credential_source_class="inline_static_secret")
        result = self.certifier.certify(evidence, Verifier(self.now), now=self.now)
        self.assertIn("credential_source_class_invalid", result.missing_requirements)

    def test_secret_like_material_in_evidence_is_rejected(self):
        evidence = replace(self.bundle(), trust_store_id="token=should-never-be-here")
        result = self.certifier.certify(evidence, Verifier(self.now), now=self.now)
        self.assertIn("secret_material_forbidden:trust_store_id", result.missing_requirements)

    def test_authority_generation_must_be_positive_integer(self):
        evidence = replace(self.bundle(), authority_generation=0)
        result = self.certifier.certify(evidence, Verifier(self.now), now=self.now)
        self.assertIn("authority_generation_invalid", result.missing_requirements)

    def test_require_production_ready_raises_structured_failure(self):
        evidence = replace(self.bundle(), credential_source_class="invalid")
        with self.assertRaises(HardeningError) as cm:
            self.certifier.require_production_ready(evidence, Verifier(self.now), now=self.now)
        self.assertEqual(cm.exception.code, "CFHS_PRODUCTION_INFRASTRUCTURE_NOT_READY")


if __name__ == "__main__":
    unittest.main()
