import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kernel.certification_plane_attestation import CertificationPlaneAdapterAttestation, CertificationPlaneAdapterReadiness, CertificationPlaneDeploymentIdentity
from kernel.certification_plane_enrollment import SharedAdapterEnrollmentRegistry
from kernel.certification_plane_enrollment_authority import (
    AdapterEnrollmentAuthorization,
    EnrollmentAuthorityTrustReadiness,
    ProductionAdapterEnrollmentAuthorityGate,
    ReferenceAdapterEnrollmentAuthorityTrustStore,
    VerifiedAdapterEnrollmentAuthorization,
)
from kernel.ha_certification_runtime import HACertificationRecord
from kernel.hardening import HardeningError
from kernel.shared_certification_plane import SharedStateCertificationPlane
from kernel.shared_state_backend import SharedBackendCapabilities, SQLiteSharedStateBackend
from kernel.trust import sha256_hex


class Backend(SQLiteSharedStateBackend):
    def __init__(self, path, now):
        super().__init__(path, backend_id="enrollment-authority-backend-v08"); self.now = now
    def authoritative_now(self): return self.now
    def capabilities(self):
        return SharedBackendCapabilities(self.backend_id, True, True, True, True, True, True, True, True)

class ProductionStore(ReferenceAdapterEnrollmentAuthorityTrustStore):
    def readiness(self): return EnrollmentAuthorityTrustReadiness(True, self.trust_store_id)

class Verifier:
    def __init__(self, now): self.now = now
    def verify(self, auth, deployment):
        return VerifiedAdapterEnrollmentAuthorization(auth.digest(), deployment.digest(), auth.authority_id, auth.authority_class, auth.key_id, auth.authority_generation, auth.enrollment_generation, self.now.isoformat(), sha256_hex({"verified": auth.digest()}))

class EnrollmentAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.now=datetime(2026,9,7,5,0,tzinfo=timezone.utc)
        self.backend=Backend(Path(self.tmp.name)/"authority.db", self.now); self.plane=SharedStateCertificationPlane(self.backend, fence_ttl_seconds=5)
        self.cluster="authority-cluster"; self._seed(); self.registry=SharedAdapterEnrollmentRegistry(self.plane, fence_ttl_seconds=5)
        self.deployment=CertificationPlaneDeploymentIdentity.from_plane(self.plane,deployment_id="prod-adapter-1",cluster_id=self.cluster,adapter_name="company-os-ha-certification-plane",adapter_version="0.8.3",adapter_implementation_digest=sha256_hex({"impl":1}),topology_evidence_digest=sha256_hex({"topology":1}),probe_evidence_digest=sha256_hex({"probes":1}))
        self.attestation=CertificationPlaneAdapterAttestation("att-1",self.deployment.digest(),"release-authority","independent_release_attestation","release-key",1,"att-nonce",(self.now-timedelta(seconds=5)).isoformat(),(self.now+timedelta(seconds=180)).isoformat())
        self.readiness=CertificationPlaneAdapterReadiness(True,(),self.deployment.digest(),self.attestation.digest(),sha256_hex({"release-receipt":1}),"production-release-trust")
        self.gate=ProductionAdapterEnrollmentAuthorityGate(); self.store=ProductionStore("production-enrollment-trust"); self.verifier=Verifier(self.now)
    def tearDown(self): self.backend.close(); self.tmp.cleanup()
    def _seed(self):
        rec=HACertificationRecord("cert",self.backend.backend_id,self.cluster,61,"nonce",sha256_hex({"e":1}),sha256_hex({"a":1}),sha256_hex({"c":1}),self.now.isoformat(),(self.now+timedelta(seconds=600)).isoformat(),"ACTIVE")
        self.plane.prepare_handoff(cluster_id=self.cluster,topology_epoch=61,handoff_digest="h",bootstrap_state_digest="b"*64,control_state_digest="c"*64,owner_id="seed")
        self.plane.activate(rec,owner_id="seed",handoff_digest="h"); self.plane.close_handoff(cluster_id=self.cluster,topology_epoch=61,handoff_digest="h",certification_id="cert",owner_id="seed")
    def auth(self, **kw):
        vals=dict(authorization_id="enroll-auth-1",purpose="activate_certification_plane_adapter",deployment_id=self.deployment.deployment_id,deployment_digest=self.deployment.digest(),readiness_digest=self.gate.readiness_digest(self.readiness),attestation_digest=self.attestation.digest(),verifier_receipt_digest=self.readiness.verifier_receipt_digest,trust_store_id=self.readiness.trust_store_id,enrollment_generation=1,authority_id="production-enrollment-authority",authority_class="independent_enrollment_authority",key_id="enrollment-key-1",authority_generation=1,authorization_nonce="enrollment-nonce-1",issued_at=(self.now-timedelta(seconds=5)).isoformat(),expires_at=(self.now+timedelta(seconds=120)).isoformat()); vals.update(kw); return AdapterEnrollmentAuthorization(**vals)
    def enroll(self, auth=None, **kw): return self.gate.authorize_and_enroll(self.registry,self.readiness,self.deployment,self.attestation,auth or self.auth(),self.verifier,self.store,owner_id="authority-enroller",now=self.now,**kw)

    def test_valid_external_authority_enrolls_exact_generation(self): self.assertEqual(self.enroll().generation,1)
    def test_reference_authority_store_cannot_promote(self):
        with self.assertRaises(HardeningError): self.gate.authorize_and_enroll(self.registry,self.readiness,self.deployment,self.attestation,self.auth(),self.verifier,ReferenceAdapterEnrollmentAuthorityTrustStore(),owner_id="x",now=self.now)
    def test_missing_authorization_or_verifier_denied(self):
        with self.assertRaises(HardeningError): self.gate.authorize_and_enroll(self.registry,self.readiness,self.deployment,self.attestation,None,self.verifier,self.store,owner_id="x",now=self.now)
        with self.assertRaises(HardeningError): self.gate.authorize_and_enroll(self.registry,self.readiness,self.deployment,self.attestation,self.auth(),None,self.store,owner_id="x",now=self.now)
    def test_wrong_purpose_denied(self):
        with self.assertRaises(HardeningError): self.enroll(self.auth(purpose="generic_write"))
    def test_deployment_binding_substitution_denied(self):
        with self.assertRaises(HardeningError): self.enroll(self.auth(deployment_digest="0"*64))
    def test_readiness_binding_substitution_denied(self):
        with self.assertRaises(HardeningError): self.enroll(self.auth(readiness_digest="1"*64))
    def test_release_attestation_binding_substitution_denied(self):
        with self.assertRaises(HardeningError): self.enroll(self.auth(attestation_digest="2"*64))
    def test_release_provenance_binding_substitution_denied(self):
        with self.assertRaises(HardeningError): self.enroll(self.auth(verifier_receipt_digest="3"*64))
    def test_expired_or_future_authorization_denied(self):
        with self.assertRaises(HardeningError): self.enroll(self.auth(expires_at=(self.now-timedelta(seconds=1)).isoformat()))
        with self.assertRaises(HardeningError): self.enroll(self.auth(issued_at=(self.now+timedelta(seconds=61)).isoformat(),expires_at=(self.now+timedelta(seconds=120)).isoformat()))
    def test_untrusted_authority_class_denied(self):
        with self.assertRaises(HardeningError): self.enroll(self.auth(authority_class="self_asserted"))
    def test_verifier_binding_mismatch_denied(self):
        class Bad(Verifier):
            def verify(s,a,d): return replace(super().verify(a,d), deployment_digest="4"*64)
        self.verifier=Bad(self.now)
        with self.assertRaises(HardeningError): self.enroll()
    def test_authority_generation_rollback_denied(self):
        self.enroll(); a2=self.auth(authorization_id="a2",authorization_nonce="n2",authority_generation=2,enrollment_generation=2,key_id="k2"); self.enroll(a2)
        with self.assertRaises(HardeningError): self.enroll(self.auth(authorization_id="a3",authorization_nonce="n3",authority_generation=1,enrollment_generation=3))
    def test_nonce_replay_with_changed_content_denied(self):
        self.enroll()
        with self.assertRaises(HardeningError): self.enroll(self.auth(enrollment_generation=2))
    def test_enrollment_generation_is_authority_selected_not_caller_selected(self):
        rec=self.enroll(self.auth(enrollment_generation=7)); self.assertEqual(rec.generation,7)
    def test_non_ready_adapter_cannot_be_authorized_into_runtime(self):
        self.readiness=replace(self.readiness,production_ready=False,missing_requirements=("backend",))
        with self.assertRaises(HardeningError): self.enroll()

if __name__ == "__main__": unittest.main()
