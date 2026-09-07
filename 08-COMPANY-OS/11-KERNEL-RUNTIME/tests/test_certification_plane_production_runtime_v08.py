import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kernel.certification_plane_attestation import CertificationPlaneAdapterAttestation, CertificationPlaneAdapterReadiness, CertificationPlaneDeploymentIdentity
from kernel.certification_plane_enrollment import EnrolledCertificationPlaneRuntime, SharedAdapterEnrollmentRegistry
from kernel.certification_plane_enrollment_authority import AdapterEnrollmentAuthorization, EnrollmentAuthorityTrustReadiness, ProductionAdapterEnrollmentAuthorityGate, ReferenceAdapterEnrollmentAuthorityTrustStore, VerifiedAdapterEnrollmentAuthorization
from kernel.certification_plane_production_runtime import ProductionCertificationPlaneRuntime, ProductionCertificationPlaneRuntimeWiring, SharedProductionEnrollmentActivationRegistry
from kernel.ha_certification_runtime import HACertificationRecord
from kernel.hardening import HardeningError
from kernel.shared_certification_plane import SharedStateCertificationPlane
from kernel.shared_state_backend import SharedBackendCapabilities, SQLiteSharedStateBackend
from kernel.trust import sha256_hex


class Backend(SQLiteSharedStateBackend):
    def __init__(self, path, now):
        super().__init__(path, backend_id="production-runtime-backend-v08"); self.now=now
    def authoritative_now(self): return self.now
    def capabilities(self): return SharedBackendCapabilities(self.backend_id, True, True, True, True, True, True, True, True)

class ProductionStore(ReferenceAdapterEnrollmentAuthorityTrustStore):
    def readiness(self): return EnrollmentAuthorityTrustReadiness(True, self.trust_store_id)

class Verifier:
    def __init__(self, now): self.now=now
    def verify(self,a,d): return VerifiedAdapterEnrollmentAuthorization(a.digest(),d.digest(),a.authority_id,a.authority_class,a.key_id,a.authority_generation,a.enrollment_generation,self.now.isoformat(),sha256_hex({"verify":a.digest()}))


class ProductionRuntimeWiringV08Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/"prod-runtime.db"; self.now=datetime(2026,9,7,5,30,tzinfo=timezone.utc)
        self.backend=Backend(self.path,self.now); self.plane=SharedStateCertificationPlane(self.backend,fence_ttl_seconds=5); self.cluster="prod-runtime-cluster"; self._seed()
        self.registry=SharedAdapterEnrollmentRegistry(self.plane,fence_ttl_seconds=5); self.activation=SharedProductionEnrollmentActivationRegistry(self.registry,fence_ttl_seconds=5)
        self.current=self.deployment(); self.enrolled_runtime=EnrolledCertificationPlaneRuntime(self.plane,self.registry,lambda:self.current)
        self.gate=ProductionAdapterEnrollmentAuthorityGate(); self.store=ProductionStore("test-prod-enrollment-authority"); self.verifier=Verifier(self.now)
        self.wiring=ProductionCertificationPlaneRuntimeWiring(self.enrolled_runtime,self.registry,self.activation,self.gate,lambda:self.current)
    def tearDown(self): self.backend.close(); self.tmp.cleanup()
    def _seed(self):
        r=HACertificationRecord("cert",self.backend.backend_id,self.cluster,71,"n",sha256_hex({"e":1}),sha256_hex({"a":1}),sha256_hex({"c":1}),self.now.isoformat(),(self.now+timedelta(seconds=600)).isoformat(),"ACTIVE")
        self.plane.prepare_handoff(cluster_id=self.cluster,topology_epoch=71,handoff_digest="h",bootstrap_state_digest="b"*64,control_state_digest="c"*64,owner_id="seed")
        self.plane.activate(r,owner_id="seed",handoff_digest="h"); self.plane.close_handoff(cluster_id=self.cluster,topology_epoch=71,handoff_digest="h",certification_id="cert",owner_id="seed")
    def deployment(self,version="0.8.4",impl=None):
        return CertificationPlaneDeploymentIdentity.from_plane(self.plane,deployment_id="prod-runtime-deployment",cluster_id=self.cluster,adapter_name="company-os-ha-certification-plane",adapter_version=version,adapter_implementation_digest=impl or sha256_hex({"impl":version}),topology_evidence_digest=sha256_hex({"topology":version}),probe_evidence_digest=sha256_hex({"probes":version}))
    def material(self,deployment=None,generation=1,authority_generation=1,key="k1",nonce=None):
        d=deployment or self.current; att=CertificationPlaneAdapterAttestation(f"att-{generation}",d.digest(),"release-authority","independent_release_attestation",f"release-{generation}",generation,f"att-nonce-{generation}",(self.now-timedelta(seconds=5)).isoformat(),(self.now+timedelta(seconds=180)).isoformat())
        ready=CertificationPlaneAdapterReadiness(True,(),d.digest(),att.digest(),sha256_hex({"release":att.digest()}),"prod-release-trust")
        auth=AdapterEnrollmentAuthorization(f"auth-{generation}","activate_certification_plane_adapter",d.deployment_id,d.digest(),self.gate.readiness_digest(ready),att.digest(),ready.verifier_receipt_digest,ready.trust_store_id,generation,"prod-enrollment-authority","independent_enrollment_authority",key,authority_generation,nonce or f"auth-nonce-{generation}",(self.now-timedelta(seconds=5)).isoformat(),(self.now+timedelta(seconds=120)).isoformat())
        return d,att,ready,auth
    def activate(self,material=None):
        d,a,r,auth=material or self.material(); return self.wiring.authorize_activate_runtime(r,d,a,auth,self.verifier,self.store,owner_id="wire",now=self.now)

    def test_direct_registry_enrollment_cannot_unlock_production_runtime(self):
        d,a,r,_=self.material(); self.registry.enroll(r,d,a,generation=1,owner_id="direct")
        runtime=ProductionCertificationPlaneRuntime(self.enrolled_runtime,self.activation,lambda:self.current)
        with self.assertRaises(HardeningError) as cm: runtime.require_active()
        self.assertEqual(cm.exception.code,"CFHS_HA_PRODUCTION_ACTIVATION_REQUIRED")
    def test_authority_activation_receipt_unlocks_guarded_runtime(self):
        runtime=self.activate(); self.assertEqual(runtime.require_active()["backend_id"],self.backend.backend_id); self.assertEqual(self.activation.get(self.current.deployment_id).enrollment_generation,1)
    def test_exact_authority_activation_retry_is_idempotent(self):
        m=self.material(); self.activate(m); first=self.activation.get(self.current.deployment_id); self.activate(m); second=self.activation.get(self.current.deployment_id); self.assertEqual(first.version,second.version); self.assertEqual(first.authorization_digest,second.authorization_digest)
    def test_enrollment_without_activation_receipt_recovers_on_authorized_retry(self):
        d,a,r,auth=self.material(); self.gate.authorize_and_enroll(self.registry,r,d,a,auth,self.verifier,self.store,owner_id="phase1",now=self.now)
        with self.assertRaises(HardeningError): ProductionCertificationPlaneRuntime(self.enrolled_runtime,self.activation,lambda:self.current).current()
        self.activation.record_authorized_activation(self.registry.get(d.deployment_id),auth,owner_id="phase2"); self.assertEqual(ProductionCertificationPlaneRuntime(self.enrolled_runtime,self.activation,lambda:self.current).require_active()["cluster_id"],self.cluster)
    def test_tampered_activation_receipt_fails_closed(self):
        self.activate(); key=self.activation.object_key(self.current.deployment_id); obj=self.backend.read(key); bad=dict(obj.value); bad["deployment_digest"]="0"*64; self.backend.compare_and_swap(key,obj.version,bad)
        with self.assertRaises(HardeningError) as cm: ProductionCertificationPlaneRuntime(self.enrolled_runtime,self.activation,lambda:self.current).require_active()
        self.assertEqual(cm.exception.code,"CFHS_HA_PRODUCTION_ACTIVATION_STALE")
    def test_direct_enrollment_rotation_makes_old_activation_stale(self):
        self.activate(); d2=self.deployment("0.8.5"); a2=CertificationPlaneAdapterAttestation("att-2",d2.digest(),"release-authority","independent_release_attestation","release-2",2,"att-nonce-2",(self.now-timedelta(seconds=5)).isoformat(),(self.now+timedelta(seconds=180)).isoformat()); r2=CertificationPlaneAdapterReadiness(True,(),d2.digest(),a2.digest(),sha256_hex({"r":2}),"prod-release-trust"); self.registry.enroll(r2,d2,a2,generation=2,owner_id="direct-rotate"); self.current=d2
        with self.assertRaises(HardeningError) as cm: ProductionCertificationPlaneRuntime(self.enrolled_runtime,self.activation,lambda:self.current).require_active()
        self.assertEqual(cm.exception.code,"CFHS_HA_PRODUCTION_ACTIVATION_STALE")
    def test_authorized_rotation_updates_activation_and_runtime(self):
        self.activate(); d2=self.deployment("0.8.5"); self.current=d2; runtime=self.activate(self.material(d2,2,2,"k2")); self.assertEqual(self.activation.get(d2.deployment_id).enrollment_generation,2); self.assertEqual(runtime.require_active()["cluster_id"],self.cluster)
    def test_activation_generation_rollback_is_rejected(self):
        self.activate(); d2=self.deployment("0.8.5"); self.current=d2; self.activate(self.material(d2,2,2,"k2")); old_enrollment=self.registry.get(d2.deployment_id)
        old_auth=self.material(self.deployment("0.8.4"),1,1,"k1","old-new-nonce")[3]
        with self.assertRaises(HardeningError): self.activation.record_authorized_activation(old_enrollment,old_auth,owner_id="rollback")
    def test_authority_generation_rollback_is_rejected_on_higher_enrollment(self):
        self.activate(); d2=self.deployment("0.8.5"); self.current=d2; self.activate(self.material(d2,2,3,"k3")); d3=self.deployment("0.8.6"); self.current=d3; d,a,r,auth=self.material(d3,3,2,"k2"); enrollment=self.registry.enroll(r,d,a,generation=3,owner_id="direct3")
        with self.assertRaises(HardeningError) as cm: self.activation.record_authorized_activation(enrollment,auth,owner_id="bad-authority")
        self.assertEqual(cm.exception.code,"CFHS_AUTHORITY_ROLLBACK")
    def test_cross_process_activation_receipt_is_visible(self):
        self.activate(); b2=Backend(self.path,self.now); p2=SharedStateCertificationPlane(b2,fence_ttl_seconds=5); r2=SharedAdapterEnrollmentRegistry(p2,fence_ttl_seconds=5); a2=SharedProductionEnrollmentActivationRegistry(r2,fence_ttl_seconds=5)
        try: self.assertEqual(a2.require_matches(r2.get(self.current.deployment_id)).authority_id,"prod-enrollment-authority")
        finally: b2.close()
    def test_restart_preserves_authority_activation_receipt(self):
        self.activate(); self.backend.close(); b2=Backend(self.path,self.now); p2=SharedStateCertificationPlane(b2,fence_ttl_seconds=5); r2=SharedAdapterEnrollmentRegistry(p2,fence_ttl_seconds=5); a2=SharedProductionEnrollmentActivationRegistry(r2,fence_ttl_seconds=5)
        try: self.assertEqual(a2.get(self.current.deployment_id).authorization_digest,self.material()[3].digest())
        finally: b2.close(); self.backend=Backend(self.path,self.now); self.plane=SharedStateCertificationPlane(self.backend,fence_ttl_seconds=5)
    def test_enrollment_revocation_overrides_existing_activation_receipt(self):
        runtime=self.activate(); self.registry.revoke(self.current.deployment_id,"emergency revoke",owner_id="revoker")
        with self.assertRaises(HardeningError) as cm: runtime.require_active()
        self.assertEqual(cm.exception.code,"CFHS_HA_ENROLLMENT_REVOKED")

if __name__ == "__main__": unittest.main()
