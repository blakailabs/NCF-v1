import unittest

from kernel.google_spanner_transport_v091 import GoogleSpannerTransportConfig, GoogleSpannerTransportV091
from kernel.hardening import HardeningError


class FakeSnapshot:
    read_timestamp = "2026-09-08T20:00:00Z"
    def __enter__(self): return self
    def __exit__(self,*a): return False
    def execute_sql(self,*a,**k): return [(3,"2026-09-08T19:59:59Z")]

class FakeTxn:
    def __init__(self, fence=4): self.fence=fence; self.updates=[]
    def execute_sql(self, sql, **kwargs):
        if "cfhs_shared_fences" in sql: return [(self.fence,)]
        return [(7,)]
    def execute_update(self, sql, **kwargs): self.updates.append((sql,kwargs)); return 1

class FakeDatabase:
    def __init__(self): self.txn=FakeTxn()
    def snapshot(self): return FakeSnapshot()
    def run_in_transaction(self, fn): return fn(self.txn)

class FakeInstance:
    def __init__(self, db): self.db=db
    def database(self, database_id): self.database_id=database_id; return self.db

class FakeClient:
    def __init__(self, project, db): self.project=project; self.db=db
    def instance(self, instance_id): self.instance_id=instance_id; return FakeInstance(self.db)

class FakeModule:
    def __init__(self, db): self.db=db
    def Client(self, project): return FakeClient(project,self.db)


class GoogleSpannerTransportTests(unittest.TestCase):
    def cfg(self, **kw):
        d=dict(project_id="cfhs-kernel-cert",instance_id="kernel-ha-cert-01",database_id="cfhs-cert")
        d.update(kw); return GoogleSpannerTransportConfig(**d)

    def test_emulator_target_denied(self):
        with self.assertRaises(HardeningError): GoogleSpannerTransportV091(self.cfg(emulator_host="localhost:9010"))

    def test_invalid_identifier_denied(self):
        with self.assertRaises(HardeningError): GoogleSpannerTransportV091(self.cfg(project_id="bad id"))

    def test_lazy_transport_starts_disconnected(self):
        t=GoogleSpannerTransportV091(self.cfg(), lambda _: FakeModule(FakeDatabase()))
        self.assertFalse(t.connected)

    def test_connect_uses_explicit_project_instance_database(self):
        t=GoogleSpannerTransportV091(self.cfg(), lambda _: FakeModule(FakeDatabase())); t.connect(); self.assertTrue(t.connected)

    def test_sdk_import_failure_is_structured(self):
        def bad(_): raise ImportError("no")
        with self.assertRaises(HardeningError) as cm: GoogleSpannerTransportV091(self.cfg(), bad).connect()
        self.assertEqual(cm.exception.code,"CFHS_SPANNER_SDK_UNAVAILABLE")

    def test_read_requires_connection(self):
        with self.assertRaises(HardeningError): GoogleSpannerTransportV091(self.cfg(), lambda _:None).strong_read("/x")

    def test_strong_read_observation_shape(self):
        t=GoogleSpannerTransportV091(self.cfg(), lambda _: FakeModule(FakeDatabase())); t.connect(); r=t.strong_read("/x")
        self.assertEqual((r["read_consistency"],r["object_version"]),("strong",3))

    def test_unknown_write_operation_denied(self):
        t=GoogleSpannerTransportV091(self.cfg(), lambda _: FakeModule(FakeDatabase())); t.connect()
        with self.assertRaises(HardeningError): t.run_read_write("drop_table",{})

    def test_stale_cas_probe_is_observation_only(self):
        t=GoogleSpannerTransportV091(self.cfg(), lambda _: FakeModule(FakeDatabase())); t.connect(); r=t.run_read_write("stale_cas_probe",{"object_key":"/x","stale_expected_version":6})
        self.assertFalse(r["mutation_applied"])

    def test_atomic_live_result_is_not_synthesized(self):
        t=GoogleSpannerTransportV091(self.cfg(), lambda _: FakeModule(FakeDatabase())); t.connect(); r=t.run_read_write("fenced_cas_journal",{})
        self.assertFalse(r["committed"])
        self.assertIn("LIVE_RESULT_BINDING_REQUIRED",r["provider_code"])


if __name__=="__main__": unittest.main()
