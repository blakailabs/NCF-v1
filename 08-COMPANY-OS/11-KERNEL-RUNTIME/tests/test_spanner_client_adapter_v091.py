import unittest
from kernel.hardening import HardeningError
from kernel.spanner_client_adapter_v091 import SpannerClientAdapterV091


class FakeTransport:
    def __init__(self): self.calls=[]; self.read={"read_consistency":"strong","observed_commit_timestamp":"2026-09-08T20:00:00Z"}; self.outcomes={}
    def strong_read(self,key): self.calls.append(("read",key)); return dict(self.read)
    def run_read_write(self,op,request): self.calls.append((op,request)); return dict(self.outcomes[op])

def atomic(): return {"committed":True,"provider_code":"OK","attempts":2,"commit_timestamp":"2026-09-08T20:00:01Z","single_read_write_transaction":True,"fence_asserted":True,"object_cas_applied":True,"journal_appended":True,"object_version":2,"fence_token":4,"journal_version":9,"journal_object_version":2,"journal_fence_token":4,"journal_commit_timestamp":"2026-09-08T20:00:01Z"}

class SpannerClientAdapterTests(unittest.TestCase):
    def test_network_disabled_by_default(self):
        with self.assertRaises(HardeningError): SpannerClientAdapterV091(FakeTransport()).strong_read("/x")
    def test_mutations_independently_disabled(self):
        with self.assertRaises(HardeningError): SpannerClientAdapterV091(FakeTransport(),True).stale_cas_probe("/x",1)
    def test_strong_read_calls_transport_and_validates(self):
        t=FakeTransport(); a=SpannerClientAdapterV091(t,True); self.assertEqual(a.strong_read("/x")["read_consistency"],"strong")
    def test_invalid_object_key_rejected_before_transport(self):
        t=FakeTransport(); a=SpannerClientAdapterV091(t,True)
        with self.assertRaises(HardeningError): a.strong_read("relative")
        self.assertEqual(t.calls,[])
    def test_stale_cas_rejection_observed(self):
        t=FakeTransport(); t.outcomes["stale_cas_probe"]={"stale_expected_version":1,"mutation_applied":False,"journal_appended":False}
        self.assertFalse(SpannerClientAdapterV091(t,True,True).stale_cas_probe("/x",1)["mutation_applied"])
    def test_stale_cas_acceptance_fails(self):
        t=FakeTransport(); t.outcomes["stale_cas_probe"]={"stale_expected_version":1,"mutation_applied":True,"journal_appended":False}
        with self.assertRaises(HardeningError): SpannerClientAdapterV091(t,True,True).stale_cas_probe("/x",1)
    def test_atomic_mutation_returns_kernel_shape(self):
        t=FakeTransport(); t.outcomes["fenced_cas_journal"]=atomic(); r=SpannerClientAdapterV091(t,True,True).fenced_cas_journal(object_key="/x",expected_version=1,fence_token=4,journal_stream="s",expected_journal_version=8,payload_digest="abc")
        self.assertEqual((r["object_version"],r["journal_version"],r["attempts"]),(2,9,2))
    def test_atomic_mutation_rejects_split_transaction(self):
        t=FakeTransport(); o=atomic(); o["single_read_write_transaction"]=False; t.outcomes["fenced_cas_journal"]=o
        with self.assertRaises(HardeningError): SpannerClientAdapterV091(t,True,True).fenced_cas_journal(object_key="/x",expected_version=1,fence_token=4,journal_stream="s",expected_journal_version=8,payload_digest="abc")
    def test_request_validation_precedes_transport(self):
        t=FakeTransport(); a=SpannerClientAdapterV091(t,True,True)
        with self.assertRaises(HardeningError): a.fenced_cas_journal(object_key="/x",expected_version=-1,fence_token=4,journal_stream="s",expected_journal_version=8,payload_digest="abc")
        self.assertEqual(t.calls,[])
    def test_fence_acquire_requires_monotonic_token(self):
        t=FakeTransport(); t.outcomes["acquire_fence"]={"committed":True,"provider_code":"OK","attempts":1,"commit_timestamp":"t","fence_token":6}
        self.assertEqual(SpannerClientAdapterV091(t,True,True).acquire_fence("f",5)["fence_token"],6)
    def test_fence_acquire_rejects_stale_token(self):
        t=FakeTransport(); t.outcomes["acquire_fence"]={"committed":True,"provider_code":"OK","attempts":1,"commit_timestamp":"t","fence_token":5}
        with self.assertRaises(HardeningError): SpannerClientAdapterV091(t,True,True).acquire_fence("f",5)
    def test_transport_receives_no_credentials(self):
        t=FakeTransport(); t.outcomes["fenced_cas_journal"]=atomic(); SpannerClientAdapterV091(t,True,True).fenced_cas_journal(object_key="/x",expected_version=1,fence_token=4,journal_stream="s",expected_journal_version=8,payload_digest="abc")
        self.assertNotIn("credential", str(t.calls).lower())

if __name__=="__main__": unittest.main()
