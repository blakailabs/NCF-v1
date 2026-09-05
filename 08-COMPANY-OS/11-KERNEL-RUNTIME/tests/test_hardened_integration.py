import tempfile,threading,unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from kernel.runtime import CompanyKernel,RequestContext
from kernel.server_v02 import HardenedKernel
from kernel.hardening import HardeningError
ROOT=Path(__file__).resolve().parents[1]
class LocalHandler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        b=b'{"company_os":"reachable"}';self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
class HardenedIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.srv=ThreadingHTTPServer(('127.0.0.1',0),LocalHandler);threading.Thread(target=self.srv.serve_forever,daemon=True).start()
        core=CompanyKernel.from_file(self.tmp.name,ROOT/'examples/kernel.config.json');self.hk=HardenedKernel(core,str(ROOT/'examples/policies'),{'127.0.0.1'},True);self.owner_boot=RequestContext('human:owner','kernel:bootstrap','trace:boot')
        owner=self.hk.sessions.issue('human:owner',300);self.owner_token=owner['bearer_token'];proc=core.spawn_process(self.owner_boot,'ops-hardening','agent:ops');self.proc_id=proc['process_id'];self.agent_token=self.hk.issue_session(self.owner_boot,'agent:ops',300)['bearer_token']
    def tearDown(self):self.srv.shutdown();self.srv.server_close();self.tmp.cleanup()
    def test_authenticated_process_binding(self):
        ctx=self.hk.authenticated_context(self.agent_token,self.proc_id,'trace:agent');self.assertEqual(ctx.actor_id,'agent:ops')
        with self.assertRaises(HardeningError):self.hk.authenticated_context(self.agent_token,'kernel:bootstrap','trace:bad')
    def test_policy_can_reduce_base_authority(self):
        ctx=self.hk.authenticated_context(self.agent_token,self.proc_id,'trace:refund');d=self.hk.authorize(ctx,'payments.refund','/dev/payments/primary',{'amount':5000});self.assertEqual(d['decision'],'ELEVATION_REQUIRED');self.assertIn('elevate-high-refund',d['matched_policies'])
    def test_readonly_live_device_and_audit_chain(self):
        ctx=self.hk.authenticated_context(self.agent_token,self.proc_id,'trace:http');r=self.hk.invoke_readonly_http(ctx,f'http://127.0.0.1:{self.srv.server_port}/status','PUBLIC');self.assertEqual(r['status'],200);self.assertTrue(self.hk.audit_chain.verify()['valid'])
    def test_restricted_external_data_denied(self):
        ctx=self.hk.authenticated_context(self.agent_token,self.proc_id,'trace:restricted')
        with self.assertRaises(HardeningError) as cm:self.hk.invoke_readonly_http(ctx,f'http://127.0.0.1:{self.srv.server_port}/status','RESTRICTED')
        self.assertEqual(cm.exception.code,'CFHS_POLICY_DENIED')
if __name__=='__main__':unittest.main()
