import json,os,sqlite3,tempfile,threading,unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from kernel.hardening import EnvironmentSecretBroker,HardeningError,PolicyEngine,ReadOnlyHTTPAdapter,SessionManager,TamperEvidentAuditChain
ROOT=Path(__file__).resolve().parents[1]
class QuietHandler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        body=b'{"status":"ok"}'; self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.db=sqlite3.connect(Path(self.tmp.name)/'test.db'); self.db.row_factory=sqlite3.Row
    def tearDown(self): self.db.close(); self.tmp.cleanup()
    def test_session_hash_auth_and_revoke(self):
        sm=SessionManager(self.db); s=sm.issue('human:owner',60); row=self.db.execute('select token_hash from kernel_sessions where id=?',(s['session_id'],)).fetchone(); self.assertNotEqual(row['token_hash'],s['bearer_token']); self.assertEqual(sm.authenticate(s['bearer_token']),'human:owner'); sm.revoke(s['session_id']);
        with self.assertRaises(HardeningError):sm.authenticate(s['bearer_token'])
    def test_policy_restrictive_only(self):
        pe=PolicyEngine(ROOT/'examples/policies'); self.assertEqual(pe.evaluate('agent:ops','payments.refund','/dev/payments/primary',{'amount':5000}).effect,'ELEVATION_REQUIRED'); self.assertEqual(pe.evaluate('agent:ops','http.get','/dev/http/readonly',{'classification':'RESTRICTED','external':True}).effect,'DENY')
    def test_policy_rejects_allow(self):
        p=Path(self.tmp.name)/'p';p.mkdir();(p/'bad.json').write_text(json.dumps({'id':'bad','effect':'ALLOW'}));
        with self.assertRaises(HardeningError):PolicyEngine(p)
    def test_audit_chain_detects_tampering(self):
        p=Path(self.tmp.name)/'audit.jsonl';a=TamperEvidentAuditChain(p);a.append({'event':'one'});a.append({'event':'two'});self.assertTrue(a.verify()['valid']);lines=p.read_text().splitlines();r=json.loads(lines[0]);r['event']='tampered';lines[0]=json.dumps(r);p.write_text('\n'.join(lines)+'\n');self.assertFalse(a.verify()['valid'])
    def test_secret_broker_lease_hides_value(self):
        os.environ['CFHS_TEST_ONLY_VALUE']='TEST_ONLY_VALUE';b=EnvironmentSecretBroker();lease=b.lease('secret://env/CFHS_TEST_ONLY_VALUE','mock-device',10);self.assertNotIn('value',lease);self.assertEqual(b.resolve_for_adapter(lease['lease_id'],'mock-device'),'TEST_ONLY_VALUE');b.revoke(lease['lease_id']);
        with self.assertRaises(HardeningError):b.resolve_for_adapter(lease['lease_id'],'mock-device')
    def test_readonly_http_live_local(self):
        srv=ThreadingHTTPServer(('127.0.0.1',0),QuietHandler);threading.Thread(target=srv.serve_forever,daemon=True).start()
        try:
            a=ReadOnlyHTTPAdapter({'127.0.0.1'},allow_http_localhost=True,max_bytes=1024);r=a.get(f'http://127.0.0.1:{srv.server_port}/health');self.assertEqual(r['status'],200);self.assertEqual(r['side_effect_class'],'S0')
            with self.assertRaises(HardeningError):a.get('http://example.com/')
        finally:srv.shutdown();srv.server_close()
if __name__=='__main__':unittest.main()
