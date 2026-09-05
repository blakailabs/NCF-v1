#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from .runtime import CompanyKernel, KernelError, RequestContext

class Handler(BaseHTTPRequestHandler):
    kernel: CompanyKernel = None  # type: ignore
    def log_message(self, fmt, *args): pass
    def _json(self):
        n=int(self.headers.get('Content-Length','0')); raw=self.rfile.read(n) if n else b'{}'; return json.loads(raw or b'{}')
    def _ctx(self):
        actor=self.headers.get('X-CFHS-Actor-ID'); proc=self.headers.get('X-CFHS-Process-ID'); trace=self.headers.get('X-CFHS-Trace-ID')
        if not actor or not proc or not trace: raise KernelError('CFHS_INVALID_REQUEST','Missing CFHS actor/process/trace headers')
        return RequestContext(actor, proc, trace, self.headers.get('X-CFHS-Correlation-ID'))
    def _send(self, code, obj):
        data=json.dumps(obj,indent=2).encode(); self.send_response(code); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
    def _error(self, e, trace='trace_unknown'):
        req='req_unknown'; code=403 if e.code in ('CFHS_POLICY_DENIED','CFHS_ELEVATION_REQUIRED') else 400; self._send(code,e.as_dict(req,trace))
    def do_GET(self):
        try:
            p=urlparse(self.path).path
            if p=='/v1/health': return self._send(200,self.kernel.health())
            ctx=self._ctx()
            if p=='/v1/audit': return self._send(200,{"records":self.kernel.audit_records()})
            if p.startswith('/v1/processes/'):
                pid=p.split('/')[-1]; row=self.kernel.store.one('SELECT * FROM processes WHERE id=?',(pid,))
                if not row: raise KernelError('CFHS_NOT_FOUND','Process not found')
                return self._send(200,dict(row))
            raise KernelError('CFHS_NOT_FOUND','Endpoint not found')
        except KernelError as e: self._error(e,self.headers.get('X-CFHS-Trace-ID','trace_unknown'))
        except Exception as e: self._send(500,{"error":{"code":"CFHS_INTERNAL","message":str(e)}})
    def do_POST(self):
        try:
            p=urlparse(self.path).path; body=self._json(); ctx=self._ctx()
            if p=='/v1/authorize': return self._send(200,self.kernel.authorize(ctx,body['action'],body['resource'],body.get('context')))
            if p=='/v1/elevations': return self._send(201,self.kernel.request_elevation(ctx,body['action'],body['resource'],body.get('scope',{}),body.get('reason','')))
            if p.startswith('/v1/elevations/') and p.endswith('/approve'):
                eid=p.split('/')[-2]; return self._send(200,self.kernel.approve_elevation(ctx,eid,int(body.get('ttl_seconds',600))))
            if p=='/v1/processes': return self._send(201,self.kernel.spawn_process(ctx,body['name'],body['owner'],body.get('metadata'),body.get('parent_process_id')))
            if p.startswith('/v1/processes/') and p.endswith('/checkpoints'):
                pid=p.split('/')[-2]; return self._send(201,self.kernel.checkpoint(ctx,pid,body.get('state',{})))
            if p.startswith('/v1/devices/') and p.endswith('/invoke'):
                did=p.split('/')[-2]; return self._send(200,self.kernel.invoke_device(ctx,did,body['operation'],body.get('arguments',{}),self.headers.get('Idempotency-Key')))
            raise KernelError('CFHS_NOT_FOUND','Endpoint not found')
        except KernelError as e: self._error(e,self.headers.get('X-CFHS-Trace-ID','trace_unknown'))
        except Exception as e: self._send(500,{"error":{"code":"CFHS_INTERNAL","message":str(e)}})

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--state-dir',required=True); ap.add_argument('--config',required=True); ap.add_argument('--host',default='127.0.0.1'); ap.add_argument('--port',type=int,default=8042); a=ap.parse_args()
    Handler.kernel=CompanyKernel.from_file(a.state_dir,a.config)
    srv=ThreadingHTTPServer((a.host,a.port),Handler); print(f'Company Kernel v0.1 listening on http://{a.host}:{a.port}',flush=True); srv.serve_forever()
if __name__=='__main__': main()
