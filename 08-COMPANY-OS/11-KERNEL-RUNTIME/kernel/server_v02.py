#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from datetime import datetime,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlparse
from .runtime import CompanyKernel,KernelError,RequestContext
from .hardening import HardeningError,PolicyEngine,ReadOnlyHTTPAdapter,SessionManager,TamperEvidentAuditChain

class HardenedKernel:
    def __init__(self,core:CompanyKernel,policy_dir:str,readonly_hosts:set[str],allow_http_localhost:bool=False):
        self.core=core; self.sessions=SessionManager(core.store.conn); self.policies=PolicyEngine(policy_dir); self.audit_chain=TamperEvidentAuditChain(core.state_dir/'audit-chain.jsonl'); self.http=ReadOnlyHTTPAdapter(readonly_hosts,allow_http_localhost=allow_http_localhost)
    def _chain(self,ctx,kind,result): return self.audit_chain.append({'time':datetime.now(timezone.utc).isoformat(),'actor_id':ctx.actor_id,'process_id':ctx.process_id,'trace_id':ctx.trace_id,'kind':kind,'result':result})
    def authenticated_context(self,bearer,process_id,trace_id,correlation_id=None):
        actor=self.sessions.authenticate(bearer); self._validate_process_binding(actor,process_id); return RequestContext(actor,process_id,trace_id,correlation_id)
    def _validate_process_binding(self,actor,process_id):
        if process_id.startswith('kernel:'):
            if actor!='human:owner': raise HardeningError('CFHS_POLICY_DENIED','Kernel bootstrap process is owner-only')
            return
        row=self.core.store.one('SELECT owner FROM processes WHERE id=?',(process_id,))
        if not row: raise HardeningError('CFHS_NOT_FOUND','Process not found')
        if row['owner']==actor:return
        p=self.core._principal(actor); caps=json.loads(p['capabilities_json'])
        if not any(c.get('action') in ('kernel.process.supervise','*') for c in caps): raise HardeningError('CFHS_POLICY_DENIED','Actor is not bound to this process')
    def authorize(self,ctx,action,resource,context=None):
        base=self.core.authorize(ctx,action,resource,context)
        if base['decision']=='ALLOW':
            restriction=self.policies.evaluate(ctx.actor_id,action,resource,context or {})
            if restriction:
                base=dict(base); base['decision']=restriction.effect; base['matched_policies']=list(base.get('matched_policies',[]))+list(restriction.policy_ids); base['constraints']=dict(base.get('constraints',{}))|restriction.constraints
        self._chain(ctx,'authorization',base); return base
    def issue_session(self,ctx,principal_id,ttl_seconds=3600):
        d=self.authorize(ctx,'kernel.session.issue','/sys/identity/sessions',{'principal_id':principal_id})
        if d['decision']!='ALLOW': raise HardeningError('CFHS_POLICY_DENIED','Session issuance not authorized',d)
        self.core._principal(principal_id); result=self.sessions.issue(principal_id,ttl_seconds); self._chain(ctx,'session.issued',{k:v for k,v in result.items() if k!='bearer_token'}); return result
    def invoke_readonly_http(self,ctx,url,classification='PUBLIC'):
        d=self.authorize(ctx,'http.get','/dev/http/readonly',{'external':True,'classification':classification,'url':url})
        if d['decision']=='DENY': raise HardeningError('CFHS_POLICY_DENIED','Read-only HTTP denied',d)
        if d['decision']=='ELEVATION_REQUIRED': raise HardeningError('CFHS_ELEVATION_REQUIRED','Read-only HTTP requires elevation',d)
        result=self.http.get(url); safe={'url':url,'status':result['status'],'bytes':result['bytes'],'side_effect_class':'S0'}; self.core.audit(ctx,'device.invoke','http.get','/dev/http/readonly','ALLOW',safe); self._chain(ctx,'device.invoke',safe); return result

class Handler(BaseHTTPRequestHandler):
    hardened:HardenedKernel=None # type: ignore
    def log_message(self,*args):pass
    def _json(self):
        n=int(self.headers.get('Content-Length','0')); return json.loads(self.rfile.read(n) if n else b'{}')
    def _send(self,code,obj):
        data=json.dumps(obj,indent=2).encode(); self.send_response(code); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
    def _bearer(self):
        a=self.headers.get('Authorization','')
        if not a.startswith('Bearer '): raise HardeningError('CFHS_UNAUTHENTICATED','Bearer kernel session required')
        return a[7:]
    def _ctx(self):
        pid=self.headers.get('X-CFHS-Process-ID'); trace=self.headers.get('X-CFHS-Trace-ID')
        if not pid or not trace: raise HardeningError('CFHS_INVALID_REQUEST','Process and trace headers required')
        return self.hardened.authenticated_context(self._bearer(),pid,trace,self.headers.get('X-CFHS-Correlation-ID'))
    def _error(self,e):
        c=401 if getattr(e,'code','')=='CFHS_UNAUTHENTICATED' else 403 if getattr(e,'code','') in {'CFHS_POLICY_DENIED','CFHS_ELEVATION_REQUIRED'} else 400
        self._send(c,{'error':{'code':getattr(e,'code','CFHS_INTERNAL'),'message':str(e),'details':getattr(e,'details',{})}})
    def do_GET(self):
        try:
            p=urlparse(self.path).path
            if p=='/v2/health':
                x=self.hardened.core.health(); x['hardening_version']='0.2'; x['audit_chain']=self.hardened.audit_chain.verify(); return self._send(200,x)
            self._ctx()
            if p=='/v2/audit/verify': return self._send(200,self.hardened.audit_chain.verify())
            raise HardeningError('CFHS_NOT_FOUND','Endpoint not found')
        except (HardeningError,KernelError) as e:self._error(e)
        except Exception as e:self._send(500,{'error':{'code':'CFHS_INTERNAL','message':str(e)}})
    def do_POST(self):
        try:
            p=urlparse(self.path).path; body=self._json(); ctx=self._ctx()
            if p=='/v2/authorize': return self._send(200,self.hardened.authorize(ctx,body['action'],body['resource'],body.get('context')))
            if p=='/v2/sessions': return self._send(201,self.hardened.issue_session(ctx,body['principal_id'],body.get('ttl_seconds',3600)))
            if p=='/v2/devices/http-readonly/invoke': return self._send(200,self.hardened.invoke_readonly_http(ctx,body['url'],body.get('classification','PUBLIC')))
            raise HardeningError('CFHS_NOT_FOUND','Endpoint not found')
        except (HardeningError,KernelError) as e:self._error(e)
        except Exception as e:self._send(500,{'error':{'code':'CFHS_INTERNAL','message':str(e)}})

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--state-dir',required=True); ap.add_argument('--config',required=True); ap.add_argument('--policy-dir',required=True); ap.add_argument('--host',default='127.0.0.1'); ap.add_argument('--port',type=int,default=8043); ap.add_argument('--readonly-host',action='append',default=[]); ap.add_argument('--bootstrap-principal',default='human:owner'); ap.add_argument('--allow-http-localhost',action='store_true'); a=ap.parse_args()
    core=CompanyKernel.from_file(a.state_dir,a.config); Handler.hardened=HardenedKernel(core,a.policy_dir,set(a.readonly_host),a.allow_http_localhost); bootstrap=Handler.hardened.sessions.issue(a.bootstrap_principal,900); print('BOOTSTRAP_SESSION='+bootstrap['bearer_token'],flush=True); srv=ThreadingHTTPServer((a.host,a.port),Handler); print(f'Company Kernel hardening v0.2 listening on http://{a.host}:{a.port}',flush=True); srv.serve_forever()
if __name__=='__main__':main()
