from __future__ import annotations
import hashlib,hmac,ipaddress,json,os,secrets,socket,sqlite3,urllib.parse,urllib.request
from dataclasses import dataclass
from datetime import datetime,timedelta,timezone
from pathlib import Path
from typing import Any

def now(): return datetime.now(timezone.utc)
class HardeningError(Exception):
    def __init__(self,code:str,message:str,details:dict[str,Any]|None=None): super().__init__(message); self.code=code; self.details=details or {}

class SessionManager:
    def __init__(self,conn:sqlite3.Connection):
        self.conn=conn; self.conn.execute('CREATE TABLE IF NOT EXISTS kernel_sessions(id TEXT PRIMARY KEY,principal_id TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL,expires_at TEXT NOT NULL,revoked_at TEXT)'); self.conn.commit()
    def _hash(self,t): return hashlib.sha256(t.encode()).hexdigest()
    def issue(self,principal_id:str,ttl_seconds:int=3600):
        ttl=max(60,min(int(ttl_seconds),86400)); token='cks_'+secrets.token_urlsafe(32); sid='sess_'+secrets.token_hex(10); created=now(); exp=created+timedelta(seconds=ttl)
        self.conn.execute('INSERT INTO kernel_sessions(id,principal_id,token_hash,created_at,expires_at) VALUES(?,?,?,?,?)',(sid,principal_id,self._hash(token),created.isoformat(),exp.isoformat())); self.conn.commit()
        return {'session_id':sid,'principal_id':principal_id,'bearer_token':token,'expires_at':exp.isoformat()}
    def authenticate(self,token:str):
        digest=self._hash(token); row=self.conn.execute('SELECT principal_id,token_hash,expires_at,revoked_at FROM kernel_sessions WHERE token_hash=?',(digest,)).fetchone()
        if not row or not hmac.compare_digest(row['token_hash'],digest) or row['revoked_at'] or datetime.fromisoformat(row['expires_at'])<=now(): raise HardeningError('CFHS_UNAUTHENTICATED','Invalid, revoked, or expired kernel session')
        return str(row['principal_id'])
    def revoke(self,sid:str): self.conn.execute('UPDATE kernel_sessions SET revoked_at=? WHERE id=?',(now().isoformat(),sid)); self.conn.commit()

@dataclass(frozen=True)
class PolicyDecision: effect:str; policy_ids:tuple[str,...]; constraints:dict[str,Any]
class PolicyEngine:
    def __init__(self,policy_dir:str|Path): self.dir=Path(policy_dir); self.policies=[]; self.reload()
    def reload(self):
        self.policies=[]
        if not self.dir.exists(): return
        for p in sorted(self.dir.glob('*.json')):
            doc=json.loads(p.read_text()); docs=doc if isinstance(doc,list) else doc.get('policies',[doc])
            for x in docs:
                if x.get('enabled',True):
                    if x.get('effect') not in {'DENY','ELEVATION_REQUIRED'}: raise HardeningError('CFHS_INVALID_POLICY',f'Policy may only restrict authority: {p}')
                    self.policies.append(x)
    def _m(self,v,p): return p=='*' or v==p or (p.endswith('*') and v.startswith(p[:-1]))
    def evaluate(self,principal,action,resource,context=None):
        c=context or {}; matches=[]
        for p in self.policies:
            if not(self._m(principal,p.get('principal','*')) and self._m(action,p.get('action','*')) and self._m(resource,p.get('resource','*'))): continue
            cond=p.get('conditions',{})
            if 'amount_gt' in cond and not float(c.get('amount',0))>float(cond['amount_gt']): continue
            if 'classification_in' in cond and c.get('classification') not in cond['classification_in']: continue
            if 'external' in cond and bool(c.get('external',False))!=bool(cond['external']): continue
            matches.append(p)
        if not matches:return None
        effect='DENY' if any(p['effect']=='DENY' for p in matches) else 'ELEVATION_REQUIRED'
        return PolicyDecision(effect,tuple(p.get('id','policy') for p in matches),{'matched':len(matches)})

class TamperEvidentAuditChain:
    def __init__(self,path:str|Path): self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True); self.path.touch(exist_ok=True)
    def _canon(self,o): return json.dumps(o,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    def _head(self):
        h='GENESIS'
        for line in self.path.read_text().splitlines():
            if line.strip(): h=json.loads(line)['record_hash']
        return h
    def append(self,record):
        r=dict(record); r['previous_hash']=self._head(); r.pop('record_hash',None); r['record_hash']=hashlib.sha256(self._canon(r)).hexdigest()
        with self.path.open('a') as f:f.write(json.dumps(r,sort_keys=True)+'\n')
        return r
    def verify(self):
        prev='GENESIS'; count=0
        for n,line in enumerate(self.path.read_text().splitlines(),1):
            if not line.strip():continue
            rec=json.loads(line); claimed=rec.pop('record_hash')
            if rec.get('previous_hash')!=prev:return {'valid':False,'line':n,'reason':'previous_hash_mismatch','count':count}
            calc=hashlib.sha256(self._canon(rec)).hexdigest()
            if not hmac.compare_digest(claimed,calc):return {'valid':False,'line':n,'reason':'record_hash_mismatch','count':count}
            prev=claimed; count+=1
        return {'valid':True,'count':count,'head_hash':prev}

class EnvironmentSecretBroker:
    def __init__(self): self._leases={}
    def lease(self,secret_ref:str,audience:str,ttl_seconds:int=60):
        prefix='secret://env/'
        if not secret_ref.startswith(prefix): raise HardeningError('CFHS_SECRET_DENIED','Reference broker only supports secret://env/')
        name=secret_ref[len(prefix):]
        if name not in os.environ: raise HardeningError('CFHS_SECRET_DENIED','Secret reference unavailable')
        lid='lease_'+secrets.token_hex(10); exp=now()+timedelta(seconds=max(5,min(int(ttl_seconds),300))); self._leases[lid]={'value':os.environ[name],'audience':audience,'expires':exp,'ref':secret_ref}
        return {'lease_id':lid,'secret_ref':secret_ref,'audience':audience,'expires_at':exp.isoformat()}
    def resolve_for_adapter(self,lid,audience):
        x=self._leases.get(lid)
        if not x or x['expires']<=now() or x['audience']!=audience: raise HardeningError('CFHS_SECRET_DENIED','Invalid or expired secret lease')
        return x['value']
    def revoke(self,lid): self._leases.pop(lid,None)

class ReadOnlyHTTPAdapter:
    def __init__(self,allowed_hosts:set[str],max_bytes=262144,timeout_seconds=3.0,allow_http_localhost=False): self.allowed_hosts={h.lower() for h in allowed_hosts}; self.max_bytes=max_bytes; self.timeout=timeout_seconds; self.allow_local=allow_http_localhost
    def _validate(self,url):
        p=urllib.parse.urlparse(url); host=(p.hostname or '').lower()
        if p.username or p.password or host not in self.allowed_hosts: raise HardeningError('CFHS_DEVICE_DENIED','URL is not allowed')
        if p.scheme!='https' and not(self.allow_local and p.scheme=='http' and host in {'localhost','127.0.0.1'}): raise HardeningError('CFHS_DEVICE_DENIED','Only HTTPS is permitted')
        if not self.allow_local:
            try:
                for info in socket.getaddrinfo(host,p.port or 443,type=socket.SOCK_STREAM):
                    ip=ipaddress.ip_address(info[4][0])
                    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved: raise HardeningError('CFHS_DEVICE_DENIED','Resolved address is not public')
            except socket.gaierror as e: raise HardeningError('CFHS_DEVICE_UNAVAILABLE','Host resolution failed') from e
        return p
    def get(self,url):
        p=self._validate(url); req=urllib.request.Request(url,method='GET',headers={'User-Agent':'CFHS-ReadOnly-Device/0.2','Accept':'application/json,text/plain,*/*'})
        with urllib.request.urlopen(req,timeout=self.timeout) as resp:
            data=resp.read(self.max_bytes+1)
            if len(data)>self.max_bytes: raise HardeningError('CFHS_RESOURCE_EXHAUSTED','Response exceeded byte ceiling')
            return {'url':urllib.parse.urlunparse(p),'status':int(resp.status),'content_type':resp.headers.get('Content-Type','application/octet-stream'),'body':data.decode('utf-8',errors='replace'),'bytes':len(data),'side_effect_class':'S0'}
