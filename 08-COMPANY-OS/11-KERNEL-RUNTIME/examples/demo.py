#!/usr/bin/env python3
from pathlib import Path
import json, tempfile
from kernel.runtime import CompanyKernel, KernelError, RequestContext

ROOT=Path(__file__).resolve().parents[1]
state=Path(tempfile.mkdtemp(prefix='company-kernel-demo-'))
k=CompanyKernel.from_file(state, ROOT/'examples/kernel.config.json')
owner=RequestContext('human:owner','proc:owner-console','trace:demo-owner')
agent=RequestContext('agent:ops','proc:ops-agent','trace:demo-agent')

print('1 HEALTH', k.health())
proc=k.spawn_process(owner,'ops-demo','agent:ops',{'purpose':'kernel acceptance demo'})
agent.process_id=proc['process_id']
k.set_process_state(owner,proc['process_id'],'RUNNING')

mail=k.invoke_device(agent,'mail-primary','mail.send',{'to':'customer@example.test','subject':'Hello','resource_amount':1},'demo-mail-1')
print('2 ALLOW', mail['status'], mail['side_effect_class'])

try:
    k.invoke_device(agent,'payments-primary','payments.refund',{'amount':5000,'currency':'USD'},'demo-refund-1')
except KernelError as e:
    print('3 ELEVATION REQUIRED', e.code)

elev=k.request_elevation(agent,'payments.refund','/dev/payments/primary',{'max_amount':5000},'Customer exception approved by owner')
print('4 REQUEST',elev['status'])
print('5 APPROVE',k.approve_elevation(owner,elev['elevation_id'])['status'])
refund=k.invoke_device(agent,'payments-primary','payments.refund',{'amount':5000,'currency':'USD'},'demo-refund-1')
print('6 ELEVATED ALLOW',refund['status'])

try:
    k.invoke_device(agent,'payments-primary','payments.capture',{'amount':10},'demo-unauth-1')
except KernelError as e:
    print('7 DENY/NOT FOUND',e.code)

ck=k.checkpoint(agent,proc['process_id'],{'step':7,'last_action':'refund','safe_to_resume':True})
print('8 CHECKPOINT',ck['checkpoint_id'])

k2=CompanyKernel.from_file(state, ROOT/'examples/kernel.config.json')
restored=k2.latest_checkpoint(proc['process_id'])
print('9 RESTART RESTORE',restored['state'])
print('10 AUDIT RECORDS',len(k2.audit_records()))
print(json.dumps({'state_dir':str(state),'process_id':proc['process_id'],'checkpoint':restored,'audit_count':len(k2.audit_records())},indent=2))
