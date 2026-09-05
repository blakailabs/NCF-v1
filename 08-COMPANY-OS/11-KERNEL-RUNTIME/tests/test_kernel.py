import tempfile, unittest
from pathlib import Path
from kernel.runtime import CompanyKernel, KernelError, RequestContext

ROOT=Path(__file__).resolve().parents[1]

class KernelTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.k=CompanyKernel.from_file(self.tmp.name, ROOT/'examples/kernel.config.json')
        self.owner=RequestContext('human:owner','proc:owner','trace:owner')
        self.agent=RequestContext('agent:ops','proc:agent','trace:agent')
        self.proc=self.k.spawn_process(self.owner,'test','agent:ops'); self.agent.process_id=self.proc['process_id']
    def tearDown(self): self.tmp.cleanup()
    def test_allow_mail_and_idempotency(self):
        a=self.k.invoke_device(self.agent,'mail-primary','mail.send',{'to':'x@example.test','resource_amount':1},'mail-1')
        b=self.k.invoke_device(self.agent,'mail-primary','mail.send',{'to':'DIFFERENT@example.test','resource_amount':1},'mail-1')
        self.assertEqual(a['invocation_id'],b['invocation_id'])
    def test_default_deny(self):
        d=self.k.authorize(self.agent,'code.deploy','/dev/code/prod',{})
        self.assertEqual(d['decision'],'DENY')
    def test_elevation_flow(self):
        d=self.k.authorize(self.agent,'payments.refund','/dev/payments/primary',{'amount':5000})
        self.assertEqual(d['decision'],'ELEVATION_REQUIRED')
        e=self.k.request_elevation(self.agent,'payments.refund','/dev/payments/primary',{'max_amount':5000},'test')
        self.k.approve_elevation(self.owner,e['elevation_id'],60)
        d2=self.k.authorize(self.agent,'payments.refund','/dev/payments/primary',{'amount':5000})
        self.assertEqual(d2['decision'],'ALLOW')
    def test_checkpoint_survives_restart(self):
        self.k.checkpoint(self.agent,self.proc['process_id'],{'step':3})
        k2=CompanyKernel.from_file(self.tmp.name, ROOT/'examples/kernel.config.json')
        self.assertEqual(k2.latest_checkpoint(self.proc['process_id'])['state']['step'],3)
    def test_resource_ceiling(self):
        for i in range(100): self.k.invoke_device(self.agent,'mail-primary','mail.send',{'to':f'{i}@example.test','resource_amount':1},f'mail-{i}')
        with self.assertRaises(KernelError) as cm:
            self.k.invoke_device(self.agent,'mail-primary','mail.send',{'to':'overflow@example.test','resource_amount':1},'mail-overflow')
        self.assertEqual(cm.exception.code,'CFHS_POLICY_DENIED')
    def test_approver_required(self):
        e=self.k.request_elevation(self.agent,'payments.refund','/dev/payments/primary',{'max_amount':5000},'test')
        with self.assertRaises(KernelError): self.k.approve_elevation(self.agent,e['elevation_id'])

if __name__=='__main__': unittest.main()
