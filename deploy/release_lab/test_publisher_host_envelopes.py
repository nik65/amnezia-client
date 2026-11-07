"""Actual host create/start wire shapes remain distinct from guest proof; no VM."""
import copy,hashlib,unittest
from pathlib import PureWindowsPath
from .publisher_controller import ConcretePublisherOps as Ops,PublisherError
RUN='p17-test';CASE='publisher-clean';VM='11111111-1111-1111-1111-111111111111';PARENT='22222222-2222-2222-2222-222222222222';SHA='a'*64
ROOT=PureWindowsPath(r'C:\ProgramData\AmneziaReleaseLab\hyperv\runs')/RUN/'windows-x64/cases'/CASE
PARENT_DISK=r'C:\ProgramData\AmneziaReleaseLab\hyperv\windows-x64\parent.vhdx'
def plan():return {'schema':1,'backend':'hyperv','profile':'windows-x64','transport':'hyperv-powershell-direct','ready':True,'parent_state':'Off','host_network_mutation':False,'parent_sha256':SHA,'parent_vm_id':PARENT,'parent_vhdx':PARENT_DISK,'child_root':r'C:\ProgramData\AmneziaReleaseLab\hyperv\runs\RUN_ID\windows-x64\cases\CASE_ID','cases':[CASE]}
def made():
 child={'schema':1,'backend':'hyperv','profile':'windows-x64','run_id':RUN,'case_id':CASE,'vm_id':VM,'vm_name':f'AmneziaLab-{RUN}-{CASE}-'+hashlib.sha256((RUN+'|'+CASE).encode()).hexdigest()[:12],'state':'created','transport':'hyperv-powershell-direct','run_root':str(ROOT),'child_vhdx':str(ROOT/'disk/child.vhdx'),'parent_vhdx':PARENT_DISK,'parent_vm_id':PARENT,'parent_sha256':SHA,'parent_sha256_before':SHA,'parent_sha256_after':SHA}
 config={'vm_id':VM,'state':'Off','generation':2,'processors':4,'memory_bytes':8589934592,'network_adapter_count':0,'dvd_count':0,'secure_boot':True,'secure_boot_template':'MicrosoftWindows','vtp_enabled':True,'key_protector_present':True,'vhd_type':'Differencing','child_vhdx':child['child_vhdx'],'parent_vhdx':PARENT_DISK,'fixed_memory_readback':{'dynamic_memory_enabled':False,'startup_bytes':8589934592}}
 readback={'before_sha256':SHA,'after_sha256':SHA,'before_vm_id':PARENT,'after_vm_id':PARENT,'before_vhdx':PARENT_DISK,'after_vhdx':PARENT_DISK}
 # Same four-field host wire shape observed from a real owned create-only run.
 return {'action':'create-child','child':child,'configuration':config,'parent_readback':readback}
def started():
 m=made();m['action']='start';m.pop('parent_readback');m['parent_sha256']=SHA;m['child']['state']='running';m['configuration']['state']='Running';worker={'process_pid':17,'process_uuid':VM,'process_start_time':'observed-start','source':'Msvm_ComputerSystem.ProcessID'};m['worker']=worker;m['child'].update({k:worker[k] for k in ('process_pid','process_uuid','process_start_time')});return m
class Tests(unittest.TestCase):
 def validate(self,v,action='create-child',parent=None,expected=None):return Ops._require_owned_host_envelope(v,action,run_id=RUN,case_id=CASE,parent=parent or plan(),expected_child=expected)
 def test_real_wire_shape_cannot_claim_guest_origin(self):
  v=made();self.assertEqual(set(v),{'action','child','configuration','parent_readback'})
  with self.assertRaises(PublisherError):Ops._require_envelope(v,'create-child')
  self.assertIs(self.validate(v),v);self.assertNotIn('origin',v)
 def test_plan_requires_sealed_off_parent_and_typed_proof(self):
  self.assertIsNotNone(Ops._require_host_plan(plan()))
  for field,value in [('ready',False),('schema',True),('backend','qemu'),('parent_state','Running'),('host_network_mutation',True),('parent_sha256','wrong'),('parent_vm_id','not-uuid'),('parent_vhdx',r'C:\unowned\p.vhdx'),('child_root',r'C:\unowned'),('cases',None),('cases',CASE)]:
   v=plan();v[field]=value
   with self.subTest(field=field),self.assertRaises(PublisherError):Ops._require_host_plan(v)
 def test_foreign_marker_config_or_parent_never_accepted(self):
  changes=[('child','run_id','other'),('child','case_id','control'),('child','vm_id',PARENT),('child','vm_name','foreign'),('child','profile','linux'),('child','parent_vm_id',VM),('child','parent_sha256','b'*64),('child','run_root',r'C:\unowned'),('child','child_vhdx',r'C:\unowned.vhdx'),('configuration','vm_id',PARENT),('configuration','network_adapter_count',1),('configuration','memory_bytes',4294967296),('configuration','memory_bytes',True),('configuration','secure_boot',False),('configuration','vtp_enabled',False),('parent_readback','after_sha256','b'*64),('parent_readback','before_vm_id',VM)]
  for group,field,value in changes:
   v=made();v[group][field]=value
   with self.subTest(group=group,field=field),self.assertRaises(PublisherError):self.validate(v)
 def test_wrong_host_action_or_fabricated_guest_rejected(self):
  for field,value in [('action','probe'),('origin','guest'),('origin','other'),('injected',True)]:
   v=made();v[field]=value
   with self.assertRaises(PublisherError):self.validate(v)
 def test_started_host_requires_same_created_vm_and_actual_worker(self):
  v=started();self.assertIs(self.validate(v,'start',expected=made()['child']),v)
  for group,field,value in [('child','vm_id',PARENT),('worker','process_uuid',PARENT),('worker','process_pid',True),('worker','process_pid',0),('worker','process_start_time',''),('worker','source','untrusted'),('configuration','state','Off')]:
   v=started();v[group][field]=value
   with self.subTest(group=group,field=field),self.assertRaises(PublisherError):self.validate(v,'start',expected=made()['child'])
  with self.assertRaises(PublisherError):self.validate(started(),'start',expected=None)
 def test_actual_start_child_uses_host_contract_then_strict_guest_probe(self):
  class Controller:
   def __init__(self):self.calls=[];self.run={'run_id':RUN,'profiles':{'windows-x64':{}}};self.records=[];self.bad_parent=False
   def hyperv_call(self,action,**kwargs):
    self.calls.append(action)
    if action=='plan':return plan()
    if action=='create-child':return made()
    if action=='start':return started()
    return {'action':'probe','transport':'hyperv-powershell-direct','origin':'guest','injected':False,'vm_id':VM,'parent_sha256':'b'*64 if self.bad_parent else SHA}
   def get_run(self,run):return self.run
   def _record_hyperv_case(self,*args,**kwargs):self.records.append((args,kwargs))
   def load_state(self):return {'runs':{RUN:self.run}}
   def save_state(self,state):self.run=state['runs'][RUN]
  controller=Controller();result=Ops(controller).start_child(RUN,CASE)
  self.assertEqual(controller.calls,['plan','create-child','start','probe']);self.assertEqual(result['vm_id'],VM);self.assertEqual(result['process_pid'],17)
  controller=Controller();controller.bad_parent=True
  with self.assertRaises(PublisherError):Ops(controller).start_child(RUN,CASE)
 def test_guest_probe_stays_strict(self):
  v={'action':'probe','transport':'hyperv-powershell-direct','origin':'guest','injected':False,'vm_id':VM};self.assertIs(Ops._require_envelope(v,'probe',vm_id=VM),v)
  for field,value in [('origin','controller'),('transport','host'),('injected',True),('vm_id',PARENT)]:
   bad=dict(v);bad[field]=value
   with self.assertRaises(PublisherError):Ops._require_envelope(bad,'probe',vm_id=VM)
if __name__=='__main__':unittest.main()
