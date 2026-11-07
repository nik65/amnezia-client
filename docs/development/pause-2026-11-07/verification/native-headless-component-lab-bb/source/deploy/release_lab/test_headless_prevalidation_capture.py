"""Real driver/bridge calls with inert dependencies; no guest or installer."""
import base64,hashlib,json,os,stat
from pathlib import Path
from types import SimpleNamespace as NS
import pytest
from . import headless_native_e2e_driver as base
from . import linux_headless_driver as prepared
from .test_headless_native_acceptance import plan

def captured(path):
 record=json.loads(path.read_text());raw=base64.b64decode(record['bytes_base64']);assert record['sha256']==hashlib.sha256(raw).hexdigest();assert record['size']==len(raw);assert not record['truncated'];return json.loads(raw)

@pytest.mark.parametrize('kind',[base.PreexistingQgaBridge,prepared.PreparedPreexistingBridge])
@pytest.mark.parametrize('failure',['validator','json','success','nonzero'])
def test_actual_baseline_bridge_captures_before_parse_and_validation(tmp_path,monkeypatch,kind,failure):
 response={'stdout':'invalid private raw' if failure=='json' else json.dumps({'origin':'guest','transport':'qga','private':'exact-raw'}),'stderr':'private stderr','exitcode':7 if failure=='nonzero' else 0}
 bridge=kind.__new__(kind);bridge.plan=NS(nonce='b'*32);bridge.root='/owned';bridge.plan_path='/owned/plan';bridge.script='/owned/helper';bridge.ownership_check=lambda:None;bridge.qga=NS(write_file=lambda *a:None,guest_exec_wait=lambda *a,**kw:response)
 connected={'connected':'original'}
 class BoundArchive:
  parent=tmp_path
  def resolve(self):return self
  def read_text(self):return json.dumps(connected)
  def __str__(self):return '/var/lib/amnezia-release-lab/receipts/owned/connected.json'
 original=RuntimeError('validator-inert')
 def validate(*a):
  assert captured(next(tmp_path.glob('*prevalidation.private.json')))==response
  if failure=='validator':raise original
  return {'baseline':'validated'}
 monkeypatch.setattr(base,'validate_baseline_owned',validate)
 if failure=='success':assert bridge.crash_and_restart(connected,BoundArchive())=={'baseline':'validated'}
 else:
  with pytest.raises(Exception) as error:bridge.crash_and_restart(connected,BoundArchive())
  if failure=='validator':assert error.value is original
 assert captured(next(tmp_path.glob('*prevalidation.private.json')))==response

@pytest.mark.parametrize('module,driver_class',[(base,base.HeadlessNativeE2EDriver),(prepared,prepared.PreparedHeadlessDriver)])
@pytest.mark.parametrize('failure',[None,'update','rollback','reboot','oversize','update-cleanup'])
def test_real_orchestration_retains_each_unvalidated_receipt_and_cleanup(tmp_path,monkeypatch,module,driver_class,failure):
 if failure=='oversize':monkeypatch.setattr(base,'CAPTURE_LIMIT',16)
 p=plan();state={'version':p.baseline.version};calls=[];native=NS()
 def identity(release,label):
  assert release.version==state['version'];calls.append(label);return {'label':label}
 native.identity=identity;native.cli_json=lambda *a:{}
 armed={'phase':None}
 class Observation:
  def __init__(self,native,phase,timeout,**kwargs):assert kwargs=={'failure_archive':tmp_path};self.phase=phase
  def __enter__(self):armed['phase']=self.phase;calls.append('arm-'+self.phase);return self
  def collect(self):calls.append('collect-'+self.phase);return {}
  def __exit__(self,*a):armed['phase']=None
 monkeypatch.setattr(module,'PendingObservation',Observation)
 def stage_profile():
  assert armed['phase']=='restart_pending';calls.append('stage-profile');return {'profile_store':{}}
 native.stage_profile=stage_profile
 for name in ('update_pending','update_stable','rollback_pending','rollback_stable'):setattr(native,'collect_'+name,lambda:{})
 def wait(collector,*a,**kw):
  if collector is native.collect_update_stable:state['version']=p.candidate.version
  if collector is native.collect_rollback_stable:state['version']=p.baseline.version
  return {}
 native.wait_for=wait
 for name in ('update','rollback','reboot'):setattr(native,'build_'+name+'_receipt',lambda _name=name,**kw:{'kind':_name,'private':'raw '+_name})
 native.validate_fixture_cleanup=lambda *a:{}
 fixture=NS(prepare_and_connect=lambda:{},crash_and_restart=lambda *a:{},promote_systemd_baseline=lambda *a:None,boot_id=lambda *a:'boot',disable_update_profile=lambda:{},cleanup=lambda *a:calls.append('fixture-cleanup') or {})
 server=NS(start=lambda:None,reset=lambda:None,collect=lambda:{},stop=lambda *a:calls.append('http-stop') or {})
 def rollback(*a):
  assert armed['phase']=='rollback_restart_pending';calls.append('trigger-rollback');assert calls.index('candidate-before')<calls.index('arm-rollback_restart_pending')<calls.index('trigger-rollback');return {'cli_process':{},'cli_response':{}}
 collector=NS(trigger_rollback=rollback,reboot_and_collect=lambda *a:{'boot_id_before':'old','boot_id_after':'new','after_raw':{},'raw_sources':{}})
 original=RuntimeError('fixed-private-validator-failure')
 for name in ('update','rollback','reboot'):
  def validate(*a,_name=name):
   assert captured(tmp_path/(p.attempt_nonce+'-'+_name+'-prevalidation.private.json'))=={'kind':_name,'private':'raw '+_name}
   if failure==_name or failure=='update-cleanup' and _name=='update':raise original
  monkeypatch.setattr(module,'validate_'+name+'_receipt',validate)
 if failure=='update-cleanup':
  def broken_cleanup(*a):calls.append('fixture-cleanup');raise RuntimeError('inert-cleanup')
  fixture.cleanup=broken_cleanup
 driver=driver_class(p,native,server,fixture,collector,tmp_path)
 if failure:
  with pytest.raises(RuntimeError) as caught:driver.run()
  if failure=='oversize':
   assert isinstance(caught.value,base.HeadlessE2EError);assert json.loads(next(tmp_path.glob('*update-prevalidation.private.json')).read_text())['truncated']
  else:assert caught.value is original
 else:assert set(driver.run())>={'update','rollback','reboot','cleanup'}
 assert 'fixture-cleanup' in calls and 'http-stop' in calls
 if failure is None:assert calls.index('candidate-before')<calls.index('trigger-rollback')<calls.index('baseline-after')


def test_private_capture_bound_immutable_and_symlink(tmp_path,monkeypatch):
 path=base.capture_prevalidation(tmp_path,'attempt',{'private':'value'});assert captured(path)=={'private':'value'}
 if os.name=='posix':assert stat.S_IMODE(path.stat().st_mode)==0o600
 with pytest.raises(FileExistsError):base.capture_prevalidation(tmp_path,'attempt',{'new':1})
 monkeypatch.setattr(base,'CAPTURE_LIMIT',16)
 with pytest.raises(base.HeadlessE2EError,match='bound'):base.capture_prevalidation(tmp_path,'large',{'private':'x'*100})
 record=json.loads((tmp_path/'large-prevalidation.private.json').read_text());raw=json.dumps({'private':'x'*100},sort_keys=True,separators=(',',':')).encode();assert record['truncated'];assert record['size']==len(raw);assert record['sha256']==hashlib.sha256(raw).hexdigest();assert base64.b64decode(record['bytes_base64'])==raw[:16]
 if os.name=='posix':
  link=tmp_path/'link';link.symlink_to(tmp_path,target_is_directory=True)
  with pytest.raises(base.HeadlessE2EError):base.capture_prevalidation(link,'reject',{})
