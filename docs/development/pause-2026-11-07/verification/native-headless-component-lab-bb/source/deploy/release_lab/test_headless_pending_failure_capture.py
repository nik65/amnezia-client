"""Actual staged observer lifecycle with inert owned-native dependencies only."""
import ast,base64,hashlib,importlib.util,json,os,pathlib,sys,subprocess,time
from types import SimpleNamespace as NS
from unittest.mock import patch
import pytest
from deploy.release_lab import headless_native_e2e_driver as archive_module
from deploy.release_lab import headless_native_qga_adapter as adapter
HERE=pathlib.Path(__file__).resolve().parent
STAGE=HERE
def load(name,file):
 spec=importlib.util.spec_from_file_location(name,STAGE/file);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
observer=load('deploy.release_lab._pending_failure_observer','headless_pending_observer.py')
NONCE='a'*48

def envelope():
 raw=b'{"private":"original snapshot bytes"}'
 return {'snapshotBytesBase64':base64.b64encode(raw).decode(),'snapshotSize':len(raw),'snapshotSHA256':hashlib.sha256(raw).hexdigest()}
def read_capture(root):
 record=json.loads(next(root.glob('*observer-failure-prevalidation.private.json')).read_text());raw=base64.b64decode(record['bytes_base64']);assert record['sha256']==hashlib.sha256(raw).hexdigest();assert not record['truncated'];return json.loads(raw)
def make_native(root,fault=None):
 calls=[];original=RuntimeError('private primary stays original');cleanup=RuntimeError('private stop error');snapshot=envelope()
 def json_call(path,args,timeout):
  if args[1]==observer.FAILURE_SNAPSHOT:
   calls.append('snapshot');assert timeout==6
   if fault=='snapshot':raise OSError('private secondary')
   return snapshot
  op=json.loads(args[2])['op'];calls.append(op)
  if op=='arm':
   if fault=='arm':raise original
   return {'pid':123,'start_ticks':456}
  if op=='read':
   if fault=='collect':raise original
   return {'failure':{'nonce':NONCE,'phase':'restart_pending','error':'private source failure'}}
  if op=='stop':
   if 'snapshot' in calls and fault!='archive':assert read_capture(root)['snapshot']==snapshot if fault!='snapshot' else read_capture(root)['snapshotErrorType']=='OSError'
   if fault=='stop':raise cleanup
   return {}
 native=NS(plan=NS(attempt_nonce=NONCE),_json=json_call)
 return native,calls,original,cleanup,snapshot

@pytest.mark.parametrize('fault',['collect','snapshot','archive'])
def test_collect_failure_snapshot_before_stop_primary_retained(tmp_path,monkeypatch,fault):
 native,calls,primary,_,snapshot=make_native(tmp_path,'collect' if fault=='collect' else fault)
 if fault=='archive':monkeypatch.setattr(archive_module,'capture_prevalidation',lambda *a:(_ for _ in ()).throw(OSError('private archive')))
 item=observer.PendingObservation(native,'restart_pending',.2,failure_archive=tmp_path)
 with pytest.raises(Exception) as caught:
  with item:item.collect()
 if fault=='collect':assert caught.value is primary
 else:assert isinstance(caught.value,adapter.HeadlessNativeQgaError);assert 'private source failure' not in str(caught.value)
 assert calls==['arm','read','snapshot','stop']
 if fault=='snapshot':assert read_capture(tmp_path)['snapshotErrorType']=='OSError'
 if fault=='archive':assert any('archive unavailable: OSError' in note for note in caught.value.__notes__)
 else:
  value=read_capture(tmp_path)
  if fault!='collect':assert value['observerResponse']['failure']['error']=='private source failure'


def test_arm_failure_captured_without_masking(tmp_path):
 native,calls,primary,_,_=make_native(tmp_path,'arm')
 with pytest.raises(RuntimeError) as caught:observer.PendingObservation(native,'restart_pending',.1,failure_archive=tmp_path).__enter__()
 assert caught.value is primary;assert calls==['arm','snapshot'];assert read_capture(tmp_path)['stage']=='arm'

@pytest.mark.parametrize('body_error',[False,True])
def test_stop_failure_preserves_existing_primary_and_one_capture(tmp_path,body_error):
 native,calls,primary,cleanup,_=make_native(tmp_path,'stop');item=observer.PendingObservation(native,'restart_pending',.1,failure_archive=tmp_path)
 if body_error:
  with pytest.raises(RuntimeError) as caught:
   with item:raise primary
  assert caught.value is primary;assert calls==['arm','snapshot','stop'];assert any('stop failed: RuntimeError' in n for n in primary.__notes__)
 else:
  with pytest.raises(RuntimeError) as caught:
   with item:pass
  assert caught.value is cleanup;assert calls==['arm','stop','snapshot']
 assert read_capture(tmp_path)['releasePass'] is False


def test_ownership_denial_does_not_dispatch_snapshot_guest_command(tmp_path):
 native=adapter.HeadlessNativeQgaAdapter.__new__(adapter.HeadlessNativeQgaAdapter);native.plan=NS(attempt_nonce=NONCE,outer_binding='owned');native.snapshot=lambda:'changed';calls=[];native.qga=NS(guest_exec_wait=lambda *a,**k:calls.append('unauthorized'))
 item=observer.PendingObservation(native,'restart_pending',.1,failure_archive=tmp_path)
 with pytest.raises(adapter.HeadlessNativeQgaError):item.__enter__()
 assert calls==[];assert read_capture(tmp_path)['snapshotErrorType']=='HeadlessNativeQgaError'


def test_success_never_takes_failure_snapshot(tmp_path):
 native,calls,_,_,_=make_native(tmp_path)
 values={}
 for key,path in [('pending_state',observer.UPDATE_STATE),('pending_journal',observer.UPDATE_JOURNAL)]:
  raw=json.dumps({'state' if key=='pending_state' else 'phase':'restart_pending'}).encode();values[key]={'origin':'guest','transport':'qga','path':path,'uid':0,'gid':0,'mode':'0600','size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'bytes_b64':base64.b64encode(raw).decode()}
 old=native._json
 def json_call(path,args,timeout):
  if args[1]==observer.CONTROL and json.loads(args[2])['op']=='read':calls.append('read');return {'nonce':NONCE,'phase':'restart_pending','records':values}
  return old(path,args,timeout)
 native._json=json_call
 with observer.PendingObservation(native,'restart_pending',.1,failure_archive=tmp_path) as item:assert item.collect()==values
 assert calls==['arm','read','stop'];assert not list(tmp_path.iterdir())

@pytest.mark.skipif(os.name!='posix',reason='actual bounded pipe helper requires POSIX selectors')
def test_actual_embedded_command_bounds_and_timeout_without_services():
 tree=ast.parse(observer.FAILURE_SNAPSHOT);nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))];scope={};exec(compile(ast.Module(body=nodes,type_ignores=[]),'snapshot-functions','exec'),scope)
 for argv in ([sys.executable,'-c','import os;os.write(1,b"x"*1000000);os.write(2,b"y"*1000000)'],[sys.executable,'-c','import time;time.sleep(10)']):
  scope['budget']=200000;scope['deadline']=time.monotonic()+4;start=time.monotonic();result=scope['command'](argv);assert time.monotonic()-start<3
  assert result['truncated'] or result['timeout'];assert not result['completeStdout'] and not result['completeStderr'];assert result['stdoutRetainedSize']<=16000;assert result['stderrRetainedSize']<=4000;assert scope['budget']>=180000


def test_both_drivers_bind_authorized_archive_path():
 for file in ('headless_native_e2e_driver.py','linux_headless_driver.py'):
  tree=ast.parse((STAGE/file).read_text());calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='PendingObservation'];assert len(calls)==2
  for call in calls:
   value=next(k.value for k in call.keywords if k.arg=='failure_archive');assert isinstance(value,ast.Attribute) and isinstance(value.value,ast.Name) and value.value.id=='self' and value.attr=='archive_root'
