"""Actual embedded-program and deadline regressions; never services/VM/network."""
import base64,json,os,subprocess,sys,tempfile,io,contextlib
from pathlib import Path
from unittest.mock import Mock
import pytest
from deploy.release_lab.headless_native_qga_adapter import HeadlessNativeQgaAdapter,HeadlessNativeQgaError,READ_SET,STAGE
from deploy.release_lab.headless_native_http_fixture import TRUST_KEY_READ,HeadlessNativeHttpFixture,HeadlessHttpFixtureError
from deploy.release_lab.test_headless_native_qga_adapter import plan
ROOT=os.name=='posix' and getattr(os,'geteuid',lambda:1)()==0

def embedded(source,*args):return subprocess.run([sys.executable,'-c',source,*map(str,args)],capture_output=True,text=True,timeout=5)

@pytest.mark.skipif(not ROOT,reason='actual root-owned isolated POSIX files')
def test_stage_preserves_product_object_version_and_other_metadata(tmp_path):
 key=tmp_path/'key';key.write_bytes(b'public');key.chmod(0o600);store=tmp_path/'profiles.json'
 store.write_text(json.dumps({'version':1,'profiles':[{'id':'old','opaque':7}],'metadata':{'keep':True}}))
 result=embedded(STAGE,store,key,json.dumps({'id':'new'}),__import__('hashlib').sha256(b'public').hexdigest())
 assert result.returncode==0,result.stderr
 actual=json.loads(store.read_bytes());assert actual=={'version':1,'profiles':[{'id':'old','opaque':7},{'id':'new'}],'metadata':{'keep':True}}
 assert store.stat().st_uid==0 and store.stat().st_mode&0o777==0o600

@pytest.mark.skipif(not ROOT,reason='actual root-owned isolated POSIX files')
@pytest.mark.parametrize('value',[[],{'version':True,'profiles':[]},{'version':2,'profiles':[]},{'version':1,'profiles':[42]}])
def test_stage_refuses_invalid_existing_store_without_overwrite(tmp_path,value):
 key=tmp_path/'key';key.write_bytes(b'key');key.chmod(0o600);store=tmp_path/'profiles.json';raw=json.dumps(value).encode();store.write_bytes(raw)
 result=embedded(STAGE,store,key,'{"id":"new"}',__import__('hashlib').sha256(b'key').hexdigest())
 assert result.returncode!=0 and store.read_bytes()==raw

@pytest.mark.skipif(not ROOT,reason='actual root-owned isolated POSIX files')
def test_atomic_observation_waits_for_initial_files_and_retired_journal(tmp_path):
 state,journal=tmp_path/'state',tmp_path/'journal';spec={'files':{'pending_state':str(state),'pending_journal':str(journal)},'absent':{}}
 result=embedded(READ_SET,json.dumps(spec));assert result.returncode==0 and json.loads(result.stdout)=={'not_ready':'required-file-absent'}
 for p in [state,journal]:p.write_text('{}');p.chmod(0o600)
 result=embedded(READ_SET,json.dumps(spec));assert result.returncode==0,result.stderr
 records=json.loads(result.stdout)['records'];assert set(records)=={'pending_state','pending_journal'}
 assert all(base64.b64decode(v['bytes_b64'])==b'{}' and v['uid']==0 for v in records.values())
 stable={'files':{'stable_state':str(state)},'absent':{'retired_journal':str(journal)}}
 assert json.loads(embedded(READ_SET,json.dumps(stable)).stdout)=={'not_ready':'journal-not-retired'}
 journal.unlink();assert set(json.loads(embedded(READ_SET,json.dumps(stable)).stdout)['records'])=={'stable_state','retired_journal'}

@pytest.mark.skipif(not ROOT,reason='actual POSIX no-follow/nonblocking semantics')
@pytest.mark.parametrize('kind',['symlink','fifo','oversize','writable'])
def test_observation_identity_failures_do_not_become_retry(tmp_path,kind):
 p=tmp_path/'state'
 if kind=='symlink':p.symlink_to(tmp_path/'missing')
 elif kind=='fifo':os.mkfifo(p)
 else:p.write_bytes(b'x'*(262145 if kind=='oversize' else 1));p.chmod(0o666 if kind=='writable' else 0o600)
 result=embedded(READ_SET,json.dumps({'files':{'state':str(p)},'absent':{}}));assert result.returncode!=0

@pytest.mark.skipif(not ROOT,reason='protected actual root directory and owner metadata')
@pytest.mark.parametrize('mode,expected',[(0o640,True),(0o600,True),(0o644,False),(0o660,False)])
def test_installer_trust_key_permissions_use_actual_same_fd(mode,expected):
 with tempfile.TemporaryDirectory(dir='/root') as folder:
  p=Path(folder)/'key';p.write_bytes(b'public');os.chown(p,0,65534);p.chmod(mode)
  # No group creation: the fixture substitutes only the name lookup for the
  # actual root-owned temporary key's existing GID. File/syscall proofs stay real.
  prefix='import grp,types,os;grp.getgrnam=lambda _:types.SimpleNamespace(gr_gid=65534)\n'
  result=embedded(prefix+TRUST_KEY_READ,p)
  assert (result.returncode==0) is expected
  if expected:
   value=json.loads(result.stdout);assert value['mode']==mode and value['same_fd_identity'] is True and value['protected_ancestors'] is True

def adapter(clock=None,sleeper=None,snapshot=None,qga=None):
 p=plan();return HeadlessNativeQgaAdapter(qga or Mock(),p,snapshot or (lambda:p.outer_binding),clock=clock or (lambda:0),sleeper=sleeper or (lambda _:None))

def test_poll_retries_only_explicit_file_not_ready():
 now=[0];qga=Mock();qga.guest_exec_wait.side_effect=[{'exitcode':0,'stdout':'{"not_ready":"required-file-absent"}'},{'exitcode':0,'stdout':'{"records":{"pending_state":{},"pending_journal":{}}}'}]
 a=adapter(clock=lambda:now[0],sleeper=lambda v:now.__setitem__(0,now[0]+v),qga=qga)
 assert a.wait_for(a.collect_update_pending,bool,timeout=20,label='update')=={'pending_state':{},'pending_journal':{}}
 assert qga.guest_exec_wait.call_count==2 and now[0]==1

def test_late_collection_result_is_rejected():
 now=[0];a=adapter(clock=lambda:now[0])
 def collect():now[0]=2;return {'ready':True}
 with pytest.raises(HeadlessNativeQgaError,match='deadline'):a.wait_for(collect,lambda _:True,timeout=1,label='update')

def test_late_readiness_function_is_rejected():
 now=[0];a=adapter(clock=lambda:now[0])
 def ready(_):now[0]=2;return True
 with pytest.raises(HeadlessNativeQgaError,match='deadline'):a.wait_for(lambda:{},ready,timeout=1,label='update')

def test_outer_ownership_change_during_collection_fails():
 live=[plan().outer_binding];a=adapter(snapshot=lambda:live[0])
 def collect():live[0]=None;return {'ready':True}
 with pytest.raises(HeadlessNativeQgaError,match='ownership'):a.wait_for(collect,lambda _:True,timeout=1,label='update')

def test_real_collector_failure_is_not_swallowed_as_absence():
 qga=Mock();qga.guest_exec_wait.side_effect=RuntimeError('transport fail');a=adapter(qga=qga)
 with pytest.raises(RuntimeError,match='transport fail'):a.wait_for(a.collect_update_pending,bool,timeout=10,label='update')
 assert qga.guest_exec_wait.call_count==1

@pytest.mark.parametrize('field,value',[('uid',False),('gid',True),('amnezia_gid',0),('mode',0o644),('protected_ancestors',False),('same_fd_identity',False),('regular',False)])
def test_trust_metadata_must_preserve_installed_identity(field,value):
 f=object.__new__(HeadlessNativeHttpFixture);f.plan=plan()
 row={'path':'/etc/amnezia/update-public-key.pem','sha256':f.plan.candidate.key_sha256,'size':123,'uid':0,'gid':1000,'amnezia_gid':1000,'mode':0o640,'protected_ancestors':True,'regular':True,'same_fd_identity':True,field:value}
 f._json=lambda *a:row
 with pytest.raises(HeadlessHttpFixtureError,match='trust key identity'):f._trust()

@pytest.mark.skipif(not ROOT,reason='actual post-open POSIX ownership and no-follow semantics')
@pytest.mark.parametrize('change',['symlink','writable','owner','valid-replacement'])
def test_post_open_identity_violation_is_fatal_not_retry(tmp_path,monkeypatch,change):
 p=tmp_path/'state';p.write_text('{}');p.chmod(0o600);other=tmp_path/'other';other.write_text('{}');other.chmod(0o600)
 real_fstat=os.fstat;calls=[0]
 def fstat(fd):
  if os.readlink('/proc/self/fd/'+str(fd))==str(p):
   calls[0]+=1
   if calls[0]==2:
    if change=='symlink':p.rename(tmp_path/'old');p.symlink_to(other)
    elif change=='writable':p.chmod(0o666)
    elif change=='owner':os.chown(p,65534,65534)
    else:p.rename(tmp_path/'old');p.write_text('{}');p.chmod(0o600)
  return real_fstat(fd)
 monkeypatch.setattr(os,'fstat',fstat);monkeypatch.setattr(sys,'argv',['embedded',json.dumps({'files':{'state':str(p)},'absent':{}})])
 output=io.StringIO()
 with contextlib.redirect_stdout(output):
  if change=='valid-replacement':
   with pytest.raises(SystemExit) as stopped:exec(READ_SET,{})
   assert stopped.value.code==0
  else:
   with pytest.raises(SystemExit,match='file identity'):exec(READ_SET,{})
 if change=='valid-replacement':assert json.loads(output.getvalue())['not_ready']=='file-transition-during-observation'
 else:assert not output.getvalue()
