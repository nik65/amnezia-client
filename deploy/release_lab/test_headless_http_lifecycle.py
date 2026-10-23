"""Staged producer contract over owned loopback sockets; no app/guest/build."""
import base64,contextlib,hashlib,importlib.util,json,os,pathlib,subprocess,sys,threading,time
from http.server import ThreadingHTTPServer
from types import SimpleNamespace as NS
from urllib.request import Request,urlopen
from unittest.mock import patch
import pytest
from deploy.release_lab import nested_cuttlefish_server_fixture_adapter as adapter
HERE=pathlib.Path(__file__).resolve().parent
STAGE=HERE
def load(name,file):
 spec=importlib.util.spec_from_file_location(name,STAGE/file);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
pending_module=load('deploy.release_lab.headless_pending_observer','headless_pending_observer.py')
server_module=load('http_contract_server','headless_native_fixture_server.py')
http_module=load('deploy.release_lab._http_contract_fixture','headless_native_http_fixture.py')
base_module=load('deploy.release_lab._http_contract_base','headless_native_e2e_driver.py')
with patch.dict(sys.modules,{'deploy.release_lab.headless_native_e2e_driver':base_module}):
 prepared_module=load('deploy.release_lab._http_contract_prepared','linux_headless_driver.py')

@contextlib.contextmanager
def fixture(tmp_path,handler=None):
 manifest=tmp_path/'manifest';manifest.write_bytes(b'exact manifest bytes');artifact=tmp_path/'artifact';artifact.write_bytes(b'exact artifact bytes'*100);log=tmp_path/'requests';log.write_bytes(b'');os.chmod(log,0o600)
 server=ThreadingHTTPServer(('127.0.0.1',0),handler or server_module.H)
 server.fixture={'run':'owned-http-contract','nonce':'b'*48,'manifest':manifest,'manifest_path':'/manifest','artifact':artifact,'artifact_path':'/artifact','log':log,'lock':threading.Lock(),'rows':0,'limited':False,'reset':False}
 thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
 try:yield server,'http://127.0.0.1:'+str(server.server_port),log
 finally:server.shutdown();server.server_close();thread.join(3)
def script(code,args):
 result=subprocess.run([sys.executable,'-c',code,*map(str,args)],capture_output=True,text=True,timeout=15)
 assert result.returncode==0,result.stderr
 return json.loads(result.stdout)
def reset(url,log,tmp_path,nonce='b'*48):return script(adapter.RESET,[url+'/__lab__/attempt/reset?nonce='+nonce+'&run_id=owned-http-contract',log,tmp_path/'cursor','c'*48,'owned-http-contract',nonce])

@pytest.mark.skipif(os.name!='posix',reason='actual imported programs require POSIX NOFOLLOW')
def test_actual_producer_reset_read_log_and_observation_conversion(tmp_path,monkeypatch):
 with fixture(tmp_path) as (server,url,log):
  health=urlopen(url+'/healthz',timeout=3).read();r=reset(url,log,tmp_path)
  row=r['cleared_health_request'];assert row['bytes']==len(health)==row['content_length'];assert row['sha256']==hashlib.sha256(health).hexdigest();assert row['run_id']=='owned-http-contract';assert row['attempt_nonce']=='b'*48;assert r['ok'];assert log.read_bytes()==b''
  for path in ('manifest','artifact'):
   data=urlopen(url+'/'+path,timeout=3).read();assert data==(tmp_path/path).read_bytes()
  raw=script(adapter.READ_LOG,[log,tmp_path/'cursor',1<<20]);assert [x['path'] for x in raw['rows']]==['/manifest','/artifact']
  assert all(x['eof'] and type(x['observed_at']) is float for x in raw['rows'])
  for row in raw['rows']:assert row['sha256']==hashlib.sha256((tmp_path/row['path'].strip('/')).read_bytes()).hexdigest()
  # Loopback is deliberately not a guest acceptance peer; exercise actual collect
  # conversion with only the semantic gate replaced by an observation spy.
  from deploy.release_lab.test_headless_native_acceptance import plan
  f=http_module.HeadlessNativeHttpFixture.__new__(http_module.HeadlessNativeHttpFixture);f.plan=plan();f.reset_receipt=r;f.log=str(log);f.pid=123;f.ticks=456;f.trust={};f._json=lambda *a:raw
  monkeypatch.setattr(http_module,'validate_http_receipt',lambda p,v:v)
  result=f.collect();assert all(x['observed_at'].endswith('Z') for x in result['requests']);assert result['requests'][0]['path']=='/manifest'

@pytest.mark.skipif(os.name!='posix',reason='actual producer requires POSIX NOFOLLOW')
@pytest.mark.parametrize('path',['healthz','manifest','artifact'])
def test_client_eof_waits_for_delayed_actual_log_commit(tmp_path,path):
 entered=threading.Event();release=threading.Event();done=threading.Event();out=[]
 class Delayed(server_module.H):
  def record(self,*args):entered.set();assert release.wait(3);super().record(*args)
 with fixture(tmp_path,Delayed) as (server,url,log):
  def fetch():
   try:
    with urlopen(url+'/'+path,timeout=4) as response:out.append((response.version,response.headers.get('Content-Length'),response.read()))
   finally:done.set()
  thread=threading.Thread(target=fetch);thread.start();assert entered.wait(2);assert not done.wait(.1);assert not log.read_bytes();release.set();thread.join(4);assert done.is_set();assert len(out)==1;assert out[0][0]==10;assert out[0][1] is None
  row=json.loads(log.read_text());assert row['bytes']==row['content_length']==len(out[0][2]);assert row['sha256']==hashlib.sha256(out[0][2]).hexdigest()

@pytest.mark.skipif(os.name!='posix',reason='actual RESET POSIX program')
def test_head_has_length_but_is_not_accepted_as_health_get(tmp_path):
 with fixture(tmp_path) as (server,url,log):
  with urlopen(Request(url+'/healthz',method='HEAD'),timeout=3) as response:assert int(response.headers['Content-Length'])>0;assert response.read()==b''
  # HEAD has no body: its genuine row must never pass the existing GET gate.
  end=time.monotonic()+2
  while not log.read_bytes() and time.monotonic()<end:time.sleep(.01)
  row=json.loads(log.read_text());assert row['bytes']==0;assert row['method']=='HEAD'
  result=subprocess.run([sys.executable,'-c',adapter.RESET,url+'/__lab__/attempt/reset?nonce='+'b'*48+'&run_id=owned-http-contract',str(log),str(tmp_path/'cursor'),'c'*48,'owned-http-contract','b'*48],capture_output=True,text=True,timeout=3)
  assert result.returncode!=0;assert 'health request row' in result.stderr

def test_record_failure_never_fabricates_success_row(tmp_path):
 class Broken(server_module.H):
  def record(self,*args):raise OSError('inert fsync failure')
 with fixture(tmp_path,Broken) as (server,url,log):
  urlopen(url+'/healthz',timeout=3).read();assert log.read_bytes()==b''
  if os.name=='posix':
   result=subprocess.run([sys.executable,'-c',adapter.RESET,url+'/__lab__/attempt/reset?nonce='+'b'*48+'&run_id=owned-http-contract',str(log),str(tmp_path/'cursor'),'c'*48,'owned-http-contract','b'*48],capture_output=True,text=True,timeout=3)
   assert result.returncode!=0;assert 'health request row' in result.stderr

@pytest.mark.parametrize('module,kind',[(base_module,base_module.HeadlessNativeE2EDriver),(prepared_module,prepared_module.PreparedHeadlessDriver)])
def test_actual_driver_reset_failure_still_attempts_fenced_abort_and_retains_primary(tmp_path,module,kind,monkeypatch):
 from deploy.release_lab.test_headless_native_acceptance import plan
 p=plan();calls=[];original=RuntimeError('inert reset failure')
 native=NS(identity=lambda *a:{},cli_json=lambda *a:{})
 fixture_obj=NS(prepare_and_connect=lambda:{},crash_and_restart=lambda *a:{},promote_systemd_baseline=lambda *a:None,boot_id=lambda *a:'boot',cleanup=lambda *a:calls.append('fixture-cleanup'))
 def reset_error():raise original
 def collect_error():calls.append('collect');raise RuntimeError('fixture not reset')
 server=NS(start=lambda:calls.append('start'),reset=reset_error,collect=collect_error,abort=lambda:calls.append('owned-abort') or {'diagnosticOnly':True,'releasePass':False},stop=lambda *a:calls.append('semantic-stop'))
 driver=kind(p,native,server,fixture_obj,None,tmp_path)
 with pytest.raises(RuntimeError) as e:driver.run()
 assert e.value is original;assert calls==['start','collect','owned-abort','fixture-cleanup'];assert 'semantic-stop' not in calls

def test_abort_uses_exact_existing_stop_fences_without_forged_http_receipt():
 from deploy.release_lab.test_headless_native_acceptance import plan
 f=http_module.HeadlessNativeHttpFixture.__new__(http_module.HeadlessNativeHttpFixture);f.plan=plan();f.pid=123;f.ticks=456;f.script='/owned/script';calls=[]
 raw={'pid':123,'start_ticks':456,'identity_rechecked':True,'stopped':True,'listener_closed':True,'unknown_survivors':[]}
 f._json=lambda code,args:calls.append((code,args)) or raw
 result=f.abort();assert calls==[(http_module.STOP,['123','456','/owned/script',f.plan.attempt_nonce,f.plan.fixture.endpoint.rsplit(':',1)[1]])];assert result['diagnosticOnly'];assert not result['releasePass'];assert not result['trustedExport'];assert 'http_receipt_sha256' not in result
 f.ticks=None
 with pytest.raises(http_module.HeadlessHttpFixtureError):f.abort()
@pytest.mark.skipif(os.name!='posix',reason='actual imported STOP needs procfs and owned child')
@pytest.mark.parametrize('foreign',[False,True])
def test_actual_stop_does_not_report_its_own_controller_as_survivor(tmp_path,foreign):
 import selectors
 wrapper=tmp_path/'owned-loopback-server.py'
 wrapper.write_text("import importlib.util,json,pathlib,sys,threading\nfrom http.server import ThreadingHTTPServer\nspec=importlib.util.spec_from_file_location('actual_staged_server',sys.argv[2]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\ns=ThreadingHTTPServer(('127.0.0.1',0),m.H);s.fixture={'run':'owned-http-contract','nonce':sys.argv[1],'manifest':pathlib.Path(sys.argv[3]),'manifest_path':'/manifest','artifact':pathlib.Path(sys.argv[3]),'artifact_path':'/artifact','log':pathlib.Path(sys.argv[4]),'lock':threading.Lock(),'rows':0,'limited':False,'reset':False};print(s.server_port,flush=True);s.serve_forever()\n")
 artifact=tmp_path/'bytes';artifact.write_bytes(b'fixture');log=tmp_path/'log';log.write_bytes(b'');os.chmod(log,0o600);nonce='d'*48
 foreign_process=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)',str(wrapper),nonce]) if foreign else None
 process=subprocess.Popen([sys.executable,str(wrapper),nonce,str(STAGE/'headless_native_fixture_server.py'),str(artifact),str(log)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 try:
  poll=selectors.DefaultSelector();poll.register(process.stdout,selectors.EVENT_READ);assert poll.select(5);port=int(process.stdout.readline());poll.close()
  raw=(pathlib.Path('/proc')/str(process.pid)/'stat').read_text();ticks=int(raw[raw.rfind(')')+2:].split()[19])
  reaper=threading.Thread(target=process.wait,daemon=True);reaper.start()
  result=script(http_module.STOP,[process.pid,ticks,wrapper,nonce,port]);reaper.join(3)
  assert result['identity_rechecked'] and result['stopped'] and result['listener_closed'];assert result['unknown_survivors']==([foreign_process.pid] if foreign else [])
 finally:
  if foreign_process is not None:foreign_process.terminate();foreign_process.wait(timeout=5)
  if process.poll() is None:process.terminate()
  process.wait(timeout=5)

@pytest.mark.skipif(os.name!='posix',reason='actual READ_LOG POSIX program')
@pytest.mark.parametrize('field,value',[('run_id','foreign'),('attempt_nonce','foreign'),('timestamp',False)])
def test_read_log_rejects_tampered_row_identity(tmp_path,field,value):
 with fixture(tmp_path) as (server,url,log):
  urlopen(url+'/healthz',timeout=3).read();reset(url,log,tmp_path);urlopen(url+'/manifest',timeout=3).read();row=json.loads(log.read_text());row[field]=value;log.write_text(json.dumps(row)+'\n')
  result=subprocess.run([sys.executable,'-c',adapter.READ_LOG,str(log),str(tmp_path/'cursor'),str(1<<20)],capture_output=True,text=True,timeout=3);assert result.returncode!=0;assert 'row identity' in result.stderr

def test_headless_reset_does_not_accept_imported_error_receipt():
 from deploy.release_lab.test_headless_native_acceptance import plan
 f=http_module.HeadlessNativeHttpFixture.__new__(http_module.HeadlessNativeHttpFixture);f.plan=plan();f.log='/owned/log';f.reset_receipt=None;raw={'ok':False,'error':{'private':'not public'}};f._json=lambda *a:raw
 with pytest.raises(http_module.HeadlessHttpFixtureError) as caught:f.reset()
 assert f.reset_receipt is None;assert f.reset_failure_receipt is raw;assert 'not public' not in str(caught.value)

def test_headless_stop_derivation_is_only_checked_self_exclusion():
 assert hashlib.sha256(adapter.STOP.encode()).hexdigest()==http_module._STOP_SOURCE_SHA256
 assert adapter.STOP.count(http_module._STOP_SCAN)==1
 assert http_module.STOP==adapter.STOP.replace(http_module._STOP_SCAN,' if not q.name.isdigit() or int(q.name)==os.getpid(): continue')

@pytest.mark.parametrize('module,kind',[(base_module,base_module.HeadlessNativeE2EDriver),(prepared_module,prepared_module.PreparedHeadlessDriver)])
@pytest.mark.parametrize('archive_failure',[False,True])
def test_actual_reset_error_is_privately_durable_before_abort_without_masking(tmp_path,module,kind,archive_failure,monkeypatch):
 from deploy.release_lab.test_headless_native_acceptance import plan
 p=plan();calls=[];raw={'ok':False,'pre_reset':{'bytes_b64':base64.b64encode(b'original private raw').decode()},'error':{'type':'HTTPError','bytes_b64':base64.b64encode(b'private http error').decode()}}
 f=http_module.HeadlessNativeHttpFixture.__new__(http_module.HeadlessNativeHttpFixture);f.plan=p;f.log='/owned/log';f.reset_receipt=None;f.pid=123;f.ticks=456;f.script='/owned/script';f.start=lambda:None
 leaf=tmp_path/(p.attempt_nonce+'-http-reset-error-prevalidation.private.json')
 def json_response(code,args):
  if code==adapter.RESET:return raw
  assert code==http_module.STOP
  calls.append('abort')
  if not archive_failure:
   record=json.loads(leaf.read_text());assert json.loads(base64.b64decode(record['bytes_base64']))==raw
  return {'identity_rechecked':True,'stopped':True,'listener_closed':True,'unknown_survivors':[]}
 f._json=json_response
 if archive_failure:
  original_capture=base_module.capture_prevalidation
  def failed_capture(root,name,value):
   if name.endswith('-http-reset-error'):raise OSError('inert archive failure')
   return original_capture(root,name,value)
  monkeypatch.setattr(base_module,'capture_prevalidation',failed_capture)
 native=NS(identity=lambda *a:{},cli_json=lambda *a:{})
 preexisting=NS(prepare_and_connect=lambda:{},crash_and_restart=lambda *a:{},promote_systemd_baseline=lambda *a:None,boot_id=lambda *a:'boot',cleanup=lambda *a:calls.append('preexisting-cleanup'))
 driver=kind(p,native,f,preexisting,None,tmp_path)
 with pytest.raises(http_module.HeadlessHttpFixtureError) as error:driver.run()
 assert 'reset failed' in str(error.value);assert 'private http error' not in str(error.value);assert calls==['abort','preexisting-cleanup']
 if archive_failure:assert any('private reset failure archive unavailable: OSError' in note for note in error.value.__notes__)
 else:
  record=json.loads(leaf.read_text());assert not record['truncated'];assert record['sha256']==hashlib.sha256(base64.b64decode(record['bytes_base64'])).hexdigest()
