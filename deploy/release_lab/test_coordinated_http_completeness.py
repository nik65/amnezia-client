"""Ordinary defensive completeness tests: fixed valid paths and small bounds.

No crafted network inputs, guest programs, host services or host aliases run.
"""
import base64,contextlib,hashlib,importlib.util,json,os,pathlib,sys,threading,time
from types import SimpleNamespace as NS
from urllib.request import urlopen
import pytest
from deploy.release_lab import headless_native_fixture_server as legacy
from deploy.release_lab.nested_cuttlefish_server_fixture_adapter import READ_LOG
HERE=pathlib.Path(__file__).resolve().parent
SOURCE=HERE/'headless_coordinated_http_fixture.py'
if not SOURCE.is_file():SOURCE=HERE/'staged/deploy/release_lab/headless_coordinated_http_fixture.py'
assert SOURCE.is_file(), 'coordinated fixture source is missing'
assert hashlib.sha256(SOURCE.read_bytes()).hexdigest()=='ff51b645bd712f615ba979d9815258cb56701d9ab6f0e1dcfcb2fb0c23adce69', 'fixture source binding differs'
SPEC=importlib.util.spec_from_file_location('deploy.release_lab._coverage_staged',SOURCE);M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)
pytestmark=pytest.mark.skipif(os.name!='posix' or getattr(os,'geteuid',lambda:1)()!=0,reason='actual protected POSIX temporary fixtures')
class Stopped(RuntimeError):pass

def common():
 scope={};exec(M.COMMON,scope);return scope

def handler(directory,cfg,events=None,write_hook=None):
 helpers=common();scope={'server_module':legacy,'directory':directory,'cfg':cfg,'os':os,'json':json,'time':time,'blob':helpers['blob'],'syncdir':helpers['syncdir'],'write_new':write_hook or helpers['write_new']}
 exec(M.COVERAGE_HANDLER,scope);cls=scope['CoverageHandler']
 def stopped(self):
  if events is not None:events.append('exit')
  raise Stopped('only owned wrapper would exit')
 cls._coverage_exit=stopped
 return cls,scope,helpers

@contextlib.contextmanager
def loopback(tmp_path,monkeypatch,*,row_cap=4096,byte_cap=1048576,write_hook=None):
 monkeypatch.setattr(legacy,'MAX_ROWS',row_cap);monkeypatch.setattr(legacy,'MAX_LOG',byte_cap)
 cfg={'run_id':'valid-run','attempt_nonce':'a'*48};cls,scope,helpers=handler(tmp_path,cfg,write_hook=write_hook)
 class Quiet(legacy.ThreadingHTTPServer):
  def handle_error(self,*a):pass
 for name in ('manifest','artifact'):(tmp_path/name).write_bytes(('signed '+name+' bytes').encode())
 log=tmp_path/'requests.jsonl';helpers['write_new'](log,b'')
 server=Quiet(('127.0.0.1',0),cls);server.fixture={'run':cfg['run_id'],'nonce':cfg['attempt_nonce'],'manifest':tmp_path/'manifest','manifest_path':'/manifest','artifact':tmp_path/'artifact','artifact_path':'/artifact','log':log,'lock':threading.RLock(),'rows':0,'limited':False,'reset':False}
 thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
 try:yield server,'http://127.0.0.1:'+str(server.server_port),helpers,scope
 finally:server.shutdown();server.server_close();thread.join(3)

@pytest.mark.parametrize('kind',['rows','bytes'])
def test_fixed_valid_requests_small_bounds_persist_failure_and_reject_epoch(tmp_path,monkeypatch,kind):
 with loopback(tmp_path,monkeypatch,row_cap=1 if kind=='rows' else 4096,byte_cap=32 if kind=='bytes' else 1048576) as (server,url,helpers,scope):
  data=urlopen(url+'/manifest',timeout=3).read();assert data==(tmp_path/'manifest').read_bytes()
  if kind=='rows':urlopen(url+'/manifest',timeout=3).read()
  assert (tmp_path/'coverage-failed.json').exists();assert (tmp_path/'coverage-pending.json').exists();assert server.fixture['limited'] is True
  assert (tmp_path/'coverage-failed.json').stat().st_mode&0o777==0o600
  with pytest.raises(RuntimeError,match='coverage incomplete'):helpers['require_coverage'](tmp_path)
  with pytest.raises(Exception):urlopen(url+'/artifact',timeout=2).read()
  assert all(json.loads(x)['path']=='/manifest' for x in (tmp_path/'requests.jsonl').read_bytes().splitlines())


def test_normal_record_matches_unchanged_legacy_and_clears_guard_after_fsync(tmp_path,monkeypatch):
 cfg={'run_id':'valid-run','attempt_nonce':'a'*48};cls,scope,helpers=handler(tmp_path,cfg);clock=NS(time=lambda:123456.25);scope['time']=clock;monkeypatch.setattr(legacy,'time',clock)
 logs=[]
 for kind in (legacy.H,cls):
  log=tmp_path/('legacy' if kind is legacy.H else 'guarded');helpers['write_new'](log,b'');logs.append(log)
  obj=object.__new__(kind);obj.server=NS(fixture={'run':cfg['run_id'],'nonce':cfg['attempt_nonce'],'log':log,'lock':threading.RLock(),'rows':0,'limited':False});obj.path='/manifest';obj.command='GET';obj.client_address=('127.0.0.1',1)
  if kind is cls:obj._coverage_guard=tmp_path/'coverage-pending.json';helpers['write_new'](obj._coverage_guard,b'pending')
  obj.record(200,12,12,'b'*64);assert obj.server.fixture['rows']==1
 assert logs[0].read_bytes()==logs[1].read_bytes();assert not (tmp_path/'coverage-pending.json').exists();assert not (tmp_path/'coverage-failed.json').exists()

@pytest.mark.parametrize('fault',['open','write','fsync'])
def test_append_failures_keep_durable_guard_and_failure_before_limited(tmp_path,monkeypatch,fault):
 cfg={'run_id':'valid-run','attempt_nonce':'a'*48};events=[];helpers=common();log=tmp_path/'requests.jsonl';helpers['write_new'](log,b'')
 def write(path,data):helpers['write_new'](path,data);events.append('durable-'+path.name)
 cls,scope,_=handler(tmp_path,cfg,events,write)
 class State(dict):
  def __setitem__(self,key,value):
   if key=='limited' and value is True:
    assert (tmp_path/'coverage-failed.json').exists();events.append('limited')
   return super().__setitem__(key,value)
 obj=object.__new__(cls);obj.server=NS(fixture=State(run=cfg['run_id'],nonce=cfg['attempt_nonce'],log=log,lock=threading.RLock(),rows=0,limited=False));obj.path='/manifest';obj.command='GET';obj.client_address=('127.0.0.1',1);obj._coverage_guard=tmp_path/'coverage-pending.json';helpers['write_new'](obj._coverage_guard,b'pending')
 descriptors=set()
 class Proxy:
  def __getattr__(self,name):return getattr(os,name)
  def open(self,path,flags,*a,**kw):
   if pathlib.Path(path)==log and flags&os.O_APPEND:
    if fault=='open':raise OSError('ordinary append failure')
    fd=os.open(path,flags,*a,**kw);descriptors.add(fd);return fd
   return os.open(path,flags,*a,**kw)
  def write(self,fd,data):
   if fd in descriptors and fault=='write':return 0
   return os.write(fd,data)
  def fsync(self,fd):
   if fd in descriptors and fault=='fsync':raise OSError('ordinary fsync failure')
   return os.fsync(fd)
 scope['os']=Proxy()
 with pytest.raises(Stopped):obj.record(200,12,12,'b'*64)
 assert obj._coverage_guard.exists();assert events.index('durable-coverage-failed.json')<events.index('limited')<events.index('exit')
 with pytest.raises(RuntimeError):helpers['require_coverage'](tmp_path)


def test_guard_creation_failure_does_not_send_body_or_continue(tmp_path,monkeypatch):
 attempts=[]
 def failed_write(path,data):attempts.append(path.name);raise OSError('ordinary storage failure')
 with loopback(tmp_path,monkeypatch,write_hook=failed_write) as (server,url,helpers,scope):
  with pytest.raises(Exception):urlopen(url+'/manifest',timeout=2).read()
  assert (tmp_path/'requests.jsonl').read_bytes()==b'';assert server.fixture['rows']==0;assert server.fixture['limited'] is False;assert attempts[:2]==['coverage-pending.json','coverage-failed.json']


def prepare_epochs(root):
 helpers=common();cfg={'run_id':'valid-run','case_id':'case','attempt_nonce':'a'*48,'endpoint':'http://10.254.1.2:17866'};rows=[]
 for index in range(2):
  directory=root/'epochs'/str(index);directory.mkdir(parents=True,mode=0o700);log=directory/'requests.jsonl';helpers['write_new'](log,b'');cursor=directory/'cursor';helpers['write_new'](cursor,helpers['blob']({'run_id':cfg['run_id'],'attempt_nonce':cfg['attempt_nonce'],'log_inode':log.stat().st_ino,'reset_token':'token','offset':0}));rows.append({'epoch':str(index),'request_log':str(log),'cursor':str(cursor)})
 helpers['checked']=lambda path,limit=1048576:pathlib.Path(path).read_bytes()
 return helpers,cfg,rows

@pytest.mark.parametrize('epoch',[0,1])
@pytest.mark.parametrize('marker',['coverage-failed.json','coverage-pending.json'])
def test_readonly_collection_rejects_any_old_or_new_incomplete_epoch_before_read(tmp_path,epoch,marker):
 helpers,cfg,rows=prepare_epochs(tmp_path);(tmp_path/'epochs'/str(epoch)/marker).write_bytes(b'partial-or-complete-failure')
 with pytest.raises(RuntimeError,match='coverage incomplete'):helpers['collect_epochs'](cfg,tmp_path,rows,READ_LOG,b''.join(helpers['blob'](r) for r in rows))


def test_readonly_collection_detects_failure_published_during_read(tmp_path):
 helpers,cfg,rows=prepare_epochs(tmp_path);original=helpers['require_coverage'];calls=[0]
 def require(directory):
  calls[0]+=1
  if calls[0]==2:(directory/'coverage-failed.json').write_bytes(b'failure')
  return original(directory)
 helpers['require_coverage']=require
 with pytest.raises(RuntimeError,match='coverage incomplete'):helpers['collect_epochs'](cfg,tmp_path,rows,READ_LOG,b''.join(helpers['blob'](r) for r in rows))


def test_clean_collection_returns_all_epochs_and_binds_new_wrapper_source(tmp_path):
 helpers,cfg,rows=prepare_epochs(tmp_path);result=helpers['collect_epochs'](cfg,tmp_path,rows,READ_LOG,b''.join(helpers['blob'](r) for r in rows))
 assert len(result['epochs'])==2;assert all(e['transcript']['rows']==[] for e in result['epochs']);assert 'COVERAGE_HANDLER=' in M.wrapper_source();compile(M.wrapper_source(),'wrapper','exec');compile(M.control_source(),'control','exec')
 assert "threading.RLock()" in M.WRAPPER_BODY
