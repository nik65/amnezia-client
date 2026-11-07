"""Owned-guest persistent signed HTTP fixture; inert until explicitly started.

Never operates on a host interface. All guest operations use the native adapter's
existing ownership fence and an exact canonical run/profile marker.
"""
from __future__ import annotations
import base64
from dataclasses import asdict
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path,PurePosixPath
import re
from .headless_native_acceptance import receipt_sha256,validate_http_receipt
from .headless_native_fixture_server import artifact_path
from .headless_native_http_fixture import HeadlessNativeHttpFixture
from .headless_native_e2e_driver import capture_prevalidation
from .nested_cuttlefish_server_fixture_adapter import RESET,READ_LOG

class CoordinatedHttpError(RuntimeError):pass

def derive_endpoint(nonce):
 if not isinstance(nonce,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{15,95}',nonce):raise CoordinatedHttpError('fixture nonce')
 digest=hashlib.sha256(nonce.encode()).digest()
 return f'http://10.254.{1+digest[0]%254}.{1+digest[1]%254}:17866'
endpoint_for_nonce=derive_endpoint

COMMON=r'''
import base64,contextlib,fcntl,hashlib,importlib.util,io,json,os,pathlib,re,selectors,signal,socket,stat,subprocess,sys,threading,time,urllib.request
MAX=1048576

def digest(data):return hashlib.sha256(data).hexdigest()
def checked(path,limit=MAX):
 p=pathlib.Path(path)
 for parent in p.parents:
  s=parent.lstat()
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError('protected fixture ancestry')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as stream:
  a=os.fstat(stream.fileno())
  if not stat.S_ISREG(a.st_mode) or a.st_uid!=0 or a.st_nlink!=1 or a.st_mode&0o022 or a.st_size>limit:
   reasons=[]
   if not stat.S_ISREG(a.st_mode):reasons.append('not-regular')
   if a.st_uid!=0:reasons.append('non-root-uid')
   if a.st_nlink!=1:reasons.append('link-count')
   if a.st_mode&0o022:reasons.append('group-or-world-writable')
   if a.st_size>limit:reasons.append('size-limit')
   metadata={'regular':stat.S_ISREG(a.st_mode),'uid':a.st_uid,'gid':a.st_gid,'mode':format(stat.S_IMODE(a.st_mode),'04o'),'nlink':a.st_nlink,'size':a.st_size,'limit':limit,'inputbasename':p.name[:80],'reasons':reasons}
   raise RuntimeError('protected fixture file '+json.dumps(metadata,sort_keys=True,separators=(',',':')))
  b=stream.read(limit+1);z=os.fstat(stream.fileno());n=p.lstat()
  key=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),s.st_nlink)
  if len(b)>limit or len(b)!=z.st_size or key(a)!=key(z) or key(z)!=key(n):raise RuntimeError('fixture file changed')
  return b

def write_new(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
 syncdir(pathlib.Path(path).parent)
def syncdir(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def blob(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def command(argv,timeout=4):
 process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);poll=selectors.DefaultSelector();data={'out':bytearray(),'err':bytearray()};end=time.monotonic()+timeout
 try:
  for name,pipe in [('out',process.stdout),('err',process.stderr)]:os.set_blocking(pipe.fileno(),False);poll.register(pipe,selectors.EVENT_READ,name)
  while poll.get_map():
   left=end-time.monotonic()
   if left<=0:raise RuntimeError('owned fixture command deadline')
   for key,_ in poll.select(min(.1,left)):
    raw=os.read(key.fileobj.fileno(),4096)
    if not raw:poll.unregister(key.fileobj);continue
    name=key.data;limit=MAX if name=='out' else 65536
    if len(data[name])+len(raw)>limit:raise RuntimeError('owned fixture command output bound')
    data[name].extend(raw)
  process.wait(timeout=max(.01,end-time.monotonic()))
  if process.returncode:raise RuntimeError('owned fixture command failed')
  return bytes(data['out'])
 finally:
  if process.poll() is None:
   try:os.killpg(process.pid,signal.SIGKILL)
   except ProcessLookupError:pass
  process.wait(timeout=1);poll.close();process.stdout.close();process.stderr.close()

def config_paths(cfg):
 nonce=cfg['attempt_nonce']
 if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{15,95}',nonce):raise RuntimeError('fixture nonce')
 h=hashlib.sha256(nonce.encode()).digest();address=f'10.254.{1+h[0]%254}.{1+h[1]%254}'
 if cfg['endpoint']!='http://'+address+':17866' or cfg['profile']!='linux-headless-x64':raise RuntimeError('fixture endpoint binding')
 root=pathlib.Path('/var/lib/amnezia-release-lab/coordinated-http')/nonce;unit='amnezia-lab-http-'+nonce+'.service'
 return root,unit,address

def unit_bytes(cfg):
 root,unit,address=config_paths(cfg)
 return ('[Unit]\nDescription=Owned Amnezia release-lab HTTP fixture\nBefore=amneziad.service\n[Service]\nType=notify\nNotifyAccess=main\nExecStart=/usr/bin/python3 '+str(root/'server-wrapper.py')+' '+str(root/'owner.json')+'\nTimeoutStartSec=15\nTimeoutStopSec=8\nKillMode=control-group\nRestart=no\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n').encode()
def marker(cfg):
 p=pathlib.Path('/tmp/amnezia-release-lab-marker');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno());raw=f.read(257)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or raw!=('amnezia-release-lab:'+cfg['run_id']+':'+cfg['profile']).encode():raise RuntimeError('canonical guest marker')
def enabled_proof(cfg):
 root,unit,address=config_paths(cfg);link=pathlib.Path('/etc/systemd/system/multi-user.target.wants')/unit
 for parent in link.parents:
  st=parent.lstat()
  if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise RuntimeError('enabled unit parent')
 st=link.lstat()
 if not stat.S_ISLNK(st.st_mode) or st.st_uid!=0:raise RuntimeError('enabled unit identity')
 target=os.readlink(link);resolved=os.path.normpath(target if os.path.isabs(target) else str(link.parent/target))
 if resolved!=str(pathlib.Path('/etc/systemd/system')/unit):raise RuntimeError('enabled unit target')
 return {'path':str(link),'target':target,'uid':st.st_uid,'unit_sha256':digest(unit_bytes(cfg))}

def owned(cfg):
 root,unit,address=config_paths(cfg)
 if json.loads(checked(root/'owner.json',65536))!=cfg:raise RuntimeError('owned fixture marker differs')
 if checked(pathlib.Path('/etc/systemd/system')/unit,16384)!=unit_bytes(cfg):raise RuntimeError('owned fixture unit differs')
 for name,key in [('server.py','server'),('server-wrapper.py','wrapper')]:
  data=checked(root/name,131072)
  if digest(data)!=cfg[key+'_sha256'] or len(data)!=cfg[key+'_size']:raise RuntimeError('owned source differs')
 return root,unit,address

def addresses():
 value=json.loads(command(['/usr/sbin/ip','-j','address','show']))
 return [dict(a,ifname=row.get('ifname')) for row in value for a in row.get('addr_info',[]) if a.get('family')=='inet']
def boot_id():
 fd=os.open('/proc/sys/kernel/random/boot_id',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as stream:value=stream.read(128).decode().strip()
 if not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',value):raise RuntimeError('kernel boot identity')
 return value
def process_identity(pid):
 p=pathlib.Path('/proc')/str(pid);raw=(p/'stat').read_text();fields=raw[raw.rfind(')')+2:].split()
 return {'pid':pid,'start_ticks':int(fields[19]),'boot_id':boot_id()}
def live_wrapper(cfg,row):
 root,unit,address=config_paths(cfg)
 pid=int(command(['/usr/bin/systemctl','show',unit,'--property=MainPID','--value']).decode().strip());current=process_identity(pid)
 if any(current[k]!=row[k] for k in ('pid','start_ticks','boot_id')):raise RuntimeError('live epoch identity')
 proc=pathlib.Path('/proc')/str(pid)
 with proc.joinpath('cmdline').open('rb') as stream:argv=stream.read(4097).rstrip(b'\0').split(b'\0')
 if argv!=[b'/usr/bin/python3',str(root/'server-wrapper.py').encode(),str(root/'owner.json').encode()] or proc.joinpath('status').stat().st_uid!=0 or process_identity(pid)!=current:raise RuntimeError('live wrapper argv/UID identity')
 return current

def daemon_snapshot(ready_us):
 argv=['/usr/bin/systemctl','show','amneziad.service','-pMainPID','-pActiveState','-pSubState','-pExecMainStartTimestampMonotonic','-pActiveEnterTimestampMonotonic','-pFragmentPath','-pDropInPaths','-pInvocationID']
 raw=command(argv,1);props=dict(line.split('=',1) for line in raw.decode().splitlines() if '=' in line)
 pid=int(props.get('MainPID','0'))
 if props.get('ActiveState')!='active' or props.get('SubState')!='running' or pid<=1 or int(props.get('ExecMainStartTimestampMonotonic','0'))<ready_us or int(props.get('ActiveEnterTimestampMonotonic','0'))<ready_us:return None
 before=process_identity(pid);raw_after=command(argv,1);second=process_identity(pid)
 if before!=second or raw_after!=raw:raise RuntimeError('daemon observation identity changed')
 return {**before,'observed_monotonic_us':time.monotonic_ns()//1000,'properties':props,'systemctl_bytes_base64':base64.b64encode(raw).decode(),'systemctl_sha256':digest(raw)}

def require_coverage(directory):
 if os.path.lexists(directory/'coverage-failed.json') or os.path.lexists(directory/'coverage-pending.json'):raise RuntimeError('HTTP epoch coverage incomplete')

def collect_epochs(cfg,root,rows,read_log_code,ledger_raw):
 epochs=[];total=0
 for row in rows:
  epoch_directory=root/'epochs'/row['epoch'];require_coverage(epoch_directory)
  old=sys.argv;out=io.StringIO()
  try:
   sys.argv=['read-log',row['request_log'],row['cursor'],str(MAX)]
   with contextlib.redirect_stdout(out):exec(compile(read_log_code,'owned-read-log','exec'),{})
  finally:sys.argv=old
  raw=out.getvalue().encode();require_coverage(epoch_directory)
  transcript=json.loads(raw);log_raw=checked(row['request_log'])
  if len(log_raw)!=transcript['log_size'] or digest(log_raw)!=transcript['log_sha256']:raise RuntimeError('HTTP epoch transcript changed')
  require_coverage(epoch_directory);total+=len(raw)
  if total>450000:raise RuntimeError('full epoch transcript bound')
  observations=[];paths=sorted((root/'epochs'/row['epoch']).glob('daemon-observation-*.json'))
  if len(paths)>32:raise RuntimeError('daemon observation count')
  for path in paths:
   observation_raw=checked(path,65536);total+=len(observation_raw)
   if total>450000:raise RuntimeError('full epoch observation bound')
   observation=json.loads(observation_raw)
   if observation['boot_id']!=row['boot_id'] or path.name!='daemon-observation-'+str(observation['pid'])+'-'+str(observation['start_ticks'])+'.json':raise RuntimeError('daemon observation file binding')
   observations.append({'daemon_observation':observation,'daemon_observation_bytes_base64':base64.b64encode(observation_raw).decode(),'daemon_observation_sha256':digest(observation_raw)})
  epochs.append({**row,'daemon_observations':observations,'transcript':json.loads(raw),'transcript_bytes_base64':base64.b64encode(raw).decode(),'transcript_sha256':digest(raw)})
 return {'schema':'amnezia-coordinated-http-ledger-v1','run_id':cfg['run_id'],'case_id':cfg['case_id'],'attempt_nonce':cfg['attempt_nonce'],'endpoint':cfg['endpoint'],'epochs':epochs,'raw_ledger_bytes_base64':base64.b64encode(ledger_raw).decode(),'raw_ledger_sha256':digest(ledger_raw),'diagnosticOnly':True,'releasePass':False}

def record_daemon(directory,row):
 observation=daemon_snapshot(row['ready_monotonic_us'])
 if observation is None:return
 if observation['boot_id']!=row['boot_id']:raise RuntimeError('daemon checkpoint boot changed')
 path=directory/('daemon-observation-'+str(observation['pid'])+'-'+str(observation['start_ticks'])+'.json')
 if path.exists():
  old=json.loads(checked(path))
  if any(old[k]!=observation[k] for k in ('boot_id','pid','start_ticks','properties','systemctl_sha256')):raise RuntimeError('daemon checkpoint incarnation drift')
 else:
  if len(list(directory.glob('daemon-observation-*.json')))>=32:raise RuntimeError('daemon checkpoint count')
  write_new(path,blob(observation))

def create_alias(cfg,directory,identity):
 root,unit,address=config_paths(cfg)
 epoch=identity['boot_id']+'-'+str(identity['pid'])+'-'+str(identity['start_ticks'])
 if directory!=root/'epochs'/epoch:raise RuntimeError('alias epoch path')
 if any(a.get('local')==address for a in addresses()):raise RuntimeError('alias already present')
 intent={**identity,'run_id':cfg['run_id'],'attempt_nonce':cfg['attempt_nonce'],'address':address,'prefixlen':32,'preexisting':False}
 write_new(directory/'alias-intent.json',blob(intent));command(['/usr/sbin/ip','address','add',address+'/32','dev','lo'])
 if sum(a.get('local')==address and a.get('prefixlen')==32 and a.get('ifname')=='lo' for a in addresses())!=1:raise RuntimeError('owned alias creation proof')
 write_new(directory/'alias-owned.json',blob(intent))

def remove_alias(cfg):
 root,unit,address=config_paths(cfg);existing=[a for a in addresses() if a.get('local')==address]
 if existing:
  proofs=[];directories=list((root/'epochs').iterdir())
  if len(directories)>256:raise RuntimeError('alias proof count')
  for directory in directories:
   if directory.is_symlink() or not directory.is_dir():raise RuntimeError('alias proof directory')
   proof_path=directory/'alias-owned.json'
   if not proof_path.exists():continue
   proof=json.loads(checked(proof_path))
   if proof.get('boot_id')==boot_id():
    if directory.name!=proof['boot_id']+'-'+str(proof['pid'])+'-'+str(proof['start_ticks']) or proof.get('run_id')!=cfg['run_id']:raise RuntimeError('alias proof binding')
    proofs.append(proof)
  if len(proofs)!=1 or proofs[0].get('preexisting') is not False or proofs[0].get('address')!=address or proofs[0].get('attempt_nonce')!=cfg['attempt_nonce'] or any(a.get('prefixlen')!=32 or a.get('ifname')!='lo' for a in existing):raise RuntimeError('alias removal ownership proof')
  command(['/usr/sbin/ip','address','del',address+'/32','dev','lo'])
 if any(a.get('local')==address for a in addresses()):raise RuntimeError('owned alias survivor')

def append_epoch(root,row):
 path=root/'epochs.jsonl';fd=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
 with os.fdopen(fd,'ab') as out:
  fcntl.flock(out.fileno(),fcntl.LOCK_EX)
  if os.fstat(out.fileno()).st_size+len(blob(row))>MAX:raise RuntimeError('epoch ledger bound')
  out.write(blob(row));out.flush();os.fsync(out.fileno())
 syncdir(root)
'''

COVERAGE_HANDLER = r"""
class CoverageHandler(server_module.H):
 def _coverage_exit(self):os._exit(75)
 def _coverage_fail(self,reason):
  # A durable pending guard already precedes every response. Never forget it.
  marker=directory/'coverage-failed.json'
  try:
   if not os.path.lexists(marker):write_new(marker,blob({'schema':'amnezia-http-coverage-failed-v1','run_id':cfg['run_id'],'attempt_nonce':cfg['attempt_nonce'],'epoch':directory.name,'reason':reason}))
  except BaseException:
   self._coverage_exit();raise RuntimeError('owned fixture coverage stopped')
  self.server.fixture['limited']=True
  self._coverage_exit();raise RuntimeError('owned fixture coverage stopped')
 def serve(self,body):
  f=self.server.fixture
  with f['lock']:
   if os.path.lexists(directory/'coverage-failed.json') or os.path.lexists(directory/'coverage-pending.json'):self._coverage_fail('prior-incomplete')
   tracked=server_module.urlsplit(self.path).path not in ('/__lab__/attempt/reset','/__lab__/request-log')
   self._coverage_guard=None
   if tracked:
    self._coverage_guard=directory/'coverage-pending.json'
    try:write_new(self._coverage_guard,blob({'schema':'amnezia-http-coverage-pending-v1','run_id':cfg['run_id'],'attempt_nonce':cfg['attempt_nonce'],'epoch':directory.name}))
    except BaseException:self._coverage_fail('guard-write')
   try:return super().serve(body)
   except BaseException:self._coverage_fail('response-or-record-error')
 def record(self,status,size,length,digest):
  f=self.server.fixture
  with f['lock']:
   if self._coverage_guard is None:self._coverage_fail('record-without-guard')
   if f['limited']:self._coverage_fail('prior-limit')
   # Exact unchanged H.record row and append semantics; only failure handling differs.
   row={'attempt_nonce':f['nonce'],'bytes':size,'client':self.client_address[0],'content_length':length,'method':self.command,'path':self.path.split('?',1)[0],'run_id':f['run'],'sha256':digest,'status':status,'timestamp':time.time()};line=(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode()
   if f['rows']>=server_module.MAX_ROWS or f['log'].stat().st_size+len(line)>server_module.MAX_LOG:self._coverage_fail('log-bound')
   try:
    fd=os.open(f['log'],os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
    try:
     view=memoryview(line);written=0
     while view:
      n=os.write(fd,view)
      if n<=0:raise OSError('short request-log write')
      written+=n;view=view[n:]
     os.fsync(fd)
    finally:os.close(fd)
    if written!=len(line):raise OSError('short request-log write')
    f['rows']+=1
    self._coverage_guard.unlink();syncdir(directory);self._coverage_guard=None
   except BaseException:self._coverage_fail('log-or-guard-commit')
"""

WRAPPER_BODY=r'''
owner=pathlib.Path(sys.argv[1]);cfg=json.loads(checked(owner,65536));root,unit,address=owned(cfg)
if owner!=root/'owner.json':raise RuntimeError('wrapper owner path')
identity=process_identity(os.getpid());epoch=identity['boot_id']+'-'+str(identity['pid'])+'-'+str(identity['start_ticks']);directory=root/'epochs'/epoch;directory.mkdir(mode=0o700);syncdir(directory.parent)
create_alias(cfg,directory,identity)
manifest=checked(root/'manifest.json',cfg['manifest_size']);artifact=checked(root/'artifact.tar.gz',cfg['artifact_size'])
if digest(manifest)!=cfg['manifest_sha256'] or digest(artifact)!=cfg['artifact_sha256']:raise RuntimeError('signed fixture bytes differ')
spec=importlib.util.spec_from_file_location('owned_signed_fixture',root/'server.py');server_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(server_module)
server_module.artifact_path(json.loads(manifest),cfg['artifact_sha256'],cfg['artifact_size'],cfg['artifact_path'])
exec(compile(COVERAGE_HANDLER,'owned-http-coverage-handler','exec'))
log=directory/'requests.jsonl';write_new(log,b'');listener=server_module.ThreadingHTTPServer((address,17866),CoverageHandler)
listener.fixture={'run':cfg['run_id'],'nonce':cfg['attempt_nonce'],'manifest':root/'manifest.json','manifest_path':cfg['manifest_path'],'artifact':root/'artifact.tar.gz','artifact_path':cfg['artifact_path'],'log':log,'lock':threading.RLock(),'rows':0,'limited':False,'reset':False}
thread=threading.Thread(target=listener.serve_forever,daemon=True);thread.start()
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));urllib.request.install_opener(opener)
health=opener.open(cfg['endpoint']+'/healthz',timeout=3).read()
if json.loads(health).get('run_id')!=cfg['run_id']:raise RuntimeError('initial owned health')
old=sys.argv;out=io.StringIO();cursor=directory/'cursor.json'
try:
 sys.argv=['reset',cfg['endpoint']+'/__lab__/attempt/reset?nonce='+cfg['attempt_nonce']+'&run_id='+cfg['run_id'],str(log),str(cursor),cfg['attempt_nonce'],cfg['run_id'],cfg['attempt_nonce']]
 with contextlib.redirect_stdout(out):exec(compile(RESET_CODE,'owned-reset','exec'),{})
finally:sys.argv=old
reset=json.loads(out.getvalue())
if reset.get('ok') is not True:raise RuntimeError('boot reset failed')
row={**identity,'ready_monotonic_us':time.monotonic_ns()//1000,'epoch':epoch,'request_log':str(log),'cursor':str(cursor),'reset_receipt':reset,'server_sha256':cfg['server_sha256'],'wrapper_sha256':cfg['wrapper_sha256'],'unit_sha256':digest(unit_bytes(cfg)),'enablement':enabled_proof(cfg),'address':address,'run_id':cfg['run_id'],'attempt_nonce':cfg['attempt_nonce']}
write_new(directory/'ready.json',blob(row));append_epoch(root,row)
notify=os.environ.get('NOTIFY_SOCKET')
if not notify:raise RuntimeError('systemd notify binding absent')
sock=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
try:sock.connect(('\0'+notify[1:]) if notify.startswith('@') else notify);sock.sendall(b'READY=1')
finally:sock.close()
thread.join()
'''

def unit_source(nonce):
 root=PurePosixPath('/var/lib/amnezia-release-lab/coordinated-http')/nonce
 return ('[Unit]\nDescription=Owned Amnezia release-lab HTTP fixture\nBefore=amneziad.service\n[Service]\nType=notify\nNotifyAccess=main\nExecStart=/usr/bin/python3 '+str(root/'server-wrapper.py')+' '+str(root/'owner.json')+'\nTimeoutStartSec=15\nTimeoutStopSec=8\nKillMode=control-group\nRestart=no\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n').encode()

def wrapper_source():return COMMON+'\nRESET_CODE='+repr(RESET)+'\nCOVERAGE_HANDLER='+repr(COVERAGE_HANDLER)+'\n'+WRAPPER_BODY

CONTROL_BODY=r'''
cfg=json.loads(sys.argv[1]);action=sys.argv[2];marker(cfg);root,unit,address=config_paths(cfg)
if action=='install':
 if root.exists():owned(cfg);result={'installed':True,'reused':True,'enablement':enabled_proof(cfg)}
 else:
  for parent in [root.parent.parent,root.parent]:
   if not parent.exists():parent.mkdir(mode=0o700)
   s=parent.lstat()
   if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError('fixture parent differs')
  unit_path=pathlib.Path('/etc/systemd/system')/unit
  if os.path.lexists(unit_path):raise RuntimeError('unit already exists')
  root.mkdir(mode=0o700);(root/'epochs').mkdir(mode=0o700);sources=json.loads(sys.argv[3])
  for name,key in [('server.py','server'),('server-wrapper.py','wrapper')]:
   data=base64.b64decode(sources[key],validate=True)
   if len(data)!=cfg[key+'_size'] or digest(data)!=cfg[key+'_sha256']:raise RuntimeError('new source binding')
   write_new(root/name,data)
  for name,key in [('manifest.json','manifest'),('artifact.tar.gz','artifact')]:
   data=checked(cfg[key+'_guest_path'],cfg[key+'_size'])
   if len(data)!=cfg[key+'_size'] or digest(data)!=cfg[key+'_sha256']:raise RuntimeError('fixture input bytes')
   write_new(root/name,data)
  write_new(root/'owner.json',blob(cfg));write_new(root/'epochs.jsonl',b'');write_new(unit_path,unit_bytes(cfg));owned(cfg)
  command(['/usr/bin/systemctl','daemon-reload']);command(['/usr/bin/systemctl','enable',unit]);result={'installed':True,'reused':False,'enablement':enabled_proof(cfg)}
else:
 root,unit,address=owned(cfg)
 if action=='start':command(['/usr/bin/systemctl','start',unit],15)
 ledger_raw=checked(root/'epochs.jsonl');rows=[json.loads(x) for x in ledger_raw.splitlines()]
 if action in ('start','snapshot','reset','ledger'):
  if not rows or len(rows)>256:raise RuntimeError('epoch ledger count')
  for row in rows:
   if row['run_id']!=cfg['run_id'] or row['attempt_nonce']!=cfg['attempt_nonce'] or row['address']!=address or row['server_sha256']!=cfg['server_sha256'] or row['wrapper_sha256']!=cfg['wrapper_sha256'] or row['unit_sha256']!=digest(unit_bytes(cfg)):raise RuntimeError('epoch binding')
   directory=root/'epochs'/row['epoch']
   if pathlib.Path(row['request_log'])!=directory/'requests.jsonl' or pathlib.Path(row['cursor'])!=directory/'cursor.json' or json.loads(checked(directory/'ready.json'))!=row:raise RuntimeError('epoch ready binding')
  live_wrapper(cfg,rows[-1])
  if rows[-1]['boot_id']==boot_id():record_daemon(root/'epochs'/rows[-1]['epoch'],rows[-1])
  if action in ('start','snapshot'):
   result={'schema':'amnezia-coordinated-http-start-v1',**rows[-1],'ready':True}
  elif action=='reset':result=rows[0]['reset_receipt']
  else:
   result=collect_epochs(cfg,root,rows,READ_LOG_CODE,ledger_raw)
 elif action=='cleanup':
  command(['/usr/bin/systemctl','stop',unit],12)
  survivors=[]
  for row in rows:
   if row['boot_id']!=boot_id():continue
   proc=pathlib.Path('/proc')/str(row['pid'])
   if proc.exists() and process_identity(row['pid'])['start_ticks']==row['start_ticks']:survivors.append(row['pid'])
  for proc in pathlib.Path('/proc').iterdir():
   if not proc.name.isdigit() or int(proc.name)==os.getpid():continue
   try:
    argv=proc.joinpath('cmdline').read_bytes().rstrip(b'\0').split(b'\0')
    if str(root/'server-wrapper.py').encode() in argv and str(root/'owner.json').encode() in argv:survivors.append(int(proc.name))
   except OSError:pass
  if survivors:raise RuntimeError('owned fixture process survivor')
  probe=socket.socket();probe.settimeout(1)
  try:closed=probe.connect_ex((address,17866))!=0
  finally:probe.close()
  if not closed:raise RuntimeError('owned listener survivor')
  enabled_proof(cfg);remove_alias(cfg)
  command(['/usr/bin/systemctl','disable',unit]);owned(cfg);(pathlib.Path('/etc/systemd/system')/unit).unlink();command(['/usr/bin/systemctl','daemon-reload'])
  result={'schema':'amnezia-coordinated-http-cleanup-v1','stopped':True,'alias_removed':True,'unit_removed':not os.path.lexists(pathlib.Path('/etc/systemd/system')/unit),'listener_closed':closed,'unknown_survivors':survivors,'evidence_preserved':True,'run_id':cfg['run_id'],'attempt_nonce':cfg['attempt_nonce'],'diagnosticOnly':True,'releasePass':False}
 else:raise RuntimeError('fixture action')
raw=json.dumps(result,separators=(',',':'))
if len(raw.encode())>800000:raise RuntimeError('fixture response bound')
print(raw)
'''

def control_source():return COMMON+'\nREAD_LOG_CODE='+repr(READ_LOG)+'\n'+CONTROL_BODY

def expected_sources_for_plan(plan,server_source=None):
 plan.validate()
 if plan.fixture.endpoint!=derive_endpoint(plan.attempt_nonce):raise CoordinatedHttpError('source plan endpoint')
 source=Path(server_source or Path(__file__).with_name('headless_native_fixture_server.py'))
 return {'server_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'wrapper_sha256':hashlib.sha256(wrapper_source().encode()).hexdigest(),'unit_sha256':hashlib.sha256(unit_source(plan.attempt_nonce)).hexdigest()}

class CoordinatedHeadlessHttpFixture:
 def __init__(self,native,plan,manifest_guest_path,artifact_guest_path,server_source=None,*,archive_root=None):
  plan.validate()
  if native.plan!=plan or plan.fixture.endpoint!=derive_endpoint(plan.attempt_nonce):raise CoordinatedHttpError('native plan endpoint binding')
  self.native,self.plan=native,plan;self.archive_root=Path(archive_root or Path('/var/lib/amnezia-release-lab/receipts')/plan.attempt_nonce/'coordinated-http');self.sequence=0;self.trust=None;self.reset_receipt=None
  source=Path(server_source or Path(__file__).with_name('headless_native_fixture_server.py'));self.server_source=source;server=source.read_bytes();wrapper=wrapper_source().encode();self.sources={'server':base64.b64encode(server).decode(),'wrapper':base64.b64encode(wrapper).decode()}
  paths=[PurePosixPath(str(x)) for x in (manifest_guest_path,artifact_guest_path)]
  if len(set(paths))!=2 or any(not p.is_absolute() or '..' in p.parts or PurePosixPath('/var/lib/amnezia-release-lab/fixture') not in p.parents for p in paths):raise CoordinatedHttpError('owned source paths')
  c=plan.candidate
  if type(c.tar_size) is not int or not 0<c.tar_size<=64*1024*1024 or type(c.manifest_size) is not int or not 0<c.manifest_size<=1048576:raise CoordinatedHttpError('fixture byte limits')
  self.cfg={'run_id':plan.run_id,'case_id':plan.case_id,'profile':'linux-headless-x64','attempt_nonce':plan.attempt_nonce,'endpoint':plan.fixture.endpoint,'manifest_path':plan.fixture.manifest_path,'artifact_path':plan.fixture.artifact_path,'manifest_guest_path':str(paths[0]),'artifact_guest_path':str(paths[1]),'manifest_sha256':c.manifest_sha256,'manifest_size':c.manifest_size,'artifact_sha256':c.tar_sha256,'artifact_size':c.tar_size,'server_sha256':hashlib.sha256(server).hexdigest(),'server_size':len(server),'wrapper_sha256':hashlib.sha256(wrapper).hexdigest(),'wrapper_size':len(wrapper)}
 def _check(self):self.native._check()
 def _json(self,code,args,timeout=20):
  self._check();original=self.native._exec('/usr/bin/python3',['-c',code,*args],timeout);self._check()
  self.archive_root.mkdir(mode=0o700,parents=True,exist_ok=True);self.sequence+=1;capture_prevalidation(self.archive_root,self.plan.attempt_nonce+'-http-'+str(self.sequence),original)
  self._last_raw_result=original
  try:return json.loads(original['stdout'])
  except (KeyError,TypeError,ValueError) as error:raise CoordinatedHttpError('fixture JSON response') from error
 def _run(self,action,timeout=20):return self._json(control_source(),[json.dumps(self.cfg),action,json.dumps(self.sources)],timeout)
 def expected_sources(self):return expected_sources_for_plan(self.plan,self.server_source)
 def install(self):return self._run('install')
 def snapshot_start(self):return self._run('start',20)
 def start(self):
  self.trust=HeadlessNativeHttpFixture._trust(self);self.install();return self.snapshot_start()
 def reset(self):self.reset_receipt=self._run('reset');return self.reset_receipt
 def ledger(self):return self._run('ledger')
 def collect(self):
  value=self.ledger();row=value['epochs'][0];raw=row['transcript'];requests=[dict(r,observed_at=datetime.fromtimestamp(r['observed_at'],timezone.utc).isoformat().replace('+00:00','Z')) for r in raw['rows']]
  p=self.plan;now=datetime.now(timezone.utc).isoformat().replace('+00:00','Z');receipt={'schema':1,'operation':'headless-native-http','run_id':p.run_id,'case_id':p.case_id,'attempt_nonce':p.attempt_nonce,'origin':'server-fixture','transport':'qga','injected':False,'outer_binding':asdict(p.outer_binding),'observed_at':now,'fixture':{'marker':f'amnezia-release-lab:{p.run_id}:{p.case_id}:{p.attempt_nonce}','listener':p.fixture.endpoint,'run_id':p.run_id,'case_id':p.case_id,'attempt_nonce':p.attempt_nonce,'pid':row['pid'],'start_ticks':row['start_ticks']},'requests':requests,'raw_receipt_sha256':receipt_sha256(raw),'trust_key':dict(self.trust or {})}
  return validate_http_receipt(p,receipt)
 def cleanup(self):
  value=self._run('cleanup');original=self._last_raw_result;raw=original['stdout'].encode();p=self.plan
  return {'schema':1,'operation':'headless-coordinated-http-cleanup','run_id':p.run_id,'case_id':p.case_id,'attempt_nonce':p.attempt_nonce,'origin':'guest','transport':'qga','injected':False,'observed_at':datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),'outer_binding':asdict(p.outer_binding),'fixture_cleanup':value,'raw_sources':{'fixture_cleanup':{'origin':'guest','transport':'qga','path':'coordinated-http:cleanup','exit_code':original.get('exitcode',original.get('exit_code')),'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'bytes_b64':base64.b64encode(raw).decode()}}}
 def abort(self):return self.cleanup()
