"""Pre-armed guest-only pending capture. Does not create acceptance facts."""
import base64
import hashlib
import json
import time

from .headless_native_acceptance import UPDATE_STATE, UPDATE_JOURNAL, ID_RE
from .headless_native_qga_adapter import READ_SET, HeadlessNativeQgaError

# The actual existing READ_SET supplies the byte/ownership/transition contract.
WATCH = r'''
import contextlib,hashlib,io,json,os,pathlib,stat,sys,time
p=json.loads(sys.argv[1]); root=pathlib.Path(p['root']); start=time.monotonic()
def emit(name,value):
 data=json.dumps(value,separators=(',',':')).encode()
 if len(data)>400000:raise RuntimeError('capture bound')
 temporary=root/(name+'.writing')
 fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:
  f.write(data);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),0o400)
 if os.path.lexists(root/name):raise RuntimeError('observer output exists')
 os.rename(temporary,root/name)
def failed(kind,error,tb):
 try:emit('failure.json',{'nonce':p['nonce'],'phase':p['phase'],'error_type':kind.__name__,'error':str(error)[:2000]})
 except BaseException:pass
sys.excepthook=failed
def read():
 out=io.StringIO(); old=sys.argv
 try:
  sys.argv=['read-set',json.dumps(p['spec'])]
  with contextlib.redirect_stdout(out):
   try:exec(compile(p['read_set'],'READ_SET','exec'),{})
   except SystemExit as e:
    if e.code not in (None,0):raise RuntimeError('READ_SET exit: '+str(e.code)[:2000])
 finally:sys.argv=old
 return json.loads(out.getvalue())
def phase(v):
 rows=v.get('records',{})
 if set(rows)!={'pending_state','pending_journal'}:return False
 import base64
 state=json.loads(base64.b64decode(rows['pending_state']['bytes_b64'],validate=True))
 journal=json.loads(base64.b64decode(rows['pending_journal']['bytes_b64'],validate=True))
 return state.get('state')==p['phase'] and journal.get('phase')==p['phase']
# Refuse an already pending transaction before advertising readiness.
if phase(read()):raise RuntimeError('preexisting pending transaction')
emit('ready.json',{'pid':os.getpid(),'nonce':p['nonce'],'phase':p['phase']})
while time.monotonic()-start<p['timeout']:
 value=read()
 if phase(value):
  emit('capture.json',{'nonce':p['nonce'],'phase':p['phase'],'records':value['records']});break
 time.sleep(.005)
else:emit('expired.json',{'nonce':p['nonce']})
'''

CONTROL = r'''
import hashlib,json,os,pathlib,select,signal,stat,subprocess,sys,time
p=json.loads(sys.argv[1]);root=pathlib.Path(p['root'])
def safe_dir(include_root=True):
 for x in ([root] if include_root else [])+list(root.parents):
  s=x.lstat()
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError('observer directory identity')
 if include_root and stat.S_IMODE(root.lstat().st_mode)!=0o700:raise RuntimeError('observer directory privacy')
def raw(name):
 fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o400 or s.st_size>400000:raise RuntimeError('observer file identity')
  b=f.read(400001);a=os.fstat(f.fileno());n=(root/name).lstat()
  key=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_uid,x.st_mode,x.st_nlink)
  if key(s)!=key(a) or key(a)!=key(n) or len(b)!=s.st_size:raise RuntimeError('observer file changed')
 return json.loads(b)
def identity(pid):
 r=pathlib.Path('/proc')/str(pid);st=r.joinpath('stat').read_text();cmd=r.joinpath('cmdline').read_bytes()
 if r.stat().st_uid!=0:raise RuntimeError('observer process owner')
 return {'pid':pid,'ticks':int(st[st.rfind(')')+2:].split()[19]),'cmd_sha':hashlib.sha256(cmd).hexdigest()}
def failure_value(error):
 return {'failure':{'nonce':p['nonce'],'phase':p['phase'],'error_type':'ObserverControlError','error':error,'identity':p.get('identity')}}
def completed():
 try:return raw('capture.json')
 except FileNotFoundError:pass
 try:return {'failure':raw('failure.json')}
 except FileNotFoundError:pass
 try:raw('expired.json')
 except FileNotFoundError:return None
 return failure_value('observer expired without capture')
if p['op']=='arm':
 safe_dir(False);root.mkdir(mode=0o700);safe_dir()
 child=subprocess.Popen(['/usr/bin/python3','-c',p['watch'],json.dumps(p['watch_args'])],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
 try:
  own=identity(child.pid);end=time.monotonic()+5
  while time.monotonic()<end:
   if child.poll() is not None:raise RuntimeError('observer exited before ready')
   try:ready=raw('ready.json')
   except FileNotFoundError:time.sleep(.01);continue
   if ready!={'pid':child.pid,'nonce':p['nonce'],'phase':p['phase']} or identity(child.pid)!=own:raise RuntimeError('observer readiness identity')
   print(json.dumps(own));break
  else:raise RuntimeError('observer readiness deadline')
 except BaseException as primary:
  try:
   if child.poll() is None:child.terminate()
   try:child.wait(timeout=3)
   except subprocess.TimeoutExpired:
    child.kill();child.wait(timeout=3)
  except BaseException as cleanup:primary.add_note('observer arm cleanup failed: '+str(cleanup))
  raise
else:
 safe_dir()
 if p['op']=='read':
  value=completed()
  if value is None and p.get('identity') is not None:
   dead=False;changed=False
   try:fd=os.pidfd_open(p['identity']['pid'])
   except ProcessLookupError:dead=True
   else:
    try:
     poll=select.poll();poll.register(fd,select.POLLIN);dead=bool(poll.poll(0))
     if not dead:changed=identity(p['identity']['pid'])!=p['identity']
    except ProcessLookupError:dead=True
    finally:os.close(fd)
   if dead:
    # Publication can occur between first read and exit observation.
    value=completed()
    if value is None:value=failure_value('observer died without capture')
   elif changed:value=failure_value('observer incarnation changed')
  print(json.dumps(value or {}))
 elif p['op']=='stop':
  try:fd=os.pidfd_open(p['identity']['pid'])
  except ProcessLookupError:pass
  else:
   try:
    poll=select.poll();poll.register(fd,select.POLLIN)
    if not poll.poll(0):
     if identity(p['identity']['pid'])!=p['identity']:raise RuntimeError('observer incarnation changed')
     signal.pidfd_send_signal(fd,signal.SIGTERM)
     if not poll.poll(3000):
      signal.pidfd_send_signal(fd,signal.SIGKILL)
      if not poll.poll(3000):raise RuntimeError('observer stop deadline')
   except ProcessLookupError:pass
   finally:os.close(fd)
  print('{}')
'''


FAILURE_SNAPSHOT = r"""
import base64,hashlib,json,os,pathlib,re,selectors,signal,stat,subprocess,sys,time
nonce,phase=sys.argv[1:];budget=200000;deadline=time.monotonic()+4
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{15,95}',nonce) or phase not in ('restart_pending','rollback_restart_pending'):raise SystemExit('snapshot binding')
root=pathlib.Path('/var/lib/amnezia-release-lab/pending-'+nonce+'-'+phase)
def read(path,observer=False):
 global budget
 row={'path':str(path)}
 if time.monotonic()>=deadline:return dict(row,deadline=True)
 try:
  if observer:
   for parent in (root,*root.parents):
    st=parent.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise RuntimeError('observer root identity')
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  with os.fdopen(fd,'rb') as stream:
   before=os.fstat(stream.fileno());row.update(uid=before.st_uid,gid=before.st_gid,mode=stat.S_IMODE(before.st_mode),size=before.st_size)
   if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_nlink!=1:raise RuntimeError('snapshot file identity')
   data=stream.read(min(24000,budget));budget-=len(data);after=os.fstat(stream.fileno());named=path.lstat()
   key=lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_uid,v.st_gid,stat.S_IMODE(v.st_mode),v.st_nlink)
   row.update(retainedSize=len(data),truncated=len(data)<before.st_size,retainedSHA256=hashlib.sha256(data).hexdigest(),bytesBase64=base64.b64encode(data).decode(),sameIdentity=key(before)==key(after)==key(named))
 except BaseException as error:
  row['errorType']=type(error).__name__
  if isinstance(error,OSError):row['errno']=error.errno
 return row

def command(argv):
 global budget
 result={'argv':argv,'stdoutBase64':'','stderrBase64':'','truncated':False,'timeout':False};streams={};data={'stdout':bytearray(),'stderr':bytearray()};process=None;poll=selectors.DefaultSelector()
 try:
  if time.monotonic()>=deadline:return dict(result,deadline=True)
  process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  for name,pipe in [('stdout',process.stdout),('stderr',process.stderr)]:os.set_blocking(pipe.fileno(),False);poll.register(pipe,selectors.EVENT_READ,name)
  end=min(deadline,time.monotonic()+1)
  while poll.get_map():
   remaining=end-time.monotonic()
   if remaining<=0:result['timeout']=True;break
   for key,_ in poll.select(min(.05,remaining)):
    chunk=os.read(key.fileobj.fileno(),4096)
    if not chunk:poll.unregister(key.fileobj);continue
    name=key.data;limit=16000 if name=='stdout' else 4000;room=min(limit-len(data[name]),budget)
    data[name].extend(chunk[:max(0,room)]);budget-=min(len(chunk),max(0,room))
    if len(chunk)>room:result['truncated']=True;break
   if result['truncated']:break
  if result['timeout'] or result['truncated']:
   try:os.killpg(process.pid,signal.SIGKILL)
   except ProcessLookupError:pass
  process.wait(timeout=max(.01,min(.5,max(0,deadline-time.monotonic()))));result['returncode']=process.returncode
 except BaseException as error:
  result['errorType']=type(error).__name__
 finally:
  if process is not None:
   if process.poll() is None:
    try:os.killpg(process.pid,signal.SIGKILL)
    except ProcessLookupError:pass
   try:process.wait(timeout=.5)
   except BaseException as error:result['reapErrorType']=type(error).__name__
   for pipe in (process.stdout,process.stderr):
    if pipe is not None:pipe.close()
  poll.close()
 for name in ('stdout','stderr'):
  raw=bytes(data[name]);result[name+'Base64']=base64.b64encode(raw).decode();result[name+'RetainedSize']=len(raw);result[name+'RetainedSHA256']=hashlib.sha256(raw).hexdigest()
 result['completeStdout']=result['completeStderr']=not(result['timeout'] or result['truncated'] or result.get('errorType') or result.get('reapErrorType'))
 return result
rows=[read(pathlib.Path('/var/lib/amnezia/headless-updates.json')),read(pathlib.Path('/var/lib/amnezia/updates/transaction.json'))]
rows.extend(read(root/name,True) for name in ('ready.json','failure.json','capture.json','expired.json'))
commands=[command(['/usr/local/bin/amnezia-cli','--socket','/run/amnezia/amneziad.sock','--json','doctor']),command(['/usr/bin/journalctl','-u','amneziad.service','-n','60','--no-pager','-o','short-monotonic'])]
raw=json.dumps({'diagnosticOnly':True,'releasePass':False,'nonce':nonce,'phase':phase,'files':rows,'commands':commands,'rawRetained':200000-budget,'rawBudget':200000},separators=(',',':')).encode()
print(json.dumps({'snapshotBytesBase64':base64.b64encode(raw).decode(),'snapshotSize':len(raw),'snapshotSHA256':hashlib.sha256(raw).hexdigest()},separators=(',',':')))
"""

class PendingObservation:
    def __init__(self,native,phase,timeout,*,failure_archive=None):
        if phase not in {'restart_pending','rollback_restart_pending'} or isinstance(timeout,bool) or not isinstance(timeout,(int,float)) or not 0<timeout<=600:
            raise HeadlessNativeQgaError('observer arguments')
        nonce=native.plan.attempt_nonce
        if not ID_RE.fullmatch(nonce) or len(nonce)<16:raise HeadlessNativeQgaError('observer nonce')
        self.native=native;self.phase=phase;self.timeout=timeout;self.nonce=nonce;self.identity=None
        self.failure_archive=failure_archive;self._failure_captured=False;self._last_response=None
        self.root='/var/lib/amnezia-release-lab/pending-'+nonce+'-'+phase
    def _control(self,op,**extra):
        return self.native._json('/usr/bin/python3',['-c',CONTROL,json.dumps(dict(op=op,root=self.root,nonce=self.nonce,phase=self.phase,**extra))],15 if op=='arm' else 10)
    def _capture_failure(self,primary,stage):
        if self.failure_archive is None or self._failure_captured:return
        self._failure_captured=True
        value={'diagnosticOnly':True,'releasePass':False,'stage':stage,'originalErrorType':type(primary).__name__,'observerResponse':self._last_response}
        try:value['snapshot']=self.native._json('/usr/bin/python3',['-c',FAILURE_SNAPSHOT,self.nonce,self.phase],6)
        except BaseException as capture_error:
            value['snapshotErrorType']=type(capture_error).__name__
            primary.add_note('pending observer private snapshot unavailable: '+type(capture_error).__name__)
        try:
            from .headless_native_e2e_driver import capture_prevalidation
            capture_prevalidation(self.failure_archive,self.nonce+'-'+self.phase+'-observer-failure',value)
        except BaseException as archive_error:primary.add_note('pending observer private failure archive unavailable: '+type(archive_error).__name__)
    def __enter__(self):
        spec={'files':{'pending_state':UPDATE_STATE,'pending_journal':UPDATE_JOURNAL},'absent':{}}
        args=dict(root=self.root,nonce=self.nonce,phase=self.phase,timeout=self.timeout,read_set=READ_SET,spec=spec)
        try:self.identity=self._control('arm',watch=WATCH,watch_args=args)
        except BaseException as primary:self._capture_failure(primary,'arm');raise
        return self
    def collect(self):
        try:return self._collect()
        except BaseException as primary:self._capture_failure(primary,'collect');raise
    def _collect(self):
        end=time.monotonic()+self.timeout
        while time.monotonic()<end:
            value=self._control('read',identity=self.identity);self._last_response=value
            if value:
                if set(value)=={'failure'}:
                    failure=value['failure']
                    if not isinstance(failure,dict) or failure.get('nonce')!=self.nonce or failure.get('phase')!=self.phase:raise HeadlessNativeQgaError('observer failure binding')
                    raise HeadlessNativeQgaError('pending observer failed; private diagnostic requested')
                if set(value)!={'nonce','phase','records'} or value['nonce']!=self.nonce or value['phase']!=self.phase:
                    raise HeadlessNativeQgaError('observer capture binding')
                records=value['records']
                if not isinstance(records,dict) or set(records)!={'pending_state','pending_journal'}:raise HeadlessNativeQgaError('observer records')
                for key,path in [('pending_state',UPDATE_STATE),('pending_journal',UPDATE_JOURNAL)]:
                    r=records[key];data=base64.b64decode(r['bytes_b64'],validate=True)
                    if r.get('origin')!='guest' or r.get('transport')!='qga' or r.get('path')!=path or (type(r.get('uid')) is not int or r['uid']!=0) or (type(r.get('gid')) is not int or r['gid']<0) or r.get('mode')!='0600' or type(r.get('size')) is not int or r['size']!=len(data) or r.get('sha256')!=hashlib.sha256(data).hexdigest():raise HeadlessNativeQgaError('observer original record identity')
                    obj=json.loads(data)
                    if obj.get('state' if key=='pending_state' else 'phase')!=self.phase:raise HeadlessNativeQgaError('observer original phase')
                return records
            time.sleep(.1)
        raise HeadlessNativeQgaError('observer capture deadline')
    def __exit__(self,typ,error,tb):
        if error is not None:self._capture_failure(error,'body')
        if self.identity:
            try:self._control('stop',identity=self.identity)
            except BaseException as cleanup:
                if error is not None:error.add_note('pending observer stop failed: '+type(cleanup).__name__)
                else:self._capture_failure(cleanup,'stop');raise
