"""Owned-QGA raw collector for the distinct retained-coordinator contract.

No acceptance/PASS is created here. Legacy native validators are untouched.
Large retained executables cross QGA as bounded file chunks, not giant JSON.
"""
from __future__ import annotations
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time

from .headless_native_acceptance import FIXED_STORE, FIXED_KEY, FIXED_SOCKET, UPDATE_STATE, UPDATE_JOURNAL
from .headless_native_qga_adapter import HeadlessNativeQgaAdapter, STAGE, IDENTITY
from .headless_native_reboot_collector import ROLLBACK
from .linux_headless_driver import OwnedRebootCollector

ROOT='/var/lib/amnezia/rollback-coordinator'
RETAINED=ROOT+'/amnezia-cli'
RECORD=ROOT+'/coordinator.json'
UNIT='/etc/systemd/system/amnezia-rollback-coordinator.service'
ARCHIVE_LIMIT=256*1024*1024


class CoordinatedCollectionError(RuntimeError):pass


def _directory_fd(path):
    path=Path(path).absolute();flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
    fd=os.open(path.anchor,flags)
    try:
        for component in path.parts[1:]:
            if component in ('.','..'):raise CoordinatedCollectionError('private archive path escaped')
            next_fd=os.open(component,flags,dir_fd=fd);os.close(fd);fd=next_fd
        return fd
    except BaseException:os.close(fd);raise


IO_COMMON=r'''
import base64,hashlib,json,os,pathlib,re,stat,sys,time
class Transition(RuntimeError):pass
def emit(value):print(json.dumps(value,separators=(',',':')),flush=True)
def fdidentity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def directory(path):
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for part in pathlib.PurePosixPath(path).parts[1:]:
   if part in ('','..','.'):raise RuntimeError('directory escaped')
   nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
   s=os.fstat(fd)
   if s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError('unprotected source directory')
  return fd
 except BaseException:os.close(fd);raise
def private(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
def context(run,case,nonce,create=False):
 if any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}',x) for x in (run,case,nonce)):raise RuntimeError('invalid collector context')
 root=pathlib.Path('/var/lib/amnezia/.release-lab-coordinated-'+nonce)
 expected=json.dumps({'run_id':run,'case_id':case,'attempt_nonce':nonce},sort_keys=True).encode()
 if create:
  f=os.open('/tmp/amnezia-release-lab-marker',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   s=os.fstat(f);marker=('amnezia-release-lab:'+run+':linux-headless-x64').encode()
   if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_size!=len(marker) or os.read(f,4096)!=marker:raise RuntimeError('canonical guest marker differs')
  finally:os.close(f)
  os.mkdir(root,0o700);private(root/'owner.json',expected)
 d=directory(str(root))
 try:
  if stat.S_IMODE(os.fstat(d).st_mode)!=0o700:raise RuntimeError('collector directory mode')
  f=os.open('owner.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=d)
  try:
   s=os.fstat(f)
   if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size!=len(expected) or os.read(f,4096)!=expected:raise RuntimeError('collector owner marker')
  finally:os.close(f)
 finally:os.close(d)
 return root
def source(key,root):
 fixed={'profiles':('/var/lib/amnezia/profiles.json',0o600,16*1024*1024),
 'record':('/var/lib/amnezia/rollback-coordinator/coordinator.json',0o600,48*1024*1024),
 'retained':('/var/lib/amnezia/rollback-coordinator/amnezia-cli',0o500,64*1024*1024),
 'unit':('/etc/systemd/system/amnezia-rollback-coordinator.service',0o644,16384),
 'state':('/var/lib/amnezia/headless-updates.json',0o600,4*1024*1024),
 'journal':('/var/lib/amnezia/updates/transaction.json',0o600,4*1024*1024)}
 if key in fixed:return fixed[key]
 if key in ('rollback_stdout','resume_stdout'):return(str(root/('output-'+key.split('_')[0])),0o600,1048576)
 if key=='unit_state':return(str(root/'unit-state.json'),0o600,1048576)
 raise RuntimeError('source is not allowlisted')
def snapshot(path,mode,limit,logical,root,label,kind='file',inspected=None,metadata=False,allow_empty=False):
 d=directory(str(pathlib.PurePosixPath(path).parent));name=pathlib.PurePosixPath(path).name
 try:
  parent_before=os.fstat(d)
  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=d)
  try:
   before=os.fstat(fd)
   if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=mode or not (0 if allow_empty else 1)<=before.st_size<=limit:raise RuntimeError('protected descriptor identity')
   target=root/('capture-'+label);out=os.open(os.devnull,os.O_WRONLY) if metadata else os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);digest=hashlib.sha256();size=0
   with os.fdopen(out,'wb') as stream:
    while True:
     chunk=os.read(fd,min(65536,limit+1-size))
     if not chunk:break
     size+=len(chunk)
     if size>limit:raise RuntimeError('protected descriptor bound')
     stream.write(chunk);digest.update(chunk)
    stream.flush()
    if not metadata:os.fsync(stream.fileno())
   after=os.fstat(fd);named=os.stat(name,dir_fd=d,follow_symlinks=False)
   parent_after=os.stat(str(pathlib.PurePosixPath(path).parent),follow_symlinks=False)
   parent_id=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)
   if parent_id(parent_before)!=parent_id(parent_after):raise Transition('protected source parent changed')
   if fdidentity(before)!=fdidentity(after) or fdidentity(after)!=fdidentity(named) or size!=after.st_size:raise Transition('protected descriptor changed')
   result={'origin':'guest','transport':'qga','path':logical,'source_path':path,'kind':'guest-descriptor-metadata' if metadata else kind,'inspected_path':inspected,'uid':after.st_uid,'gid':after.st_gid,'mode':format(mode,'04o'),'size':size,'sha256':digest.hexdigest(),'nofollow':True,'regular':True,'nlink':after.st_nlink,'stable_identity':True}
   if not metadata:result.update(physical_path=str(target),physical_mode='0600')
   return result
  finally:os.close(fd)
 finally:os.close(d)
'''

IO_PROGRAM=IO_COMMON+r'''
operation,key,label,run,case,nonce=sys.argv[1:]
root=context(run,case,nonce,operation=='init')
if not re.fullmatch('[a-z0-9-]{1,96}',label):raise RuntimeError('invalid capture label')
if operation=='init':emit({'initialized':True})
elif operation=='diagnostic-stat':
 path,mode,limit=source(key,root);d=directory(str(pathlib.PurePosixPath(path).parent))
 try:
  try:
   value=os.stat(pathlib.PurePosixPath(path).name,dir_fd=d,follow_symlinks=False)
   emit({'diagnostic_only':True,'path':path,'expected_mode':format(mode,'04o'),'limit':limit,'exists':True,'uid':value.st_uid,'gid':value.st_gid,'mode':format(stat.S_IMODE(value.st_mode),'04o'),'regular':stat.S_ISREG(value.st_mode),'symlink':stat.S_ISLNK(value.st_mode),'nlink':value.st_nlink,'size':value.st_size,'dev':value.st_dev,'ino':value.st_ino})
  except FileNotFoundError:emit({'diagnostic_only':True,'path':path,'exists':False})
 finally:os.close(d)
elif operation in ('read','metadata','diagnostic-read'):
 if operation=='diagnostic-read' and key not in ('rollback_stdout','resume_stdout'):raise RuntimeError('empty diagnostic source not allowlisted')
 path,mode,limit=source(key,root)
 logical={'rollback_stdout':'cli:update-rollback','resume_stdout':'cli:coordinator-resume','unit_state':'systemctl:amnezia-rollback-coordinator.service'}.get(key,path)
 if operation=='metadata' and key!='retained':raise RuntimeError('metadata source not allowlisted')
 try:result=snapshot(path,mode,limit,logical,root,label,kind='guest-exec-outcome' if key in ('rollback_stdout','resume_stdout','unit_state') else 'file',metadata=operation=='metadata',allow_empty=operation=='diagnostic-read')
 except FileNotFoundError:emit({'not_ready':'required-file-absent'})
 except Transition:emit({'not_ready':'file-transition'})
 else:emit(result)
elif operation=='absence':
 if key not in ('journal','unit'):raise RuntimeError('absence path not allowlisted')
 path,_,_=source(key,root);d=directory(str(pathlib.PurePosixPath(path).parent))
 try:
  try:os.stat(pathlib.PurePosixPath(path).name,dir_fd=d,follow_symlinks=False)
  except FileNotFoundError:exists=False
  else:exists=True
 finally:os.close(d)
 evidence=root/('outcome-'+label);private(evidence,json.dumps({'exists':exists},separators=(',',':')).encode())
 emit(snapshot(str(evidence),0o600,4096,path+'.absence',root,label,'guest-lstat-outcome',path))
else:raise RuntimeError('operation not allowlisted')
'''

UNIT_PROGRAM=IO_COMMON+r'''
import subprocess
run,case,nonce=sys.argv[1:];root=context(run,case,nonce)
def command(args):
 import selectors,time,signal
 p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);selector=selectors.DefaultSelector();buffers={'stdout':bytearray(),'stderr':bytearray()};deadline=time.monotonic()+10
 try:
  for label,pipe in [('stdout',p.stdout),('stderr',p.stderr)]:os.set_blocking(pipe.fileno(),False);selector.register(pipe,selectors.EVENT_READ,label)
  while selector.get_map():
   if time.monotonic()>=deadline:raise RuntimeError('unit command deadline')
   for key,_ in selector.select(min(.1,max(0,deadline-time.monotonic()))):
    data=os.read(key.fileobj.fileno(),65536)
    if not data:selector.unregister(key.fileobj);continue
    if sum(map(len,buffers.values()))+len(data)>262144:raise RuntimeError('unit output bound')
    buffers[key.data].extend(data)
  p.wait(timeout=max(.001,deadline-time.monotonic()))
  return{'argv':args,'exit_code':p.returncode,'stdout':buffers['stdout'].decode(errors='replace'),'stderr':buffers['stderr'].decode(errors='replace')}
 finally:
  selector.close()
  if p.poll() is None:
   try:os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError:pass
  p.wait();p.stdout.close();p.stderr.close()
name='amnezia-rollback-coordinator.service'
value={'unit':name,'show':command(['/usr/bin/systemctl','show',name,'-pMainPID','-pExecMainPID','-pExecMainCode','-pExecMainStatus','-pActiveState','-pSubState']),
 'is_enabled':command(['/usr/bin/systemctl','is-enabled',name])}
value['enabled']=value['is_enabled']['stdout'].strip()
path=root/'unit-state.json'
if path.exists():
 s=path.lstat()
 if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600:raise RuntimeError('unit output identity')
 path.unlink()
private(path,json.dumps(value,separators=(',',':')).encode());emit({'captured':True})
'''

def process_program():
    # No inherited RLIMIT_FSIZE: the real CLI must copy its retained executable.
    # Bound only observer-owned stdout/stderr, never unrelated child files.
    return IO_COMMON+r'''
import selectors,signal,subprocess
run,case,nonce=sys.argv[4:];root=context(run,case,nonce);argv=json.loads(sys.argv[1]);expected=sys.argv[2];output=pathlib.Path(sys.argv[3]);limit=1048576
allowed=[['/usr/local/bin/amnezia-cli','--socket','/run/amnezia/amneziad.sock','--json','update-rollback'],['/var/lib/amnezia/rollback-coordinator/amnezia-cli','--rollback-coordinator','resume']]
if argv not in allowed:raise RuntimeError('fixed official/retained argv')
verb='rollback' if argv==allowed[0] else 'resume'
if output!=root/('output-'+verb):raise RuntimeError('process output escaped collector')
parent=directory(str(root));fd=None;p=None;selector=selectors.DefaultSelector();identity=None;count=0;digest=hashlib.sha256();capture_reason=None
try:
 fd=os.open(output.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent);created=os.fstat(fd)
 if not stat.S_ISREG(created.st_mode) or created.st_uid!=0 or created.st_gid!=0 or created.st_nlink!=1 or stat.S_IMODE(created.st_mode)!=0o600:raise RuntimeError('process output identity')
 invoked_at=__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
 p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 proc=pathlib.Path('/proc')/str(p.pid);deadline=time.monotonic()+60;identity_deadline=min(deadline,time.monotonic()+5)
 def observe():
  raw=proc.joinpath('stat').read_text();fields=raw[raw.rfind(')')+2:].split();exe=proc.joinpath('exe').resolve(strict=True);cmd=proc.joinpath('cmdline').read_bytes();args=[x.decode() for x in cmd.rstrip(b'\0').split(b'\0')]
  uids=[int(x) for x in next(line for line in proc.joinpath('status').read_text().splitlines() if line.startswith('Uid:')).split()[1:]]
  if str(exe)!=argv[0] or args!=argv:return None
  if uids!=[0,0,0,0] or hashlib.sha256(proc.joinpath('exe').read_bytes()).hexdigest()!=expected:raise RuntimeError('CLI root/hash identity')
  return {'pid':p.pid,'start_ticks':int(fields[19]),'exe':str(exe),'exe_sha256':expected,'argv':args,'cmdline_sha256':hashlib.sha256(cmd).hexdigest(),'uid_slots':uids,'invoked_at':invoked_at,'observed_at':__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')}
 while time.monotonic()<identity_deadline:
  try:identity=observe()
  except (FileNotFoundError,ProcessLookupError):break
  if identity is not None:break
  time.sleep(.001)
 if identity is None:raise RuntimeError('CLI identity not observed')
 try:
  again=observe()
  if again is not None and any(again[key]!=identity[key] for key in ('pid','start_ticks','exe','exe_sha256','argv','cmdline_sha256','uid_slots')):raise RuntimeError('CLI process changed')
 except (FileNotFoundError,ProcessLookupError):pass
 for stream in (p.stdout,p.stderr):os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ)
 while selector.get_map():
  if time.monotonic()>=deadline:capture_reason='deadline';break
  for key,_ in selector.select(min(.1,max(0,deadline-time.monotonic()))):
   data=os.read(key.fileobj.fileno(),65536)
   if not data:selector.unregister(key.fileobj);continue
   retained=data[:max(0,limit-count)]
   if retained:
    position=0
    while position<len(retained):
     written=os.write(fd,retained[position:])
     if written<=0:raise RuntimeError('process output short write')
     position+=written
    digest.update(retained);count+=len(retained)
   if len(retained)!=len(data):capture_reason='output-limit';break
  if capture_reason:break
 if capture_reason is None:
  try:p.wait(timeout=max(.001,deadline-time.monotonic()))
  except subprocess.TimeoutExpired:capture_reason='deadline'
 if capture_reason is not None:
  try:os.killpg(p.pid,signal.SIGKILL)
  except ProcessLookupError:pass
 p.wait();os.fsync(fd);after=os.fstat(fd);named=os.stat(output.name,dir_fd=parent,follow_symlinks=False)
 current_parent=os.stat(str(root),follow_symlinks=False);held_parent=os.fstat(parent)
 if (current_parent.st_dev,current_parent.st_ino,current_parent.st_uid,current_parent.st_gid,current_parent.st_mode)!=(held_parent.st_dev,held_parent.st_ino,held_parent.st_uid,held_parent.st_gid,held_parent.st_mode):raise RuntimeError('process output parent changed')
 if (after.st_dev,after.st_ino,after.st_uid,after.st_gid,after.st_nlink,stat.S_IMODE(after.st_mode),after.st_size)!=(created.st_dev,created.st_ino,0,0,1,0o600,count) or fdidentity(after)!=fdidentity(named):raise RuntimeError('process output changed')
 identity['exit_code']=p.returncode
 print(json.dumps({'process':identity,'capture':{'reason':capture_reason,'truncated':capture_reason=='output-limit','size':count,'limit':limit,'sha256':digest.hexdigest()}},separators=(',',':')))
finally:
 selector.close()
 if p is not None:
  if p.poll() is None:
   try:os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError:pass
  p.wait();p.stdout.close();p.stderr.close()
 if fd is not None:os.close(fd)
 os.close(parent)
'''


def observation_program():
    marker="print(json.dumps({'version':version,"
    if IDENTITY.count(marker)!=1:raise CoordinatedCollectionError('native identity observer source changed')
    return IDENTITY[:IDENTITY.index(marker)]+r'''
import os,selectors,signal,time,base64
args=['/usr/local/bin/amnezia-cli','--socket','/run/amnezia/amneziad.sock','--json','doctor']
child=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
selector=selectors.DefaultSelector();buffers={'stdout':bytearray(),'stderr':bytearray()};counts={'stdout':0,'stderr':0};deadline=time.monotonic()+30
try:
 for name,stream in [('stdout',child.stdout),('stderr',child.stderr)]:os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
 while selector.get_map():
  if time.monotonic()>=deadline:raise RuntimeError('bounded held doctor timeout')
  for key,_ in selector.select(min(.1,max(.001,deadline-time.monotonic()))):
   chunk=os.read(key.fileobj.fileno(),8192)
   if not chunk:selector.unregister(key.fileobj);continue
   name=key.data;counts[name]+=len(chunk);retained=sum(len(x) for x in buffers.values());buffers[name].extend(chunk[:max(0,524288-retained)])
   if sum(counts.values())>524288:raise RuntimeError('bounded held doctor output exceeded')
 if child.wait(timeout=max(.001,deadline-time.monotonic()))!=0:raise RuntimeError('actual held doctor failed')
 doctor=json.loads(buffers['stdout'])
except BaseException as error:
 print(json.dumps({'kind':'private-doctor-failure','error_type':type(error).__name__,'counts':counts,'stdout_base64':base64.b64encode(buffers['stdout']).decode(),'stderr_base64':base64.b64encode(buffers['stderr']).decode(),'truncated':sum(counts.values())>524288}),flush=True)
 raise
finally:
 selector.close()
 if child.returncode is None:
  try:os.killpg(child.pid,signal.SIGKILL)
  except ProcessLookupError:pass
 child.wait();child.stdout.close();child.stderr.close()
again=proc.joinpath('stat').read_text();after_ticks=int(again[again.rfind(')')+2:].split()[19])
if after_ticks!=ticks or hashlib.sha256(proc.joinpath('exe').read_bytes()).hexdigest()!=daemon_sha:raise RuntimeError('held daemon changed during doctor')
print(json.dumps({'pair':{'amneziad':{'sha256':daemon_sha,'size':int(daemon_size)},'amnezia-cli':{'sha256':cli_sha,'size':int(cli_size)}},'version':version,'daemon_pid':pid,'start_ticks':str(ticks),'doctor':doctor},separators=(',',':')))
'''



CANONICAL_MARKER_REARM=r'''import os,stat,json,hashlib,sys,re
run,profile,expected_boot=sys.argv[1:]
if not re.fullmatch('[A-Za-z0-9_.-]{1,160}',run) or profile!='linux-headless-x64':raise RuntimeError('canonical marker binding')
boot=open('/proc/sys/kernel/random/boot_id').read().strip()
if boot!=expected_boot:raise RuntimeError('canonical marker boot changed')
root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:parent=os.open('tmp',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
finally:os.close(root)
name='amnezia-release-lab-marker';data=('amnezia-release-lab:'+run+':'+profile).encode();created=False
try:
 p=os.fstat(parent)
 if not stat.S_ISDIR(p.st_mode) or p.st_uid!=0 or p.st_gid!=0 or stat.S_IMODE(p.st_mode)!=0o1777:raise RuntimeError('canonical tmp identity')
 try:fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent);created=True
 except FileExistsError:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600:raise RuntimeError('canonical marker identity')
  if created:
   if os.write(fd,data)!=len(data):raise RuntimeError('canonical marker short write')
   os.fsync(fd);os.lseek(fd,0,os.SEEK_SET)
  before_read=os.fstat(fd)
  if before_read.st_size!=len(data) or os.read(fd,len(data)+1)!=data:raise RuntimeError('canonical marker content')
  after=os.fstat(fd);named=os.stat(name,dir_fd=parent,follow_symlinks=False)
  fields=lambda value:(value.st_dev,value.st_ino,value.st_uid,value.st_gid,value.st_nlink,stat.S_IMODE(value.st_mode),value.st_size,value.st_mtime_ns,value.st_ctime_ns)
  if fields(before_read)!=fields(after) or fields(after)!=fields(named):raise RuntimeError('canonical marker path changed')
  os.fsync(parent)
  fresh=os.open('/tmp',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   now=os.fstat(fresh)
   if (now.st_dev,now.st_ino,now.st_uid,now.st_gid,stat.S_IMODE(now.st_mode))!=(p.st_dev,p.st_ino,0,0,0o1777):raise RuntimeError('canonical tmp changed')
  finally:os.close(fresh)
  if open('/proc/sys/kernel/random/boot_id').read().strip()!=boot:raise RuntimeError('canonical marker boot changed')
  print(json.dumps({'path':'/tmp/'+name,'sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'uid':after.st_uid,'gid':after.st_gid,'mode':stat.S_IMODE(after.st_mode),'nlink':after.st_nlink,'dev':after.st_dev,'ino':after.st_ino,'boot_id':boot,'run_id':run,'profile_id':profile,'created':created},separators=(',',':')))
 finally:os.close(fd)
finally:os.close(parent)
'''

class CoordinatedRebootCollector(OwnedRebootCollector):
    def reboot_and_collect(self,boot_id_before,expected,timeout=300):
        # Rearm only after genuine owned new boot and persistent nonce proof.
        receipt=super().reboot_and_collect(boot_id_before,expected,timeout=timeout)
        after=receipt.get('boot_id_after')
        if not isinstance(after,str) or not after or after==boot_id_before:raise CoordinatedCollectionError('genuine new boot required before canonical marker rearm')
        self._check()
        response=self.native._exec('/usr/bin/python3',['-c',CANONICAL_MARKER_REARM,self.plan.run_id,'linux-headless-x64',after],20)
        self._check()
        if type(response.get('exitcode')) is not int or response['exitcode']!=0:raise CoordinatedCollectionError('canonical marker rearm guest command failed')
        observed=json.loads(response['stdout'])
        if not isinstance(observed,dict):raise CoordinatedCollectionError('canonical marker rearm evidence shape')
        data=('amnezia-release-lab:'+self.plan.run_id+':linux-headless-x64').encode()
        if observed.get('boot_id')!=after or observed.get('run_id')!=self.plan.run_id or observed.get('profile_id')!='linux-headless-x64' or observed.get('path')!='/tmp/amnezia-release-lab-marker' or observed.get('sha256')!=hashlib.sha256(data).hexdigest() or observed.get('size')!=len(data) or any(type(observed.get(key)) is not int or observed[key]!=value for key,value in [('uid',0),('gid',0),('mode',0o600),('nlink',1)]):raise CoordinatedCollectionError('canonical marker rearm readback differs')
        return {**receipt,'raw_sources':{**receipt['raw_sources'],'canonical_marker_rearm':observed}}


    def stage_persistent_marker(self):
        self._check()
        path=f'/var/lib/amnezia/release-lab-native-{self.plan.attempt_nonce}.json'
        code=IO_COMMON+r'''
path,nonce=sys.argv[1:];data=(json.dumps({'attempt_nonce':nonce},separators=(',',':'))+'\n').encode()
try:f=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
except FileNotFoundError:private(path,data)
else:
 try:
  s=os.fstat(f)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size!=len(data) or os.read(f,len(data)+1)!=data:raise RuntimeError('existing reboot marker differs')
 finally:os.close(f)
parent=directory(str(pathlib.PurePosixPath(path).parent))
try:os.fsync(parent)
finally:os.close(parent)
emit({'path':path,'sha256':hashlib.sha256(data).hexdigest(),'size':len(data)})
'''
        observed=self._json(code,[path,self.plan.attempt_nonce],20)
        raw=self.native.raw_file(path)
        if (raw.get('sha256'),raw.get('size'))!=(observed.get('sha256'),observed.get('size')):raise CoordinatedCollectionError('reboot marker readback changed')
        return raw


class CoordinatedRollbackCollector:
    def __init__(self,qga,plan,native,official_reboot_collector,owned,archive_root):
        plan.validate()
        if os.name!='posix':raise CoordinatedCollectionError('owned Linux collector requires POSIX descriptors')
        if not isinstance(native,HeadlessNativeQgaAdapter) or native.qga is not qga or native.plan!=plan:raise CoordinatedCollectionError('owned native adapter binding required')
        self.qga,self.plan,self.native,self.reboot,self.owned=qga,plan,native,official_reboot_collector,owned
        self.archive=Path(archive_root).absolute()/('coordinated-'+plan.attempt_nonce)
        parent=_directory_fd(self.archive.parent)
        try:
            if os.fstat(parent).st_uid!=os.getuid():raise CoordinatedCollectionError('private archive parent ownership')
            os.mkdir(self.archive.name,0o700,dir_fd=parent)
            self._archive_fd=os.open(self.archive.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        finally:os.close(parent)
        self._archive_identity()
        self._lock=threading.Lock();self._sequence=0;self._initialized=False

    def _archive_identity(self):
        held=os.fstat(self._archive_fd)
        if held.st_uid!=os.getuid() or stat.S_IMODE(held.st_mode)!=0o700:raise CoordinatedCollectionError('private archive identity')
        current=_directory_fd(self.archive)
        try:
            actual=os.fstat(current)
            if (actual.st_dev,actual.st_ino)!=(held.st_dev,held.st_ino):raise CoordinatedCollectionError('private archive ancestor changed')
        finally:os.close(current)

    def _archive_file(self,name):
        self._archive_identity()
        descriptor=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self._archive_fd)
        try:os.fchmod(descriptor,0o600)
        except BaseException:os.close(descriptor);raise
        return descriptor

    def close(self):
        descriptor=getattr(self,'_archive_fd',None)
        if descriptor is not None:os.close(descriptor);self._archive_fd=None

    def __del__(self):
        try:self.close()
        except (OSError,AttributeError):pass

    def _check(self):
        self.native._check()
        if self.owned()!=self.plan.outer_binding:raise CoordinatedCollectionError('outer ownership changed')

    def _name(self,label):
        if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,159}',label):raise CoordinatedCollectionError('archive label invalid')
        with self._lock:self._sequence+=1;return f'{label}-{self._sequence:06d}'

    def archive_original(self,name,value):
        target=self.archive/(self._name(name)+'.json');digest=hashlib.sha256();size=0
        fd=self._archive_file(target.name)
        with os.fdopen(fd,'wb') as stream:
            for chunk in json.JSONEncoder(separators=(',',':'),ensure_ascii=True).iterencode(value):
                data=chunk.encode();size+=len(data)
                if size>ARCHIVE_LIMIT:raise CoordinatedCollectionError('coordinated original exceeds explicit archive bound')
                stream.write(data);digest.update(data)
            stream.flush();os.fsync(stream.fileno())
        self._archive_identity()
        return {'path':str(target),'size':size,'sha256':digest.hexdigest()}

    def _exec(self,code,args,timeout=60):
        self._check()
        try:result=self.native._exec('/usr/bin/python3',['-c',code,*args],timeout)
        except BaseException as error:
            failure=error;seen=set();capture=None
            while failure is not None and id(failure) not in seen and len(seen)<16:
                seen.add(id(failure));capture=getattr(failure,'private_failure_capture',None)
                if capture is not None:break
                failure=failure.__cause__ or failure.__context__
            if capture is not None:
                try:
                    value=capture();value['body_base64']=base64.b64encode(value.pop('body')).decode();self.archive_original('failed-qga',value)
                except BaseException as secondary:error.add_note('Private coordinated capture unavailable: '+type(secondary).__name__)
            raise
        self.archive_original('qga-response',result);self._check()
        return json.loads(result['stdout'])

    def _args(self):return [self.plan.run_id,self.plan.case_id,self.plan.attempt_nonce]

    def _initialize(self,timeout=60):
        if not self._initialized:
            self._exec(IO_PROGRAM,['init','profiles',self._name('init'),*self._args()],min(60,timeout));self._initialized=True

    def _pull(self,record,*,deadline=None,allow_empty=False):
        size=record.get('size');path=record.get('physical_path')
        root='/var/lib/amnezia/.release-lab-coordinated-'+self.plan.attempt_nonce+'/capture-'
        if type(size) is not int or not (0 if allow_empty else 1)<=size<=64*1024*1024 or not isinstance(path,str) or not path.startswith(root) or '/' in path[len(root):]:raise CoordinatedCollectionError('capture stream binding')
        self._check();opened=self.qga.request('guest-file-open',{'path':path,'mode':'r'});handle=opened.get('return')
        if type(handle) is not int:raise CoordinatedCollectionError('capture stream handle')
        data=bytearray();target=self.archive/(self._name('raw-binary')+'.bin');digest=hashlib.sha256()
        primary=None;deadline=min(time.monotonic()+120,deadline) if deadline is not None else time.monotonic()+120
        try:
            fd=self._archive_file(target.name)
            with os.fdopen(fd,'wb') as stream:
                while True:
                    if time.monotonic()>=deadline:raise CoordinatedCollectionError('bounded capture stream deadline exceeded')
                    self._check();reply=self.qga.request('guest-file-read',{'handle':handle,'count':min(65536,size-len(data)+1)})['return']
                    if time.monotonic()>=deadline:raise CoordinatedCollectionError('bounded capture stream deadline exceeded')
                    chunk=base64.b64decode(reply.get('buf-b64',''),validate=True)
                    if type(reply.get('count')) is not int or reply['count']!=len(chunk) or len(chunk)>65536 or len(data)+len(chunk)>size:raise CoordinatedCollectionError('bounded capture stream changed')
                    if reply.get('eof') is not True and len(chunk)<min(65536,size-len(data)):raise CoordinatedCollectionError('capture stream returned unexpected short regular read')
                    data.extend(chunk);stream.write(chunk);digest.update(chunk)
                    if reply.get('eof') is True:break
                    if not chunk:raise CoordinatedCollectionError('capture stream made no progress')
                stream.flush();os.fsync(stream.fileno())
        except BaseException as error:primary=error;raise
        finally:
            try:self.qga.request('guest-file-close',{'handle':handle})
            except BaseException as close_error:
                if primary is None:raise
                primary.add_note('Capture handle close failed: '+type(close_error).__name__)
        self._check()
        self._archive_identity()
        if len(data)!=size or digest.hexdigest()!=record.get('sha256'):raise CoordinatedCollectionError('capture stream hash/size')
        return {**record,'bytes_b64':base64.b64encode(data).decode()}

    def _read(self,key,*,absence=False,allow_missing=False,timeout=120,diagnostic_empty=False):
        if type(timeout) not in (int,float) or not 0<timeout<=120:raise CoordinatedCollectionError('bounded source read required')
        deadline=time.monotonic()+timeout
        def remaining():
            value=deadline-time.monotonic()
            if value<=0:raise CoordinatedCollectionError('coordinated source read deadline exceeded')
            return value
        self._initialize(remaining());operation='diagnostic-read' if diagnostic_empty else 'absence' if absence else 'metadata' if key=='retained' else 'read'
        try:record=self._exec(IO_PROGRAM,[operation,key,self._name('snapshot'),*self._args()],remaining())
        except BaseException as primary:
            try:
                diagnostic=self._exec(IO_PROGRAM,['diagnostic-stat',key,self._name('failed-source-stat'),*self._args()],min(20,remaining()))
                self.archive_original('failed-source-stat',diagnostic)
            except BaseException as secondary:primary.add_note('Private source metadata unavailable: '+type(secondary).__name__)
            raise
        remaining()
        if set(record)=={'not_ready'}:
            if allow_missing:return record
            raise CoordinatedCollectionError('required coordinated source not stable/present')
        result=record if key=='retained' else self._pull(record,deadline=deadline,allow_empty=diagnostic_empty)
        if diagnostic_empty:result={**result,'diagnostic_only':True}
        self.archive_original('raw-envelope',result);remaining();return result

    @staticmethod
    def _object(record):return json.loads(base64.b64decode(record['bytes_b64'],validate=True))

    def _unit_state(self):
        self._exec(UNIT_PROGRAM,self._args(),30);return self._read('unit_state')

    def raw_absence(self,path):
        if path not in (UPDATE_JOURNAL,UNIT):raise CoordinatedCollectionError('absence source not allowlisted')
        return self._read('journal' if path==UPDATE_JOURNAL else 'unit',absence=True)

    def stage_disabled_owned_profile(self):
        self._initialize()
        profile={'id':'release-lab-'+self.plan.attempt_nonce,'name':'release-lab native updater','protocol':'wireguard','configPath':'/etc/amnezia/profiles/release-lab.conf',
                 'forwardRoutes':list(self.plan.fixture.forward_routes),'autoUpdate':False,'updateManifestUrl':self.plan.fixture.endpoint.rstrip('/')+self.plan.fixture.manifest_path,'updatePublicKeyPath':FIXED_KEY}
        response=self.native._exec('/usr/bin/python3',['-c',STAGE,FIXED_STORE,FIXED_KEY,json.dumps(profile,separators=(',',':')),self.plan.candidate.key_sha256])
        self.archive_original('disabled-profile-stage',response);return self._read('profiles')

    def _run(self,verb,timeout):
        if verb not in ('rollback','resume') or type(timeout) is not int or not 0<timeout<=600:raise CoordinatedCollectionError('fixed process verb/deadline required')
        self._initialize()
        argv=['/usr/local/bin/amnezia-cli','--socket',FIXED_SOCKET,'--json','update-rollback'] if verb=='rollback' else [RETAINED,'--rollback-coordinator','resume']
        output='/var/lib/amnezia/.release-lab-coordinated-'+self.plan.attempt_nonce+'/output-'+verb
        try:value=self._exec(process_program(),[json.dumps(argv),self.plan.candidate.cli_sha256,output,*self._args()],timeout)
        except BaseException as error:
            try:self._read(verb+'_stdout',diagnostic_empty=True)
            except BaseException as secondary:error.add_note('Private process output unavailable: '+type(secondary).__name__)
            raise
        self.archive_original(verb+'-process',value)
        try:raw=self._read(verb+'_stdout')
        except BaseException as primary:
            try:self._read(verb+'_stdout',diagnostic_empty=True)
            except BaseException as secondary:primary.add_note('Private diagnostic process output unavailable: '+type(secondary).__name__)
            raise
        process=value.get('process')
        if not isinstance(process,dict) or process.get('argv')!=argv or process.get('exe_sha256')!=self.plan.candidate.cli_sha256 or process.get('uid_slots')!=[0,0,0,0] or type(process.get('exit_code')) is not int or process['exit_code']!=0:raise CoordinatedCollectionError('actual official/retained process failed')
        capture=value.get('capture')
        if not isinstance(capture,dict) or capture.get('reason') is not None or capture.get('truncated') is not False or type(capture.get('size')) is not int or not 0<capture['size']<=1048576 or capture.get('limit')!=1048576 or (capture['size'],capture.get('sha256'))!=(raw.get('size'),raw.get('sha256')):raise CoordinatedCollectionError('actual process output capture failed')
        return process,raw

    def read_snapshot(self,phase):
        if phase not in ('held','held-reboot','resumed'):raise CoordinatedCollectionError('snapshot phase not allowlisted')
        prefix={'held':'held','held-reboot':'held_reboot','resumed':'resumed'}[phase]
        result={prefix+'_record':self._read('record'),prefix+'_profiles' if phase!='held' else 'paused_profiles':self._read('profiles')}
        if phase=='held':result.update(retained_executable=self._read('retained'),retained_unit=self._read('unit'),held_state=self._read('state'))
        if phase!='resumed':result[prefix+'_journal_absence']=self._read('journal',absence=True)
        else:result.update(retired_unit=self._read('unit'),retired_unit_state=self._unit_state())
        return result

    def _wait_record(self,phase,timeout):
        if type(timeout) is not int or not 0<timeout<=600:raise CoordinatedCollectionError('bounded coordinated wait required')
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            record=self._read('record',allow_missing=True,timeout=min(120,deadline-time.monotonic()))
            if time.monotonic()>=deadline:break
            if 'not_ready' in record:
                time.sleep(.2);continue
            if self._object(record).get('phase')==phase:return record
            time.sleep(.2)
        raise CoordinatedCollectionError('coordinator phase evidence deadline exceeded')

    def trigger_and_wait_held(self,timeout=300):
        if type(timeout) is not int or not 0<timeout<=600:raise CoordinatedCollectionError('bounded coordinated wait required')
        # QGA is a single channel: never overlap host guest-exec calls to chase
        # an optional fast process. Authority is the genuine durable product
        # record, not a synthetic PID or a second manually invoked run.
        original=self._read('profiles')
        process,stdout=self._run('rollback',90);self._wait_record('held',timeout)
        raw=self.read_snapshot('held');raw.update(original_profiles=original,rollback_stdout=stdout,coordinator_unit_state=self._unit_state())
        return {'rollback_process':process,'coordinator_process':None,'raw_sources':raw}

    def reboot_held(self,boot_before,held_snapshot,timeout=300):
        observed=self.reboot.reboot_and_collect(boot_before,self.plan.baseline,timeout=timeout)
        self.archive_original('held-reboot-original',observed)
        sources=self.read_snapshot('held-reboot');held=held_snapshot.get('raw_sources',held_snapshot)
        release=self.plan.baseline
        after=self._exec(observation_program(),[release.version,release.amneziad_sha256,str(release.amneziad_size),release.cli_sha256,str(release.cli_size)],90)
        return {'held_reboot':{'boot_id_before':observed['boot_id_before'],'boot_id_after':observed['boot_id_after'],
                    'prior_held_record_sha256':held['held_record']['sha256'],'after':after,'native_observation':observed},'raw_sources':sources}

    def resume_and_collect(self,held_snapshot,timeout=120):
        process,stdout=self._run('resume',timeout);self._wait_record('resumed',timeout)
        sources=self.read_snapshot('resumed');sources['resume_stdout']=stdout
        return {'resume_process':process,'raw_sources':sources}
