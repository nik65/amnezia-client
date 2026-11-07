"""Diagnostic-only LLDB controller for an already owned nested Android guest."""
from __future__ import annotations

import base64, hashlib, json, re, time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Mapping

try:
 from .nested_cuttlefish_lldb import BUNDLE_ARCHIVE_NAME,BUNDLE_ARCHIVE_SHA256,BUNDLE_ARCHIVE_SIZE,BUNDLE_MANIFEST_SHA256,BUNDLE_MEMBERS,LldbAttachPlan, build_diagnostic_entrypoint, build_sb_driver, parse_sb_output
 from .nested_cuttlefish_runner import AssetSpec, InnerPlan, NestedCuttlefishError, OuterOwnership, validate_boot_receipt
except ImportError:
 from nested_cuttlefish_lldb import BUNDLE_ARCHIVE_NAME,BUNDLE_ARCHIVE_SHA256,BUNDLE_ARCHIVE_SIZE,BUNDLE_MANIFEST_SHA256,BUNDLE_MEMBERS,LldbAttachPlan, build_diagnostic_entrypoint, build_sb_driver, parse_sb_output
 from nested_cuttlefish_runner import AssetSpec, InnerPlan, NestedCuttlefishError, OuterOwnership, validate_boot_receipt

SHA=re.compile(r"[0-9a-f]{64}")

class LldbControllerError(NestedCuttlefishError): pass

EXTRACT=r'''import hashlib,json,os,pathlib,stat,sys,tarfile
archive=pathlib.Path(sys.argv[1]);dest=pathlib.Path(sys.argv[2]);expected=sys.argv[3]
if dest.exists() or dest.is_symlink():raise SystemExit('diagnostic root exists')
with tarfile.open(archive,'r:*') as tf:
 members=tf.getmembers();names=[m.name for m in members]
 if len(names)!=len(set(names)) or 'manifest.json' not in names:raise SystemExit('bundle manifest missing')
 manifest=tf.extractfile('manifest.json').read()
 if hashlib.sha256(manifest).hexdigest()!=expected:raise SystemExit('bundle manifest hash mismatch')
 rows=json.loads(manifest);allowed={r['path']:r for r in rows}
 if any('__pycache__' in p.split('/') or p.endswith(('.pyc','.pyo')) for p in allowed):raise SystemExit('generated Python cache in bundle')
 if set(names)!={'manifest.json',*allowed}:raise SystemExit('bundle members differ from manifest')
 dest.mkdir(mode=0o700,parents=True)
 for m in members:
  if m.name=='manifest.json':continue
  row=allowed[m.name];target=dest/m.name
  if dest not in target.parents:raise SystemExit('bundle traversal')
  target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
  if m.isfile():
   data=tf.extractfile(m).read()
   if len(data)!=row.get('size') or hashlib.sha256(data).hexdigest()!=row.get('sha256'):raise SystemExit('bundle member mismatch')
   fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700 if m.name in ('bin/lldb','lib/clang/17/lib/linux/aarch64/lldb-server') else 0o600)
   with os.fdopen(fd,'wb') as f:f.write(data)
  elif m.issym():
   resolved=(target.parent/m.linkname).resolve(strict=False)
   if row.get('target')!=m.linkname or m.linkname.startswith('/') or dest not in resolved.parents:raise SystemExit('unsafe bundle symlink')
   os.symlink(m.linkname,target)
  else:raise SystemExit('unsupported bundle member')
print(json.dumps({'root':str(dest),'manifest_sha256':expected,'member_count':len(rows),'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'archive_size':archive.stat().st_size},sort_keys=True,separators=(',',':')))'''

WRITE_DRIVER=r'''import hashlib,json,os,pathlib,sys
p=pathlib.Path(sys.argv[1]);data=sys.argv[2].encode()
p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as f:f.write(data)
print(json.dumps({'path':str(p),'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}))'''

RUN_DRIVER=r'''import base64,hashlib,json,os,pathlib,resource,subprocess,sys
argv=json.loads(sys.argv[1]);env=json.loads(sys.argv[2]);limit=int(sys.argv[3]);timeout=float(sys.argv[4]);path=pathlib.Path(sys.argv[5]);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
def bound():resource.setrlimit(resource.RLIMIT_FSIZE,(limit,limit))
try:r=subprocess.run(argv,stdout=fd,stderr=subprocess.STDOUT,env={**os.environ,**env},timeout=timeout,preexec_fn=bound)
except subprocess.TimeoutExpired as e:
 r=None
finally:os.close(fd)
data=path.read_bytes()
if len(data)>limit:raise SystemExit('LLDB producer output exceeded bound')
print(json.dumps({'exit_code':124 if r is None else r.returncode,'timed_out':r is None,'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'bytes_b64':base64.b64encode(data).decode()}))'''

@dataclass(frozen=True)
class LldbDiagnosticBundle:
 asset: AssetSpec
 manifest_sha256: str
 manifest_members: int
 def validate(self)->None:
  self.asset.validate()
  if (self.asset.name!=BUNDLE_ARCHIVE_NAME or self.asset.size!=BUNDLE_ARCHIVE_SIZE or self.asset.sha256!=BUNDLE_ARCHIVE_SHA256
      or self.manifest_sha256!=BUNDLE_MANIFEST_SHA256 or self.manifest_members!=BUNDLE_MEMBERS):raise LldbControllerError('LLDB bundle contract')

class NestedAndroidLldbController:
 def __init__(self,bridge:Any,plan:InnerPlan,boot:Mapping[str,Any],bundle:LldbDiagnosticBundle,snapshot:Callable[[],OuterOwnership],archive:Callable[[Mapping[str,Any]],Mapping[str,Any]],native_collect:Callable[[int,int|None,str,float],Mapping[str,Any]]):
  plan.validate();validate_boot_receipt(plan,boot);bundle.validate()
  if bridge.plan!=plan or not callable(archive) or not callable(native_collect):raise LldbControllerError('diagnostic binding')
  self.bridge,self.qga,self.plan,self.boot,self.bundle,self.snapshot,self.archive,self.native_collect=bridge,bridge.qga,plan,dict(boot),bundle,snapshot,archive,native_collect
  self.adb=f'{plan.root}/runtime/host/bin/adb';self.serial=boot['network']['adb_connection']['endpoint'];self.server_pid=None;self.server_ticks=None;self.marker=None;self.marker_sha=None;self.forward=None;self.tracee=None;self.rooted=False;self.initial=None
  self.diagnostic_deadline=None;self.capability_rows=[];self._record_capability=False
 def _check(self):
  if self.snapshot()!=self.plan.ownership:raise LldbControllerError('outer ownership changed')
 def _outer_result(self,label,path,args,timeout):
  if self.diagnostic_deadline is not None:
   remaining=self.diagnostic_deadline-time.monotonic()
   if remaining<=0:raise LldbControllerError('diagnostic deadline expired')
   timeout=min(timeout,max(.1,remaining))
  argv=[path,*args];before=self.snapshot()
  if before!=self.plan.ownership:raise LldbControllerError('outer ownership changed')
  started=time.monotonic();empty=self._stream_receipt('');row={'label':label,'argv':argv,'pid':None,'rc':None,'timed_out':False,'classification':'incomplete','timeout_seconds':timeout,'stdout':dict(empty),'stderr':dict(empty),'ownership_before':asdict(before),'ownership_after':None,'error':None}
  try:
   launched=self.qga.guest_exec(path,args);pid=launched.get('pid') if isinstance(launched,Mapping) else None
   if isinstance(pid,bool) or not isinstance(pid,int) or pid<=0:raise LldbControllerError('QGA guest PID malformed')
   deadline=started+timeout;payload=None
   while time.monotonic()<deadline:
    status=self.qga.request('guest-exec-status',{'pid':pid});candidate=status.get('return') if isinstance(status,Mapping) else None
    if not isinstance(candidate,Mapping):raise LldbControllerError('QGA status malformed')
    if candidate.get('exited') is True:payload=candidate;break
    if candidate.get('exited') not in (False,None):raise LldbControllerError('QGA exited flag malformed')
    time.sleep(min(.05,max(0,deadline-time.monotonic())))
   if payload is None:
    row.update(pid=pid,timed_out=True,classification='timeout');return row
   rc=payload.get('exitcode')
   if isinstance(rc,bool) or not isinstance(rc,int):raise LldbControllerError('QGA exit code malformed')
   row.update(pid=pid,rc=rc,classification='success' if rc==0 else 'nonzero')
   row['stdout']=self._stream_receipt(payload.get('out-data',''));row['stderr']=self._stream_receipt(payload.get('err-data',''))
   if row['stdout']['malformed'] or row['stderr']['malformed']:raise LldbControllerError('QGA output base64 malformed')
   if row['stdout']['overflow'] or row['stderr']['overflow']:raise LldbControllerError('QGA capability output oversized')
   return row
  except BaseException as exc:
   row.update(classification='malformed',error={'type':type(exc).__name__,'sha256':hashlib.sha256(str(exc).encode()).hexdigest()});raise
  finally:
   try:
    after=self.snapshot();row['ownership_after']=asdict(after)
    if after!=self.plan.ownership:raise LldbControllerError('outer ownership changed')
   finally:
    if self._record_capability:self.capability_rows.append(row)
 def _stream_receipt(self,encoded):
  encoded_bytes=encoded.encode('utf-8','replace') if isinstance(encoded,str) else repr(encoded).encode()[:4096];encoded_prefix=encoded_bytes[:4096]
  base={'observed_total_size':None,'prefix_size':0,'prefix_sha256':hashlib.sha256(b'').hexdigest(),'prefix_b64':'','overflow':False,'malformed':False,'encoded_size':len(encoded_bytes),'encoded_prefix_sha256':hashlib.sha256(encoded_prefix).hexdigest(),'encoded_prefix_b64':base64.b64encode(encoded_prefix).decode()}
  if not isinstance(encoded,str):base['malformed']=True;return base
  try:data=base64.b64decode(encoded,validate=True) if encoded else b''
  except Exception:base['malformed']=True;return base
  prefix=data[:4096];base.update(observed_total_size=len(data),prefix_size=len(prefix),prefix_sha256=hashlib.sha256(prefix).hexdigest(),prefix_b64=base64.b64encode(prefix).decode(),overflow=len(data)>65536);return base
 def _outer(self,path,args,timeout):
  row=self._outer_result('outer-command',path,args,timeout)
  if row.get('timed_out') is True:raise LldbControllerError('owned outer command timed out')
  if row.get('rc')!=0:raise LldbControllerError('owned outer command failed')
  return {'pid':row['pid'],'exitcode':row['rc'],'stdout':base64.b64decode(row['stdout']['prefix_b64']).decode('utf-8','replace'),'stderr':base64.b64decode(row['stderr']['prefix_b64']).decode('utf-8','replace')}
 def _adb(self,args,timeout=5):return self._outer(self.adb,['-P',self.plan.adb_endpoint.rsplit(':',1)[1],'-s',self.serial,*args],timeout)
 def _shell(self,*args,timeout=5):return str(self._adb(['shell',*args],timeout).get('stdout','')).strip()
 def _capability(self):
  self.capability_rows=[];self._record_capability=True
  try:return self._capability_inner()
  finally:self._record_capability=False
 def _capability_inner(self):
  keys=('ro.build.type','ro.debuggable','ro.secure','ro.build.version.sdk');props={k:self._shell('getprop',k) for k in keys}
  before={'props':props,'uid':self._shell('id','-u'),'domain':self._shell('id','-Z'),'selinux':self._shell('getenforce'),'adbd':self._shell('sh','-c','p=$(pidof adbd); [ -n "$p" ] && printf "%s|" "$p" && cut -d" " -f22 /proc/$p/stat')}
  if props['ro.build.type'] not in ('userdebug','eng') or props['ro.debuggable']!='1' or before['uid']!='2000':return {'supported':False,'before':before,'rows':self.capability_rows}
  self._adb(['root'],8);self._adb(['wait-for-device'],8);after={'props':{k:self._shell('getprop',k) for k in keys},'uid':self._shell('id','-u'),'domain':self._shell('id','-Z'),'selinux':self._shell('getenforce'),'adbd':self._shell('sh','-c','p=$(pidof adbd); [ -n "$p" ] && printf "%s|" "$p" && cut -d" " -f22 /proc/$p/stat')}
  if after['props']!=props or after['uid']!='0' or after['domain']!='u:r:su:s0' or after['selinux']!=before['selinux'] or after['adbd']==before['adbd']:raise LldbControllerError('adb root/rebind proof failed')
  self.rooted=True;self.initial=before
  data=f'amnezia-lldb:{self.plan.ownership.run_id}:{self.plan.ownership.attempt_nonce}:{self.plan.apk.package}'
  self.marker=f'/data/local/tmp/amz-lldb-{self.plan.ownership.attempt_nonce[:12]}.marker';self._adb(['shell','sh','-c','umask 077; test ! -e "$1"; printf %s "$2" > "$1"; chown 0:0 "$1"; chmod 600 "$1"','amz-marker',self.marker,data])
  read=self._shell('cat',self.marker)
  if read!=data:raise LldbControllerError('inner marker readback')
  self.marker_sha=hashlib.sha256(data.encode()).hexdigest()
  return {'supported':True,'before':before,'after':after,'marker':{'path':self.marker,'sha256':self.marker_sha,'size':len(data)},'rows':self.capability_rows}
 def _identity(self):
  raw=self._shell('sh','-c','p=$(pidof "$1"); case "$p" in *" "*|"") exit 41;; esac; uid=$(awk \'/^Uid:/{print $2}\' /proc/$p/status); ticks=$(cut -d" " -f22 /proc/$p/stat); printf "%s|%s|%s" "$p" "$uid" "$ticks"','amz-pid',self.plan.apk.package)
  m=re.fullmatch(r'([1-9]\d*)\|([1-9]\d*)\|([1-9]\d*)',raw)
  if not m:raise LldbControllerError('unique app identity missing')
  return tuple(map(int,m.groups()))
 def _death_correlated(self,native,pid,epoch):
  if not isinstance(native,Mapping) or native.get('expected_pid')!=pid or native.get('launch_epoch')!=epoch:return False
  text=[]
  for row in native.get('sources',[]):
   if isinstance(row,Mapping) and row.get('label') in ('crash','all-since-launch') and isinstance(row.get('output'),Mapping):
    try:text.append(base64.b64decode(row['output']['bytes_b64'],validate=True).decode('utf-8','replace'))
    except Exception:return False
  joined='\n'.join(text)
  signal=re.search(r'Fatal signal 11[^\r\n]*\bpid\s*[:=, ]+\s*'+str(pid)+r'\b',joined,re.I) is not None
  death=re.search(r'Process\s+'+re.escape(self.plan.apk.package)+r'[^\r\n]{0,80}\bpid\s*[:=( ]+\s*'+str(pid)+r'\b[^\r\n]{0,80}(?:has died|died)',joined,re.I) is not None
  return signal and death
 def _cleanup(self,deadline):
  rows=[]
  def one(label,fn):
   if time.monotonic()>=deadline:rows.append({'step':label,'passed':False,'reason':'cleanup-deadline'});return False
   try:fn();rows.append({'step':label,'passed':True});return True
   except BaseException as e:rows.append({'step':label,'passed':False,'reason':type(e).__name__});return False
  def remove_forward():
   self._adb(['forward','--remove',f'tcp:{self.forward}'],1);rows=str(self._adb(['forward','--list'],1).get('stdout','')).splitlines()
   if any(f'tcp:{self.forward}' in x for x in rows):raise LldbControllerError('forward survived cleanup')
  def stop_server():
   self._adb(['shell','sh','-c','p="$1"; t="$2"; [ "$(cut -d" " -f22 /proc/$p/stat 2>/dev/null)" = "$t" ] && kill "$p" || [ ! -e /proc/$p ]','amz-server',str(self.server_pid),str(self.server_ticks)],1)
   if self._shell('sh','-c','[ ! -e /proc/$1 ] || [ "$(cut -d" " -f22 /proc/$1/stat)" != "$2" ]','amz-server-check',str(self.server_pid),str(self.server_ticks),timeout=1):raise LldbControllerError('unexpected server cleanup output')
  def remove_marker():
   self._adb(['shell','sh','-c','[ "$(sha256sum "$1" | cut -d" " -f1)" = "$2" ] && rm "$1"','amz-marker-clean',self.marker,self.marker_sha],1)
  def verify_tracee():
   if not self.tracee:return
   p,t=self.tracee;state=self._shell('sh','-c','[ ! -e /proc/$1 ] && { printf gone; exit; }; [ "$(cut -d" " -f22 /proc/$1/stat)" != "$2" ] && { printf reused; exit; }; awk \'/^State:/{print $2}\' /proc/$1/status','amz-tracee',str(p),str(t),timeout=1)
   if state not in ('gone','reused') and state in ('T','t'):raise LldbControllerError('tracee remains stopped')
  if self.forward:one('forward-remove',remove_forward)
  if self.server_pid and self.server_ticks:
   one('server-stop',stop_server)
  released=one('tracee-release',verify_tracee)
  if released:one('force-stop',lambda:self._adb(['shell','am','force-stop',self.plan.apk.package],1))
  else:rows.append({'step':'force-stop','passed':False,'reason':'tracee-release-unproven'})
  if self.marker:one('marker-remove',remove_marker)
  if self.rooted:
   one('unroot',lambda:self._adb(['unroot'],2));one('rebind-shell',lambda:self._adb(['wait-for-device'],2))
   one('root-state-restored',lambda:(_ for _ in ()).throw(LldbControllerError('root state not restored')) if self._shell('id','-u',timeout=1)!='2000' or self._shell('getenforce',timeout=1)!=self.initial['selinux'] else None)
  return {'deadline_seconds':60,'deadline_monotonic':deadline,'steps':rows,'passed':all(x['passed'] for x in rows)}
 def run(self,launch:Callable[[],Any],epoch:str)->dict:
  if not re.fullmatch(r'\d{10,}(?:\.\d{3})?',epoch):raise LldbControllerError('launch epoch')
  primary=None;ack=None;record=None
  try:
   staged=self.bridge.stage_additional_asset(self.bundle.asset);dest=f'{self.plan.root}/runtime/diagnostics';extracted=self.bridge._exec_json('/usr/bin/python3',['-c',EXTRACT,staged['guest_path'],dest,self.bundle.manifest_sha256],120)
   if extracted.get('archive_sha256')!=self.bundle.asset.sha256 or extracted.get('archive_size')!=self.bundle.asset.size or extracted.get('manifest_sha256')!=self.bundle.manifest_sha256 or extracted.get('member_count')!=self.bundle.manifest_members:raise LldbControllerError('LLDB bundle extraction proof')
   capability=self._capability()
   if capability.get('supported') is not True:raise LldbControllerError('LLDB capability unsupported')
   remote=f'/data/local/tmp/amz-lldb-server-{self.plan.ownership.attempt_nonce[:12]}';server=f'{dest}/lib/clang/17/lib/linux/aarch64/lldb-server';self._adb(['push',server,remote],20);self._adb(['shell','chmod','700',remote])
   server_sha='c1c0849dc507689428e127905e9fddcb220f6925b238bfb26e012cbad893b950'
   if self._shell('sha256sum',remote).split()[0]!=server_sha:raise LldbControllerError('inner lldb-server hash')
   self.diagnostic_deadline=time.monotonic()+60
   launch();pid,uid,ticks=self._identity();pid2,uid2,ticks2=self._identity();self.tracee=(pid,ticks)
   if (pid,uid,ticks)!=(pid2,uid2,ticks2):raise LldbControllerError('PID identity changed before attach')
   inner=41000+int(self.plan.ownership.attempt_nonce[:4],16)%10000;outer=inner+1
   server_raw=self._shell('sh','-c','nohup "$1" gdbserver "127.0.0.1:$2" --attach "$3" >"$4" 2>&1 & printf %s $!','amz-server',remote,str(inner),str(pid),f'{self.plan.root}/evidence/lldb-server.log')
   if not re.fullmatch(r'[1-9]\d*',server_raw):raise LldbControllerError('lldb-server PID')
   self.server_pid=int(server_raw);self.server_ticks=int(self._shell('sh','-c','cut -d" " -f22 /proc/$1/stat','amz-ticks',server_raw));self._adb(['forward',f'tcp:{outer}',f'tcp:{inner}']);self.forward=outer
   forwards=str(self._adb(['forward','--list']).get('stdout','')).splitlines()
   if sum(f'tcp:{outer} tcp:{inner}' in x for x in forwards)!=1:raise LldbControllerError('exact outer-local forward proof')
   ap=LldbAttachPlan(self.plan.ownership.run_id,self.plan.ownership.attempt_nonce,self.plan.apk.package,pid,uid,ticks,f'connect://127.0.0.1:{outer}',dest);driver=build_sb_driver(ap,self.diagnostic_deadline-20);driver_path=f'{dest}/evidence/lldb-{self.plan.ownership.attempt_nonce[:12]}.py';written=self.bridge._exec_json('/usr/bin/python3',['-c',WRITE_DRIVER,driver_path,driver],min(20,max(.1,self.diagnostic_deadline-time.monotonic()-10)))
   if written.get('sha256')!=hashlib.sha256(driver.encode()).hexdigest() or written.get('size')!=len(driver.encode()):raise LldbControllerError('driver write proof')
   entry=build_diagnostic_entrypoint(ap,driver_path);output_path=f'{dest}/evidence/lldb-output-{self.plan.ownership.attempt_nonce[:12]}.log';remaining=self.diagnostic_deadline-time.monotonic()
   if remaining<=12:raise LldbControllerError('insufficient driver transport margin')
   child_timeout=remaining-12;outer_timeout=remaining-10
   raw=self._outer('/usr/bin/python3',['-c',RUN_DRIVER,json.dumps(entry['argv'],separators=(',',':')),json.dumps(entry['env'],separators=(',',':')),str(entry['output_limit']),str(child_timeout),output_path],outer_timeout);wrapper=json.loads(raw.get('stdout',''))
   output=base64.b64decode(wrapper.get('bytes_b64',''),validate=True)
   if wrapper.get('timed_out') is True:
    sb={'schema':1,'acceptance':False,'classification':'diagnostic-timeout','signal_claim':False,'stack_claim':False,'states':[],'identity':{k:getattr(ap,k) for k in ('run_id','attempt_nonce','package','pid','uid','start_ticks')},'signal_policy':None,'lldb_file':f'{dest}/lib/python3.10/site-packages/lldb/__init__.py'}
   else:sb=parse_sb_output(output,ap)
   native=None
   if sb.get('classification')=='native-sigsegv' and sb.get('exit_status')==11:
    native=self.native_collect(pid,None,epoch,self.diagnostic_deadline-10)
    if not self._death_correlated(native,pid,epoch):sb={k:v for k,v in sb.items() if k!='threads'};sb.update({'classification':'android-death-correlation-missing','stack_claim':False});native=None
   record={'schema':1,'operation':'nested-android-lldb-diagnostic','acceptance':False,'run_id':self.plan.ownership.run_id,'attempt_nonce':self.plan.ownership.attempt_nonce,'outer_ownership':asdict(self.plan.ownership),'bundle':{'name':self.bundle.asset.name,'sha256':self.bundle.asset.sha256,'size':self.bundle.asset.size,'manifest_sha256':self.bundle.manifest_sha256,'members':self.bundle.manifest_members},'stage':staged,'extraction':extracted,'capability':capability,'process':{'pid':pid,'uid':uid,'start_ticks':ticks},'forward':{'outer_loopback_port':outer,'inner_loopback_port':inner},'server':{'pid':self.server_pid,'start_ticks':self.server_ticks,'remote':remote,'sha256':server_sha},'driver':written,'entrypoint':entry,'sb':sb,'native_crash':native}
  except BaseException as e:
   primary=e
   if record is None:record={'schema':1,'operation':'nested-android-lldb-diagnostic','acceptance':False,'run_id':self.plan.ownership.run_id,'attempt_nonce':self.plan.ownership.attempt_nonce,'outer_ownership':asdict(self.plan.ownership),'classification':'diagnostic-failure','capability':{'supported':False,'rows':list(self.capability_rows)},'error':{'type':type(e).__name__,'sha256':hashlib.sha256(str(e).encode()).hexdigest()}}
  try:
   ack=self.archive(record)
   if not isinstance(ack,Mapping) or ack.get('origin')!='controller' or ack.get('immutable') is not True or not SHA.fullmatch(str(ack.get('sha256',''))) or not isinstance(ack.get('size'),int) or ack['size']<=0:raise LldbControllerError('diagnostic archive ACK')
  except BaseException as e:
   error=primary or e;setattr(error,'retain_owned_evidence',True);raise error
  cleanup=self._cleanup(self.diagnostic_deadline if self.diagnostic_deadline is not None else time.monotonic());record={**record,'controller_archive':dict(ack),'cleanup':cleanup}
  if not cleanup['passed']:
   error=primary or LldbControllerError('diagnostic cleanup incomplete');setattr(error,'retain_owned_evidence',True);raise error
  if primary is not None:raise primary
  return record
