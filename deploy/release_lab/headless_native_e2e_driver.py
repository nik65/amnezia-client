"""Bounded orchestration for genuine headless N-1 -> N -> rollback -> reboot."""
from __future__ import annotations
import json,os,re
from dataclasses import asdict,dataclass
from datetime import datetime,timezone
from pathlib import Path
from typing import Any,Mapping
from .headless_native_acceptance import NativeUpdatePlan,UPDATE_STATE,validate_update_receipt,validate_rollback_receipt,validate_reboot_receipt
from .headless_native_qga_adapter import HeadlessNativeQgaAdapter
from .headless_native_http_fixture import HeadlessNativeHttpFixture
from .headless_preexisting_fixture import FixturePlan,validate_baseline_owned,validate_connected,_sha

class HeadlessE2EError(RuntimeError): pass
def _now():return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def _state(raw:Mapping,key:str)->str:
 try:
  row=raw[key];data=__import__('base64').b64decode(row['bytes_b64'],validate=True);return str(json.loads(data)['state'])
 except Exception:return ''

class PreexistingQgaBridge:
 """Executes the reviewed guest helper and its durable crash authorization chain."""
 def __init__(self,qga:Any,plan:FixturePlan,script_source:Path,script_path:str):
  self.qga,self.plan,self.script=qga,plan,script_path;self.root=plan.owned_root;self.plan_path=f"{self.root}/plan.json";data=script_source.read_bytes();self.script_sha=__import__('hashlib').sha256(data).hexdigest();self.script_size=len(data);qga.write_file(script_path,data)
 def _run(self,action,*extra,timeout=120):
  r=self.qga.guest_exec_wait('/usr/bin/python3',[self.script,action,'--plan',self.plan_path,*extra],timeout=timeout)
  try:v=json.loads(r['stdout'])
  except Exception as e:raise HeadlessE2EError(f'preexisting {action} receipt missing') from e
  if not isinstance(v,dict) or v.get('origin')!='guest' or v.get('transport')!='qga':raise HeadlessE2EError(f'preexisting {action} receipt origin')
  return v
 def prepare_and_connect(self):
  verify="import hashlib,json,pathlib,stat,sys;p=pathlib.Path(sys.argv[1]);b=p.read_bytes();s=p.stat();print(json.dumps({'sha256':hashlib.sha256(b).hexdigest(),'size':len(b),'mode':format(stat.S_IMODE(s.st_mode),'04o'),'uid':s.st_uid}))"
  v=json.loads(self.qga.guest_exec_wait('/usr/bin/python3',['-c',verify,self.script],timeout=30)['stdout'])
  if v.get('sha256')!=self.script_sha or v.get('size')!=self.script_size or v.get('mode') not in ('0600','0700') or v.get('uid')!=0:raise HeadlessE2EError('preexisting helper staging identity')
  self.qga.write_file(self.plan_path,(json.dumps(asdict(self.plan),sort_keys=True)+'\n').encode());self._run('prepare')
  value=self._run('connect-collect','--deadline','90');return validate_connected(self.plan,value)
 def crash_and_restart(self,connected,controller_archive:Path):
  durable=f'{self.root}/connected.json';raw=(json.dumps(dict(connected),sort_keys=True,separators=(',',':'))+'\n').encode();self.qga.write_file(durable,raw)
  archive=controller_archive.resolve();disk=json.loads(archive.read_text());digest=_sha(disk)
  if disk!=dict(connected) or digest!=_sha(connected) or not str(archive).startswith('/var/lib/amnezia-release-lab/receipts/'):raise HeadlessE2EError('controller archive binding')
  return validate_baseline_owned(self.plan,connected,self._run('baseline-handoff','--connected',durable,'--deadline','120'))
 def boot_id(self,legacy):return str(legacy['boot_id'])
 def promote_systemd_baseline(self,legacy):
  cli_hash=getattr(self,'legacy_cli_sha256',None)
  if not isinstance(cli_hash,str) or not re.fullmatch(r'[0-9a-f]{64}',cli_hash): raise HeadlessE2EError('legacy CLI identity unavailable')
  code="""import hashlib,json,os,pathlib,signal,subprocess,sys,time
p=json.loads(sys.argv[1]);legacy=json.loads(sys.argv[2]);cli_hash=sys.argv[4];src=pathlib.Path(p['legacy_daemon']['path']);src_cli=pathlib.Path(p['owned_root'])/'legacy/amnezia-cli';dst=pathlib.Path(p['setup_daemon']['path']);dst_cli=pathlib.Path(p['cli']['path']);root=pathlib.Path(p['owned_root']);backup=root/'setup-daemon.backup';backup_cli=root/'setup-cli.backup'
def exact(q,h):
 if q.is_symlink() or not q.is_file():raise RuntimeError('binary identity is not a regular file')
 b=q.read_bytes()
 if hashlib.sha256(b).hexdigest()!=h:raise RuntimeError('binary hash mismatch')
 return b
def writeall(fd,data):
 view=memoryview(data)
 while view:
  n=os.write(fd,view)
  if not isinstance(n,int) or isinstance(n,bool) or n<=0:raise OSError('short write')
  view=view[n:]
def syncdir(q): d=os.open(q,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
def write_blob(path,data,mode,uid,gid):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode);writeall(fd,data);os.fchmod(fd,mode);os.fchown(fd,uid,gid);os.fsync(fd);os.close(fd);syncdir(path.parent)
def replace_from(src_path,dst_path,expected):
 st=dst_path.lstat();tmp=dst_path.with_name(dst_path.name+'.lab-new')
 if tmp.exists() or tmp.is_symlink():raise RuntimeError('binary replacement temporary exists')
 data=exact(src_path,expected);write_blob(tmp,data,st.st_mode&0o777,st.st_uid,st.st_gid);exact(tmp,expected);os.replace(tmp,dst_path);syncdir(dst_path.parent);exact(dst_path,expected)
old=exact(dst,p['setup_daemon']['sha256']);old_cli=exact(dst_cli,p['cli']['sha256']);new=exact(src,p['legacy_daemon']['sha256']);new_cli=exact(src_cli,cli_hash)
if backup.exists() or backup.is_symlink() or backup_cli.exists() or backup_cli.is_symlink():raise RuntimeError('baseline binary backup already exists')
write_blob(backup,old,0o600,0,0);write_blob(backup_cli,old_cli,0o600,0,0);exact(backup,p['setup_daemon']['sha256']);exact(backup_cli,p['cli']['sha256'])
ident=legacy['daemon'];proc=pathlib.Path('/proc')/str(ident['pid']);raw=proc.joinpath('stat').read_text();f=raw[raw.rfind(')')+2:].split();assert int(f[19])==ident['start_ticks'] and hashlib.sha256(proc.joinpath('exe').read_bytes()).hexdigest()==p['legacy_daemon']['sha256'];os.kill(ident['pid'],signal.SIGTERM)
for _ in range(200):
 if not proc.exists():break
 time.sleep(.05)
else:raise SystemExit('legacy survivor')
drop=pathlib.Path('/run/systemd/system/amneziad.service.d')/('90-amnezia-lab-'+sys.argv[3]+'.conf');drop.unlink(missing_ok=True)
try:
 replace_from(src,dst,p['legacy_daemon']['sha256']);replace_from(src_cli,dst_cli,cli_hash)
except BaseException as exc:
 try:replace_from(backup,dst,p['setup_daemon']['sha256']);replace_from(backup_cli,dst_cli,p['cli']['sha256'])
 except BaseException as restore:raise RuntimeError('baseline binary switch rollback incomplete') from restore
 raise RuntimeError('baseline binary switch failed') from exc
try:
 subprocess.run(['systemctl','daemon-reload'],check=True);subprocess.run(['systemctl','start','amneziad.service'],check=True)
except BaseException as exc:
 try:
  replace_from(backup,dst,p['setup_daemon']['sha256']);replace_from(backup_cli,dst_cli,p['cli']['sha256']);subprocess.run(['systemctl','daemon-reload'],check=True);subprocess.run(['systemctl','start','amneziad.service'],check=True)
 except BaseException as restore:raise RuntimeError('baseline service rollback incomplete') from restore
 raise RuntimeError('baseline service start failed') from exc
pid=int(subprocess.run(['systemctl','show','-p','MainPID','--value','amneziad.service'],capture_output=True,text=True,check=True).stdout);q=pathlib.Path('/proc')/str(pid);r=q.joinpath('stat').read_text();g=r[r.rfind(')')+2:].split();assert hashlib.sha256(q.joinpath('exe').read_bytes()).hexdigest()==p['legacy_daemon']['sha256'] and hashlib.sha256(dst_cli.read_bytes()).hexdigest()==cli_hash;print(json.dumps({'pid':pid,'start_ticks':int(g[19]),'exe':str(q.joinpath('exe').resolve()),'exe_sha256':p['legacy_daemon']['sha256'],'cli_path':str(dst_cli),'cli_sha256':cli_hash,'backup_sha256':p['setup_daemon']['sha256'],'backup_cli_sha256':p['cli']['sha256']}))"""
  r=self.qga.guest_exec_wait('/usr/bin/python3',['-c',code,json.dumps(asdict(self.plan)),json.dumps(dict(legacy)),self.plan.tag,cli_hash],timeout=120);return json.loads(r['stdout'])
 def cleanup(self,active_receipt):
  code="""import hashlib,json,pathlib,subprocess
pid=int(subprocess.run(['/usr/bin/systemctl','show','-p','MainPID','--value','amneziad.service'],capture_output=True,text=True,check=True).stdout);p=pathlib.Path('/proc')/str(pid);raw=p.joinpath('stat').read_text();f=raw[raw.rfind(')')+2:].split();cmd=p.joinpath('cmdline').read_bytes();exe=p.joinpath('exe').resolve(strict=True);print(json.dumps({'pid':pid,'start_ticks':int(f[19]),'exe':str(exe),'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'uid':p.joinpath('status').stat().st_uid,'cmdline_sha256':hashlib.sha256(cmd).hexdigest()}))"""
  r=self.qga.guest_exec_wait('/usr/bin/python3',['-c',code],timeout=30);daemon=json.loads(r['stdout']);path=f'{self.root}/active.json';value={'run_id':self.plan.run_id,'profile':self.plan.profile,'nonce':self.plan.nonce,'daemon':daemon};self.qga.write_file(path,(json.dumps(value)+'\n').encode());receipt=self._run('cleanup','--active-daemon',path)
  restore="import hashlib,os,pathlib,sys\ndef restore(b,d,h):\n p=pathlib.Path(b);q=pathlib.Path(d);x=p.read_bytes();assert hashlib.sha256(x).hexdigest()==h;tmp=q.with_name(q.name+'.lab-restore');fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o755);os.write(fd,x);os.fsync(fd);os.close(fd);os.replace(tmp,q);z=os.open(q.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(z);os.close(z);assert hashlib.sha256(q.read_bytes()).hexdigest()==h\nrestore(sys.argv[1],sys.argv[2],sys.argv[3]);restore(sys.argv[4],sys.argv[5],sys.argv[6])"
  self.qga.guest_exec_wait('/usr/bin/python3',['-c',restore,f'{self.root}/setup-daemon.backup',self.plan.setup_daemon.path,self.plan.setup_daemon.sha256,f'{self.root}/setup-cli.backup',self.plan.cli.path,self.plan.cli.sha256],timeout=30);return receipt

@dataclass
class HeadlessNativeE2EDriver:
 plan:NativeUpdatePlan; native:HeadlessNativeQgaAdapter; server:HeadlessNativeHttpFixture; preexisting:PreexistingQgaBridge; collector:Any; archive_root:Path
 def _archive(self,name:str,value:Mapping)->Path:
  root=self.archive_root.resolve();root.mkdir(parents=True,exist_ok=True)
  path=(root/f"{self.plan.attempt_nonce}-{name}.json").resolve()
  if path.parent!=root or path.exists() or path.is_symlink():raise HeadlessE2EError("immutable archive conflict")
  data=(json.dumps(dict(value),sort_keys=True,separators=(',',':'))+'\n').encode();fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  try:
   with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
  except BaseException:
   path.unlink(missing_ok=True);raise
  return path
 def run(self,*,update_timeout:int=600,rollback_timeout:int=600,reboot_timeout:int=300)->dict:
  self.plan.validate();http=None;primary=None;server_started=False;preexisting_started=False;cleaned=False
  try:
   connected=self.preexisting.prepare_and_connect();preexisting_started=True;connected_archive=self._archive('preexisting-connected',connected)
   legacy=self.preexisting.crash_and_restart(connected,connected_archive);self._archive('baseline-legacy-start',legacy);self.preexisting.promote_systemd_baseline(legacy)
   before=self.native.identity(self.plan.baseline,'baseline-before');boot=self.preexisting.boot_id(legacy)
   before_doctor=self.native.cli_json(['/usr/local/bin/amnezia-cli','--socket','/run/amnezia/amneziad.sock','--json','doctor'],'cli:doctor')
   self.server.start();server_started=True;self.server.reset();staged=self.native.stage_profile()
   pending=self.native.wait_for(self.native.collect_update_pending,lambda x:_state(x,'pending_state')=='restart_pending',timeout=update_timeout,label='native update pending')
   stable=self.native.wait_for(self.native.collect_update_stable,lambda x:_state(x,'stable_state')=='updated',timeout=update_timeout,label='native update stable')
   after=self.native.identity(self.plan.candidate,'candidate-after');http=self.server.collect()
   update=self.native.build_update_receipt(before_raw=before,after_raw=after,boot_id=boot,raw_sources={"before_doctor":before_doctor,"profile_store":staged['profile_store'],**pending,**stable},http_receipt=http,observed_at=_now());validate_update_receipt(self.plan,update,http);self._archive('update',update)
   rb=self.collector.trigger_rollback(self.plan.candidate.cli_sha256);rb_pending=self.native.wait_for(self.native.collect_rollback_pending,lambda x:_state(x,'pending_state')=='rollback_restart_pending',timeout=rollback_timeout,label='rollback pending');rb_stable=self.native.wait_for(self.native.collect_rollback_stable,lambda x:_state(x,'stable_state')=='rolled_back',timeout=rollback_timeout,label='rollback stable')
   rollback=self.native.build_rollback_receipt(before_raw=self.native.identity(self.plan.candidate,'candidate-before'),after_raw=self.native.identity(self.plan.baseline,'baseline-after'),boot_id=boot,cli_process=rb['cli_process'],raw_sources={"cli_response":rb['cli_response'],**rb_pending,**rb_stable},update_receipt=update,observed_at=_now());validate_rollback_receipt(self.plan,rollback,update);self._archive('rollback',rollback)
   observed=self.collector.reboot_and_collect(boot,self.plan.baseline,reboot_timeout)
   reboot=self.native.build_reboot_receipt(boot_id_before=observed['boot_id_before'],boot_id_after=observed['boot_id_after'],after_raw=observed['after_raw'],raw_sources=observed['raw_sources'],expected_release=self.plan.baseline,prior_receipt=rollback,observed_at=_now());validate_reboot_receipt(self.plan,reboot,self.plan.baseline,rollback);self._archive('reboot',reboot)
   cleanup=self.native.validate_fixture_cleanup(self.server.stop(http),http);server_started=False;self.preexisting.cleanup(reboot);preexisting_started=False;cleaned=True;self._archive('cleanup',cleanup)
   return {"update":update,"rollback":rollback,"reboot":reboot,"cleanup":cleanup}
  except BaseException as exc:primary=exc;raise
  finally:
   if primary is not None:
    try:self._archive('failure',{"error_type":type(primary).__name__,"error":str(primary),"observed_at":_now()})
    except BaseException as e:primary.add_note(f"failure archive also failed: {e}")
    if server_started:
     try:
      if http is None:http=self.server.collect()
      self.server.stop(http)
     except BaseException as e:primary.add_note(f"server fixture cleanup also failed: {e}")
    if preexisting_started:
     try:self.preexisting.cleanup({})
     except BaseException as e:primary.add_note(f"preexisting cleanup also failed: {e}")
