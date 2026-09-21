"""Guest-origin rollback CLI and reboot-persistence collector.

The returned values are raw inputs for HeadlessNativeQgaAdapter receipt
constructors.  This module never sets an acceptance boolean.
"""
from __future__ import annotations
import base64,hashlib,json,re,time
from typing import Any,Callable,Mapping

from .headless_native_acceptance import FIXED_SOCKET,UPDATE_STATE,NativeUpdatePlan,ReleaseBytes
from .headless_native_qga_adapter import HeadlessNativeQgaAdapter,HeadlessNativeQgaError

CLI="/usr/local/bin/amnezia-cli"; DAEMON="/usr/local/bin/amneziad"
ROLLBACK_ARGV=[CLI,"--socket",FIXED_SOCKET,"--json","update-rollback"]

ROLLBACK=r'''import hashlib,json,os,pathlib,resource,subprocess,sys,time
argv=json.loads(sys.argv[1]); expected=sys.argv[2]; output=pathlib.Path(sys.argv[3]); limit=1048576;fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
if argv!=['/usr/local/bin/amnezia-cli','--socket','/run/amnezia/amneziad.sock','--json','update-rollback']: raise SystemExit('argv')
def bound(): resource.setrlimit(resource.RLIMIT_FSIZE,(limit+1,limit+1))
p=subprocess.Popen(argv,stdout=fd,stderr=subprocess.STDOUT,preexec_fn=bound);os.close(fd)
proc=pathlib.Path('/proc')/str(p.pid); deadline=time.monotonic()+5; identity=None
while time.monotonic()<deadline:
 try:
  raw=proc.joinpath('stat').read_text(); f=raw[raw.rfind(')')+2:].split(); exe=proc.joinpath('exe').resolve(strict=True); cmd=proc.joinpath('cmdline').read_bytes(); args=[x.decode() for x in cmd.rstrip(b'\0').split(b'\0')]
  if str(exe)==argv[0] and args==argv:
   data=exe.read_bytes()
   if hashlib.sha256(data).hexdigest()!=expected:
    p.kill();p.wait();output.unlink(missing_ok=True);raise SystemExit('cli hash')
   identity={'pid':p.pid,'start_ticks':int(f[19]),'exe':str(exe),'exe_sha256':expected,'argv':args,'cmdline_sha256':hashlib.sha256(cmd).hexdigest()};break
 except (FileNotFoundError,ProcessLookupError): break
 time.sleep(.001)
if identity is None:
 p.kill();p.wait();output.unlink(missing_ok=True);raise SystemExit('CLI identity not observed')
try:p.wait(timeout=60)
except subprocess.TimeoutExpired:p.kill();p.wait();output.unlink(missing_ok=True);raise SystemExit('CLI timeout')
out=output.read_bytes();output.unlink();identity['exit_code']=p.returncode
if len(out)>limit:raise SystemExit('CLI output bound')
print(json.dumps({'process':identity,'stdout_b64':__import__('base64').b64encode(out).decode(),'stdout_sha256':hashlib.sha256(out).hexdigest(),'stdout_size':len(out)},separators=(',',':')))
'''
MARKER=r'''import hashlib,json,os,pathlib,sys
p=pathlib.Path(sys.argv[1]); nonce=sys.argv[2]; p.parent.mkdir(parents=True,exist_ok=True); data=(json.dumps({'attempt_nonce':nonce},separators=(',',':'))+'\n').encode();fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
os.chown(p,0,0);d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(d)
finally:os.close(d)
print(json.dumps({'path':str(p),'sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'uid':p.stat().st_uid,'mode':format(p.stat().st_mode&0o777,'04o')},separators=(',',':')))
'''
SERVICE=r'''import json,subprocess
def one(args):
 p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
 if p.returncode: raise SystemExit('systemctl')
 return p.stdout.strip()
print(json.dumps({'enabled':one(['/usr/bin/systemctl','is-enabled','amneziad.service']),'active':one(['/usr/bin/systemctl','is-active','amneziad.service'])},separators=(',',':')))
'''

class HeadlessNativeRebootCollector:
 def __init__(self,qga:Any,plan:NativeUpdatePlan,native:HeadlessNativeQgaAdapter,outer_live_snapshot:Callable[[],Any],*,clock=time.monotonic,sleep=time.sleep):
  plan.validate();self.qga,self.plan,self.native,self.snapshot,self.clock,self.sleep=qga,plan,native,outer_live_snapshot,clock,sleep
 def _check(self):
  if self.snapshot()!=self.plan.outer_binding:raise HeadlessNativeQgaError("outer ownership changed")
 def _json(self,code,args,timeout):
  self._check();r=self.qga.guest_exec_wait("/usr/bin/python3",["-c",code,*args],timeout=timeout);self._check()
  try:v=json.loads(r.get("stdout",""))
  except Exception as e:raise HeadlessNativeQgaError("guest collector returned no JSON") from e
  if not isinstance(v,dict):raise HeadlessNativeQgaError("guest collector JSON shape")
  return v
 @staticmethod
 def _raw(path,data):return {"origin":"guest","transport":"qga","path":path,"bytes_b64":base64.b64encode(data).decode(),"sha256":hashlib.sha256(data).hexdigest(),"size":len(data),"uid":0,"gid":0,"mode":"0600"}
 def trigger_rollback(self,cli_sha256:str,timeout=90):
  if not re.fullmatch(r"[0-9a-f]{64}",cli_sha256):raise HeadlessNativeQgaError("rollback CLI hash")
  output=f"/var/lib/amnezia/.release-lab-rollback-{self.plan.attempt_nonce}.json";v=self._json(ROLLBACK,[json.dumps(ROLLBACK_ARGV,separators=(",",":")),cli_sha256,output],timeout);p=v.get("process")
  if not isinstance(p,Mapping) or p.get("argv")!=ROLLBACK_ARGV or p.get("exe")!=CLI or p.get("exe_sha256")!=cli_sha256 or isinstance(p.get("exit_code"),bool) or p.get("exit_code")!=0:raise HeadlessNativeQgaError("official rollback CLI failed")
  try:data=base64.b64decode(v.get("stdout_b64"),validate=True);parsed=json.loads(data)
  except Exception as e:raise HeadlessNativeQgaError("rollback CLI raw response") from e
  if v.get("stdout_size")!=len(data) or v.get("stdout_sha256")!=hashlib.sha256(data).hexdigest() or not isinstance(parsed,Mapping):raise HeadlessNativeQgaError("rollback CLI response identity")
  return {"cli_process":dict(p),"cli_response":self._raw("cli:update-rollback",data)}
 def stage_persistent_marker(self):
  path=f"/var/lib/amnezia/release-lab-native-{self.plan.attempt_nonce}.json";v=self._json(MARKER,[path,self.plan.attempt_nonce],20)
  if v.get("path")!=path or v.get("uid")!=0 or v.get("mode")!="0600":raise HeadlessNativeQgaError("persistent marker stage")
  raw=self.native.raw_file(path)
  if raw.get("sha256")!=v.get("sha256") or raw.get("size")!=v.get("size"):raise HeadlessNativeQgaError("persistent marker readback")
  return raw
 def reboot_and_collect(self,boot_id_before:str,expected:ReleaseBytes,timeout=180):
  marker=self.stage_persistent_marker();self._check();started=self.qga.guest_exec("/usr/bin/systemctl",["reboot"])
  if not isinstance(started,Mapping) or isinstance(started.get("pid"),bool) or not isinstance(started.get("pid"),int):raise HeadlessNativeQgaError("reboot request PID")
  deadline=self.clock()+timeout;after=""
  while self.clock()<deadline:
   self._check()
   try:
    if self.qga.sync():
     r=self.qga.guest_exec_wait("/usr/bin/cat",["/proc/sys/kernel/random/boot_id"],timeout=min(10,max(1,deadline-self.clock())));after=str(r.get("stdout","")).strip()
     if after and after!=boot_id_before:break
   except Exception:pass
   self.sleep(min(1,max(0,deadline-self.clock())))
  if not after or after==boot_id_before:raise HeadlessNativeQgaError("bounded reboot/QGA reconnect timed out")
  identity=self.native.identity(expected,"post-reboot");marker_after=self.native.raw_file(marker["path"])
  if marker_after.get("sha256")!=marker.get("sha256") or marker_after.get("size")!=marker.get("size"):raise HeadlessNativeQgaError("persistent marker changed across reboot")
  service=self.native._json_record(SERVICE,[],"systemctl:amneziad.service")
  return {"boot_id_before":boot_id_before,"boot_id_after":after,"reboot_request_pid":started["pid"],"after_raw":identity,"raw_sources":{"persistent_marker":marker_after,"service":service,"stable_state":self.native.raw_file(UPDATE_STATE),"doctor":self.native.cli_json([CLI,"--socket",FIXED_SOCKET,"--json","doctor"],"cli:doctor")}}
