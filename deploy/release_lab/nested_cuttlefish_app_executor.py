"""Fail-closed QGA/ADB executor for nested Cuttlefish UI updates."""
from __future__ import annotations
import base64,hashlib,ipaddress,json,math,re,time
from dataclasses import asdict,dataclass
from typing import Any,Callable,Mapping
from urllib.parse import quote,urlparse
try:
 from .nested_cuttlefish_runner import ApkSpec,InnerPlan,NestedCuttlefishError,OuterOwnership,receipt_sha,validate_app_update_receipt,validate_boot_receipt
except ImportError:  # direct lab.py execution
 from nested_cuttlefish_runner import ApkSpec,InnerPlan,NestedCuttlefishError,OuterOwnership,receipt_sha,validate_app_update_receipt,validate_boot_receipt

SHA=re.compile(r"[0-9a-f]{64}"); XML_MAX=1<<20; LOG_MAX=2<<20; PNG_MAX=16<<20
INSTALLERS=("com.android.packageinstaller","com.google.android.packageinstaller","com.android.permissioncontroller")

@dataclass(frozen=True)
class AppFixture:
 endpoint:str; run_id:str; attempt_nonce:str; manifest_path:str; manifest_sha256:str; manifest_size:int; artifact_path:str; pid:int; start_ticks:int
 profile:str="server-router"; marker:str=""; outer_ownership:Mapping[str,Any]|None=None
 def validate(self,plan:InnerPlan):
  p=urlparse(self.endpoint)
  try:h=ipaddress.ip_address(p.hostname or "")
  except ValueError as e:raise NestedCuttlefishError("fixture endpoint") from e
  if p.scheme!="http" or h.version!=4 or not h.is_private or h.is_loopback or not p.port:raise NestedCuttlefishError("fixture endpoint")
  if self.run_id!=plan.ownership.run_id or self.attempt_nonce!=plan.ownership.attempt_nonce:raise NestedCuttlefishError("fixture identity")
  if self.profile!="server-router" or self.marker!=f"amnezia-release-lab:{self.run_id}:server-router":raise NestedCuttlefishError("fixture marker/profile")
  if not isinstance(self.outer_ownership,Mapping) or set(self.outer_ownership)!={"pid","start_ticks","uuid","qmp_socket","qga_socket"}:raise NestedCuttlefishError("fixture outer binding")
  if isinstance(self.pid,bool) or self.pid<=1 or isinstance(self.start_ticks,bool) or self.start_ticks<=0 or not SHA.fullmatch(self.manifest_sha256) or self.manifest_size<=0:raise NestedCuttlefishError("fixture bytes/process identity")
  canonical_name=quote(plan.apk.name,safe="-._~")
  if self.manifest_path!="/manifest.json" or self.artifact_path!=f"/files/artifacts/{plan.apk.sha256}/{canonical_name}":raise NestedCuttlefishError("fixture paths differ from semantic gate")

class NestedAppExecutor:
 def __init__(self,qga:Any,plan:InnerPlan,boot_receipt:Mapping[str,Any],baseline:ApkSpec,fixture:AppFixture,outer_live_snapshot:Callable[[],OuterOwnership],fixture_outer_snapshot:Callable[[],Mapping[str,Any]],fixture_call:Callable[[str,Mapping[str,Any],float],Mapping[str,Any]],*,failure_archive:Callable[[Mapping[str,Any]],Mapping[str,Any]]|None=None,clock=time.monotonic,sleep=time.sleep):
  plan.validate();validate_boot_receipt(plan,boot_receipt);baseline.validate();fixture.validate(plan)
  if baseline.package!=plan.apk.package or baseline.sha256==plan.apk.sha256:raise NestedCuttlefishError("baseline identity")
  self.qga,self.plan,self.boot,self.baseline,self.fixture,self.snapshot,self.fixture_snapshot,self.fixture_call=qga,plan,dict(boot_receipt),baseline,fixture,outer_live_snapshot,fixture_outer_snapshot,fixture_call
  self.clock,self.sleep,self.failure_archive=clock,sleep,failure_archive;self.adb=f"{plan.root}/runtime/host/bin/adb";self.serial=self.boot["network"]["adb_connection"]["endpoint"];self.capture_seq=0;self.last_command=None
  if not callable(failure_archive):raise NestedCuttlefishError("app failure archive callback missing")
  if self.boot["boot"]["serial"]!=self.serial.replace(":","_"):raise NestedCuttlefishError("ADB serial is not boot-bound")
 def _check(self):
  if self.snapshot()!=self.plan.ownership:raise NestedCuttlefishError("outer ownership changed")
 def _check_fixture(self):
  if self.fixture_snapshot()!=dict(self.fixture.outer_ownership):raise NestedCuttlefishError("fixture outer ownership changed")
 def _left(self,d,cap=30):
  n=d-self.clock()
  if n<=0:raise NestedCuttlefishError("total update deadline expired")
  return min(cap,n)
 def _adb(self,args,d,cap=30):
  self._check();r=self.qga.guest_exec_wait(self.adb,["-P",self.plan.adb_endpoint.rsplit(":",1)[1],"-s",self.serial,*args],timeout=self._left(d,cap));self._check()
  rc=r.get("exitcode",r.get("exit_code")) if isinstance(r,Mapping) else None
  stdout=str(r.get("stdout","")).encode();stderr=str(r.get("stderr","")).encode();self.last_command={"argv":[self.adb,"-P",self.plan.adb_endpoint.rsplit(":",1)[1],"-s",self.serial,*args],"exit_code":rc,"stdout":self._bounded_command_bytes(stdout),"stderr":self._bounded_command_bytes(stderr)}
  if isinstance(rc,bool) or rc!=0:raise NestedCuttlefishError("ADB command failed")
  return r
 def _request(self,name,args,d):
  self._check();left=self._left(d)
  if hasattr(self.qga,"request_bounded"):r=self.qga.request_bounded(name,args,timeout=left)
  elif hasattr(self.qga,"timeout"):
   old=self.qga.timeout;self.qga.timeout=min(float(old),left)
   try:r=self.qga.request(name,args)
   finally:self.qga.timeout=old
  else:raise NestedCuttlefishError("QGA transport has no deadline-aware request API")
  self._check()
  if not isinstance(r,Mapping) or "return" not in r or "error" in r:raise NestedCuttlefishError(f"QGA {name} failed")
  return r
 def _read_file(self,path,d,limit):
  opened=self._request("guest-file-open",{"path":path,"mode":"r"},d);handle=opened.get("return") if isinstance(opened,Mapping) else None
  if isinstance(handle,bool) or not isinstance(handle,int):raise NestedCuttlefishError("QGA evidence open failed")
  data=bytearray();primary=None
  try:
   while True:
    r=self._request("guest-file-read",{"handle":handle,"count":65536},d);v=r.get("return",{}) if isinstance(r,Mapping) else {}
    try:chunk=base64.b64decode(v.get("buf-b64",""),validate=True)
    except Exception as e:raise NestedCuttlefishError("QGA evidence chunk invalid") from e
    if len(data)+len(chunk)>limit:raise NestedCuttlefishError("QGA evidence oversized")
    data.extend(chunk)
    if v.get("eof") is True:return bytes(data)
    if not chunk:raise NestedCuttlefishError("QGA evidence made no progress")
  except BaseException as e:primary=e;raise
  finally:
   try:self._request("guest-file-close",{"handle":handle},self.clock()+10)
   except BaseException as close_error:
    if primary is None:raise
    primary.add_note(f"QGA evidence close also failed: {close_error}")
 def _fx(self,action,d):
  self._check();self._check_fixture();r=self.fixture_call(action,asdict(self.fixture),self._left(d));self._check();self._check_fixture()
  if not isinstance(r,Mapping):raise NestedCuttlefishError("fixture returned no receipt")
  common={"schema":1,"run_id":self.fixture.run_id,"profile":self.fixture.profile,"attempt_nonce":self.fixture.attempt_nonce,"marker":self.fixture.marker,"origin":"guest","transport":"qga","injected":False,"outer_ownership":dict(self.fixture.outer_ownership),"pid":self.fixture.pid,"start_ticks":self.fixture.start_ticks,"listener":self.fixture.endpoint,"manifest_sha256":self.fixture.manifest_sha256,"manifest_size":self.fixture.manifest_size,"artifact_sha256":self.plan.apk.sha256,"artifact_size":self.plan.apk.size}
  if any(r.get(k)!=v for k,v in common.items()):raise NestedCuttlefishError(f"fixture {action} provenance")
  return dict(r)
 def _capture_result(self,args,d,label,limit,command_cap=None):
  self.capture_seq+=1;path=f"{self.plan.root}/evidence/{self.plan.ownership.attempt_nonce[:12]}-{self.capture_seq:02d}-{label}"
  code="""import hashlib,json,os,pathlib,resource,subprocess,sys
argv=json.loads(sys.argv[1]);p=pathlib.Path(sys.argv[2]);limit=int(sys.argv[3]);p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
def bound(): resource.setrlimit(resource.RLIMIT_FSIZE,(limit+1,limit+1))
rc=125
try:
 try: rc=subprocess.run(argv,stdout=fd,stderr=subprocess.DEVNULL,timeout=float(sys.argv[4]),preexec_fn=bound).returncode
 except subprocess.TimeoutExpired: rc=124
finally: os.close(fd)
b=p.read_bytes();print(json.dumps({'path':str(p),'size':len(b),'sha256':hashlib.sha256(b).hexdigest(),'rc':rc},separators=(',',':')))
"""
  remaining=self._left(d);inner=max(.1,remaining-5) if command_cap is None else min(float(command_cap),max(.1,remaining-5));outer=min(remaining,inner+5)
  argv=[self.adb,"-P",self.plan.adb_endpoint.rsplit(":",1)[1],"-s",self.serial,*args];self._check();r=self.qga.guest_exec_wait("/usr/bin/python3",["-c",code,json.dumps(argv,separators=(",",":")),path,str(limit),str(inner)],timeout=outer);self._check()
  try:m=json.loads(r.get("stdout",""))
  except Exception as e:raise NestedCuttlefishError("bounded capture receipt missing") from e
  if m.get("path")!=path or m.get("rc") not in (0,124) or not isinstance(m.get("size"),int) or m["size"]>limit or not SHA.fullmatch(str(m.get("sha256",""))):raise NestedCuttlefishError("bounded capture failed")
  b=self._read_file(path,d,limit)
  if len(b)!=m["size"] or hashlib.sha256(b).hexdigest()!=m["sha256"]:raise NestedCuttlefishError("bounded capture readback mismatch")
  self.last_command={"argv":argv,"exit_code":m["rc"],"stdout":self._bounded_command_bytes(b),"stderr":self._bounded_command_bytes(b"")};return b,m
 def _capture(self,args,d,label,limit,command_cap=None):
  b,m=self._capture_result(args,d,label,limit,command_cap)
  if m["rc"]!=0:raise NestedCuttlefishError("bounded capture command timed out")
  return b
 @staticmethod
 def _raw(label,b):return {"origin":"guest","transport":"qga-adb","path":label,"size":len(b),"sha256":hashlib.sha256(b).hexdigest(),"bytes_b64":base64.b64encode(b).decode()}
 @staticmethod
 def _bounded_command_bytes(data):
  return {"size":len(data),"sha256":hashlib.sha256(data).hexdigest(),"bytes_b64":base64.b64encode(data).decode() if len(data)<=6144 else None,"excerpt_b64":base64.b64encode(data[:4096]).decode()}
 def _keyguard(self,d):
  argv=["shell","dumpsys","window","policy"];raw=self._capture(argv,d,"keyguard-policy",6144,10);text=raw.decode(errors="replace")
  showing=re.findall(r"(?m)^\s*showing=(true|false)\s*$",text);secure=re.findall(r"(?m)^\s*secure=(true|false)\s*$",text)
  if len(showing)!=1 or len(secure)!=1:self._app_failure("keyguard-state-ambiguous",{"keyguard_raw":{"argv":argv,"size":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"bytes_b64":base64.b64encode(raw).decode(),"showing_candidates":showing[:32],"secure_candidates":secure[:32]}},d,"app-precondition")
  return {"argv":argv,"showing":showing[0]=="true","secure":secure[0]=="true","raw":self._raw("adb:keyguard-policy",raw)}
 def _unlock(self,d):
  before=self._keyguard(d);commands=[]
  if before["secure"]:raise NestedCuttlefishError("test guest keyguard is secure")
  if before["showing"]:
   for argv in (["shell","wm","dismiss-keyguard"],["shell","input","keyevent","82"]):
    raw=self._capture(argv,d,"keyguard-command",65536,10);commands.append({"argv":argv,"exit_code":0,"raw":self._raw("adb:keyguard-command",raw)})
  after=self._keyguard(d)
  if after["secure"] or after["showing"]:raise NestedCuttlefishError("test guest keyguard remained locked")
  return {"before":before,"commands":commands,"after":after,"passed":True}
 def _package(self,version,d):
  dumpsys_argv=["shell","dumpsys","package",self.plan.apk.package]
  b=self._capture(dumpsys_argv,d,"package",XML_MAX)
  versions=[int(x) for x in re.findall(rb"versionCode=(\d+)",b)];users=[int(x) for x in re.findall(rb"userId=(\d+)",b)]
  v=re.search(rb"versionCode=(\d+)",b);u=re.search(rb"userId=(\d+)",b)
  if versions!=[version]:
   relevant=b"\n".join(line[:512] for line in b.splitlines() if b"versionCode=" in line or b"userId=" in line)[:4096]
   diagnostic={"size":len(b),"sha256":hashlib.sha256(b).hexdigest(),"version_code_candidates":versions[:32],"user_id_candidates":users[:32],"relevant_lines":relevant.decode("utf-8","replace")}
   raise NestedCuttlefishError("package version/uid readback mismatch: "+json.dumps(diagnostic,sort_keys=True,separators=(",",":")))
  uid_argv=["shell","cmd","package","list","packages","-U",self.plan.apk.package]
  uid_bytes=self._capture(uid_argv,d,"package-uid",65536);lines=[x for x in uid_bytes.decode("utf-8","strict").splitlines() if x]
  match=re.fullmatch(r"package:"+re.escape(self.plan.apk.package)+r" uid:([1-9]\d*)",lines[0]) if len(lines)==1 else None
  if not match:
   diagnostic={"size":len(uid_bytes),"sha256":hashlib.sha256(uid_bytes).hexdigest(),"line_count":len(lines),"excerpt":uid_bytes[:4096].decode("utf-8","replace")}
   raise NestedCuttlefishError("package UID readback mismatch: "+json.dumps(diagnostic,sort_keys=True,separators=(",",":")))
  uid=int(match.group(1))
  state={"version_code":int(v.group(1)),"uid":uid,"dumpsys":{"argv":dumpsys_argv,"exit_code":0,"output":self._raw("adb:dumpsys-package",b)},"uid_lookup":{"argv":uid_argv,"exit_code":0,"output":self._raw("adb:cmd-package-list-U",uid_bytes)}}
  return state,uid
 def install_baseline(self,path,timeout=420):
  if path==f"{self.plan.root}/input/{self.plan.apk.name}":raise NestedCuttlefishError("candidate direct install forbidden")
  if isinstance(timeout,bool) or not isinstance(timeout,int) or not 300<=timeout<=600:raise NestedCuttlefishError("baseline timeout")
  try:return self._install_baseline(path,timeout)
  except BaseException as exc:
   if getattr(exc,"archive_durable",False) or getattr(exc,"retain_owned_evidence",False):raise
   self._app_failure("baseline-exception",{"error_type":type(exc).__name__,"error_sha256":hashlib.sha256(str(exc).encode()).hexdigest(),"last_command":self.last_command},self.clock()+20,"app-baseline")
 def _install_baseline(self,path,timeout=420):
  d=self.clock()+timeout;self._check();r=self.qga.guest_exec_wait("/usr/bin/python3",["-c","import hashlib,json,pathlib,sys;p=pathlib.Path(sys.argv[1]);b=p.read_bytes();print(json.dumps({'size':len(b),'sha256':hashlib.sha256(b).hexdigest()}))",path],timeout=self._left(d,60));self._check()
  import json
  try:i=json.loads(r.get("stdout",""))
  except Exception as e:raise NestedCuttlefishError("baseline guest rehash missing") from e
  if i!={"size":self.baseline.size,"sha256":self.baseline.sha256}:raise NestedCuttlefishError("baseline guest bytes mismatch")
  installed=self._adb(["install","-r",path],d,180)
  if "Success" not in str(installed.get("stdout","")):raise NestedCuttlefishError("baseline install failed")
  package,uid=self._package(self.baseline.version_code,d)
  unlock=self._unlock(d);monkey_argv=["shell","monkey","-p",self.baseline.package,"1"];monkey_bytes=self._capture(monkey_argv,d,"baseline-monkey",65536);monkey={"argv":monkey_argv,"exit_code":0,"output":self._raw("adb:baseline-monkey",monkey_bytes)}
  top_pid,top_uid,pkg,activity,focus=self._focus((self.baseline.package,),d);pid=str(self._adb(["shell","pidof",self.baseline.package],d).get("stdout","")).strip()
  if not re.fullmatch(r"[1-9]\d*",pid) or pid!=top_pid or uid!=int(top_uid):raise NestedCuttlefishError("baseline package PID/UID differs from activity top")
  wid="activity-top:"+top_pid
  return {"schema":2,"operation":"nested-baseline-setup","run_id":self.plan.ownership.run_id,"profile":self.plan.ownership.profile,
   "attempt_nonce":self.plan.ownership.attempt_nonce,"marker":self.plan.marker,"guest_root":self.plan.root,
   "outer_ownership":asdict(self.plan.ownership),"origin":"guest","transport":"qga","injected":False,
   "artifact":asdict(self.baseline),"guest_path":path,"guest_rehash":i,"adb_install":{"exit_code":0,"stdout_success":True},
   "package_state":package,"ui":{"package":pkg,"activity":activity,"window_id":wid,"package_pid":int(pid),"package_uid":uid,
   "version_code":self.baseline.version_code,"keyguard":unlock,"launch_probe":monkey,"focus_observations":focus},"direct_install_is_update_evidence":False,"passed":True}
 def _focus(self,allowed,d):
  argv=["shell","dumpsys","activity","top-resumed"];deadline=min(d,self.clock()+45);observations=[]
  for _ in range(3):
   try:
    raw,meta=self._capture_result(argv,deadline,"activity-top",6144,10);text=raw.decode(errors="replace")
   except BaseException as exc:
    diagnostic={"allowed":list(allowed),"observation_count":len(observations),"last":observations[-1] if observations else None,"capture_error":{"type":type(exc).__name__,"sha256":hashlib.sha256(str(exc).encode()).hexdigest()}}
    raise NestedCuttlefishError("foreground activity-top mismatch: "+json.dumps(diagnostic,sort_keys=True,separators=(",",":"))) from exc
   relevant="\n".join(line[:1024] for line in text.splitlines() if line.lstrip().startswith("ACTIVITY "))[:4096]
   matches=re.findall(r"(?m)^\s*ACTIVITY ([^/ \t]+)/([^ \t]+).*?\bpid=([1-9]\d*)\b.*?\buid=([1-9]\d*)\b",text) if meta["rc"]==0 else []
   row={"argv":argv,"exit_code":meta["rc"],"timed_out":meta["rc"]==124,"size":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"relevant_lines":relevant,"matches":[{"package":x[0],"component":x[1],"pid":int(x[2]),"uid":int(x[3])} for x in matches[:32]]}
   observations.append(row)
   if len(matches)>1:return self._focus_failure("ambiguous",allowed,observations,raw,d)
   if len(matches)==1:
    package,component,pid,uid=matches[0]
    if package not in allowed:return self._focus_failure("package-mismatch",allowed,observations,raw,d)
    return pid,uid,package,component,observations
   if self.clock()>=deadline:break
   self.sleep(min(1,self._left(deadline,1)))
  return self._focus_failure("no-authoritative-record",allowed,observations,raw if 'raw' in locals() else b"",d)
 def _focus_failure(self,reason,allowed,observations,raw,d):
  diagnostic={"allowed":list(allowed),"observation_count":len(observations),"last":observations[-1] if observations else None,"top_resumed_raw":{"size":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"bytes_b64":base64.b64encode(raw).decode()}}
  return self._app_failure(reason,diagnostic,d,"app-focus")
 def _app_failure(self,reason,diagnostic,d,phase):
  shot={"attempted":True};remaining=max(0,d-self.clock())
  try:
   png,meta=self._capture_result(["exec-out","screencap","-p"],self.clock()+min(15,max(1,remaining)),"focus-failure-screen",4194304,10)
   shot={"attempted":True,"exit_code":meta["rc"],"size":len(png),"sha256":hashlib.sha256(png).hexdigest(),"png_signature":png.startswith(b"\x89PNG\r\n\x1a\n")}
  except BaseException as exc:shot={"attempted":True,"error_type":type(exc).__name__,"error_sha256":hashlib.sha256(str(exc).encode()).hexdigest()}
  diagnostic={**diagnostic,"reason":reason,"screencap":shot}
  record={"schema":1,"outer_failure":"nested-boot","run_id":self.plan.ownership.run_id,"attempt_nonce":self.plan.ownership.attempt_nonce,"outer_ownership":asdict(self.plan.ownership),"last_probe":diagnostic,"qemu_seen":True,"phase":phase}
  try:ack=self.failure_archive(record,png if shot.get("png_signature") is True else None)
  except BaseException as exc:
   error=NestedCuttlefishError("app focus failure archive failed");setattr(error,"retain_owned_evidence",True);error.add_note("inner cleanup pending because no durable app-focus archive");raise error from exc
  image=ack.get("screenshot") if isinstance(ack,Mapping) else None
  if (not isinstance(ack,Mapping) or ack.get("origin")!="controller" or ack.get("immutable") is not True or not SHA.fullmatch(str(ack.get("sha256",""))) or not isinstance(ack.get("size"),int) or ack["size"]<=0
      or (shot.get("png_signature") is True and (not isinstance(image,Mapping) or image.get("sha256")!=shot["sha256"] or image.get("size")!=shot["size"] or not image.get("path")))):
   error=NestedCuttlefishError("app focus failure archive rejected");setattr(error,"retain_owned_evidence",True);error.add_note("inner cleanup pending because no durable app-focus archive");raise error
  error=NestedCuttlefishError(("foreground activity-top mismatch: " if phase=="app-focus" else "app precondition failed: ")+json.dumps(diagnostic,sort_keys=True,separators=(",",":")));setattr(error,"archive_durable",True);raise error
 def _tap(self,text,allowed,d):
  remote=f"/data/local/tmp/amz-{self.plan.ownership.attempt_nonce[:12]}.xml"
  while self.clock()<d:
   unlock=self._unlock(d);self._focus(allowed,d);self._adb(["shell","uiautomator","dump","--compressed",remote],d,20);x=self._capture(["shell","cat",remote],d,f"ui-{text.lower()}",XML_MAX).decode(errors="replace")
   nodes=[n for n in re.findall(r"<node\b[^>]+>",x) if f'text="{text}"' in n and any(f'package="{p}"' in n for p in allowed)]
   m=re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',nodes[0]) if len(nodes)==1 else None
   if m:
    a,b,c,e=map(int,m.groups());self._adb(["shell","input","tap",str((a+c)//2),str((b+e)//2)],d);return unlock
   self.sleep(min(1,self._left(d,1)))
  raise NestedCuttlefishError(f"bounded UI wait expired: {text}")
 def _tap_any(self,texts,allowed,d):
  remote=f"/data/local/tmp/amz-{self.plan.ownership.attempt_nonce[:12]}.xml";deadline=min(d,self.clock()+30)
  while self.clock()<deadline:
   unlock=self._unlock(deadline);self._focus(allowed,deadline);self._adb(["shell","uiautomator","dump","--compressed",remote],deadline,20);x=self._capture(["shell","cat",remote],deadline,"ui-completion",XML_MAX).decode(errors="replace")
   found=[]
   for text in texts:
    nodes=[n for n in re.findall(r"<node\b[^>]+>",x) if f'text="{text}"' in n and any(f'package="{p}"' in n for p in allowed)]
    if len(nodes)==1:found.append((text,nodes[0]))
   if len(found)>1:raise NestedCuttlefishError("ambiguous completion action")
   m=re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',found[0][1]) if len(found)==1 else None
   if m:
    a,b,c,e=map(int,m.groups());self._adb(["shell","input","tap",str((a+c)//2),str((b+e)//2)],deadline);return found[0][0],unlock
   self.sleep(min(1,self._left(deadline,1)))
  raise NestedCuttlefishError("bounded UI completion wait expired")
 @staticmethod
 def _sessions(s):return {int(x) for x in re.findall(r"(?:sessionId=|Session\{[^#]*#)(\d+)",s)}
 def _stop(self,d):
  errors=[]
  for a in (["shell","am","force-stop",self.plan.apk.package],["shell","rm","-f",f"/data/local/tmp/amz-{self.plan.ownership.attempt_nonce[:12]}.xml",f"/data/local/tmp/amz-{self.plan.ownership.attempt_nonce[:12]}.png"]):
   try:self._adb(a,d)
   except BaseException as e:errors.append(str(e))
  r=self._fx("stop",d)
  if errors or r.get("identity_rechecked") is not True or r.get("stopped") is not True or r.get("listener_closed") is not True or r.get("unknown_survivors")!=[] or not SHA.fullmatch(str(r.get("request_log_sha256",""))):raise NestedCuttlefishError("app/fixture cleanup uncertain")
  return r
 def run_update(self,timeout=180):
  if isinstance(timeout,bool) or not 60<=timeout<=300:raise NestedCuttlefishError("update timeout")
  d=self.clock()+timeout;started=False;primary=None
  try:
   started=True;s=self._fx("start",d)
   if s.get("ready") is not True or s.get("identity_rechecked") is not True:raise NestedCuttlefishError("fixture start receipt")
   z=self._fx("reset",d)
   if (isinstance(z.get("log_inode"),bool) or not isinstance(z.get("log_inode"),int) or z["log_inode"]<=0 or z.get("offset")!=0
       or not re.fullmatch(r"[0-9a-f]{48}",str(z.get("reset_token",""))) or z.get("empty_sha256")!=hashlib.sha256(b"").hexdigest()
       or not isinstance(z.get("reset_at"),(int,float)) or isinstance(z.get("reset_at"),bool) or not math.isfinite(z["reset_at"])):raise NestedCuttlefishError("fixture reset receipt")
   reset_sha=receipt_sha(z)
   epoch=str(self._adb(["shell","date","+%s.%3N"],d).get("stdout","")).strip()
   if not re.fullmatch(r"\d{10,}(?:\.\d{3})?",epoch):raise NestedCuttlefishError("logcat start time missing")
   before=self._sessions(self._capture(["shell","dumpsys","package","installer"],d,"installer-before",XML_MAX).decode(errors="replace"));installer_unlock=self._unlock(d);self._adb(["shell","monkey","-p",self.plan.apk.package,"1"],d)
   update_unlock=self._tap("Update",(self.plan.apk.package,),d);install_unlock=self._tap("Install",INSTALLERS,d)
   completion_action,completion_unlock=self._tap_any(("Done","Open"),INSTALLERS,d)
   package,uid=self._package(self.plan.apk.version_code,d);ins=self._capture(["shell","dumpsys","package","installer"],d,"installer-after",XML_MAX).decode(errors="replace")
   log=self._capture(["logcat","-d","-T",epoch,"-v","threadtime","PackageInstaller:I","PackageManager:I","AndroidRuntime:E","*:S"],d,"logcat",LOG_MAX)
   created=self._sessions(ins+log.decode(errors="replace"))-before;ok={int(x) for x in re.findall(r"session(?:Id)?[ =:#]+(\d+).*?(?:STATUS_SUCCESS|INSTALL_SUCCEEDED|success)",log.decode(errors="replace"),re.I)};sessions=created&ok
   if len(sessions)!=1 or re.search(rb"FATAL EXCEPTION|Fatal signal.*amnezia",log,re.I):raise NestedCuttlefishError("unique successful PackageInstaller session missing")
   launch_unlock=self._unlock(d);monkey_argv=["shell","monkey","-p",self.plan.apk.package,"1"];monkey_bytes=self._capture(monkey_argv,d,"candidate-monkey",65536);monkey={"argv":monkey_argv,"exit_code":0,"output":self._raw("adb:candidate-monkey",monkey_bytes)};top_pid,top_uid,pkg,activity,focus=self._focus((self.plan.apk.package,),d);pid=str(self._adb(["shell","pidof",self.plan.apk.package],d).get("stdout","")).strip()
   if not re.fullmatch(r"[1-9]\d*",pid) or pid!=top_pid or uid!=int(top_uid):raise NestedCuttlefishError("package PID/UID differs from activity top")
   wid="activity-top:"+top_pid
   remote=f"/data/local/tmp/amz-{self.plan.ownership.attempt_nonce[:12]}.png";local=f"{self.plan.root}/evidence/app.png";self._adb(["shell","screencap","-p",remote],d);self._adb(["pull",remote,local],d,60);png=self._read_file(local,d,PNG_MAX)
   if len(png)>PNG_MAX or not png.startswith(b"\x89PNG\r\n\x1a\n"):raise NestedCuttlefishError("screenshot invalid/oversized")
   h=self._fx("read-log",d);rows=h.get("requests");expected=[(self.fixture.manifest_path,self.fixture.manifest_sha256,self.fixture.manifest_size),(self.fixture.artifact_path,self.plan.apk.sha256,self.plan.apk.size)]
   times=[x.get("observed_at") for x in rows] if isinstance(rows,list) else []
   if (h.get("reset_receipt_sha256")!=reset_sha or h.get("reset_token")!=z["reset_token"] or h.get("log_inode")!=z["log_inode"] or h.get("start_offset")!=0
       or not isinstance(h.get("finished_at"),(int,float)) or isinstance(h.get("finished_at"),bool) or not math.isfinite(h["finished_at"]) or not isinstance(rows,list)
       or [(x.get("path"),x.get("sha256"),x.get("bytes")) for x in rows]!=expected
       or not all(x.get("method")=="GET" and x.get("status")==200 and x.get("content_length")==x.get("bytes") and x.get("eof") is True and x.get("peer") and isinstance(x.get("observed_at"),(int,float)) and not isinstance(x.get("observed_at"),bool) and math.isfinite(x["observed_at"]) for x in rows)
       or times!=sorted(times) or not (z["reset_at"]<=times[0]<=times[-1]<=h["finished_at"])
       or h.get("transcript_sha256")!=receipt_sha({"reset_receipt_sha256":reset_sha,"requests":rows})):raise NestedCuttlefishError("exact app HTTP transcript missing")
   keyguards=[{"phase":phase,"receipt":value} for phase,value in (("installer-monkey",installer_unlock),("update-tap",update_unlock),("install-tap",install_unlock),("completion-tap",completion_unlock),("launch-monkey",launch_unlock))]
   v={"schema":2,"operation":"nested-cuttlefish-app-update","run_id":self.plan.ownership.run_id,"profile":self.plan.ownership.profile,"attempt_nonce":self.plan.ownership.attempt_nonce,"marker":self.plan.marker,"guest_root":self.plan.root,"outer_ownership":asdict(self.plan.ownership),"origin":"guest","transport":"qga","injected":False,"boot_binding_sha256":receipt_sha(self.boot),"package_installer":{"package":self.plan.apk.package,"version_code":self.plan.apk.version_code,"artifact_sha256":self.plan.apk.sha256,"artifact_size":self.plan.apk.size,"download_sha256":self.plan.apk.sha256,"session_id":next(iter(sessions)),"status":"STATUS_SUCCESS","method":"PackageInstaller"},"http":{"fixture_nonce":self.fixture.attempt_nonce,"manifest_sha256":self.fixture.manifest_sha256,"requests":rows,"fixture_receipt_sha256":receipt_sha(h)},"ui":{"package":pkg,"activity":activity,"window_id":wid,"window_title":pkg,"package_pid":int(pid),"package_uid":uid,"version_code":self.plan.apk.version_code,"screenshot_sha256":hashlib.sha256(png).hexdigest(),"package_state":package,"keyguard":keyguards,"completion_action":completion_action,"launch_probe":monkey,"focus_observations":focus},"logcat":{"started_at":epoch,"finished_at":str(h.get("finished_at","")),"sha256":hashlib.sha256(log).hexdigest(),"size":len(log),"crashes":[]},"passed":True}
   return validate_app_update_receipt(self.plan,self.boot,v)
  except BaseException as e:
   if getattr(e,"archive_durable",False) or getattr(e,"retain_owned_evidence",False):primary=e;raise
   try:self._app_failure("update-exception",{"error_type":type(e).__name__,"error_sha256":hashlib.sha256(str(e).encode()).hexdigest(),"last_command":self.last_command},self.clock()+20,"app-update")
   except BaseException as archived:primary=archived;raise
  finally:
   if started and not getattr(primary,"retain_owned_evidence",False):
    try:self._stop(self.clock()+30)
    except BaseException as e:
     if primary is None:raise
     primary.add_note(f"fixture cleanup also failed: {e}")
 def cleanup(self,timeout=60):return {"fixture_stop":self._stop(self.clock()+timeout),"owned_remote_files_removed":True}
