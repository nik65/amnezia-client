"""Fail-closed QGA/ADB executor for nested Cuttlefish UI updates."""
from __future__ import annotations
import base64,hashlib,ipaddress,json,math,re,time
from dataclasses import asdict,dataclass
from typing import Any,Callable,Mapping
from urllib.parse import quote,urlparse
try:
 from .nested_cuttlefish_runner import ApkSpec,InnerPlan,NestedCuttlefishError,OuterOwnership,receipt_sha,validate_app_update_receipt,validate_baseline_receipt,validate_boot_receipt
except ImportError:  # direct lab.py execution
 from nested_cuttlefish_runner import ApkSpec,InnerPlan,NestedCuttlefishError,OuterOwnership,receipt_sha,validate_app_update_receipt,validate_baseline_receipt,validate_boot_receipt

SHA=re.compile(r"[0-9a-f]{64}"); XML_MAX=1<<20; LOG_MAX=2<<20; PNG_MAX=16<<20
INSTALLERS=("com.android.packageinstaller","com.google.android.packageinstaller","com.android.permissioncontroller")

def _parse_focus_text(text):
 matches=[];legacy=re.findall(r"(?m)^\s*ACTIVITY ([^/ \t]+)/([^ \t]+).*?\bpid=([1-9]\d*)\b.*?\buid=([1-9]\d*)\b",text)
 packages=re.findall(r"\bpackageName=([^\s]+)",text);components=re.findall(r"\bmActivityComponent=([^/\s]+)/([^\s]+)",text);processes=re.findall(r"(?m)^\s*app=ProcessRecord\{[^}]*\s([1-9]\d*):([^/\s]+)/u(\d+)a(\d+)\}\s*$",text)
 states=re.findall(r"(?m)^\s*state=([A-Z_]+)\s+finishing=(true|false)\s*$",text);visible_requested=re.findall(r"\bmVisibleRequested=(true|false)\b",text);visible_now=re.findall(r"\bmVisible=(true|false)\b",text);client_visible=re.findall(r"\bmClientVisible=(true|false)\b",text);reported_visible=re.findall(r"\breportedVisible=(true|false)\b",text)
 first=re.findall(r"\bfirstWindowDrawn=(true|false)\b",text);reported=re.findall(r"\breportedDrawn=(true|false)\b",text);starting=re.findall(r"\bstartingDisplayed=(true|false)\b",text);starting_data=re.findall(r"\bstartingData=([^\s]+)",text);starting_objects=bool(re.search(r"\bstarting(?:Window|Surface)=",text))
 if legacy:return [{"package":x[0],"component":x[1],"pid":int(x[2]),"uid":int(x[3]),"format":"activity","state":"RESUMED","finishing":False,"visible":True,"drawn":False,"starting_displayed":False} for x in legacy[:32]]
 if all(len(x)==1 for x in (packages,components,processes,states,visible_requested,visible_now,client_visible,reported_visible,first,reported,starting_data)) and ((starting_data==["null"] and not starting_objects and not starting) or (starting_data!=["null"] and starting_objects and len(starting)==1)):
  package=packages[0];component_package,component=components[0];pid,process_package,user,app_id=processes[0]
  if package==component_package==process_package:matches=[{"package":package,"component":component,"pid":int(pid),"uid":int(user)*100000+10000+int(app_id),"format":"key-value","state":states[0][0],"finishing":states[0][1]=="true","visible":visible_requested==visible_now==client_visible==reported_visible==["true"],"drawn":first[0]==reported[0]=="true","starting_displayed":starting==["true"]}]
 return matches

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
 def __init__(self,qga:Any,plan:InnerPlan,boot_receipt:Mapping[str,Any],baseline:ApkSpec,fixture:AppFixture,outer_live_snapshot:Callable[[],OuterOwnership],fixture_outer_snapshot:Callable[[],Mapping[str,Any]],fixture_call:Callable[[str,Mapping[str,Any],float],Mapping[str,Any]],*,failure_archive:Callable[[Mapping[str,Any]],Mapping[str,Any]]|None=None,visual_request=None,visual_poll=None,clock=time.monotonic,sleep=time.sleep):
  plan.validate();validate_boot_receipt(plan,boot_receipt);baseline.validate();fixture.validate(plan)
  if baseline.package!=plan.apk.package or baseline.sha256==plan.apk.sha256:raise NestedCuttlefishError("baseline identity")
  self.qga,self.plan,self.boot,self.baseline,self.fixture,self.snapshot,self.fixture_snapshot,self.fixture_call=qga,plan,dict(boot_receipt),baseline,fixture,outer_live_snapshot,fixture_outer_snapshot,fixture_call
  self.clock,self.sleep,self.failure_archive=clock,sleep,failure_archive;self.visual_request,self.visual_poll=visual_request,visual_poll;self.adb=f"{plan.root}/runtime/host/bin/adb";self.serial=self.boot["network"]["adb_connection"]["endpoint"];self.capture_seq=0;self.visual_seq=0;self.last_command=None;self.focus_observation_history=[];self.ui_capture_history=[];self.visual_history=[];self._diagnostic_capture=False;self.native_crash_evidence=None;self.current_launch_epoch=None
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
 def _launch_once(self,package,d,label,path):
  argv=["shell","monkey","-p",package,"1"];data,meta=self._capture_result(argv,d,label,65536,30)
  if meta["rc"] not in (0,124):raise NestedCuttlefishError("single app launch command failed")
  return {"argv":argv,"exit_code":meta["rc"],"timed_out":meta["rc"]==124,"output":self._raw(path,data)}
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
 def _read_prefix(self,path,d,limit=4096):
  opened=self._request("guest-file-open",{"path":path,"mode":"r"},d);handle=opened.get("return") if isinstance(opened,Mapping) else None
  if isinstance(handle,bool) or not isinstance(handle,int):raise NestedCuttlefishError("QGA evidence prefix open failed")
  primary=None
  try:
   r=self._request("guest-file-read",{"handle":handle,"count":limit},d);v=r.get("return",{}) if isinstance(r,Mapping) else {}
   try:return base64.b64decode(v.get("buf-b64",""),validate=True)[:limit]
   except Exception as exc:raise NestedCuttlefishError("QGA evidence prefix invalid") from exc
  except BaseException as exc:primary=exc;raise
  finally:
   try:self._request("guest-file-close",{"handle":handle},self.clock()+10)
   except BaseException as close_error:
    if primary is None:raise
    primary.add_note(f"QGA evidence prefix close also failed: {close_error}")
 def _capture_result(self,args,d,label,limit,command_cap=None):
  self.capture_seq+=1;path=f"{self.plan.root}/evidence/{self.plan.ownership.attempt_nonce[:12]}-{self.capture_seq:02d}-{label}"
  code="""import hashlib,json,os,pathlib,resource,subprocess,sys
argv=json.loads(sys.argv[1]);p=pathlib.Path(sys.argv[2]);ep=pathlib.Path(str(p)+'.stderr');limit=int(sys.argv[3]);p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);efd=os.open(ep,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
def bound(): resource.setrlimit(resource.RLIMIT_FSIZE,(limit+1,limit+1))
rc=125
try:
 try: rc=subprocess.run(argv,stdout=fd,stderr=efd,timeout=float(sys.argv[4]),preexec_fn=bound).returncode
 except subprocess.TimeoutExpired: rc=124
finally: os.close(fd);os.close(efd)
b=p.read_bytes();e=ep.read_bytes();print(json.dumps({'path':str(p),'size':len(b),'sha256':hashlib.sha256(b).hexdigest(),'stderr_path':str(ep),'stderr_size':len(e),'stderr_sha256':hashlib.sha256(e).hexdigest(),'rc':rc},separators=(',',':')))
"""
  remaining=self._left(d);inner=max(.1,remaining-5) if command_cap is None else min(float(command_cap),max(.1,remaining-5));outer=min(remaining,inner+5)
  argv=[self.adb,"-P",self.plan.adb_endpoint.rsplit(":",1)[1],"-s",self.serial,*args];self._check();r=self.qga.guest_exec_wait("/usr/bin/python3",["-c",code,json.dumps(argv,separators=(",",":")),path,str(limit),str(inner)],timeout=outer);self._check()
  transport_stdout=str(r.get("stdout","")).encode() if isinstance(r,Mapping) else b"";transport_stderr=str(r.get("stderr","")).encode() if isinstance(r,Mapping) else b"";transport_rc=r.get("exitcode",r.get("exit_code")) if isinstance(r,Mapping) else None
  self.last_command={"argv":argv,"exit_code":transport_rc,"capture_transport":{"stdout":self._bounded_command_bytes(transport_stdout),"stderr":self._bounded_command_bytes(transport_stderr)}}
  try:m=json.loads(transport_stdout.decode("utf-8","replace"))
  except Exception as e:raise NestedCuttlefishError("bounded capture receipt missing") from e
  if (not isinstance(m,Mapping) or m.get("path")!=path or m.get("stderr_path")!=path+".stderr" or not isinstance(m.get("size"),int) or isinstance(m.get("size"),bool) or m["size"]<0 or not isinstance(m.get("stderr_size"),int) or isinstance(m.get("stderr_size"),bool) or m["stderr_size"]<0 or not SHA.fullmatch(str(m.get("sha256",""))) or not SHA.fullmatch(str(m.get("stderr_sha256","")))):raise NestedCuttlefishError("bounded capture metadata invalid")
  self.last_command["capture_metadata"]={"path":path,"exit_code":m.get("rc"),"timed_out":m.get("rc")==124,"size":m["size"],"sha256":m["sha256"]}
  if m["size"]>limit:
   prefix=self._read_prefix(path,d);self.last_command["stdout"]={"size":m["size"],"sha256":m["sha256"],"bytes_b64":None,"excerpt_b64":base64.b64encode(prefix).decode(),"excerpt_size":len(prefix),"excerpt_sha256":hashlib.sha256(prefix).hexdigest(),"complete":False};self.last_command["stderr"]=self._bounded_command_bytes(b"")
   raise NestedCuttlefishError("bounded capture output exceeds limit")
  b=self._read_file(path,d,limit);stderr=self._read_file(path+".stderr",d,limit) if m["stderr_size"] else b"";self.last_capture_stderr=stderr
  self.last_command.update(exit_code=m.get("rc"),stdout=self._bounded_command_bytes(b),stderr=self._bounded_command_bytes(stderr))
  if len(b)!=m["size"] or hashlib.sha256(b).hexdigest()!=m["sha256"] or len(stderr)!=m["stderr_size"] or hashlib.sha256(stderr).hexdigest()!=m["stderr_sha256"]:raise NestedCuttlefishError("bounded capture readback mismatch")
  if isinstance(transport_rc,bool) or not isinstance(transport_rc,int) or transport_rc!=0:raise NestedCuttlefishError("bounded capture transport exit invalid")
  if isinstance(m.get("rc"),bool) or not isinstance(m.get("rc"),int) or (not self._diagnostic_capture and m["rc"] not in (0,124)):raise NestedCuttlefishError("bounded capture command exit invalid")
  return b,m
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
  argv=["shell","dumpsys","window","policy"];attempts=[]
  for index in range(3):
   raw,meta=self._capture_result(argv,d,"keyguard-policy",6144,10);attempts.append({"exit_code":meta["rc"],"timed_out":meta["rc"]==124,"raw":self._raw("adb:keyguard-policy",raw)})
   if meta["rc"]==0:break
   if meta["rc"]!=124:self._app_failure("keyguard-policy-command-failed",{"keyguard_attempts":attempts},d,"app-precondition")
   if index<2 and self.clock()<d:self.sleep(min(.5,max(0,d-self.clock())))
  if attempts[-1]["exit_code"]!=0:self._app_failure("keyguard-policy-timeout",{"keyguard_attempts":attempts},d,"app-precondition")
  text=raw.decode(errors="replace")
  showing=re.findall(r"(?m)^\s*showing=(true|false)\s*$",text);restricted=re.findall(r"(?m)^\s*inputRestricted=(true|false)\s*$",text)
  if len(showing)!=1 or len(restricted)!=1:self._app_failure("keyguard-state-ambiguous",{"keyguard_raw":{"argv":argv,"size":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"bytes_b64":base64.b64encode(raw).decode(),"showing_candidates":showing[:32],"input_restricted_candidates":restricted[:32]}},d,"app-precondition")
  return {"argv":argv,"showing":showing[0]=="true","input_restricted":restricted[0]=="true","raw":self._raw("adb:keyguard-policy",raw),"attempts":attempts}
 def _unlock(self,d):
  before=self._keyguard(d);commands=[]
  after_dismiss=None;after=before
  if before["showing"]:
   if d-self.clock()<43:raise NestedCuttlefishError("insufficient deadline for dismiss and policy proof")
   dismiss=["shell","wm","dismiss-keyguard"];raw,meta=self._capture_result(dismiss,d,"keyguard-command",65536,10);commands.append({"argv":dismiss,"exit_code":meta["rc"],"timed_out":meta["rc"]==124,"raw":self._raw("adb:keyguard-command",raw)})
   if meta["rc"] not in (0,124):raise NestedCuttlefishError("keyguard dismiss command invalid")
   after_deadline=min(d,self.clock()+32);after_dismiss=self._keyguard(after_deadline);after=after_dismiss
   if after["showing"] or after["input_restricted"]:
    if d-self.clock()<63:raise NestedCuttlefishError("insufficient deadline for menu and policy proof")
    menu=["shell","input","keyevent","82"];raw,meta=self._capture_result(menu,d,"keyguard-command",65536,30);commands.append({"argv":menu,"exit_code":meta["rc"],"timed_out":meta["rc"]==124,"raw":self._raw("adb:keyguard-command",raw)})
    if meta["rc"] not in (0,124):raise NestedCuttlefishError("keyguard menu command invalid")
    after_deadline=min(d,self.clock()+32);after=self._keyguard(after_deadline)
  after_deadline=min(d,self.clock()+32)
  for _ in range(9):
   if not after["showing"] and not after["input_restricted"]:break
   self.sleep(min(.5,max(0,after_deadline-self.clock())));after=self._keyguard(after_deadline)
  if after["showing"] or after["input_restricted"]:raise NestedCuttlefishError("test guest keyguard remained locked")
  return {"before":before,"after_dismiss":after_dismiss,"commands":commands,"after":after,"passed":True}
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
  try:return validate_baseline_receipt(self.plan,self.baseline,self._install_baseline(path,timeout))
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
  unlock=self._unlock(d);launch_epoch=str(self._adb(["shell","date","+%s.%3N"],d).get("stdout","")).strip()
  if not re.fullmatch(r"\d{10,}(?:\.\d{3})?",launch_epoch):raise NestedCuttlefishError("baseline launch epoch missing")
  monkey=self._launch_once(self.baseline.package,d,"baseline-monkey","adb:baseline-monkey")
  top_pid,top_uid,pkg,activity,focus=self._focus((self.baseline.package,),d,initial_draw=True,lifecycle_epoch=launch_epoch);pid=str(self._adb(["shell","pidof",self.baseline.package],d).get("stdout","")).strip()
  if not re.fullmatch(r"[1-9]\d*",pid) or pid!=top_pid or uid!=int(top_uid):raise NestedCuttlefishError("baseline package PID/UID differs from activity top")
  wid="activity-top:"+top_pid
  return {"schema":2,"operation":"nested-baseline-setup","run_id":self.plan.ownership.run_id,"profile":self.plan.ownership.profile,
   "attempt_nonce":self.plan.ownership.attempt_nonce,"marker":self.plan.marker,"guest_root":self.plan.root,
   "outer_ownership":asdict(self.plan.ownership),"origin":"guest","transport":"qga","injected":False,
   "artifact":asdict(self.baseline),"guest_path":path,"guest_rehash":i,"adb_install":{"exit_code":0,"stdout_success":True},
   "package_state":package,"ui":{"package":pkg,"activity":activity,"window_id":wid,"package_pid":int(pid),"package_uid":uid,
   "version_code":self.baseline.version_code,"keyguard":unlock,"launch_started_at":launch_epoch,"launch_probe":monkey,"focus_observations":focus},"direct_install_is_update_evidence":False,"passed":True}
 def _focus(self,allowed,d,initial_draw=False,lifecycle_epoch=None,max_observations=None,reserve_seconds=30):
  if lifecycle_epoch is None:lifecycle_epoch=str(self._adb(["shell","date","+%s.%3N"],d).get("stdout","")).strip()
  if not re.fullmatch(r"\d{10,}(?:\.\d{3})?",str(lifecycle_epoch)):raise NestedCuttlefishError("focus lifecycle epoch missing")
  self.current_launch_epoch=str(lifecycle_epoch)
  argv=["shell","dumpsys","activity","top-resumed"];started=self.clock();deadline=d-reserve_seconds if initial_draw else min(d,started+45);observations=[];splash_pid=None
  limit=max_observations if max_observations is not None else (32 if initial_draw else 3)
  if not isinstance(limit,int) or isinstance(limit,bool) or not 1<=limit<=32 or deadline<=started:raise NestedCuttlefishError("insufficient deadline for foreground readiness proof")
  for _ in range(limit):
   try:
    raw,meta=self._capture_result(argv,deadline,"activity-top",6144,10);text=raw.decode(errors="replace")
   except BaseException as exc:
    diagnostic={"allowed":list(allowed),"observation_count":len(observations),"last":observations[-1] if observations else None,"capture_error":{"type":type(exc).__name__,"sha256":hashlib.sha256(str(exc).encode()).hexdigest()}}
    raise NestedCuttlefishError("foreground activity-top mismatch: "+json.dumps(diagnostic,sort_keys=True,separators=(",",":"))) from exc
   keep=("ACTIVITY ","packageName=","app=ProcessRecord{","Intent {","mActivityComponent=","state=","mVisibleRequested=","firstWindowDrawn=","reportedDrawn=","startingData=","startingWindow=","startingSurface=","startingDisplayed=","Splash Screen")
   relevant="\n".join(line[:1024] for line in text.splitlines() if any(token in line.lstrip() for token in keep))[:4096]
   matches=_parse_focus_text(text) if meta["rc"]==0 else []
   def diagnostic(argv,label,maximum,cap):
    try:
     data,result=self._capture_result(argv,deadline,label,maximum,cap);return {"argv":argv,"exit_code":result["rc"],"timed_out":result["rc"]==124,"output":self._raw("adb:"+label,data)}
    except BaseException as exc:
     command=json.loads(json.dumps(self.last_command));return {"argv":argv,"capture_error":{"type":type(exc).__name__,"sha256":hashlib.sha256(str(exc).encode()).hexdigest()},"command":command}
   pidof_argv=["shell","pidof",allowed[0]];pidof=diagnostic(pidof_argv,"focus-pidof",4096,5)
   lifecycle_argv=["shell","logcat","-d","-T",str(lifecycle_epoch),"-t","200","-v","threadtime","-b","main","-b","system","-b","events","-b","crash","ActivityManager:I","ActivityTaskManager:I","AndroidRuntime:E","lmkd:I","lowmemorykiller:I","*:S"];lifecycle=diagnostic(lifecycle_argv,"focus-lifecycle",65536,5)
   row={"argv":argv,"exit_code":meta["rc"],"timed_out":meta["rc"]==124,"size":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"raw":self._raw("adb:activity-top-resumed",raw),"relevant_lines":relevant,"matches":matches,"elapsed_ms":max(0,int((self.clock()-started)*1000)),"pidof":pidof,"lifecycle":lifecycle,"logcat":None}
   if len(self.focus_observation_history)>=56:raise NestedCuttlefishError("focus observation history exceeds bound")
   observations.append(row);self.focus_observation_history.append(row)
   if len(matches)>1:return self._focus_failure("ambiguous",allowed,observations,raw,d)
   if len(matches)==1:
    match=matches[0];package,component,pid,uid=match["package"],match["component"],str(match["pid"]),str(match["uid"])
    if package not in allowed:return self._focus_failure("package-mismatch",allowed,observations,raw,d)
    if match["state"]!="RESUMED" or match["finishing"] is not False:return self._focus_failure("foreground-state-loss",allowed,observations,raw,d)
    active_start=re.findall(r"\bstartingData=([^\s]+)",text)!=["null"]
    if active_start:
     if match["drawn"] is not False:return self._focus_failure("starting-window-already-drawn",allowed,observations,raw,d)
    elif match["drawn"] is not True or match["starting_displayed"] is not False:return self._focus_failure("non-drawn-without-starting-window",allowed,observations,raw,d)
    if active_start or match["visible"] is not True:
     if splash_pid is None:splash_pid=match["pid"]
     elif splash_pid!=match["pid"]:
      self._collect_native_crash(splash_pid,match["pid"],lifecycle_epoch,d);return self._focus_failure("splash-process-changed",allowed,observations,raw,d)
     largv=["shell","logcat","-d","-t","40"]
     try:
      log,logmeta=self._capture_result(largv,deadline,"focus-progress-logcat",32768,5);logtext=log.decode("utf-8","replace");fatal=any(token in logtext for token in ("FATAL EXCEPTION","Fatal signal","Process org.amnezia.vpn has died"))
      row["logcat"]={"argv":largv,"exit_code":logmeta["rc"],"size":len(log),"sha256":hashlib.sha256(log).hexdigest(),"fatal":fatal,"relevant_lines":"\n".join(line[:1024] for line in logtext.splitlines() if any(token in line for token in (*allowed,"FATAL EXCEPTION","Fatal signal")))[:4096]}
     except BaseException as exc:return self._focus_failure("splash-logcat-capture-failed",allowed,observations,raw,d)
     if fatal:return self._focus_failure("splash-process-fatal",allowed,observations,raw,d)
     if self.clock()>=deadline:break
     self.sleep(min(1,self._left(deadline,1)));continue
    if splash_pid is not None and splash_pid!=match["pid"]:
     self._collect_native_crash(splash_pid,match["pid"],lifecycle_epoch,d);return self._focus_failure("process-changed-after-splash",allowed,observations,raw,d)
    return pid,uid,package,component,observations
   if splash_pid is not None:self._collect_native_crash(splash_pid,None,lifecycle_epoch,d)
   if self.clock()>=deadline:break
   self.sleep(min(1,self._left(deadline,1)))
  return self._focus_failure("no-authoritative-record",allowed,observations,raw if 'raw' in locals() else b"",d)
 def _focus_failure(self,reason,allowed,observations,raw,d):
  logcat={"attempted":True};argv=["shell","logcat","-d","-t","200"]
  try:
   data,meta=self._capture_result(argv,min(d,self.clock()+15),"focus-failure-logcat",65536,10);text=data.decode("utf-8","replace")
   relevant="\n".join(line[:1024] for line in text.splitlines() if any(token in line for token in (*allowed,"ActivityManager","ActivityTaskManager","AndroidRuntime")))[:4096]
   logcat={"attempted":True,"argv":argv,"exit_code":meta["rc"],"size":len(data),"sha256":hashlib.sha256(data).hexdigest(),"relevant_lines":relevant}
  except BaseException as exc:logcat={"attempted":True,"error_type":type(exc).__name__,"error_sha256":hashlib.sha256(str(exc).encode()).hexdigest()}
  diagnostic={"allowed":list(allowed),"observation_count":len(observations),"last":observations[-1] if observations else None,"focus_observations":self.focus_observation_history,"top_resumed_raw":{"size":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"bytes_b64":base64.b64encode(raw).decode()},"logcat":logcat}
  return self._app_failure(reason,diagnostic,d,"app-focus")
 def _collect_native_crash(self,expected_pid,observed_pid,epoch,d):
  if self.native_crash_evidence is not None:return self.native_crash_evidence
  commands=(("crash",["logcat","-b","crash","-d","-T",str(epoch),"-v","threadtime"],262144),("all-events",["logcat","-b","main","-b","system","-b","events","-b","crash","-d","-T",str(epoch),"-t","600","-v","threadtime"],524288),("tombstone-metadata",["shell","ls","-la","/data/tombstones"],65536),("tombstone-backtrace",["shell","dumpsys","dropbox","--print","SYSTEM_TOMBSTONE"],524288))
  rows=[]
  for label,argv,limit in commands:
   try:
    self._diagnostic_capture=True;raw,meta=self._capture_result(argv,min(d,self.clock()+12),"native-crash-"+label,limit,7)
    rows.append({"label":label,"argv":argv,"exit_code":meta["rc"],"timed_out":meta["rc"]==124,"output":self._raw("adb:native-crash-"+label,raw)})
   except BaseException as exc:
    rows.append({"label":label,"argv":argv,"capture_error":{"type":type(exc).__name__,"sha256":hashlib.sha256(str(exc).encode()).hexdigest()},"bounded_command":json.loads(json.dumps(self.last_command))})
   finally:self._diagnostic_capture=False
  self.native_crash_evidence={"schema":1,"expected_pid":int(expected_pid) if str(expected_pid).isdigit() else None,"observed_pid":int(observed_pid) if str(observed_pid).isdigit() else None,"launch_epoch":str(epoch),"sources":rows}
  return self.native_crash_evidence
 def _app_failure(self,reason,diagnostic,d,phase):
  if self.native_crash_evidence is not None and "native_crash" not in diagnostic:diagnostic={**diagnostic,"native_crash":self.native_crash_evidence}
  if phase=="app-update" and "fixture_log" not in diagnostic and not (isinstance(diagnostic.get("preflight"),Mapping) and "healthz" in diagnostic["preflight"]):
   try:
    fixture_log=self._fx("read-log",self.clock()+10);encoded=json.dumps(fixture_log,sort_keys=True,separators=(",",":"))
    diagnostic={**diagnostic,"fixture_log":fixture_log if len(encoded)<=65536 else {"oversized":True,"size":len(encoded.encode()),"sha256":hashlib.sha256(encoded.encode()).hexdigest(),"request_count":len(fixture_log.get("requests",[])) if isinstance(fixture_log.get("requests"),list) else None}}
   except BaseException as exc:diagnostic={**diagnostic,"fixture_log":{"error_type":type(exc).__name__,"error_sha256":hashlib.sha256(str(exc).encode()).hexdigest()}}
  elif phase=="app-update" and "fixture_log" not in diagnostic:diagnostic={**diagnostic,"fixture_log":{"state":"not-reset","reason":"health-preflight-failed"}}
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
  message_diagnostic={k:v for k,v in diagnostic.items() if k not in ("focus_observations","top_resumed_raw")}
  if isinstance(message_diagnostic.get("last"),Mapping):message_diagnostic["last"]={k:v for k,v in message_diagnostic["last"].items() if k!="raw"}
  error=NestedCuttlefishError(("foreground activity-top mismatch: " if phase=="app-focus" else "app precondition failed: ")+json.dumps(message_diagnostic,sort_keys=True,separators=(",",":"))[:4096]);setattr(error,"archive_durable",True);raise error
 def _tap(self,text,allowed,d,focus_allowed=None):
  remote=f"/data/local/tmp/amz-{self.plan.ownership.attempt_nonce[:12]}.xml"
  while self.clock()<d:
   unlock=self._unlock(d);self._focus(focus_allowed or allowed,d);x=self._ui_xml(remote,d,f"ui-{text.lower()}").decode(errors="replace")
   nodes=[n for n in re.findall(r"<node\b[^>]+>",x) if f'text="{text}"' in n and any(f'package="{p}"' in n for p in allowed)]
   m=re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',nodes[0]) if len(nodes)==1 else None
   if m:
    a,b,c,e=map(int,m.groups());self._adb(["shell","input","tap",str((a+c)//2),str((b+e)//2)],d);return unlock
   self.sleep(min(1,self._left(d,1)))
   raise NestedCuttlefishError(f"bounded UI wait expired: {text}")
 def _input_once(self,argv,d,label):
  raw,meta=self._capture_result(argv,d,label,65536,10)
  if meta["rc"] not in (0,124):raise NestedCuttlefishError("single UI input command failed")
  return {"argv":argv,"exit_code":meta["rc"],"timed_out":meta["rc"]==124,"output":self._raw("adb:visual-input",raw)}
 def _visual_action(self,text,allowed,d,focus_allowed=None,kind="update",downstream_reserve=300,review_window=90):
  if not callable(self.visual_request) or not callable(self.visual_poll):raise NestedCuttlefishError("visual handshake callbacks missing")
  deadline=min(d-downstream_reserve,self.clock()+review_window)
  if deadline<=self.clock():raise NestedCuttlefishError("insufficient visual handshake reserve")
  request_attempt=0
  expected_action={"update":"Update","unknown-sources":"Allow from this source"}
  if expected_action.get(kind)!=text:raise NestedCuttlefishError("visual kind/action mismatch")
  while self.clock()<deadline:
   unlock=self._unlock(deadline);top_pid,top_uid,pkg,activity,_=self._focus(focus_allowed or allowed,deadline,max_observations=12)
   visual_remote=f"/data/local/tmp/amz-{self.plan.ownership.attempt_nonce[:12]}-{self.visual_seq+1:02d}.png";visual_local=f"{self.plan.root}/evidence/visual-{self.visual_seq+1:02d}.png"
   image_monotonic=None;png_attempts=[]
   for shot_index in range(3):
    attempt_monotonic=self.clock();png_command=["shell","screencap","-p",visual_remote];raw,png_meta=self._capture_result(png_command,deadline,f"visual-{kind}",65536,10);png_attempts.append({"argv":png_command,"exit_code":png_meta["rc"],"output":self._raw("adb:visual-screencap",raw)})
    if png_meta["rc"]==0:image_monotonic=attempt_monotonic;break
    if png_meta["rc"]!=124:self._app_failure("visual-screenshot-failed",{"action":text,"attempts":png_attempts},d,"app-update")
   if png_attempts[-1]["exit_code"]!=0:self._app_failure("visual-screenshot-timeout",{"action":text,"attempts":png_attempts},d,"app-update")
   self._adb(["pull",visual_remote,visual_local],deadline,30);png=self._read_file(visual_local,deadline,PNG_MAX)
   if not png.startswith(b"\x89PNG\r\n\x1a\n"):self._app_failure("visual-screenshot-invalid",{"action":text,"size":len(png)},d,"app-update")
   request_attempt+=1;self.visual_seq+=1;now=self.clock()
   request={"schema":1,"run_id":self.plan.ownership.run_id,"attempt_nonce":self.plan.ownership.attempt_nonce,"sequence":self.visual_seq,"kind":kind,"state":"operator-unclassified","action":text,"bounds":None,"display_owner":{"package":pkg,"activity":activity,"pid":int(top_pid),"uid":int(top_uid)},"action_target":{"package":self.plan.apk.package,"version_code":self.baseline.version_code,"artifact_sha256":self.plan.apk.sha256,"artifact_size":self.plan.apk.size},"artifact_sha256":self.plan.apk.sha256,"artifact_size":self.plan.apk.size,"review_seconds":min(review_window,max(0,deadline-now)),"screenshot_attempts":png_attempts,"origin":"guest","transport":"qga-adb"}
   ack=self.visual_request(request,png);request=dict(ack.get("request_record",{})) if isinstance(ack,Mapping) else {}
   if (not isinstance(ack,Mapping) or ack.get("origin")!="controller" or ack.get("immutable") is not True
       or not SHA.fullmatch(str(ack.get("request_sha256",""))) or ack.get("png_sha256")!=hashlib.sha256(png).hexdigest()
       or ack.get("run_id")!=request.get("run_id") or ack.get("attempt_nonce")!=request.get("attempt_nonce")
       or ack.get("png_size")!=len(png) or not isinstance(ack.get("png_width"),int) or not isinstance(ack.get("png_height"),int) or ack.get("expires_at")!=request.get("expires_at") or ack.get("created_at")!=request.get("created_at")
       or not all(isinstance(ack.get(k),str) and ack.get(k) for k in ("request_id","request_path","png_path"))):
    self._app_failure("visual-request-archive-invalid",{"action":text},d,"app-update")
   decision=None
   while self.clock()<deadline:
    decision=self.visual_poll(ack)
    if decision is not None:break
    self.sleep(min(.5,self._left(deadline,.5)))
   row={"request":request,"controller":dict(ack),"decision":dict(decision) if isinstance(decision,Mapping) else None,"keyguard":unlock};self.visual_history.append(row)
   if decision is None:self._app_failure("visual-decision-expired",{"visual_handshake":self.visual_history},d,"app-update")
   if (not isinstance(decision,Mapping) or decision.get("origin")!="controller" or decision.get("immutable") is not True or decision.get("input_only") is not True
       or decision.get("request_id")!=ack["request_id"] or decision.get("request_sha256")!=ack["request_sha256"]
       or decision.get("run_id")!=request["run_id"] or decision.get("attempt_nonce")!=request["attempt_nonce"]
       or decision.get("decision") not in ("approve","refresh","reject") or not SHA.fullmatch(str(decision.get("sha256","")))):
    self._app_failure("visual-decision-invalid",{"visual_handshake":self.visual_history},d,"app-update")
   if decision.get("decision")=="reject":self._app_failure("visual-decision-rejected",{"visual_handshake":self.visual_history},d,"app-update")
   if decision.get("decision")=="refresh":
    if request_attempt>=3:self._app_failure("visual-action-not-visible",{"visual_handshake":self.visual_history,"attempts":request_attempt},d,"app-update")
    continue
   bounds=decision.get("bounds")
   if decision.get("decision")!="approve" or not isinstance(bounds,list) or len(bounds)!=4 or not (0<=bounds[0]<bounds[2]<=ack.get("png_width",0) and 0<=bounds[1]<bounds[3]<=ack.get("png_height",0)):self._app_failure("visual-decision-invalid",{"visual_handshake":self.visual_history},d,"app-update")
   # Recheck every authority immediately before the single coordinate input.
   self._check();self._check_fixture();package,uid=self._package(self.baseline.version_code if kind=="update" else self.baseline.version_code,deadline)
   verify_pid,verify_uid,verify_pkg,verify_activity,_=self._focus(focus_allowed or allowed,deadline,max_observations=3)
   if (verify_pid,verify_uid,verify_pkg,verify_activity)!=(top_pid,top_uid,pkg,activity) or (kind=="update" and uid!=int(top_uid)):
    if verify_pid!=top_pid:self._collect_native_crash(top_pid,verify_pid,self.current_launch_epoch or "0",d)
    self._app_failure("visual-preinput-binding-changed",{"visual_handshake":self.visual_history},d,"app-update")
   if d-self.clock()<downstream_reserve:self._app_failure("visual-downstream-reserve-exhausted",{"visual_handshake":self.visual_history},d,"app-update")
   # Check capture age only after every authority/focus recheck, immediately
   # before input.  A stale approval causes a fresh operator request and no tap.
   if self.clock()-image_monotonic>45:
    row["freshness"]={"accepted":False,"max_seconds":45}
    if request_attempt>=3:self._app_failure("visual-approval-not-fresh",{"visual_handshake":self.visual_history},d,"app-update")
    continue
   row["freshness"]={"accepted":True,"max_seconds":45}
   if self.clock()>deadline:self._app_failure("visual-decision-monotonic-expired",{"visual_handshake":self.visual_history},d,"app-update")
   x=(bounds[0]+bounds[2])//2;y=(bounds[1]+bounds[3])//2;argv=["shell","input","tap",str(x),str(y)];row["input"]={**self._input_once(argv,deadline,f"visual-{kind}-tap"),"x":x,"y":y};return unlock
  raise NestedCuttlefishError(f"bounded visual wait expired: {text}")

 def _fixture_diagnostic_preflight(self,d):
  endpoint=urlparse(self.fixture.endpoint);host=str(endpoint.hostname);port=str(endpoint.port)
  request=f"GET /healthz HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
  health_script=f"printf 'GET /healthz HTTP/1.1\\r\\nHost: {host}:{port}\\r\\nConnection: close\\r\\n\\r\\n' | toybox nc -w 8 {host} {port}"
  commands=(("link",["shell","ip","-details","link","show"]),("address",["shell","ip","-4","addr","show"]),("routes",["shell","ip","-4","route","show"]),("route",["shell","ip","-4","route","get",host]),("connect",["shell","toybox","nc","-z","-w","5",host,port]),("capability",["shell","toybox","nc","--help"]),("ril_state",["shell","getprop","init.svc.vendor.ril-daemon"]),("ril_log",["shell","logcat","-d","-t","200","-v","threadtime","-b","main","-b","system","-b","events","RIL*:V","libcuttlefish-rild:V","init:I","*:S"]),("healthz",["shell","sh","-c",health_script]))
  rows={}
  for label,argv in commands:
   self._diagnostic_capture=True
   try:raw,meta=self._capture_result(argv,d,"fixture-preflight-"+label,65536,10)
   finally:self._diagnostic_capture=False
   rows[label]={"argv":argv,"exit_code":meta["rc"],"timed_out":meta["rc"]==124,"output":self._raw("adb:fixture-preflight-"+label,raw),"stderr":self._raw("adb:fixture-preflight-"+label+"-stderr",self.last_capture_stderr)}
  response=base64.b64decode(rows["healthz"]["output"]["bytes_b64"]);health_value=None;body=b""
  try:
   head,body=response.split(b"\r\n\r\n",1);lines=head.split(b"\r\n");status=lines[0];headers={k.strip().lower():v.strip() for k,v in (line.split(b":",1) for line in lines[1:] if b":" in line)}
   if status!=b"HTTP/1.1 200 OK" or headers.get(b"content-length")!=str(len(body)).encode():raise ValueError("HTTP envelope")
   health_value=json.loads(body.decode("utf-8"))
  except (ValueError,UnicodeError,json.JSONDecodeError):health_value=None
  capability_bytes=base64.b64decode(rows["capability"]["output"]["bytes_b64"])+base64.b64decode(rows["capability"]["stderr"]["bytes_b64"])
  if rows["capability"]["exit_code"] not in (0,1) or b"nc" not in capability_bytes.lower() or rows["healthz"]["exit_code"]!=0 or health_value!={"status":"ok","run_id":self.fixture.run_id,"role":"consumer-fixture"}:
   self._app_failure("fixture-diagnostic-preflight-semantic-mismatch",{"preflight":rows,"health_result":health_value},d,"app-update")
  rows["health_body"]={"origin":"guest","transport":"qga-adb","path":"adb:fixture-preflight-health-body","size":len(body),"sha256":hashlib.sha256(body).hexdigest(),"bytes_b64":base64.b64encode(body).decode()}
  return rows
 def _tap_any(self,texts,allowed,d,focus_allowed=None):
  remote=f"/data/local/tmp/amz-{self.plan.ownership.attempt_nonce[:12]}.xml";deadline=min(d,self.clock()+90)
  while self.clock()<deadline:
   unlock=self._unlock(deadline);self._focus(focus_allowed or allowed,deadline);x=self._ui_xml(remote,deadline,"ui-completion").decode(errors="replace")
   found=[]
   for text in texts:
    nodes=[n for n in re.findall(r"<node\b[^>]+>",x) if f'text="{text}"' in n and any(f'package="{p}"' in n for p in allowed)]
    if len(nodes)>1:raise NestedCuttlefishError("ambiguous completion action")
    if len(nodes)==1:found.append((text,nodes[0]))
   m=re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',found[0][1]) if found else None
   if m:
    a,b,c,e=map(int,m.groups());self._adb(["shell","input","tap",str((a+c)//2),str((b+e)//2)],deadline);return found[0][0],unlock
   self.sleep(min(1,self._left(deadline,1)))
  raise NestedCuttlefishError("bounded UI completion wait expired")
 def _ui_xml(self,remote,d,label):
  dump_argv=["shell","uiautomator","dump","--compressed",remote];cat_argv=["shell","cat",remote];attempts=[]
  for index in range(3):
   dump,dump_meta=self._capture_result(dump_argv,d,label+"-dump",65536,20);attempt={"dump":{"argv":dump_argv,"exit_code":dump_meta["rc"],"timed_out":dump_meta["rc"]==124,"output":self._raw("adb:ui-dump",dump)},"cat":None};attempts.append(attempt)
   if dump_meta["rc"] not in (0,124):raise NestedCuttlefishError("UI dump command failed")
   if dump_meta["rc"]==124:
    if index<2 and self.clock()<d:self.sleep(min(.5,max(0,d-self.clock())));continue
    break
   xml,cat_meta=self._capture_result(cat_argv,d,label+"-cat",XML_MAX,10);attempt["cat"]={"argv":cat_argv,"exit_code":cat_meta["rc"],"timed_out":cat_meta["rc"]==124,"output":self._raw("adb:ui-xml",xml)}
   if cat_meta["rc"] not in (0,124):raise NestedCuttlefishError("UI XML command failed")
   if cat_meta["rc"]==0:
    if len(self.ui_capture_history)>=64:raise NestedCuttlefishError("UI capture history exceeds bound")
    self.ui_capture_history.append({"label":label,"remote":remote,"attempts":attempts});return xml
   if index<2 and self.clock()<d:self.sleep(min(.5,max(0,d-self.clock())))
  if len(self.ui_capture_history)<64:self.ui_capture_history.append({"label":label,"remote":remote,"attempts":attempts})
  self._app_failure("ui-xml-capture-timeout",{"ui_capture_observations":self.ui_capture_history},d,"app-update")
 @staticmethod
 def _sessions(s):
  rows={}
  header=r"(?:(Active Child|Active|Orphaned|Finalized) )?Session ([1-9]\d*):"
  for match in re.finditer(rf"(?ms)^\s*{header}\s*$\n(.*?)(?=^\s*{header}\s*$|\Z)",s):
   prefix=match.group(1);session=int(match.group(2));body=match.group(3)
   if session in rows:raise NestedCuttlefishError("ambiguous PackageInstaller session dump")
   if prefix is None:
    packages=re.findall(r"(?<![A-Za-z0-9_])mAppPackageName=([^\s]+)",body);statuses=re.findall(r"(?<![A-Za-z0-9_])mFinalStatus=(-?\d+)\b",body)
    if len(packages)!=1 or len(statuses)!=1:raise NestedCuttlefishError("ambiguous PackageInstaller historical session")
    rows[session]={"kind":"historical","package":packages[0],"final_status":int(statuses[0])}
   else:
    packages=re.findall(r"(?<![A-Za-z0-9_])appPackageName\s*=\s*([^\s]+)",body)
    if len(packages)>1:raise NestedCuttlefishError("ambiguous PackageInstaller active package")
    active_package=packages[0] if packages and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+",packages[0]) else None
    rows[session]={"kind":prefix.lower().replace(" ","-"),"package":active_package,"final_status":None}
  return rows
 def _stop(self,d):
  errors=[]
  for a in (["shell","am","force-stop",self.plan.apk.package],["shell","rm","-f",f"/data/local/tmp/amz-{self.plan.ownership.attempt_nonce[:12]}.xml",f"/data/local/tmp/amz-{self.plan.ownership.attempt_nonce[:12]}.png"]):
   try:self._adb(a,d)
   except BaseException as e:errors.append(str(e))
  r=self._fx("stop",d)
  if errors or r.get("identity_rechecked") is not True or r.get("stopped") is not True or r.get("listener_closed") is not True or r.get("unknown_survivors")!=[] or not SHA.fullmatch(str(r.get("request_log_sha256",""))):raise NestedCuttlefishError("app/fixture cleanup uncertain")
  return r
 def run_update(self,timeout=600):
  if isinstance(timeout,bool) or timeout!=600:raise NestedCuttlefishError("update timeout")
  d=self.clock()+timeout;started=False;primary=None
  try:
   started=True;s=self._fx("start",d)
   if s.get("ready") is not True or s.get("identity_rechecked") is not True:raise NestedCuttlefishError("fixture start receipt")
   diagnostic_preflight=self._fixture_diagnostic_preflight(min(d,self.clock()+35))
   z=self._fx("reset",d)
   health_bytes=base64.b64decode(diagnostic_preflight["health_body"]["bytes_b64"]);health_request=z.get("cleared_health_request")
   if (isinstance(z.get("log_inode"),bool) or not isinstance(z.get("log_inode"),int) or z["log_inode"]<=0 or z.get("offset")!=0
       or not re.fullmatch(r"[0-9a-f]{48}",str(z.get("reset_token",""))) or z.get("empty_sha256")!=hashlib.sha256(b"").hexdigest()
       or not isinstance(z.get("reset_at"),(int,float)) or isinstance(z.get("reset_at"),bool) or not math.isfinite(z["reset_at"])
       or not isinstance(health_request,Mapping) or set(health_request)!={"method","path","status","sha256","bytes","content_length","eof","peer","observed_at","run_id","attempt_nonce"}
       or health_request.get("run_id")!=self.fixture.run_id or health_request.get("attempt_nonce")!=self.fixture.attempt_nonce or health_request.get("method")!="GET" or health_request.get("path")!="/healthz" or health_request.get("status")!=200 or health_request.get("eof") is not True or not health_request.get("peer")
       or health_request.get("sha256")!=hashlib.sha256(health_bytes).hexdigest() or health_request.get("bytes")!=len(health_bytes) or health_request.get("content_length")!=len(health_bytes)):raise NestedCuttlefishError("fixture reset receipt")
   diagnostic_preflight["fixture_request"]=dict(z["cleared_health_request"])
   reset_sha=receipt_sha(z)
   force_argv=["shell","am","force-stop",self.plan.apk.package];force_bytes=self._capture(force_argv,d,"update-check-force-stop",65536,10);restart_unlock=self._unlock(d)
   epoch=str(self._adb(["shell","date","+%s.%3N"],d).get("stdout","")).strip()
   if not re.fullmatch(r"\d{10,}(?:\.\d{3})?",epoch):raise NestedCuttlefishError("logcat start time missing")
   restart_monkey=self._launch_once(self.plan.apk.package,d,"update-check-monkey","adb:update-check-monkey");restart_started=self.clock()
   if d-self.clock()<520:raise NestedCuttlefishError("insufficient interactive update budget after fixture restart")
   _,_,_,_,restart_focus=self._focus((self.plan.apk.package,),d,lifecycle_epoch=epoch,max_observations=12)
   update_restart={"force_stop":{"argv":force_argv,"exit_code":0,"output":self._raw("adb:update-check-force-stop",force_bytes)},"keyguard":restart_unlock,"monkey":restart_monkey,"readiness":restart_focus}
   installer_snapshot_argv=["shell","dumpsys","package","installs"];before_bytes=self._capture(installer_snapshot_argv,d,"installer-before",XML_MAX);before=self._sessions(before_bytes.decode(errors="replace"));installer_unlock=restart_unlock
   wait_until=restart_started+60
   if d-wait_until<460:raise NestedCuttlefishError("insufficient update reserve after 60 second product timer")
   if self.clock()<wait_until:self.sleep(wait_until-self.clock())
   update_unlock=self._visual_action("Update",(self.plan.apk.package,),d,kind="update",downstream_reserve=300,review_window=90);install_action,install_unlock=self._tap_any(("Install","Settings"),INSTALLERS,d,focus_allowed=(self.plan.apk.package,*INSTALLERS))
   if install_action=="Settings":
    settings_unlock=self._visual_action("Allow from this source",("com.android.settings",),d,focus_allowed=("com.android.settings",),kind="unknown-sources",downstream_reserve=100,review_window=90)
    back=self._input_once(["shell","input","keyevent","4"],d,"unknown-sources-back");self.visual_history[-1]["back"]=back;install_action,install_unlock=self._tap_any(("Install",),INSTALLERS,d,focus_allowed=(self.plan.apk.package,*INSTALLERS))
   completion_action,completion_unlock=self._tap_any(("Open","Done"),INSTALLERS,d)
   package,uid=self._package(self.plan.apk.version_code,d);session_observations=[];sessions=set()
   for poll in range(10):
    ins_bytes=self._capture(installer_snapshot_argv,d,f"installer-after-{poll}",XML_MAX);after=self._sessions(ins_bytes.decode(errors="replace"));session_observations.append(self._raw("adb:dumpsys-package-installs",ins_bytes));new=set(after)-set(before)
    sessions={sid for sid in new if after[sid]=={"kind":"historical","package":self.plan.apk.package,"final_status":1}}
    if len(new)==1 and len(sessions)==1:break
    self.sleep(min(1,self._left(d,1)))
   log=self._capture(["logcat","-d","-T",epoch,"-v","threadtime","PackageInstaller:I","PackageManager:I","AndroidRuntime:E","*:S"],d,"logcat",LOG_MAX)
   if len(sessions)!=1 or re.search(rb"FATAL EXCEPTION|Fatal signal.*amnezia",log,re.I):raise NestedCuttlefishError("unique successful PackageInstaller session missing")
   launch_unlock=self._unlock(d);monkey=self._launch_once(self.plan.apk.package,d,"candidate-monkey","adb:candidate-monkey");top_pid,top_uid,pkg,activity,focus=self._focus((self.plan.apk.package,),d,lifecycle_epoch=epoch,max_observations=12);pid=str(self._adb(["shell","pidof",self.plan.apk.package],d).get("stdout","")).strip()
   if not re.fullmatch(r"[1-9]\d*",pid) or pid!=top_pid or uid!=int(top_uid):
    self._collect_native_crash(top_pid,pid if re.fullmatch(r"[1-9]\d*",pid) else None,epoch,d);self._app_failure("candidate-package-pid-changed",{"top_pid":top_pid,"pidof":pid},d,"app-update")
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
   v={"schema":2,"operation":"nested-cuttlefish-app-update","timeout_seconds":timeout,"run_id":self.plan.ownership.run_id,"profile":self.plan.ownership.profile,"attempt_nonce":self.plan.ownership.attempt_nonce,"marker":self.plan.marker,"guest_root":self.plan.root,"outer_ownership":asdict(self.plan.ownership),"origin":"guest","transport":"qga","injected":False,"boot_binding_sha256":receipt_sha(self.boot),"diagnostic_preflight":diagnostic_preflight,"package_installer":{"package":self.plan.apk.package,"version_code":self.plan.apk.version_code,"artifact_sha256":self.plan.apk.sha256,"artifact_size":self.plan.apk.size,"download_sha256":self.plan.apk.sha256,"session_id":next(iter(sessions)),"status":"STATUS_SUCCESS","method":"PackageInstaller","snapshot_argv":installer_snapshot_argv,"session_evidence":{"before":self._raw("adb:dumpsys-package-installs",before_bytes),"after":session_observations}},"http":{"fixture_nonce":self.fixture.attempt_nonce,"manifest_sha256":self.fixture.manifest_sha256,"requests":rows,"fixture_receipt_sha256":receipt_sha(h)},"ui":{"package":pkg,"activity":activity,"window_id":wid,"window_title":pkg,"package_pid":int(pid),"package_uid":uid,"version_code":self.plan.apk.version_code,"screenshot_sha256":hashlib.sha256(png).hexdigest(),"package_state":package,"update_check_restart":update_restart,"keyguard":keyguards,"completion_action":completion_action,"launch_probe":monkey,"focus_observations":focus,"ui_capture_observations":self.ui_capture_history,"visual_handshake":self.visual_history},"logcat":{"started_at":epoch,"finished_at":str(h.get("finished_at","")),"sha256":hashlib.sha256(log).hexdigest(),"size":len(log),"crashes":[]},"passed":True}
   return validate_app_update_receipt(self.plan,self.boot,v)
  except BaseException as e:
   if getattr(e,"archive_durable",False) or getattr(e,"retain_owned_evidence",False):primary=e;raise
   try:self._app_failure("update-exception",{"error_type":type(e).__name__,"error_sha256":hashlib.sha256(str(e).encode()).hexdigest(),"last_command":self.last_command,"focus_observations":self.focus_observation_history,"ui_capture_observations":self.ui_capture_history},self.clock()+20,"app-update")
   except BaseException as archived:primary=archived;raise
  finally:
   if started and not getattr(primary,"retain_owned_evidence",False):
    try:self._stop(self.clock()+30)
    except BaseException as e:
     if primary is None:raise
     primary.add_note(f"fixture cleanup also failed: {e}")
 def cleanup(self,timeout=60):return {"fixture_stop":self._stop(self.clock()+timeout),"owned_remote_files_removed":True}
