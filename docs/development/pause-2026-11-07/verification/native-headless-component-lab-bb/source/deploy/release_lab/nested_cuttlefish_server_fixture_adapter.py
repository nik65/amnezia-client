"""QGA-owned server-router fixture callbacks for NestedAppExecutor.

This adapter launches the existing consumer fixture inside the owned
server-router guest.  It returns raw guest observations; it never infers app
or update acceptance.
"""
from __future__ import annotations
import base64,hashlib,ipaddress,json,re,secrets,time
from dataclasses import asdict,dataclass
from pathlib import PurePosixPath
from typing import Any,Callable,Mapping
from urllib.parse import quote,unquote,urlparse

try:
 from .nested_cuttlefish_runner import NestedCuttlefishError,receipt_sha
except ImportError:  # script-style operator import via deploy/release_lab on sys.path
 from nested_cuttlefish_runner import NestedCuttlefishError,receipt_sha

SHA=re.compile(r"[0-9a-f]{64}"); ID=re.compile(r"[A-Za-z0-9._-]{1,96}"); MAX_LOG=1<<20

def canonical_android_artifact_path(manifest_bytes:bytes,expected_sha256:str,expected_size:int,local_basename:str)->str:
 if not isinstance(manifest_bytes,bytes) or not SHA.fullmatch(expected_sha256) or isinstance(expected_size,bool) or expected_size<=0 or PurePosixPath(local_basename).name!=local_basename:
  raise NestedCuttlefishError("canonical Android manifest inputs")
 try:
  envelope=json.loads(manifest_bytes.decode("utf-8"));encoded=envelope["payload"]
  if not isinstance(encoded,str) or not envelope.get("signature"):raise ValueError("unsigned")
  payload=json.loads(base64.urlsafe_b64decode(encoded+"="*(-len(encoded)%4)).decode("utf-8"));artifact=payload["platforms"]["android-arm64-v8a"]
  raw=artifact["url"];parsed=urlparse(raw)
 except (KeyError,ValueError,TypeError,UnicodeDecodeError,json.JSONDecodeError) as exc:raise NestedCuttlefishError("signed Android manifest payload") from exc
 if (not isinstance(raw,str) or parsed.scheme or parsed.netloc or parsed.params or parsed.query or parsed.fragment or "\\" in parsed.path
     or any(ord(c)<32 for c in parsed.path) or artifact.get("sha256")!=expected_sha256 or artifact.get("size")!=expected_size):
  raise NestedCuttlefishError("signed Android artifact URL binding")
 path="/"+parsed.path.lstrip("/");parts=PurePosixPath(path).parts;prefix=("/","files","artifacts",expected_sha256)
 if len(parts)!=5 or parts[:4]!=prefix or not parts[4]:raise NestedCuttlefishError("signed Android artifact path")
 try:decoded=unquote(parts[4],encoding="utf-8",errors="strict")
 except UnicodeDecodeError as exc:raise NestedCuttlefishError("signed Android artifact encoding") from exc
 canonical_relative=f"files/artifacts/{expected_sha256}/{parts[4]}"
 if parsed.path!=canonical_relative or decoded!=local_basename or quote(decoded,safe="._-")!=parts[4]:raise NestedCuttlefishError("signed Android artifact basename")
 return path

def server_outer_from_vm(vm:Mapping[str,Any])->dict[str,Any]:
 value={"pid":vm.get("pid"),"start_ticks":vm.get("proc_start_time"),"uuid":vm.get("uuid"),"qmp_socket":vm.get("qmp_socket"),"qga_socket":vm.get("qga_socket")}
 if (isinstance(value["pid"],bool) or not isinstance(value["pid"],int) or value["pid"]<=1
     or isinstance(value["start_ticks"],bool) or not isinstance(value["start_ticks"],int) or value["start_ticks"]<=0
     or any(not isinstance(value[k],str) or not value[k] for k in ("uuid","qmp_socket","qga_socket"))):raise NestedCuttlefishError("server-router VM binding")
 return value

@dataclass(frozen=True)
class ServerFixturePlan:
 run_id:str; attempt_nonce:str; endpoint:str; marker:str; outer_ownership:Mapping[str,Any]
 script_path:str; script_sha256:str; script_size:int; manifest_path:str; manifest_sha256:str; manifest_size:int
 apk_path:str; apk_sha256:str; apk_size:int; artifact_path:str; request_log:str; port:int=17865
 def validate(self):
  if not ID.fullmatch(self.run_id) or not re.fullmatch(r"[0-9a-f]{48}",self.attempt_nonce):raise NestedCuttlefishError("fixture plan identity")
  if self.marker!=f"amnezia-release-lab:{self.run_id}:server-router":raise NestedCuttlefishError("fixture marker")
  if not isinstance(self.outer_ownership,Mapping) or set(self.outer_ownership)!={"pid","start_ticks","uuid","qmp_socket","qga_socket"}:raise NestedCuttlefishError("fixture outer ownership")
  parsed=urlparse(self.endpoint)
  try:address=ipaddress.ip_address(parsed.hostname or "")
  except ValueError as exc:raise NestedCuttlefishError("fixture endpoint") from exc
  if self.port!=17865 or parsed.scheme!="http" or parsed.port!=self.port or parsed.path not in ("", "/") or address.version!=4 or not address.is_private or address.is_loopback:raise NestedCuttlefishError("fixture endpoint")
  raw_paths=(self.script_path,self.manifest_path,self.apk_path,self.request_log);root=PurePosixPath("/var/lib/amnezia-release-lab/fixture")
  parsed=[PurePosixPath(p) for p in raw_paths]
  if (len(set(raw_paths))!=len(raw_paths) or any(not p.is_absolute() or ".." in p.parts or p==root or root not in p.parents for p in parsed)):
   raise NestedCuttlefishError("fixture path ownership")
  prefix=f"/files/artifacts/{self.apk_sha256}/";encoded_name=self.artifact_path[len(prefix):] if self.artifact_path.startswith(prefix) else ""
  try:decoded_name=unquote(encoded_name,encoding="utf-8",errors="strict")
  except UnicodeDecodeError as exc:raise NestedCuttlefishError("fixture artifact path") from exc
  if not encoded_name or "/" in encoded_name or decoded_name!=self.apk_path.rsplit('/',1)[1] or quote(decoded_name,safe="._-")!=encoded_name:raise NestedCuttlefishError("fixture artifact path")
  if any(not SHA.fullmatch(x) for x in (self.script_sha256,self.manifest_sha256,self.apk_sha256)) or self.script_size<=0 or self.manifest_size<=0 or self.apk_size<=0:raise NestedCuttlefishError("fixture bytes")

IDENTITY=r'''import hashlib,json,pathlib,sys
pid=int(sys.argv[1]); ticks=int(sys.argv[2]) if sys.argv[2] else None; marker=sys.argv[3]; script=pathlib.Path(sys.argv[4]); expected=sys.argv[5]
p=pathlib.Path('/proc')/str(pid); raw=p.joinpath('stat').read_text(); f=raw[raw.rfind(')')+2:].split(); start=int(f[19]); cmd=p.joinpath('cmdline').read_bytes(); argv=[x.decode() for x in cmd.rstrip(b'\0').split(b'\0')]
if ticks is not None and start!=ticks: raise SystemExit('start changed')
if str(script) not in argv or marker not in '\0'.join(argv) or hashlib.sha256(script.read_bytes()).hexdigest()!=expected: raise SystemExit('identity')
print(json.dumps({'pid':pid,'start_ticks':start,'exe':str(p.joinpath('exe').resolve(strict=True)),'cmdline_sha256':hashlib.sha256(cmd).hexdigest(),'identity_rechecked':True},separators=(',',':')))
'''
RESET=r'''import base64,hashlib,json,os,pathlib,sys,time,urllib.request
url,log,cursor,token,run,nonce=sys.argv[1:]; p=pathlib.Path(log); before=p.read_bytes()
if len(before)>1048576: raise SystemExit('pre-reset log size')
pairs=[]
for line in before.splitlines():
 x=json.loads(line)
 if x.get('run_id')!=run or x.get('attempt_nonce')!=nonce: raise SystemExit('pre-reset row identity')
 pairs.append(x)
if len(pairs)!=1 or pairs[0].get('method')!='GET' or pairs[0].get('path')!='/healthz' or pairs[0].get('status')!=200 or pairs[0].get('bytes')!=pairs[0].get('content_length'): raise SystemExit('health request row')
pre={'size':len(before),'sha256':hashlib.sha256(before).hexdigest(),'bytes_b64':base64.b64encode(before).decode(),'rows':pairs}
try:
 data=urllib.request.urlopen(url,timeout=10).read(); response=json.loads(data)
 if response!={'status':'reset','run_id':run}: raise ValueError('reset response')
except BaseException as exc:
 raw=str(exc).encode()[:65536]
 print(json.dumps({'ok':False,'run_id':run,'attempt_nonce':nonce,'pre_reset':pre,'error':{'type':type(exc).__name__,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'bytes_b64':base64.b64encode(raw).decode()}},separators=(',',':')));raise SystemExit(0)
s=p.stat(); b=p.read_bytes()
if b: raise SystemExit('log not empty')
x=pairs[0]; health={'method':x['method'],'path':x['path'],'status':x['status'],'sha256':x['sha256'],'bytes':x['bytes'],'content_length':x['content_length'],'eof':True,'peer':x['client'],'observed_at':x['timestamp'],'run_id':x['run_id'],'attempt_nonce':x['attempt_nonce']}
value={'ok':True,'reset_token':token,'log_inode':s.st_ino,'offset':0,'empty_sha256':hashlib.sha256(b).hexdigest(),'reset_at':time.time(),'run_id':run,'attempt_nonce':nonce,'cleared_health_request':health,'pre_reset':pre}
q=pathlib.Path(cursor); fd=os.open(q,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as f: json.dump(value,f,separators=(',',':'));f.flush();os.fsync(f.fileno())
print(json.dumps(value,separators=(',',':')))
'''
READ_LOG=r'''import hashlib,json,math,pathlib,sys,time
log,cursor,limit=sys.argv[1],sys.argv[2],int(sys.argv[3]); c=json.loads(pathlib.Path(cursor).read_text()); p=pathlib.Path(log); s=p.stat()
if s.st_ino!=c['log_inode'] or s.st_size>limit: raise SystemExit('log cursor/size')
b=p.read_bytes()
if len(b)!=s.st_size: raise SystemExit('log changed')
rows=[]
for line in b.splitlines():
 x=json.loads(line)
 if x.get('run_id')!=c['run_id'] or x.get('attempt_nonce')!=c['attempt_nonce'] or not isinstance(x.get('timestamp'),(int,float)) or isinstance(x.get('timestamp'),bool) or not math.isfinite(x['timestamp']): raise SystemExit('row identity')
 rows.append({'method':x.get('method'),'path':x.get('path'),'status':x.get('status'),'sha256':x.get('sha256'),'bytes':x.get('bytes'),'content_length':x.get('content_length'),'eof':x.get('bytes')==x.get('content_length'),'peer':x.get('client'),'observed_at':x.get('timestamp')})
finished=time.time(); print(json.dumps({'reset_token':c['reset_token'],'log_inode':s.st_ino,'start_offset':c['offset'],'rows':rows,'log_sha256':hashlib.sha256(b).hexdigest(),'log_size':len(b),'finished_at':finished},separators=(',',':')))
'''
STOP=r'''import hashlib,json,os,pathlib,signal,socket,sys,time
pid,start,script,marker,port=int(sys.argv[1]),int(sys.argv[2]),sys.argv[3],sys.argv[4],int(sys.argv[5]); p=pathlib.Path('/proc')/str(pid)
def check():
 raw=p.joinpath('stat').read_text(); f=raw[raw.rfind(')')+2:].split(); cmd=p.joinpath('cmdline').read_bytes(); argv=[x.decode() for x in cmd.rstrip(b'\0').split(b'\0')]
 if int(f[19])!=start or script not in argv or marker not in '\0'.join(argv): raise SystemExit('identity changed')
check();os.kill(pid,signal.SIGTERM);deadline=time.monotonic()+10
while time.monotonic()<deadline and p.exists(): time.sleep(.1)
if p.exists(): check();os.kill(pid,signal.SIGKILL)
deadline=time.monotonic()+5
while time.monotonic()<deadline and p.exists(): time.sleep(.1)
if p.exists(): raise SystemExit('survivor')
s=socket.socket();s.settimeout(1); closed=s.connect_ex(('127.0.0.1',port))!=0;s.close()
survivors=[]
for q in pathlib.Path('/proc').iterdir():
 if not q.name.isdigit(): continue
 try:
  cmd=q.joinpath('cmdline').read_bytes().decode(errors='replace')
  if script in cmd and marker in cmd: survivors.append(int(q.name))
 except OSError: pass
print(json.dumps({'pid':pid,'start_ticks':start,'identity_rechecked':True,'stopped':True,'listener_closed':closed,'unknown_survivors':survivors},separators=(',',':')))
'''

class ServerRouterFixtureAdapter:
 def __init__(self,qga:Any,plan:ServerFixturePlan,outer_live_snapshot:Callable[[],Mapping[str,Any]],*,clock=time.monotonic,sleep=time.sleep):
  plan.validate();self.qga,self.plan,self.snapshot,self.clock,self.sleep=qga,plan,outer_live_snapshot,clock,sleep;self.pid=None;self.start_ticks=None;self.reset=None;self.file_receipt_sha256=None
 @property
 def outer_binding(self):return dict(self.plan.outer_ownership)
 def app_fixture(self):
  if self.pid is None or self.start_ticks is None:raise NestedCuttlefishError("fixture not started")
  from .nested_cuttlefish_app_executor import AppFixture
  return AppFixture(self.plan.endpoint,self.plan.run_id,self.plan.attempt_nonce,"/manifest.json",self.plan.manifest_sha256,self.plan.manifest_size,self.plan.artifact_path,self.pid,self.start_ticks,"server-router",self.plan.marker,self.outer_binding)
 def _check(self):
  if self.snapshot()!=self.outer_binding:raise NestedCuttlefishError("server-router outer ownership changed")
 def _json(self,code,args,timeout):
  self._check();r=self.qga.guest_exec_wait("/usr/bin/python3",["-c",code,*args],timeout=timeout);self._check()
  try:v=json.loads(r.get("stdout",""))
  except Exception as e:raise NestedCuttlefishError("fixture guest receipt missing") from e
  if not isinstance(v,dict):raise NestedCuttlefishError("fixture guest receipt shape")
  return v
 def _common(self):
  return {"schema":1,"run_id":self.plan.run_id,"profile":"server-router","attempt_nonce":self.plan.attempt_nonce,"marker":self.plan.marker,"origin":"guest","transport":"qga","injected":False,"outer_ownership":self.outer_binding,"pid":self.pid,"start_ticks":self.start_ticks,"listener":self.plan.endpoint,"manifest_sha256":self.plan.manifest_sha256,"manifest_size":self.plan.manifest_size,"artifact_sha256":self.plan.apk_sha256,"artifact_size":self.plan.apk_size}
 def start(self,timeout=30):
  if self.pid is not None and self.start_ticks is not None:
   ident=self._json(IDENTITY,[str(self.pid),str(self.start_ticks),self.plan.attempt_nonce,self.plan.script_path,self.plan.script_sha256],timeout)
   health=self._json("import json,sys,urllib.parse,urllib.request\nurl='http://127.0.0.1:'+sys.argv[1]+'/__lab__/health?'+urllib.parse.urlencode({'run_id':sys.argv[2],'nonce':sys.argv[3]});print(urllib.request.urlopen(url,timeout=3).read().decode())",[str(self.plan.port),self.plan.run_id,self.plan.attempt_nonce],min(timeout,5))
   if health!={"status":"ok","run_id":self.plan.run_id,"role":"consumer-fixture"}:raise NestedCuttlefishError("fixture health identity")
   return {**self._common(),**ident,"ready":True,"file_receipt_sha256":self.file_receipt_sha256}
  self._check();verify=self._json("import hashlib,json,pathlib,sys\nrows=[]\nfor p,h,n in zip(sys.argv[1::3],sys.argv[2::3],sys.argv[3::3]):\n b=pathlib.Path(p).read_bytes();rows.append({'path':p,'sha256':hashlib.sha256(b).hexdigest(),'size':len(b)});assert rows[-1]['sha256']==h and rows[-1]['size']==int(n)\nprint(json.dumps({'files':rows},separators=(',',':')))",[self.plan.script_path,self.plan.script_sha256,str(self.plan.script_size),self.plan.manifest_path,self.plan.manifest_sha256,str(self.plan.manifest_size),self.plan.apk_path,self.plan.apk_sha256,str(self.plan.apk_size)],timeout)
  expected=[(self.plan.script_path,self.plan.script_sha256,self.plan.script_size),(self.plan.manifest_path,self.plan.manifest_sha256,self.plan.manifest_size),(self.plan.apk_path,self.plan.apk_sha256,self.plan.apk_size)]
  if [(x.get("path"),x.get("sha256"),x.get("size")) for x in verify.get("files",[]) if isinstance(x,Mapping)]!=expected:raise NestedCuttlefishError("fixture staged bytes")
  self.file_receipt_sha256=receipt_sha(verify)
  self._check();r=self.qga.guest_exec("/usr/bin/python3",[self.plan.script_path,"--manifest",self.plan.manifest_path,"--apk",self.plan.apk_path,"--manifest-sha256",self.plan.manifest_sha256,"--apk-sha256",self.plan.apk_sha256,"--run-id",self.plan.run_id,"--attempt-nonce",self.plan.attempt_nonce,"--port",str(self.plan.port),"--request-log",self.plan.request_log]);self._check();self.pid=r.get("pid")
  if isinstance(self.pid,bool) or not isinstance(self.pid,int):raise NestedCuttlefishError("fixture launch PID")
  deadline=self.clock()+timeout
  while self.clock()<deadline:
   try:
    ident=self._json(IDENTITY,[str(self.pid),"",self.plan.attempt_nonce,self.plan.script_path,self.plan.script_sha256],min(10,max(1,deadline-self.clock())));self.start_ticks=ident["start_ticks"]
    health=self._json("import json,sys,urllib.parse,urllib.request\nurl='http://127.0.0.1:'+sys.argv[1]+'/__lab__/health?'+urllib.parse.urlencode({'run_id':sys.argv[2],'nonce':sys.argv[3]});print(urllib.request.urlopen(url,timeout=3).read().decode())",[str(self.plan.port),self.plan.run_id,self.plan.attempt_nonce],5)
    if health=={"status":"ok","run_id":self.plan.run_id,"role":"consumer-fixture"}:return {**self._common(),**ident,"ready":True,"file_receipt_sha256":self.file_receipt_sha256}
   except Exception:self.sleep(.2)
  failure=NestedCuttlefishError("fixture bounded start expired")
  if self.start_ticks is not None:
   try:self.stop(min(20,max(1,timeout)))
   except BaseException as cleanup_error:failure.add_note(f"failed-start cleanup also failed: {cleanup_error}")
  raise failure
 def reset_log(self,timeout=20):
  if self.pid is None:raise NestedCuttlefishError("fixture not started")
  token=secrets.token_hex(24);cursor=self.plan.request_log+f".{self.plan.attempt_nonce}.cursor"
  value=self._json(RESET,[f"http://127.0.0.1:{self.plan.port}/__lab__/attempt/reset?nonce={self.plan.attempt_nonce}&run_id={self.plan.run_id}",self.plan.request_log,cursor,token,self.plan.run_id,self.plan.attempt_nonce],timeout)
  if value.get("ok") is not True:
   error=NestedCuttlefishError("fixture reset failed");setattr(error,"fixture_control_evidence",{**self._common(),**value});raise error
  self.reset={**self._common(),**value};return dict(self.reset)
 def read_log(self,timeout=20):
  if self.reset is None:raise NestedCuttlefishError("fixture log was not reset")
  cursor=self.plan.request_log+f".{self.plan.attempt_nonce}.cursor";v=self._json(READ_LOG,[self.plan.request_log,cursor,str(MAX_LOG)],timeout);rows=v.pop("rows")
  return {**self._common(),**v,"reset_receipt_sha256":receipt_sha(self.reset),"requests":rows,"transcript_sha256":receipt_sha({"reset_receipt_sha256":receipt_sha(self.reset),"requests":rows})}
 def stop(self,timeout=20):
  if self.pid is None or self.start_ticks is None:raise NestedCuttlefishError("fixture not started")
  v=self._json(STOP,[str(self.pid),str(self.start_ticks),self.plan.script_path,self.plan.attempt_nonce,str(self.plan.port)],timeout)
  log=self._json("import hashlib,json,pathlib,sys\np=pathlib.Path(sys.argv[1]);b=p.read_bytes() if p.exists() else b'';print(json.dumps({'sha256':hashlib.sha256(b).hexdigest(),'size':len(b)},separators=(',',':')))",[self.plan.request_log],10)
  return {**self._common(),**v,"request_log_sha256":log["sha256"],"request_log_size":log["size"]}
 def callback(self,action,payload,timeout):
  if not isinstance(payload,Mapping) or payload.get("run_id")!=self.plan.run_id or payload.get("attempt_nonce")!=self.plan.attempt_nonce:raise NestedCuttlefishError("fixture callback payload")
  if action=="start":return self.start(int(timeout))
  if action=="reset":return self.reset_log(int(timeout))
  if action=="read-log":return self.read_log(int(timeout))
  if action=="stop":return self.stop(int(timeout))
  raise NestedCuttlefishError("unknown fixture action")
