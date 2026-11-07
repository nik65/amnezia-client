"""QGA lifecycle for the genuine Linux-headless HTTP fixture."""
from __future__ import annotations
import hashlib,json,secrets,time
from dataclasses import asdict
from pathlib import Path,PurePosixPath
from typing import Any,Callable,Mapping
from .headless_native_acceptance import FIXED_KEY,NativeUpdatePlan,receipt_sha256,validate_http_receipt
from .nested_cuttlefish_server_fixture_adapter import IDENTITY,RESET,READ_LOG,STOP,server_outer_from_vm
# The QGA controller itself carries script/nonce in argv and is not a server survivor.
# Keep every shared target identity, stop and listener guard unchanged.
_STOP_SOURCE_SHA256='14280a1fe8139cdcb9da31660075213169c9664a9850e28757a8466d15177e77'
_STOP_SCAN=" if not q.name.isdigit(): continue"
if hashlib.sha256(STOP.encode()).hexdigest()!=_STOP_SOURCE_SHA256 or STOP.count(_STOP_SCAN)!=1:raise RuntimeError('reviewed headless STOP source differs')
STOP=STOP.replace(" if not q.name.isdigit(): continue"," if not q.name.isdigit() or int(q.name)==os.getpid(): continue")
TRUST_KEY_READ = r'''import grp,hashlib,json,os,pathlib,stat,sys
p=pathlib.Path(sys.argv[1]);expected_gid=grp.getgrnam('amnezia').gr_gid
if type(expected_gid) is not int or expected_gid<=0:raise SystemExit('trust key group identity')
for ancestor in (p.parent,*p.parent.parents):
 s=ancestor.lstat()
 if stat.S_ISLNK(s.st_mode) or not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise SystemExit('trust key ancestor identity')
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,'rb') as stream:
 before=os.fstat(stream.fileno())
 if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_gid!=expected_gid or stat.S_IMODE(before.st_mode) not in (0o600,0o640) or not 0<before.st_size<=65536:raise SystemExit('trust key identity')
 data=stream.read(65537);after=os.fstat(stream.fileno());named=p.lstat()
 identity=lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_uid,v.st_gid,stat.S_IMODE(v.st_mode))
 if len(data)>65536 or len(data)!=after.st_size or identity(before)!=identity(after) or identity(after)!=identity(named):raise SystemExit('trust key changed')
print(json.dumps({'path':str(p),'sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'uid':after.st_uid,'gid':after.st_gid,'amnezia_gid':expected_gid,'mode':stat.S_IMODE(after.st_mode),'protected_ancestors':True,'regular':True,'same_fd_identity':True}))
'''
class HeadlessHttpFixtureError(RuntimeError):pass
class HeadlessNativeHttpFixture:
 def __init__(self,qga:Any,plan:NativeUpdatePlan,server_vm:Mapping[str,Any],snapshot:Callable[[],Mapping[str,Any]],*,manifest_guest_path:str,artifact_guest_path:str,request_log:str,server_source:Path|None=None,clock=time.monotonic,sleep=time.sleep):
  plan.validate();self.qga,self.plan,self.snapshot,self.clock,self.sleep=qga,plan,snapshot,clock,sleep;self.binding=server_outer_from_vm(server_vm);root=PurePosixPath('/var/lib/amnezia-release-lab/fixture');ps=[PurePosixPath(x) for x in (manifest_guest_path,artifact_guest_path,request_log)]
  if len(set(ps))!=3 or any(not p.is_absolute() or '..' in p.parts or root not in p.parents for p in ps):raise HeadlessHttpFixtureError('fixture guest paths')
  self.manifest,self.artifact,self.log=map(str,ps);src=(server_source or Path(__file__).with_name('headless_native_fixture_server.py')).resolve();data=src.read_bytes();self.script_sha=hashlib.sha256(data).hexdigest();self.script_size=len(data);self.script=f'{root}/headless-server-{plan.attempt_nonce}.py';self.script_path=self.script;self.pid=self.ticks=None;self.reset_receipt=None;self.trust=None
  self._check();qga.write_file(self.script,data);self._check()
 def _check(self):
  if server_outer_from_vm(self.snapshot())!=self.binding:raise HeadlessHttpFixtureError('authoritative server VM snapshot mismatch')
 def _json(self,code,args,timeout=20):
  self._check();r=self.qga.guest_exec_wait('/usr/bin/python3',['-c',code,*args],timeout=timeout);self._check()
  try:v=json.loads(r['stdout'])
  except Exception as e:raise HeadlessHttpFixtureError('guest fixture receipt') from e
  if not isinstance(v,dict):raise HeadlessHttpFixtureError('guest fixture receipt shape')
  return v
 def _trust(self):
  v=self._json(TRUST_KEY_READ,[FIXED_KEY])
  if (v.get('path')!=FIXED_KEY or v.get('sha256')!=self.plan.candidate.key_sha256
      or type(v.get('size')) is not int or not 0<v['size']<=65536 or type(v.get('uid')) is not int or v['uid']!=0
      or type(v.get('gid')) is not int or type(v.get('amnezia_gid')) is not int or v['amnezia_gid']<=0 or v['gid']!=v['amnezia_gid'] or v.get('mode') not in (0o600,0o640)
      or v.get('protected_ancestors') is not True or v.get('regular') is not True or v.get('same_fd_identity') is not True):raise HeadlessHttpFixtureError('guest trust key identity')
  return v
 def start(self,timeout=30):
  self.trust=self._trust();verify="import hashlib,json,pathlib,sys;rows=[]\nfor p,h,n in zip(sys.argv[1::3],sys.argv[2::3],sys.argv[3::3]):\n b=pathlib.Path(p).read_bytes();rows.append({'path':p,'sha256':hashlib.sha256(b).hexdigest(),'size':len(b)});assert rows[-1]['sha256']==h and rows[-1]['size']==int(n)\nprint(json.dumps({'files':rows}))";args=[self.script,self.script_sha,str(self.script_size),self.manifest,self.plan.candidate.manifest_sha256,str(self.plan.candidate.manifest_size),self.artifact,self.plan.candidate.tar_sha256,str(self.plan.candidate.tar_size)];rows=self._json(verify,args,timeout)['files'];expected=[(args[i],args[i+1],int(args[i+2])) for i in range(0,9,3)]
  if [(x.get('path'),x.get('sha256'),x.get('size')) for x in rows]!=expected:raise HeadlessHttpFixtureError('fixture staged bytes')
  self._check();port=self.plan.fixture.endpoint.rsplit(':',1)[1];r=self.qga.guest_exec('/usr/bin/python3',[self.script,'--manifest',self.manifest,'--apk',self.artifact,'--manifest-sha256',self.plan.candidate.manifest_sha256,'--apk-sha256',self.plan.candidate.tar_sha256,'--manifest-path',self.plan.fixture.manifest_path,'--artifact-path',self.plan.fixture.artifact_path,'--run-id',self.plan.run_id,'--attempt-nonce',self.plan.attempt_nonce,'--port',port,'--request-log',self.log]);self._check();self.pid=r.get('pid')
  if isinstance(self.pid,bool) or not isinstance(self.pid,int):raise HeadlessHttpFixtureError('fixture PID')
  end=self.clock()+timeout;last=None
  try:
   while self.clock()<end:
    try:
     i=self._json(IDENTITY,[str(self.pid),'',self.plan.attempt_nonce,self.script,self.script_sha],min(10,max(1,end-self.clock())));self.ticks=i['start_ticks'];h=self._json("import json,sys,urllib.request;print(urllib.request.urlopen('http://127.0.0.1:'+sys.argv[1]+'/healthz',timeout=float(sys.argv[2])).read().decode())",[port,str(min(5,max(.1,end-self.clock())))],min(6,max(1,end-self.clock())))
     if h.get('role')=='headless-native-fixture' and h.get('run_id')==self.plan.run_id:return {**i,'ready':True}
    except Exception as e:last=e;self.sleep(min(.2,max(0,end-self.clock())))
   raise HeadlessHttpFixtureError('fixture start expired') from last
  except BaseException as primary:
   if self.ticks is not None:
    try:self._json(STOP,[str(self.pid),str(self.ticks),self.script,self.plan.attempt_nonce,port],min(10,max(1,timeout)))
    except BaseException as cleanup:
     if hasattr(primary,'add_note'):primary.add_note(f'fixture start cleanup failed: {cleanup!r}')
   raise
 def reset(self):
  token=secrets.token_hex(24);cursor=self.log+'.'+self.plan.attempt_nonce+'.cursor';port=self.plan.fixture.endpoint.rsplit(':',1)[1];receipt=self._json(RESET,[f'http://127.0.0.1:{port}/__lab__/attempt/reset?nonce={self.plan.attempt_nonce}&run_id={self.plan.run_id}',self.log,cursor,token,self.plan.run_id,self.plan.attempt_nonce])
  if receipt.get('ok') is not True:
   self.reset_failure_receipt=receipt
   raise HeadlessHttpFixtureError('fixture reset failed; private error receipt retained')
  self.reset_receipt=receipt;return self.reset_receipt
 def collect(self):
  if self.reset_receipt is None:raise HeadlessHttpFixtureError('fixture not reset')
  raw=self._json(READ_LOG,[self.log,self.log+'.'+self.plan.attempt_nonce+'.cursor',str(1<<20)])
  archive=getattr(self,'prevalidation_archive',None)
  if archive is not None:
   from .headless_native_e2e_driver import capture_prevalidation
   sequence=getattr(self,'collection_sequence',0)+1;self.collection_sequence=sequence
   capture_prevalidation(archive,self.plan.attempt_nonce+'-http-response-'+str(sequence),raw)
  rows=raw['rows'];dt=__import__('datetime')
  for row in rows:row['observed_at']=dt.datetime.fromtimestamp(row['observed_at'],dt.timezone.utc).isoformat().replace('+00:00','Z')
  v={'schema':1,'operation':'headless-native-http','run_id':self.plan.run_id,'case_id':self.plan.case_id,'attempt_nonce':self.plan.attempt_nonce,'origin':'server-fixture','transport':'qga','injected':False,'outer_binding':asdict(self.plan.outer_binding),'observed_at':dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00','Z'),'fixture':{'marker':f'amnezia-release-lab:{self.plan.run_id}:{self.plan.case_id}:{self.plan.attempt_nonce}','listener':self.plan.fixture.endpoint,'run_id':self.plan.run_id,'case_id':self.plan.case_id,'attempt_nonce':self.plan.attempt_nonce,'pid':self.pid,'start_ticks':self.ticks},'requests':rows,'raw_receipt_sha256':receipt_sha256(raw),'trust_key':dict(self.trust or {})};return validate_http_receipt(self.plan,v)
 def abort(self):
  # No HTTP semantic receipt exists when reset/collection failed. Stop only
  # through the unchanged owned PID/start/script/nonce/listener fence.
  if type(self.pid) is not int or type(self.ticks) is not int:raise HeadlessHttpFixtureError('owned started fixture identity unavailable')
  raw=self._json(STOP,[str(self.pid),str(self.ticks),self.script,self.plan.attempt_nonce,self.plan.fixture.endpoint.rsplit(':',1)[1]])
  return {'diagnosticOnly':True,'releasePass':False,'trustedExport':False,'operation':'headless-native-fixture-abort',**raw}
 def stop(self,http):
  raw=self._json(STOP,[str(self.pid),str(self.ticks),self.script,self.plan.attempt_nonce,self.plan.fixture.endpoint.rsplit(':',1)[1]]);return {'schema':1,'operation':'headless-native-fixture-cleanup','run_id':self.plan.run_id,'case_id':self.plan.case_id,'attempt_nonce':self.plan.attempt_nonce,'origin':'server-fixture','transport':'qga','injected':False,'outer_binding':asdict(self.plan.outer_binding),'http_receipt_sha256':receipt_sha256(http),**{k:raw[k] for k in ('pid','start_ticks','identity_rechecked','stopped','listener_closed','unknown_survivors')}}
