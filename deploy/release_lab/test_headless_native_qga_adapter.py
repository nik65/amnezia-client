import json
from unittest.mock import Mock
import pytest
from deploy.release_lab.headless_native_acceptance import (Fixture, NativeUpdatePlan, OuterBinding, ReleaseBytes,
 UPDATE_JOURNAL, ROLLBACK_RECEIPT)
from deploy.release_lab.headless_native_qga_adapter import HeadlessNativeQgaAdapter, HeadlessNativeQgaError, UNIT_PREFLIGHT

def release(v,t): return ReleaseBytes(v,t*64,1,chr(ord(t)+1)*64,2,chr(ord(t)+2)*64,3,chr(ord(t)+3)*64,4,"f"*64)
def plan(): return NativeUpdatePlan("run","case","nonce-1234567890","2026-09-13T10:00:00Z",OuterBinding(2,3,"11111111-1111-1111-1111-111111111111","/var/lib/amnezia-release-lab/r/qmp","/var/lib/amnezia-release-lab/r/qga"),release("5.0.1.38","a"),release("5.0.1.39","b"),Fixture("http://10.8.1.2:1234",("10.8.1.0/24",),"nonce-1234567890","/manifest.json","/artifact"))

class Fake:
 def __init__(self): self.calls=[]; self.boot="old"
 def guest_exec_wait(self,path,args,timeout):
  self.calls.append((path,args,timeout))
  if path=="/usr/bin/cat": return {"exitcode":0,"stdout":self.boot}
  if path.endswith("amnezia-cli"): return {"exitcode":0,"stdout":json.dumps({"ok":True,"result":{}})}
  if path=="/usr/bin/python3" and len(args)>1 and args[1]==UNIT_PREFLIGHT:
   return {"exitcode":0,"stdout":json.dumps({"unit":"amneziad.service","exec_start_raw":"{ path=/usr/local/bin/amneziad ; argv[]=/usr/local/bin/amneziad ; }","exe":"/usr/local/bin/amneziad","sha256":args[2],"size":int(args[3]),"main_pid":123 if args[4]=="post" else 0,"proc_exe_sha256":args[2] if args[4]=="post" else ""})}
  if "READ_RAW" in " ".join(args): raise AssertionError
  if args[:2]==["-c", __import__('deploy.release_lab.headless_native_qga_adapter',fromlist=['ABSENCE']).ABSENCE]: return {"exitcode":0,"stdout":"{\"exists\":false}"}
  if path=="/usr/bin/python3" and args[1].startswith("import base64"):
   return {"exitcode":0,"stdout":json.dumps({"origin":"guest","transport":"qga","path":args[3],"bytes_b64":"e30=","sha256":"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2,"uid":0,"gid":0,"mode":"0600"})}
  return {"exitcode":0,"stdout":"{\"stored\":1}"}
 def guest_exec(self,path,args): self.calls.append((path,args,None))

def test_stage_uses_exact_store_key_and_restart():
 f=Fake(); a=HeadlessNativeQgaAdapter(f,plan(),lambda:plan().outer_binding); value=a.stage_profile()
 assert set(value)=={"baseline_preflight","baseline_after_restart","profile_store","key","list_profiles"}
 assert any(c[0]=="/usr/bin/systemctl" and c[1]==["restart","amneziad.service"] for c in f.calls)
 assert all("passed" not in x for x in value.values())
 assert f.calls[0][1][1]==UNIT_PREFLIGHT
 assert next(i for i,c in enumerate(f.calls) if c[0]=="/usr/bin/systemctl") > 0
def test_ownership_checked_before_commands():
 f=Fake(); a=HeadlessNativeQgaAdapter(f,plan(),lambda:None)
 with pytest.raises(HeadlessNativeQgaError): a.stage_profile()
 assert not f.calls
def test_collectors_return_raw_records_without_acceptance_bool():
 f=Fake(); a=HeadlessNativeQgaAdapter(f,plan(),lambda:plan().outer_binding)
 for value in (a.collect_update_pending(),a.collect_update_stable(),a.trigger_rollback(),a.collect_rollback_pending(),a.collect_rollback_stable()):
  assert value and all("passed" not in record for record in value.values())
 assert any(UPDATE_JOURNAL in c[1] for c in f.calls if isinstance(c[1],list))
 assert any(ROLLBACK_RECEIPT in c[1] for c in f.calls if isinstance(c[1],list))
def test_reboot_waits_for_new_boot_id():
 f=Fake(); times=iter([0,1,2]); a=HeadlessNativeQgaAdapter(f,plan(),lambda:plan().outer_binding,clock=lambda:next(times),sleeper=lambda _:setattr(f,"boot","new"))
 assert a.reboot("old",10)=={"boot_id_before":"old","boot_id_after":"new"}
 assert f.calls[0][:2]==("/usr/bin/systemctl",["reboot"])

def test_wait_for_is_bounded_and_checks_outer_identity():
 times=iter([0,0,1,2,3]); f=Fake(); a=HeadlessNativeQgaAdapter(f,plan(),lambda:plan().outer_binding,clock=lambda:next(times),sleeper=lambda _:None)
 assert a.wait_for(lambda:{"state":"ready"},lambda x:x["state"]=="ready",timeout=3,label="update")["state"]=="ready"
 with pytest.raises(HeadlessNativeQgaError): a.wait_for(lambda:{},lambda _:False,timeout=True,label="bad")

def test_fixture_cleanup_requires_exact_pid_start_and_no_survivors(monkeypatch):
 f=Fake(); p=plan(); a=HeadlessNativeQgaAdapter(f,p,lambda:p.outer_binding)
 http={"fixture":{"pid":44,"start_ticks":55}}
 monkeypatch.setattr("deploy.release_lab.headless_native_qga_adapter.validate_http_receipt",lambda *_:dict(http))
 monkeypatch.setattr("deploy.release_lab.headless_native_qga_adapter.receipt_sha256",lambda _:"d"*64)
 base={"schema":1,"operation":"headless-native-fixture-cleanup","run_id":p.run_id,"case_id":p.case_id,
  "attempt_nonce":p.attempt_nonce,"origin":"server-fixture","transport":"qga","injected":False,
  "outer_binding":__import__('dataclasses').asdict(p.outer_binding),"http_receipt_sha256":"d"*64,
  "pid":44,"start_ticks":55,"identity_rechecked":True,"stopped":True,"listener_closed":True,"unknown_survivors":[]}
 assert a.validate_fixture_cleanup(base,http)["stopped"] is True
 base["pid"]=True
 with pytest.raises(HeadlessNativeQgaError): a.validate_fixture_cleanup(base,http)

def test_identity_must_come_from_exact_raw_guest_envelope():
 payload=json.dumps({"version":"5.0.1.38","daemon_pid":7}).encode()
 raw={"origin":"guest","transport":"qga","path":"identity:baseline-before","bytes_b64":__import__('base64').b64encode(payload).decode(),"size":len(payload),"sha256":__import__('hashlib').sha256(payload).hexdigest()}
 assert HeadlessNativeQgaAdapter._identity_from_raw(raw,"baseline-before")["daemon_pid"]==7
 raw["size"]=True
 with pytest.raises(HeadlessNativeQgaError): HeadlessNativeQgaAdapter._identity_from_raw(raw,"baseline-before")
