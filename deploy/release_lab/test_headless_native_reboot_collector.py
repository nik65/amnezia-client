import base64,hashlib,json
import pytest
from deploy.release_lab.headless_native_acceptance import ReleaseBytes
from deploy.release_lab.headless_native_qga_adapter import HeadlessNativeQgaError
from deploy.release_lab.headless_native_reboot_collector import HeadlessNativeRebootCollector,ROLLBACK,ROLLBACK_ARGV,MARKER
from deploy.release_lab.test_headless_native_acceptance import plan,BOOT,raw

class Native:
 def raw_file(self,path):return raw(path,{"attempt_nonce":plan().attempt_nonce})
 def identity(self,expected,label):return raw("identity:"+label,{"version":expected.version})
 def _json_record(self,*_):return raw("systemctl:amneziad.service",{"enabled":"enabled","active":"active"})
 def cli_json(self,*_):return raw("cli:doctor",{"ok":True,"result":{"updates":{"state":"rolled_back"}}})
class Q:
 def __init__(self):self.calls=[];self.boot=0
 def guest_exec_wait(self,path,args,timeout):
  self.calls.append((path,args,timeout));code=args[1] if args and args[0]=="-c" else ""
  if code==ROLLBACK:
   data=json.dumps({"ok":True,"result":{"updates":{"state":"rollback_restart_pending"}}}).encode();p={"pid":8,"start_ticks":9,"exe":ROLLBACK_ARGV[0],"exe_sha256":"a"*64,"argv":ROLLBACK_ARGV,"cmdline_sha256":"b"*64,"exit_code":0};return {"stdout":json.dumps({"process":p,"stdout_b64":base64.b64encode(data).decode(),"stdout_sha256":hashlib.sha256(data).hexdigest(),"stdout_size":len(data)})}
  if code==MARKER:return {"stdout":json.dumps({"path":args[2],"sha256":raw(args[2],{"attempt_nonce":plan().attempt_nonce})["sha256"],"size":raw(args[2],{"attempt_nonce":plan().attempt_nonce})["size"],"uid":0,"mode":"0600"})}
  return {"stdout":"33333333-3333-3333-3333-333333333333"}
 def guest_exec(self,path,args):self.calls.append((path,args));return {"pid":77}
 def sync(self):return True
def test_official_cli_identity_and_reboot_raw_collectors():
 p=plan();q=Q();c=HeadlessNativeRebootCollector(q,p,Native(),lambda:p.outer_binding,clock=lambda:0,sleep=lambda _:None)
 rollback=c.trigger_rollback("a"*64);assert rollback["cli_process"]["argv"]==ROLLBACK_ARGV and json.loads(base64.b64decode(rollback["cli_response"]["bytes_b64"]))["ok"]
 reboot=c.reboot_and_collect(BOOT,p.baseline,10);assert reboot["boot_id_after"]!=BOOT and reboot["raw_sources"]["persistent_marker"]
def test_wrong_cli_hash_or_outer_binding_fails_closed():
 p=plan();c=HeadlessNativeRebootCollector(Q(),p,Native(),lambda:p.outer_binding)
 with pytest.raises(HeadlessNativeQgaError,match="CLI hash"):c.trigger_rollback("bad")
 c=HeadlessNativeRebootCollector(Q(),p,Native(),lambda:None)
 with pytest.raises(HeadlessNativeQgaError,match="ownership"):c.trigger_rollback("a"*64)
def test_marker_contract_is_o_excl_root_owned_and_durable():
 assert "os.O_EXCL|os.O_NOFOLLOW" in MARKER and "os.fsync" in MARKER and "os.chown(p,0,0)" in MARKER
