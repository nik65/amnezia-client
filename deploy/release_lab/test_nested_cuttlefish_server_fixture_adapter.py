import hashlib,json,subprocess,sys
from pathlib import Path
import pytest
from deploy.release_lab.nested_cuttlefish_runner import NestedCuttlefishError,receipt_sha
from deploy.release_lab.nested_cuttlefish_server_fixture_adapter import ServerFixturePlan,ServerRouterFixtureAdapter,IDENTITY,RESET,READ_LOG,STOP,canonical_android_artifact_path,server_outer_from_vm

def test_operator_script_style_lab_import_works_in_fresh_interpreter():
 root=Path(__file__).resolve().parents[2]
 code=("import sys; sys.path.insert(0, r'"+str(root/"deploy"/"release_lab")+"'); "
       "from lab import LabController; assert LabController.__name__ == 'LabController'")
 result=subprocess.run([sys.executable,"-I","-c",code],capture_output=True,text=True,timeout=20)
 assert result.returncode==0,result.stderr

def signed_manifest(url,sha="c"*64,size=30):
 import base64
 payload={"platforms":{"android-arm64-v8a":{"url":url,"sha256":sha,"size":size}}}
 encoded=base64.urlsafe_b64encode(json.dumps(payload,separators=(",",":")).encode()).decode().rstrip("=")
 return json.dumps({"payload":encoded,"signature":"present"},separators=(",",":")).encode()

def plan():
 return ServerFixturePlan("run","1"*48,"http://10.8.1.2:17865","amnezia-release-lab:run:server-router",{"pid":2,"start_ticks":3,"uuid":"u","qmp_socket":"/qmp","qga_socket":"/qga"},"/var/lib/amnezia-release-lab/fixture/server.py","a"*64,12,"/var/lib/amnezia-release-lab/fixture/manifest.json","b"*64,20,"/var/lib/amnezia-release-lab/fixture/app.apk","c"*64,30,f"/files/artifacts/{'c'*64}/app.apk","/var/lib/amnezia-release-lab/fixture/requests.jsonl")
class Q:
 def __init__(self):self.calls=[];self.pid=44;self.health_bad=False
 def guest_exec(self,path,args):self.calls.append(("launch",args));return {"pid":self.pid}
 def guest_exec_wait(self,path,args,timeout):
  self.calls.append(("wait",args,timeout));code=args[1]
  if "zip(sys.argv" in code:
   p=plan();return {"stdout":json.dumps({"files":[{"path":p.script_path,"sha256":p.script_sha256,"size":p.script_size},{"path":p.manifest_path,"sha256":p.manifest_sha256,"size":p.manifest_size},{"path":p.apk_path,"sha256":p.apk_sha256,"size":p.apk_size}]})}
  if code==IDENTITY:return {"stdout":json.dumps({"pid":44,"start_ticks":55,"exe":"/usr/bin/python3","cmdline_sha256":"d"*64,"identity_rechecked":True})}
  if code==RESET:
   health=b'{"status":"ok","run_id":"run","role":"consumer-fixture"}'
   return {"stdout":json.dumps({"reset_token":args[5],"log_inode":9,"offset":0,"empty_sha256":hashlib.sha256(b"").hexdigest(),"reset_at":100.0,"run_id":"run","attempt_nonce":"1"*48,"cleared_health_request":{"method":"GET","path":"/healthz","status":200,"sha256":hashlib.sha256(health).hexdigest(),"bytes":len(health),"content_length":len(health),"eof":True,"peer":"10.0.2.15","observed_at":99.0,"run_id":"run","attempt_nonce":"1"*48}})}
  if "/__lab__/health" in code:return {"stdout":json.dumps({"status":"bad"} if self.health_bad else {"status":"ok","run_id":"run","role":"consumer-fixture"})}
  if code==READ_LOG:
   rows=[{"method":"GET","path":"/manifest.json","status":200,"sha256":"b"*64,"bytes":20,"content_length":20,"eof":True,"peer":"10.0.2.15","observed_at":101.0},{"method":"GET","path":f"/files/artifacts/{'c'*64}/app.apk","status":200,"sha256":"c"*64,"bytes":30,"content_length":30,"eof":True,"peer":"10.0.2.15","observed_at":102.0}]
   return {"stdout":json.dumps({"reset_token":"1"*48,"log_inode":9,"start_offset":0,"rows":rows,"log_sha256":"e"*64,"log_size":4,"finished_at":103.0})}
  if code==STOP:return {"stdout":json.dumps({"pid":44,"start_ticks":55,"identity_rechecked":True,"stopped":True,"listener_closed":True,"unknown_survivors":[]})}
  return {"stdout":json.dumps({"sha256":"e"*64,"size":4})}
def test_real_callback_sequence_binds_guest_cursor_and_cleanup(monkeypatch):
 monkeypatch.setattr("deploy.release_lab.nested_cuttlefish_server_fixture_adapter.secrets.token_hex",lambda _:"1"*48)
 p=plan();q=Q();a=ServerRouterFixtureAdapter(q,p,lambda:dict(p.outer_ownership),clock=lambda:0,sleep=lambda _:None)
 start=a.callback("start",{"run_id":"run","attempt_nonce":"1"*48},20);assert a.callback("start",{"run_id":"run","attempt_nonce":"1"*48},20)["pid"]==start["pid"];reset=a.callback("reset",{"run_id":"run","attempt_nonce":"1"*48},20);log=a.callback("read-log",{"run_id":"run","attempt_nonce":"1"*48},20);stop=a.callback("stop",{"run_id":"run","attempt_nonce":"1"*48},20)
 assert start["identity_rechecked"] and reset["log_inode"]==log["log_inode"] and log["reset_receipt_sha256"]==receipt_sha(reset)
 assert a.app_fixture().pid==start["pid"] and a.outer_binding==dict(p.outer_ownership)
 assert [x["path"] for x in log["requests"]]==["/manifest.json",p.artifact_path]
 assert stop["listener_closed"] and stop["unknown_survivors"]==[]
 assert sum(1 for x in q.calls if x[0]=="launch")==1
 assert "--marker" not in q.calls[1][1]
def test_outer_change_and_payload_forgery_fail_before_guest_call():
 p=plan();q=Q();a=ServerRouterFixtureAdapter(q,p,lambda:{**dict(p.outer_ownership),"pid":99})
 with pytest.raises(NestedCuttlefishError,match="outer ownership"):a.callback("start",{"run_id":"run","attempt_nonce":"1"*48},20)
 a=ServerRouterFixtureAdapter(q,p,lambda:dict(p.outer_ownership))
 with pytest.raises(NestedCuttlefishError,match="payload"):a.callback("reset",{"run_id":"other","attempt_nonce":"1"*48},20)
def test_plan_rejects_nonowned_paths_or_wrong_manifest_artifact_path():
 p=plan();bad=ServerFixturePlan(**{**p.__dict__,"request_log":"/tmp/log"})
 with pytest.raises(NestedCuttlefishError,match="path ownership"):bad.validate()
 bad=ServerFixturePlan(**{**p.__dict__,"artifact_path":"/app.apk"})
 with pytest.raises(NestedCuttlefishError,match="artifact path"):bad.validate()
 bad=ServerFixturePlan(**{**p.__dict__,"request_log":"/var/lib/amnezia-release-lab/fixture/../escaped"})
 with pytest.raises(NestedCuttlefishError,match="path ownership"):bad.validate()
 assert server_outer_from_vm({"pid":2,"proc_start_time":3,"uuid":"u","qmp_socket":"/qmp","qga_socket":"/qga"})==p.outer_ownership
def test_failed_start_guardedly_stops_identified_process():
 p=plan();q=Q();q.health_bad=True
 class Clock:
  def __init__(self):self.n=0
  def __call__(self):self.n+=1;return self.n
 a=ServerRouterFixtureAdapter(q,p,lambda:dict(p.outer_ownership),clock=Clock(),sleep=lambda _:None)
 with pytest.raises(NestedCuttlefishError,match="start expired"):a.start(3)
 assert any(x[0]=="wait" and x[1][1]==STOP for x in q.calls)

def test_signed_manifest_preserves_encoded_plus_and_binds_local_basename():
 sha="c"*64;name="AmneziaVPN_5.0.1.39_android9+_arm64-v8a.apk";raw=f"files/artifacts/{sha}/AmneziaVPN_5.0.1.39_android9%2B_arm64-v8a.apk"
 assert canonical_android_artifact_path(signed_manifest(raw),sha,30,name)=="/"+raw

@pytest.mark.parametrize("url",[
 "files/artifacts/"+"c"*64+"/../app.apk",
 "files//artifacts/"+"c"*64+"/AmneziaVPN_5.0.1.39_android9%2B_arm64-v8a.apk",
 "files/artifacts/"+"c"*64+"/AmneziaVPN_5.0.1.39_android9%252B_arm64-v8a.apk",
 "files/artifacts/"+"c"*64+"/AmneziaVPN_5.0.1.39_android9%2B_arm64-v8a.apk?x=1",
 "https://example.invalid/files/artifacts/"+"c"*64+"/AmneziaVPN_5.0.1.39_android9%2B_arm64-v8a.apk",
])
def test_signed_manifest_rejects_traversal_double_encoding_query_or_origin(url):
 with pytest.raises(NestedCuttlefishError):canonical_android_artifact_path(signed_manifest(url),"c"*64,30,"AmneziaVPN_5.0.1.39_android9+_arm64-v8a.apk")

def test_actual_final3_manifest_android_url_contract():
 root=__import__('pathlib').Path(__file__).resolve().parents[2];manifest=root/'dist/full-release-5.0.1.39-20260913-final3/updates/manifest.json';apk=root/'dist/full-release-5.0.1.39-20260913-final3/artifacts/AmneziaVPN_5.0.1.39_android9+_arm64-v8a.apk'
 if not manifest.is_file() or not apk.is_file():pytest.skip('actual frozen artifacts unavailable')
 data=apk.read_bytes();sha=hashlib.sha256(data).hexdigest();path=canonical_android_artifact_path(manifest.read_bytes(),sha,len(data),apk.name)
 assert "%2B" in path and "+" not in path
