import hashlib,json,pytest
import deploy.release_lab.lab as lab_module
from types import SimpleNamespace
import deploy.release_lab.nested_cuttlefish_common_adapter as common_module
from deploy.release_lab.lab import LabController,LabError,artifact_record
from deploy.release_lab.nested_cuttlefish_runner import ApkSpec
from deploy.release_lab.test_nested_cuttlefish_common_adapter import Bridge,FixtureAdapter,Executor,PrivateLink
from deploy.release_lab.test_nested_cuttlefish_runner import plan

def arm_failure_archive(link):
 calls=[];link.failure_archive=lambda record:(calls.append(record) or {"origin":"controller","immutable":True,"path":"/tmp/failure.json","sha256":"f"*64,"size":1});return calls

def arm_boot_archive(bridge):
 calls=[];bridge.boot_failure_archive=lambda record:(calls.append(record) or {"origin":"controller","immutable":True,"path":"/tmp/boot-failure.json","sha256":"e"*64,"size":1});return calls

def canonical_for(sha,name):return f"/files/artifacts/{sha}/{name}"

def test_controller_runs_and_archives_authentic_nested_common_lifecycle(tmp_path,monkeypatch):
 p=plan();b=ApkSpec("baseline.apk","/baseline.apk",7,"9"*64,p.apk.package,2186);bridge=Bridge(p);fx=FixtureAdapter();link=PrivateLink(p,fx);monkeypatch.setattr(common_module,"NestedAppExecutor",Executor)
 arm_failure_archive(link);arm_boot_archive(bridge);monkeypatch.setattr(lab_module,"canonical_android_artifact_path",lambda *_:canonical_for(p.apk.sha256,p.apk.name))
 c=LabController(tmp_path,test_mode=True);c.assert_mutation_context=lambda:None
 try:
  vm={"pid":p.ownership.pid,"proc_start_time":str(p.ownership.start_ticks),"uid":999,"uuid":p.ownership.uuid,"qmp_socket":p.ownership.qmp_socket,"qga_socket":p.ownership.qga_socket}
  server={"pid":321,"proc_start_time":"654","uid":999,"uuid":"server-uuid","qmp_socket":"/server/qmp","qga_socket":"/server/qga"}
  manifest_file=tmp_path/"manifest.json";manifest_file.write_bytes(b"manifest")
  run={"run_id":p.ownership.run_id,"baseline_version":"5.0.1.38","candidate_version":"5.0.1.39","artifacts":{"android-arm64-v8a":{"path":p.apk.source_path,"sha256":p.apk.sha256,"size":p.apk.size}},"baseline_artifacts":{"android-arm64-v8a":{"path":b.source_path,"sha256":b.sha256,"size":b.size}},"outer_artifact":{"sha256":"1"*64},"manifest":{"path":str(manifest_file),"sha256":"2"*64,"size":8},"semantic_helper_records":{"deploy/release_lab/android/consumer_fixture_server.py":{"path":"/source/consumer_fixture_server.py","sha256":"3"*64,"size":99}},"android_vulkan_records":{"deb":{"path":p.vulkan_deb_path,"sha256":p.vulkan_deb_sha256,"size":p.vulkan_deb_size}},"profiles":{"android-arm64-v8a":{"status":"created","vm":None},"linux-headless-x64":{"status":"running","vm":vm},"server-router":{"status":"running","vm":server}}}
  def bind(x,profile):return {"run_id":p.ownership.run_id,"profile":profile,"marker":f"amnezia-release-lab:{p.ownership.run_id}:{profile}","pid":x["pid"],"start_ticks":str(x["proc_start_time"]),"uid":x["uid"],"uuid":x["uuid"],"qmp_socket":x["qmp_socket"],"qga_socket":x["qga_socket"]}
  server_core={k:bind(server,"server-router")[k] for k in ("pid","start_ticks","uuid","qmp_socket","qga_socket")}
  fx.plan=SimpleNamespace(run_id=p.ownership.run_id,attempt_nonce=p.ownership.attempt_nonce,marker=bind(server,"server-router")["marker"],outer_ownership=server_core,script_path=f"/var/lib/amnezia-release-lab/fixture/{p.ownership.attempt_nonce}/consumer_fixture_server.py",script_sha256="3"*64,script_size=99,manifest_path=f"/var/lib/amnezia-release-lab/fixture/{p.ownership.attempt_nonce}/manifest.json",apk_path=f"/var/lib/amnezia-release-lab/fixture/{p.ownership.attempt_nonce}/{p.apk.name}",manifest_sha256="2"*64,manifest_size=8,apk_sha256=p.apk.sha256,apk_size=p.apk.size,artifact_path=canonical_for(p.apk.sha256,p.apk.name),endpoint=link.p.endpoint)
  link.p=SimpleNamespace(run_id=p.ownership.run_id,attempt_nonce=p.ownership.attempt_nonce,outer_binding=bind(vm,"linux-headless-x64"),server_binding=bind(server,"server-router"),endpoint=fx.plan.endpoint,application_address="10.8.1.0/32",http_objects=(SimpleNamespace(path="/manifest.json",sha256="2"*64,size=8),SimpleNamespace(path=fx.plan.artifact_path,sha256=p.apk.sha256,size=p.apk.size)))
  link.start_and_probe=lambda:{"run_id":p.ownership.run_id,"attempt_nonce":p.ownership.attempt_nonce,"ready":True,"outer_ownership":bind(vm,"linux-headless-x64"),"server_ownership":bind(server,"server-router"),"application_links":{r:{"application_address":"10.8.1.0/32","present":True} for r in ("server","outer")},"http":[{"sha256":"2"*64,"bytes":8},{"sha256":p.apk.sha256,"bytes":p.apk.size}]}
  link.cleanup=lambda:{"run_id":p.ownership.run_id,"attempt_nonce":p.ownership.attempt_nonce,"clean":True,"outer_ownership":bind(vm,"linux-headless-x64"),"server_ownership":bind(server,"server-router"),"application_cleanup":{r:{"application_address":"10.8.1.0/32","present":False} for r in ("server","outer")},"socket":{"exists":False}}
  c.save_state({"schema":1,"lab_id":"test","runs":{p.ownership.run_id:run}})
  expected=[{"path":fx.plan.script_path,"sha256":fx.plan.script_sha256,"size":fx.plan.script_size,"uid":0,"mode":"0600"},{"path":fx.plan.manifest_path,"sha256":fx.plan.manifest_sha256,"size":fx.plan.manifest_size,"uid":0,"mode":"0600"},{"path":fx.plan.apk_path,"sha256":fx.plan.apk_sha256,"size":fx.plan.apk_size,"uid":0,"mode":"0600"}]
  payload={"schema":1,"run_id":p.ownership.run_id,"attempt_nonce":p.ownership.attempt_nonce,"guest_root":f"/var/lib/amnezia-release-lab/fixture/{p.ownership.attempt_nonce}","guest_root_inode":42,"files":expected,"origin":"guest","transport":"qga","injected":False};stage_path=tmp_path/"runs"/p.ownership.run_id/"controller"/"nested-fixture-stage.json";stage_path.parent.mkdir(parents=True);stage_path.write_text(json.dumps(payload),encoding="utf-8");rec=artifact_record(stage_path);run=c.get_run(p.ownership.run_id);run["nested_android_fixture_stage"]={**rec,"attempt_nonce":p.ownership.attempt_nonce}
  dep_core={"run_id":p.ownership.run_id,"attempt_nonce":p.ownership.attempt_nonce,"outer":dict(p.ownership.__dict__),"signed_index_verifier":{"sha256":"742b5e27241e308995a4a245828a07aeff72928bb49a9f74db35a96212572fa6"}};success_path=stage_path.parent/f"host-dependency-success-{p.ownership.attempt_nonce}.json";success_path.write_text(json.dumps(dep_core),encoding="utf-8");success_rec=artifact_record(success_path);dep_payload={**dep_core,"controller_success_archive":{"origin":"controller","immutable":True,"path":str(success_path),"sha256":success_rec["sha256"],"size":success_rec["size"]}};bridge.host_dependency_receipt=dep_payload;dep_path=stage_path.parent/"host-dependencies.json";dep_path.write_text(json.dumps(dep_payload),encoding="utf-8");dep_rec=artifact_record(dep_path);run["nested_android_host_dependencies"]={**dep_rec,"attempt_nonce":p.ownership.attempt_nonce,"verifier_sha256":dep_payload["signed_index_verifier"]["sha256"],"success_archive":{"path":str(success_path),"sha256":success_rec["sha256"],"size":success_rec["size"]}};state=c.load_state();state["runs"][p.ownership.run_id]=run;c.save_state(state)
  verifier=Path(__file__).resolve().parents[2]/"dist/release-lab-fixtures/android-cvd-host-dependencies-noble-amd64-20260913/wayland-verifier-receipt.json";run=c.get_run(p.ownership.run_id);supplement=verifier.parent/"android-cvd-wayland-supplement-3b2a227c.tar";run["android_wayland_records"]={"verifier":artifact_record(verifier),"supplement":artifact_record(supplement)}
  way_core={"schema":1,"operation":"nested-wayland-install","run_id":p.ownership.run_id,"attempt_nonce":p.ownership.attempt_nonce,"outer":dict(p.ownership.__dict__),"origin":"guest","transport":"qga","injected":False};way_success=stage_path.parent/f"wayland-success-{p.ownership.attempt_nonce}.json";way_success.write_text(json.dumps(way_core),encoding="utf-8");way_success_rec=artifact_record(way_success);way_payload={**way_core,"controller_archive":{"origin":"controller","immutable":True,"path":str(way_success),"sha256":way_success_rec["sha256"],"size":way_success_rec["size"]}};way_path=stage_path.parent/f"wayland-install-{p.ownership.attempt_nonce}.json";way_path.write_text(json.dumps(way_payload),encoding="utf-8");way_rec=artifact_record(way_path);run["nested_android_wayland"]={**way_rec,"attempt_nonce":p.ownership.attempt_nonce};state=c.load_state();state["runs"][p.ownership.run_id]=run;c.save_state(state);bridge.wayland_install_receipt=way_payload;bridge.wayland_installer=SimpleNamespace(plan=SimpleNamespace(run_id=p.ownership.run_id,attempt_nonce=p.ownership.attempt_nonce,outer=dict(p.ownership.__dict__),qemu_sha256=p.qemu_aarch64_sha256,supplement_path=str(supplement),verifier_path=str(verifier)))
  original_register=c.register_android_semantic
  def register_after_archive(*args,**kwargs):
   assert (tmp_path/"exports"/p.ownership.run_id/"android-arm64-v8a"/"receipt.json").is_file()
   assert (tmp_path/"exports"/p.ownership.run_id/"android-arm64-v8a"/"evidence.json").is_file()
   return original_register(*args,**kwargs)
  c.register_android_semantic=register_after_archive
  boot_archive=bridge.boot_failure_archive;bridge.boot_failure_archive=None
  with pytest.raises(LabError,match="lacks controller boot failure archive"):
   c.run_nested_android_semantic(p.ownership.run_id,p,bridge,fx,link,b,lambda:p.ownership,lambda *a:None,lambda *a:None)
  assert bridge.calls==[] and fx.events==[] and link.events==[]
  bridge.boot_failure_archive=boot_archive
  original_qemu=bridge.wayland_installer.plan.qemu_sha256;bridge.wayland_installer.plan.qemu_sha256="0"*64
  with pytest.raises(LabError,match="Wayland receipt"):
   c.run_nested_android_semantic(p.ownership.run_id,p,bridge,fx,link,b,lambda:p.ownership,lambda *a:None,lambda *a:None)
  assert bridge.calls==[] and fx.events==[] and link.events==[]
  bridge.wayland_installer.plan.qemu_sha256=original_qemu
  saved_way_success=way_success.read_bytes();way_success.write_text('{"tampered":true}',encoding="utf-8")
  with pytest.raises(LabError,match="Wayland success archive"):
   c.run_nested_android_semantic(p.ownership.run_id,p,bridge,fx,link,b,lambda:p.ownership,lambda *a:None,lambda *a:None)
  assert bridge.calls==[] and fx.events==[] and link.events==[]
  way_success.write_bytes(saved_way_success)
  way_success.unlink()
  with pytest.raises((LabError,FileNotFoundError),match="Wayland success archive|artifact does not exist"):
   c.run_nested_android_semantic(p.ownership.run_id,p,bridge,fx,link,b,lambda:p.ownership,lambda *a:None,lambda *a:None)
  assert bridge.calls==[] and fx.events==[] and link.events==[]
  way_success.write_bytes(saved_way_success)
  result=c.run_nested_android_semantic(p.ownership.run_id,p,bridge,fx,link,b,lambda:p.ownership,lambda *a:None,lambda *a:None)
  current=c.get_run(p.ownership.run_id)["profiles"]["android-arm64-v8a"]
  assert current["status"]=="evidence-collected" and current["nested_transport"]=="qga"
  assert [x["id"] for x in current["steps"]]==["probe","reinstall","update","service-health"]
  assert result["archive"]["guest_binding"]["outer_ownership"]["uuid"]==p.ownership.uuid
  assert artifact_record(Path(current["evidence_archive"]))["size"]>0
  before=list(bridge.calls)
  with pytest.raises(LabError,match="already exists"):c.run_nested_android_semantic(p.ownership.run_id,p,bridge,fx,link,b,lambda:p.ownership,lambda *a:None,lambda *a:None)
  assert bridge.calls==before
 finally:pass

def test_foreign_fixture_plan_rejected_before_any_guest_mutation(tmp_path,monkeypatch):
 p=plan();b=ApkSpec("baseline.apk","/baseline.apk",7,"9"*64,p.apk.package,2186);bridge=Bridge(p);fx=FixtureAdapter();link=PrivateLink(p,fx);monkeypatch.setattr(common_module,"NestedAppExecutor",Executor)
 archive_calls=arm_failure_archive(link)
 arm_boot_archive(bridge)
 fx.plan=SimpleNamespace(run_id="foreign");link.p=SimpleNamespace()
 c=LabController(tmp_path,test_mode=True);c.assert_mutation_context=lambda:None
 vm={"pid":p.ownership.pid,"proc_start_time":str(p.ownership.start_ticks),"uid":999,"uuid":p.ownership.uuid,"qmp_socket":p.ownership.qmp_socket,"qga_socket":p.ownership.qga_socket}
 manifest_file=tmp_path/"manifest.json";manifest_file.write_bytes(b"manifest");monkeypatch.setattr(lab_module,"canonical_android_artifact_path",lambda *_:"/candidate.apk")
 c.save_state({"schema":1,"lab_id":"test","runs":{p.ownership.run_id:{"run_id":p.ownership.run_id,"baseline_version":"5.0.1.38","candidate_version":"5.0.1.39","artifacts":{"android-arm64-v8a":{"path":p.apk.source_path,"sha256":p.apk.sha256,"size":p.apk.size}},"outer_artifact":{"sha256":"1"*64},"manifest":{"path":str(manifest_file),"sha256":"2"*64,"size":8},"profiles":{"android-arm64-v8a":{"status":"created","vm":None},"linux-headless-x64":{"status":"running","vm":vm},"server-router":{"status":"running","vm":vm}}}}})
 with pytest.raises(LabError,match="fixture/private-link plan"):c.stage_nested_android_fixture(p.ownership.run_id,p,fx,link,b)
 assert bridge.calls==[] and fx.events==[] and link.events==[]
 assert archive_calls==[]

@pytest.mark.parametrize("tamper",["baseline","script"])
def test_frozen_baseline_and_fixture_script_rejected_before_mutation(tmp_path,monkeypatch,tamper):
 p=plan();b=ApkSpec("baseline.apk","/baseline.apk",7,"9"*64,p.apk.package,2186);bridge=Bridge(p);fx=FixtureAdapter();link=PrivateLink(p,fx);monkeypatch.setattr(common_module,"NestedAppExecutor",Executor)
 archive_calls=arm_failure_archive(link);arm_boot_archive(bridge);monkeypatch.setattr(lab_module,"canonical_android_artifact_path",lambda *_:canonical_for(p.apk.sha256,p.apk.name))
 vm={"pid":p.ownership.pid,"proc_start_time":str(p.ownership.start_ticks),"uid":999,"uuid":p.ownership.uuid,"qmp_socket":p.ownership.qmp_socket,"qga_socket":p.ownership.qga_socket};server={"pid":321,"proc_start_time":"654","uid":999,"uuid":"server","qmp_socket":"/s/qmp","qga_socket":"/s/qga"}
 def bind(x,profile):return {"run_id":p.ownership.run_id,"profile":profile,"marker":f"amnezia-release-lab:{p.ownership.run_id}:{profile}","pid":x["pid"],"start_ticks":str(x["proc_start_time"]),"uid":x["uid"],"uuid":x["uuid"],"qmp_socket":x["qmp_socket"],"qga_socket":x["qga_socket"]}
 core={k:bind(server,"server-router")[k] for k in ("pid","start_ticks","uuid","qmp_socket","qga_socket")};artifact_path=canonical_for(p.apk.sha256,p.apk.name);fx.plan=SimpleNamespace(run_id=p.ownership.run_id,attempt_nonce=p.ownership.attempt_nonce,marker=bind(server,"server-router")["marker"],outer_ownership=core,script_path="/var/lib/amnezia-release-lab/fixture/x/consumer_fixture_server.py",script_sha256="3"*64,script_size=99,manifest_sha256="2"*64,manifest_size=8,apk_sha256=p.apk.sha256,apk_size=p.apk.size,artifact_path=artifact_path,endpoint=link.p.endpoint);link.p=SimpleNamespace(run_id=p.ownership.run_id,attempt_nonce=p.ownership.attempt_nonce,outer_binding=bind(vm,"linux-headless-x64"),server_binding=bind(server,"server-router"),endpoint=fx.plan.endpoint,application_address="10.8.1.0/32",http_objects=(SimpleNamespace(path="/manifest.json",sha256="2"*64,size=8),SimpleNamespace(path=artifact_path,sha256=p.apk.sha256,size=p.apk.size)))
 manifest_file=tmp_path/"manifest.json";manifest_file.write_bytes(b"manifest")
 c=LabController(tmp_path,test_mode=True);c.assert_mutation_context=lambda:None;c.save_state({"schema":1,"lab_id":"test","runs":{p.ownership.run_id:{"run_id":p.ownership.run_id,"baseline_version":"5.0.1.38","candidate_version":"5.0.1.39","artifacts":{"android-arm64-v8a":{"path":p.apk.source_path,"sha256":p.apk.sha256,"size":p.apk.size}},"baseline_artifacts":{"android-arm64-v8a":{"path":b.source_path,"sha256":b.sha256,"size":b.size}},"outer_artifact":{"sha256":"1"*64},"manifest":{"path":str(manifest_file),"sha256":"2"*64,"size":8},"semantic_helper_records":{"deploy/release_lab/android/consumer_fixture_server.py":{"path":"/source/consumer_fixture_server.py","sha256":"3"*64,"size":99}},"android_vulkan_records":{"deb":{"path":p.vulkan_deb_path,"sha256":p.vulkan_deb_sha256,"size":p.vulkan_deb_size}},"profiles":{"android-arm64-v8a":{"status":"created","vm":None},"linux-headless-x64":{"status":"running","vm":vm},"server-router":{"status":"running","vm":server}}}}})
 if tamper=="baseline":b=ApkSpec(b.name,b.source_path,b.size,"8"*64,b.package,b.version_code)
 else:fx.plan.script_sha256="4"*64
 with pytest.raises(LabError,match="fixture/private-link plan"):c.run_nested_android_semantic(p.ownership.run_id,p,bridge,fx,link,b,lambda:p.ownership,lambda *a:None,lambda *a:None)
 assert bridge.calls==[] and fx.events==[] and link.events==[]
 assert archive_calls==[]


from pathlib import Path

def test_controller_stages_only_after_preflight_and_persists_exact_receipt(tmp_path,monkeypatch):
 files=[]
 for name,data in (("consumer_fixture_server.py",b"helper"),("manifest.json",b"manifest"),("candidate.apk",b"apk")):
  path=tmp_path/name;path.write_bytes(data);files.append((path,hashlib.sha256(data).hexdigest(),len(data)))
 run_id="stage-run";nonce="a"*48
 def vm(profile,pid):return {"pid":pid,"proc_start_time":str(pid*10),"uid":999,"uuid":profile,"qmp_socket":f"/{profile}/qmp","qga_socket":f"/{profile}/qga"}
 outer=vm("outer",20);server=vm("server",21)
 def bind(x,profile):return {"run_id":run_id,"profile":profile,"marker":f"amnezia-release-lab:{run_id}:{profile}","pid":x["pid"],"start_ticks":str(x["proc_start_time"]),"uid":x["uid"],"uuid":x["uuid"],"qmp_socket":x["qmp_socket"],"qga_socket":x["qga_socket"]}
 core={k:bind(server,"server-router")[k] for k in ("pid","start_ticks","uuid","qmp_socket","qga_socket")};guest=f"/var/lib/amnezia-release-lab/fixture/{nonce}"
 class Qga:
  def __init__(self):self.events=[];self.socket_path=server["qga_socket"];self.fail=False;self.malformed=False;self.change=False
  def guest_exec_wait(self,exe,args,timeout):
   self.events.append(("exec",args[-1] if len(args)<4 else "verify"))
   if "rows=[]" in args[1]:
    rows=[{"path":args[i],"sha256":args[i+1],"size":int(args[i+2]),"uid":0,"mode":"0600"} for i in range(2,len(args),3)];return {"exitcode":0,"stdout":json.dumps({"files":rows})}
   if self.change:current[0]={**core,"uuid":"replaced"}
   return {"exitcode":0,"stdout":"{" if self.malformed else json.dumps({"root_inode":42,"uid":0,"mode":"0o700"})}
  def write_file_from_path(self,path,source,sha,size,**bounds):
   assert hashlib.sha256(source.read_bytes()).hexdigest()==sha and source.stat().st_size==size
   self.events.append(("write",path,size))
   if self.fail:fake_clock[0]=901;raise LabError("QGA streaming deadline expired")
 fake_clock=[0];monkeypatch.setattr(lab_module.time,"monotonic",lambda:fake_clock[0])
 q=Qga();current=[core];fp=SimpleNamespace(run_id=run_id,attempt_nonce=nonce,marker=f"amnezia-release-lab:{run_id}:server-router",outer_ownership=core,script_path=f"{guest}/consumer_fixture_server.py",script_sha256=files[0][1],script_size=files[0][2],manifest_path=f"{guest}/manifest.json",manifest_sha256=files[1][1],manifest_size=files[1][2],apk_path=f"{guest}/candidate.apk",apk_sha256=files[2][1],apk_size=files[2][2],endpoint="http://10.8.1.0:17865")
 fp.artifact_path=canonical_for(files[2][1],files[2][0].name);monkeypatch.setattr(lab_module,"canonical_android_artifact_path",lambda *_:fp.artifact_path)
 fixture=SimpleNamespace(plan=fp,qga=q,snapshot=lambda:current[0]);lp=SimpleNamespace(run_id=run_id,attempt_nonce=nonce,outer_binding=bind(outer,"linux-headless-x64"),server_binding=bind(server,"server-router"),endpoint=fp.endpoint,application_address="10.8.1.0/32",http_objects=(SimpleNamespace(path="/manifest.json",sha256=files[1][1],size=files[1][2]),SimpleNamespace(path=fp.artifact_path,sha256=files[2][1],size=files[2][2])))
 private=SimpleNamespace(p=lp,failure_archive=lambda _:{"origin":"controller","immutable":True,"path":"/tmp/failure.json","sha256":"f"*64,"size":1})
 plan_obj=SimpleNamespace(ownership=SimpleNamespace(run_id=run_id,attempt_nonce=nonce),apk=SimpleNamespace(package="org.amnezia.vpn"),vulkan_deb_path="/mnt/c/Users/ivano/PycharmProjects/amnezia-client/dist/release-lab-fixtures/android-cvd-vulkan-noble-amd64-20260913/libvulkan1_1.3.275.0-1build1_amd64.deb",vulkan_deb_sha256="ccf4fe8f4461442f27ea2494c7ae650b60bd396fec2688b0c44a27d66a222f74",vulkan_deb_size=142010);base=SimpleNamespace(name=files[2][0].name,source_path=str(files[2][0]),sha256=files[2][1],size=files[2][2],package="org.amnezia.vpn")
 c=LabController(tmp_path/"state",test_mode=True);c.assert_mutation_context=lambda:None;c.save_state({"schema":1,"lab_id":"test","runs":{run_id:{"run_id":run_id,"artifacts":{"android-arm64-v8a":{"path":str(files[2][0]),"sha256":files[2][1],"size":files[2][2]}},"baseline_artifacts":{"android-arm64-v8a":{"path":str(files[2][0]),"sha256":files[2][1],"size":files[2][2]}},"manifest":{"path":str(files[1][0]),"sha256":files[1][1],"size":files[1][2]},"semantic_helper_records":{"deploy/release_lab/android/consumer_fixture_server.py":{"path":str(files[0][0]),"sha256":files[0][1],"size":files[0][2]}},"android_vulkan_records":{"deb":{"path":plan_obj.vulkan_deb_path,"sha256":plan_obj.vulkan_deb_sha256,"size":plan_obj.vulkan_deb_size}},"profiles":{"linux-headless-x64":{"vm":outer},"server-router":{"vm":server}}}}})
 receipt=c.stage_nested_android_fixture(run_id,plan_obj,fixture,private,base)
 assert [x[0] for x in q.events]==["exec","write","write","write","exec"] and receipt["files"][2]["sha256"]==files[2][1]
 assert c.get_run(run_id)["nested_android_fixture_stage"]["sha256"]==artifact_record(tmp_path/"state"/"runs"/run_id/"controller"/"nested-fixture-stage.json")["sha256"]
 failed_state=c.load_state();failed_state["runs"][run_id].pop("nested_android_fixture_stage");c2=LabController(tmp_path/"failed",test_mode=True);c2.assert_mutation_context=lambda:None;c2.save_state(failed_state);q.events=[];q.fail=True;fake_clock[0]=0
 with pytest.raises(LabError,match="streaming deadline expired"):c2.stage_nested_android_fixture(run_id,plan_obj,fixture,private,base)
 assert q.events[-1][0]=="exec" and len([x for x in q.events if x[0]=="exec"])==2
 failed_state["runs"][run_id].pop("nested_android_fixture_stage",None);c3=LabController(tmp_path/"malformed",test_mode=True);c3.assert_mutation_context=lambda:None;c3.save_state(failed_state);q.events=[];q.fail=False;q.malformed=True;fake_clock[0]=0
 with pytest.raises(LabError,match="root receipt missing"):c3.stage_nested_android_fixture(run_id,plan_obj,fixture,private,base)
 assert len([x for x in q.events if x[0]=="exec"])==2
 c4=LabController(tmp_path/"identity",test_mode=True);c4.assert_mutation_context=lambda:None;c4.save_state(failed_state);q.events=[];q.malformed=False;q.change=True;current[0]=core
 with pytest.raises(LabError,match="identity/QGA changed"):c4.stage_nested_android_fixture(run_id,plan_obj,fixture,private,base)
 assert len(q.events)==1 and q.events[0][0]=="exec"  # never delete in the replacement VM
 assert (tmp_path/"identity"/"runs"/run_id/"controller"/f"nested-fixture-stage-failure-{nonce}.json").is_file()
