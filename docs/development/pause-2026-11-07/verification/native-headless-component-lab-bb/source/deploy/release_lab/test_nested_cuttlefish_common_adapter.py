from dataclasses import asdict
import pytest
import deploy.release_lab.nested_cuttlefish_common_adapter as common_module
from deploy.release_lab.nested_cuttlefish_common_adapter import NestedCommonError,NestedCuttlefishCommonAdapter
from deploy.release_lab.nested_cuttlefish_runner import ApkSpec
from deploy.release_lab.test_nested_cuttlefish_runner import plan,stage,boot,app,base

class Bridge:
 def __init__(self,p):self.plan=p;self.calls=[];self.qga=object();self.fail_cleanup=False;self.boot_failure_archive=lambda record:{"origin":"controller","immutable":True,"path":"/archive/boot.json","sha256":"a"*64,"size":1}
 def stage(self):self.calls.append("stage");return stage()
 def stage_additional_asset(self,s):self.calls.append("baseline-stage");return {"guest_path":f"{self.plan.root}/input/{s.name}","sha256":s.sha256,"size":s.size}
 def launch_boot(self,s):self.calls.append("boot");return boot()
 def cleanup(self,b):
  self.calls.append("cleanup")
  if self.fail_cleanup:raise RuntimeError("cleanup")
  expected=sorted(x["pid"] for x in b["processes"]);r=base("nested-cuttlefish-cleanup");r.update({"terminated_pids":expected,"stopped_identities":[{"pid":x,"stopped":True} for x in expected],"unknown_survivors":[],"owned_sockets_remaining":[],"all_stopped":True,"marker_removed":True});return r
class FixtureAdapter:
 def __init__(self):self.events=[];self.snapshot=lambda:{"fixture":True};self.callback=lambda *a:{}
 def start(self):self.events.append("start");return {"ready":True}
 def app_fixture(self):return object()
 def stop(self):self.events.append("stop");return {"stopped":True}
class PrivateLink:
 def __init__(self,p,fx):
  self.events=[];self.fail_cleanup=False
  self.p=type("P",(),{"endpoint":"http://10.8.1.0:17865","application_address":"10.8.1.0/32"})()
  fx.app_fixture=lambda:type("F",(),{"endpoint":self.p.endpoint})()
  self.run_id=p.ownership.run_id;self.nonce=p.ownership.attempt_nonce
 def start_and_probe(self):self.events.append("start");return {"run_id":self.run_id,"attempt_nonce":self.nonce,"ready":True,"server_ownership":{"uuid":"server"},"outer_ownership":{"uuid":"outer"},"application_links":{r:{"application_address":"10.8.1.0/32","present":True} for r in ("server","outer")}}
 def cleanup(self):
  self.events.append("cleanup")
  if self.fail_cleanup:raise RuntimeError("link cleanup")
  return {"run_id":self.run_id,"attempt_nonce":self.nonce,"clean":True,"application_cleanup":{r:{"application_address":"10.8.1.0/32","present":False} for r in ("server","outer")}}
class Executor:
 fail_baseline=False; tamper=False
 def __init__(self,qga,p,boot_receipt,b,fixture,outer,snapshot,callback,**kwargs):self.plan=p;self.baseline=b;self.boot=dict(boot_receipt)
 def install_baseline(self,path):
  if type(self).fail_baseline:raise RuntimeError("baseline failed")
  artifact=asdict(self.baseline);artifact["sha256"]="8"*64 if type(self).tamper else artifact["sha256"]
  return {"schema":2,"operation":"nested-baseline-setup","artifact":artifact,"ui":{"version_code":self.baseline.version_code},"passed":True}
 def run_update(self):return app()

def make(monkeypatch):
 p=plan();b=ApkSpec("baseline.apk","/baseline.apk",7,"9"*64,p.apk.package,2186);bridge=Bridge(p);fx=FixtureAdapter();link=PrivateLink(p,fx);Executor.fail_baseline=False;Executor.tamper=False;monkeypatch.setattr(common_module,"NestedAppExecutor",Executor);return p,b,bridge,fx,link
def adapter(p,b,bridge,fx,link):return NestedCuttlefishCommonAdapter(p,bridge,b,"5.0.1.38","5.0.1.39",fx,link,lambda:p.ownership)
def test_full_lifecycle_derives_exact_four_common_steps(monkeypatch):
 p,b,bridge,fx,link=make(monkeypatch);events=[]
 old_fs,old_ls,old_stage=fx.start,link.start_and_probe,bridge.stage
 fx.start=lambda:(events.append("fixture"),old_fs())[1];link.start_and_probe=lambda:(events.append("link"),old_ls())[1];bridge.stage=lambda:(events.append("stage"),old_stage())[1]
 r=adapter(p,b,bridge,fx,link).run()
 assert [x["id"] for x in r["steps"]]==["probe","reinstall","update","service-health"]
 assert r["transport"]=="nested-qga" and r["candidate"]["sha256"]==p.apk.sha256
 assert bridge.calls==["stage","baseline-stage","boot","cleanup"] and fx.events==["start"] and link.events==["start","cleanup"]
 assert r["steps"][1]["raw_assertion"]["artifact"]["sha256"]==b.sha256
 assert events==["fixture","link","stage"]
def test_baseline_tamper_cannot_be_promoted_to_reinstall_and_cleanup_runs(monkeypatch):
 p,b,bridge,fx,link=make(monkeypatch);Executor.tamper=True
 with pytest.raises(NestedCommonError,match="baseline"):adapter(p,b,bridge,fx,link).run()
 assert bridge.calls[-1]=="cleanup" and fx.events==["start","stop"] and link.events[-1]=="cleanup"
def test_baseline_exception_preserves_primary_and_always_cleans(monkeypatch):
 p,b,bridge,fx,link=make(monkeypatch);Executor.fail_baseline=True;bridge.fail_cleanup=True;link.fail_cleanup=True
 with pytest.raises(RuntimeError,match="baseline failed") as caught:adapter(p,b,bridge,fx,link).run()
 assert bridge.calls[-1]=="cleanup" and fx.events==["start","stop"] and link.events[-1]=="cleanup" and any("inner cleanup" in x for x in getattr(caught.value,"__notes__",[])) and any("private-link cleanup" in x for x in getattr(caught.value,"__notes__",[]))
def test_missing_durable_app_failure_archive_retains_inner_evidence(monkeypatch):
 p,b,bridge,fx,link=make(monkeypatch)
 original=Executor.run_update
 def fail(self):
  error=RuntimeError("archive rejected");error.retain_owned_evidence=True;raise error
 Executor.run_update=fail
 try:
  with pytest.raises(RuntimeError,match="archive rejected"):adapter(p,b,bridge,fx,link).run()
  assert "cleanup" not in bridge.calls and link.events[-1]=="cleanup"
 finally:Executor.run_update=original
def test_component_plan_mismatch_rejected_before_execution(monkeypatch):
 p,b,bridge,fx,link=make(monkeypatch);bridge.plan=object()
 with pytest.raises(NestedCommonError,match="components"):adapter(p,b,bridge,fx,link).run()
 assert bridge.calls==[]
def test_inner_cleanup_failure_still_removes_private_link(monkeypatch):
 p,b,bridge,fx,link=make(monkeypatch);bridge.fail_cleanup=True
 with pytest.raises(RuntimeError,match="cleanup"):adapter(p,b,bridge,fx,link).run()
 assert link.events==["start","cleanup"]

def test_boot_failure_still_cleans_link_and_fixture_and_preserves_primary(monkeypatch):
 p,b,bridge,fx,link=make(monkeypatch)
 bridge.launch_boot=lambda _stage:(_ for _ in ()).throw(RuntimeError("boot failed"))
 link.fail_cleanup=True
 with pytest.raises(RuntimeError,match="boot failed") as caught:adapter(p,b,bridge,fx,link).run()
 assert link.events==["start","cleanup"] and fx.events==["start","stop"]
 assert any("private-link cleanup" in x for x in getattr(caught.value,"__notes__",[]))
