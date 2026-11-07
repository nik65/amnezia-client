"""Authentic nested Cuttlefish lifecycle to canonical release-lab receipt."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime,timezone
from typing import Any,Mapping
try:
 from .nested_cuttlefish_runner import ApkSpec,InnerPlan,validate_app_update_receipt,validate_boot_receipt,validate_cleanup_receipt,validate_stage_receipt
except ImportError:  # direct lab.py execution
 from nested_cuttlefish_runner import ApkSpec,InnerPlan,validate_app_update_receipt,validate_boot_receipt,validate_cleanup_receipt,validate_stage_receipt
try:
 from .nested_cuttlefish_app_executor import NestedAppExecutor
except ImportError:
 from nested_cuttlefish_app_executor import NestedAppExecutor

class NestedCommonError(RuntimeError): pass

def _now(): return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")

@dataclass
class NestedCuttlefishCommonAdapter:
 plan: InnerPlan
 bridge: Any
 baseline: ApkSpec
 baseline_version: str
 candidate_version: str
 fixture_adapter: Any
 private_link: Any
 outer_live_snapshot: Any
 visual_request: Any = None
 visual_poll: Any = None
 def run(self)->dict[str,Any]:
  if self.bridge.plan != self.plan:
   raise NestedCommonError("nested lifecycle components differ from the exact plan")
  primary=None;fixture_started=False;link_started=False;update_entered=False;cleanup=None;link_setup=None;link_cleanup=None
  stage=None;supplemental=None;boot=None;baseline=None;app=None
  try:
   # Prove the small server fixture and private path before transferring the
   # multi-gigabyte Cuttlefish payload.
   fixture_probe=self.fixture_adapter.start();fixture_started=True
   link_setup=self.private_link.start_and_probe();link_started=True
   if (link_setup.get("run_id")!=self.plan.ownership.run_id
       or link_setup.get("attempt_nonce")!=self.plan.ownership.attempt_nonce
       or link_setup.get("ready") is not True
       or self.private_link.p.endpoint!=self.fixture_adapter.app_fixture().endpoint):
    raise NestedCommonError("private link differs from fixture/run/attempt")
   fixture=self.fixture_adapter.app_fixture()
   stage=validate_stage_receipt(self.plan,self.bridge.stage())
   supplemental=self.bridge.stage_additional_asset(self.baseline)
   if supplemental.get("sha256")!=self.baseline.sha256 or supplemental.get("size")!=self.baseline.size:
    raise NestedCommonError("baseline staging receipt differs from plan")
   boot=validate_boot_receipt(self.plan,self.bridge.launch_boot(stage))
   # Baseline installation is real product setup evidence, never inferred from boot.
   executor=NestedAppExecutor(self.bridge.qga,self.plan,boot,self.baseline,fixture,self.outer_live_snapshot,
     self.fixture_adapter.snapshot,self.fixture_adapter.callback,failure_archive=self.bridge.boot_failure_archive,
     visual_request=self.visual_request,visual_poll=self.visual_poll)
   if executor.boot != boot:raise NestedCommonError("executor boot binding differs from generated boot receipt")
   baseline=executor.install_baseline(str(supplemental["guest_path"]))
   if (baseline.get("passed") is not True or baseline.get("operation")!="nested-baseline-setup"
       or (baseline.get("artifact") or {}).get("sha256")!=self.baseline.sha256
       or (baseline.get("artifact") or {}).get("size")!=self.baseline.size
       or (baseline.get("artifact") or {}).get("version_code")!=self.baseline.version_code
       or (baseline.get("ui") or {}).get("version_code")!=self.baseline.version_code):
    raise NestedCommonError("baseline install/UI receipt is incomplete")
   update_entered=True;app=validate_app_update_receipt(self.plan,boot,executor.run_update())
  except BaseException as error:
   primary=error;raise
  finally:
   deferred_cleanup_error=None
   if boot is not None and not getattr(primary,"retain_owned_evidence",False):
    try:cleanup=validate_cleanup_receipt(self.plan,self.bridge.cleanup(boot),boot)
    except BaseException as cleanup_error:
     if primary is None:deferred_cleanup_error=cleanup_error
     elif hasattr(primary,"add_note"):primary.add_note(f"inner cleanup also failed: {cleanup_error!r}")
   if link_started:
    try:link_cleanup=self.private_link.cleanup()
    except BaseException as link_error:
     if primary is not None and hasattr(primary,"add_note"):primary.add_note(f"private-link cleanup also failed: {link_error!r}")
     elif deferred_cleanup_error is not None:
      if hasattr(deferred_cleanup_error,"add_note"):deferred_cleanup_error.add_note(f"private-link cleanup also failed: {link_error!r}")
     else:deferred_cleanup_error=link_error
   if fixture_started and not update_entered:
    try:self.fixture_adapter.stop()
    except BaseException as fixture_error:
     if primary is not None and hasattr(primary,"add_note"):primary.add_note(f"fixture cleanup also failed: {fixture_error!r}")
     elif deferred_cleanup_error is not None:
      if hasattr(deferred_cleanup_error,"add_note"):deferred_cleanup_error.add_note(f"fixture cleanup also failed: {fixture_error!r}")
     else:deferred_cleanup_error=fixture_error
   if primary is None and deferred_cleanup_error is not None:raise deferred_cleanup_error
  if any(x is None for x in (stage,boot,baseline,app,cleanup,link_setup,link_cleanup)):
   raise NestedCommonError("nested lifecycle did not produce complete cleanup-bound evidence")
  stamp=_now(); candidate={"version":self.candidate_version,"version_code":self.plan.apk.version_code,"sha256":self.plan.apk.sha256,"size":self.plan.apk.size}
  steps=[
   {"id":"probe","passed":True,"observed_at":stamp,"raw_assertion":{"stage":stage,"boot":boot}},
   {"id":"reinstall","passed":True,"observed_at":stamp,"raw_assertion":baseline},
   {"id":"update","passed":True,"observed_at":stamp,"raw_assertion":app},
   {"id":"service-health","passed":True,"observed_at":stamp,"raw_assertion":{"package_installer":app["package_installer"],"ui":app["ui"],"logcat":app["logcat"]}},
  ]
  return {"schema":1,"run_id":self.plan.ownership.run_id,"profile":"android-arm64-v8a","artifact":self.plan.apk.name,
   "artifact_sha256":self.plan.apk.sha256,"artifact_size":self.plan.apk.size,"artifact_role":"candidate",
   "artifact_source":{"transport":"nested-qga","hash_verified":True,"guest_path":f"{self.plan.root}/input/{self.plan.apk.name}"},
   "baseline_version":self.baseline_version,"candidate_version":self.candidate_version,
   "guest_marker":f"amnezia-release-lab:{self.plan.ownership.run_id}:android-arm64-v8a",
   "transport":"nested-qga","origin":"guest","injected":False,"action":"update","observed_at":stamp,"steps":steps,
   "candidate":candidate,"device_identity":{"serial":boot["boot"]["serial"],"qemu_uuid":boot["boot"]["boot_id"],
   "outer_ownership":boot["outer_ownership"],"attempt_nonce":self.plan.ownership.attempt_nonce},
   "semantic":{"stage":stage,"boot":boot,"baseline":baseline,"app":app,"cleanup":cleanup,
   "private_link":link_setup,"private_link_cleanup":link_cleanup}}
