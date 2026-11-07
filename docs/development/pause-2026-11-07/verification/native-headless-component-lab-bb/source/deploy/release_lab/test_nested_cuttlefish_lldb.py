import json
import pytest

from deploy.release_lab.nested_cuttlefish_lldb import (
 BUNDLE_ARCHIVE_SHA256,BUNDLE_ARCHIVE_SIZE,BUNDLE_MANIFEST_SHA256,BUNDLE_MEMBERS,BUNDLE_UNION_SIZE,LldbAttachPlan,LldbDiagnosticError,NATIVE_FILES,
 NATIVE_PAYLOAD_SIZE,PYTHON_TREE_MANIFEST_SHA256,build_diagnostic_entrypoint,build_sb_driver,
 parse_sb_output,validate_sb_receipt,
)

def plan():
 return LldbAttachPlan("release39","a"*48,"org.amnezia.vpn",1234,10123,998877,"connect://127.0.0.1:47119","/var/lib/amnezia-release-lab/n/1234abcd/runtime/diagnostics")

def test_frozen_native_subset_and_extended_python_manifest_are_exact():
 assert len(NATIVE_FILES)==11
 assert sum(row[1] for row in NATIVE_FILES)==NATIVE_PAYLOAD_SIZE==203_987_176
 assert BUNDLE_UNION_SIZE==233_789_986
 assert (BUNDLE_ARCHIVE_SIZE,BUNDLE_MEMBERS)==(71_060_977,1_599)
 assert BUNDLE_ARCHIVE_SHA256=="3d6c10a32d8bc29b9fc4746df6819d58de2ceeb1b97fc99694bcb8b06941e4d5"
 assert BUNDLE_MANIFEST_SHA256=="bd6cd5e444a5f61929b04e4c2a701ec9c415307fdd54e0f8fa5d40ac958d3207"
 assert PYTHON_TREE_MANIFEST_SHA256=="e0feaeef1e0c017f3e0881952ff3c906c83b5085610ab452dbe48f0e26049aa8"

def test_driver_is_async_event_bound_passes_sigsegv_and_reserves_cleanup():
 source=build_sb_driver(plan())
 for token in ("SetAsync(True)","WaitForEvent","SetShouldStop(signo,True)","SetShouldNotify(signo,True)","SetShouldSuppress(signo,False)","ConnectRemote","CONTINUE_WITH_SIGNAL_PASS","FINALLY_DETACHED"):
  assert token in source
 assert plan().deadline_seconds+plan().cleanup_reserve_seconds==60

def test_driver_accepts_controller_absolute_monotonic_deadline():
 source=build_sb_driver(plan(),12345.5)
 assert '"deadline_monotonic":12345.5' in source
 assert "deadline=cfg['deadline_monotonic'] if cfg['deadline_monotonic'] is not None" in source
 assert "lldb Python binding escaped staged bundle" in source
 entry=build_diagnostic_entrypoint(plan(),plan().staged_root+"/evidence/lldb-abcdef123456.py")
 assert entry["acceptance"] is False and entry["transport"]["host_network_mutation"] is False
 assert entry["single_attach"] is True and entry["env"]["PYTHONDONTWRITEBYTECODE"]=="1"

def test_success_receipt_requires_ordered_signal_pass_and_death():
 states=[{"state":x,"at_monotonic":float(i)} for i,x in enumerate(("ATTACHED_STOPPED","POLICY_CONFIRMED","RUNNING","STOPPED_SIGSEGV","EVIDENCE_CAPTURED","CONTINUE_WITH_SIGNAL_PASS","EXITED_AFTER_PASS"))]
 value={"schema":1,"acceptance":False,"classification":"native-sigsegv","signal_claim":True,"stack_claim":True,"states":states,"identity":{"run_id":"release39","attempt_nonce":"a"*48,"package":"org.amnezia.vpn","pid":1234,"uid":10123,"start_ticks":998877},"signal_policy":{"stop":True,"notify":True,"pass":True},"lldb_file":"/var/lib/amnezia-release-lab/n/1234abcd/runtime/diagnostics/lib/python3.10/site-packages/lldb/__init__.py","threads":[{"thread_id":7,"frames":[{"pc":4096}]}],"exit_status":11,"exit_description":"signal 11"}
 raw=("noise\nAMZ_LLDB_JSON:"+json.dumps(value,separators=(",",":"))+"\n").encode()
 assert parse_sb_output(raw)["classification"]=="native-sigsegv"
 bad=json.loads(json.dumps(value));bad["states"]=[x for x in states if x["state"]!="CONTINUE_WITH_SIGNAL_PASS"]
 with pytest.raises(LldbDiagnosticError,match="state machine"):validate_sb_receipt(bad)

@pytest.mark.parametrize("classification",["attach-denied","diagnostic-timeout","diagnostic-failure"])
def test_denial_race_or_timeout_cannot_claim_stack(classification):
 value={"schema":1,"acceptance":False,"classification":classification,"signal_claim":False,"stack_claim":False,"states":[],"identity":{"run_id":"release39","attempt_nonce":"a"*48,"package":"org.amnezia.vpn","pid":1234,"uid":10123,"start_ticks":998877},"signal_policy":None,"lldb_file":"/var/lib/amnezia-release-lab/n/1234abcd/runtime/diagnostics/lib/python3.10/site-packages/lldb/__init__.py"}
 assert validate_sb_receipt(value)["acceptance"] is False
 value["stack_claim"]=True;value["threads"]=[]
 with pytest.raises(LldbDiagnosticError,match="false stack claim"):validate_sb_receipt(value)

def test_output_is_hard_bounded_and_transport_is_loopback_only():
 with pytest.raises(LldbDiagnosticError,match="2 MiB"):parse_sb_output(b"x"*(2*1024*1024+1))
 bad=plan().__dict__|{"connect_url":"connect://10.0.2.2:47119"}
 with pytest.raises(LldbDiagnosticError,match="loopback"):LldbAttachPlan(**bad).validate()
