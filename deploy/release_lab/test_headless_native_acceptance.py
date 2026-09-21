import base64, hashlib, json, pytest
try: from headless_native_acceptance import *
except ImportError: from deploy.release_lab.headless_native_acceptance import *

BOOT="22222222-2222-2222-2222-222222222222"
def rel(v,t): return ReleaseBytes(v,t*64,100,chr(ord(t)+1)*64,200,chr(ord(t)+2)*64,30,chr(ord(t)+3)*64,20,"f"*64)
def plan(): return NativeUpdatePlan("run-1","native-update","nonce-1234567890","2026-09-13T10:00:00Z",OuterBinding(10,20,"11111111-1111-1111-1111-111111111111","/var/lib/amnezia-release-lab/r/qmp","/var/lib/amnezia-release-lab/r/qga"),rel("5.0.1.38","a"),rel("5.0.1.39","b"),Fixture("http://10.8.1.253:17864",("10.8.1.0/24",),"nonce-1234567890","/manifest.json","/files/candidate.tar.gz"))
def base(op,at="2026-09-13T10:02:00Z",origin="guest"):
 p=plan(); return {"schema":1,"operation":op,"run_id":p.run_id,"case_id":p.case_id,"attempt_nonce":p.attempt_nonce,"origin":origin,"transport":"qga","injected":False,"outer_binding":asdict(p.outer_binding),"observed_at":at,"passed":True}
def ident(r,p,t): return {"version":r.version,"amneziad_sha256":r.amneziad_sha256,"amneziad_size":r.amneziad_size,"cli_sha256":r.cli_sha256,"cli_size":r.cli_size,"daemon_pid":p,"daemon_start_ticks":t}
def raw(path,obj):
 b=json.dumps(obj,separators=(",",":")).encode(); return {"origin":"guest","transport":"qga","path":path,"bytes_b64":base64.b64encode(b).decode(),"sha256":hashlib.sha256(b).hexdigest(),"size":len(b),"uid":0,"gid":0,"mode":"0600"}
def http():
 p=plan(); v=base("headless-native-http",origin="server-fixture"); v["fixture"]={"marker":f"amnezia-release-lab:{p.run_id}:{p.case_id}:{p.attempt_nonce}","listener":p.fixture.endpoint,"run_id":p.run_id,"case_id":p.case_id,"attempt_nonce":p.attempt_nonce,"pid":40,"start_ticks":400}; v["requests"]=[{"method":"GET","path":p.fixture.manifest_path,"status":200,"sha256":p.candidate.manifest_sha256,"bytes":100,"content_length":100,"eof":True,"peer":"10.8.1.10","observed_at":"2026-09-13T10:00:30Z"},{"method":"GET","path":p.fixture.artifact_path,"status":200,"sha256":p.candidate.tar_sha256,"bytes":200,"content_length":200,"eof":True,"peer":"10.8.1.10","observed_at":"2026-09-13T10:00:40Z"}]; return v
def update():
 p=plan(); h=http(); v=base("headless-native-update"); profile={"id":f"release-lab-{p.attempt_nonce}","updateManifestUrl":p.fixture.endpoint+p.fixture.manifest_path,"updatePublicKeyPath":FIXED_KEY,"autoUpdate":True}; v.update({"before":ident(p.baseline,100,1000),"after":ident(p.candidate,101,1100),"boot_id_before":BOOT,"boot_id_after":BOOT,"fixed_key_path":FIXED_KEY,"fixed_key_sha256":p.candidate.key_sha256,"verified_manifest_sha256":p.candidate.manifest_sha256,"verified_manifest_size":100,"http_receipt_sha256":receipt_sha256(h),"raw_sources":{"profile_store":raw(FIXED_STORE,[profile]),"before_doctor":raw("cli:doctor",{"ok":True,"result":{"updates":{"state":"idle"}}}),"after_doctor":raw("cli:doctor",{"ok":True,"result":{"updates":{"state":"updated"}}}),"pending_state":raw(UPDATE_STATE,{"version":2,"state":"restart_pending"}),"stable_state":raw(UPDATE_STATE,{"version":2,"state":"updated","lastAppliedVersion":p.candidate.version}),"pending_journal":raw(UPDATE_JOURNAL,{"phase":"restart_pending"}),"retired_journal":raw(UPDATE_JOURNAL+".absence",{"exists":False}),"rollback_receipt":raw(ROLLBACK_RECEIPT,{"version":1,"rollbackVersion":p.baseline.version,"rollbackHashes":{"amneziad":p.baseline.amneziad_sha256,"amnezia-cli":p.baseline.cli_sha256}})}}); return v
def rollback(u=None):
 p=plan(); u=u or update(); v=base("headless-native-rollback","2026-09-13T10:04:00Z"); v.update({"before":ident(p.candidate,101,1100),"after":ident(p.baseline,102,1200),"boot_id_before":BOOT,"boot_id_after":BOOT,"update_receipt_sha256":receipt_sha256(u),"cli_process":{"pid":200,"start_ticks":3000,"argv":["/usr/local/bin/amnezia-cli","--socket",FIXED_SOCKET,"--json","update-rollback"],"exit_code":0},"raw_sources":{"cli_response":raw("cli:update-rollback",{"ok":True,"result":{"updates":{"state":"rollback_restart_pending"}}}),"pending_state":raw(UPDATE_STATE,{"state":"rollback_restart_pending"}),"pending_journal":raw(UPDATE_JOURNAL,{"phase":"rollback_restart_pending"}),"stable_state":raw(UPDATE_STATE,{"state":"rolled_back","lastAppliedVersion":p.baseline.version}),"retired_journal":raw(UPDATE_JOURNAL+".absence",{"exists":False}),"after_doctor":raw("cli:doctor",{"ok":True,"result":{"updates":{"state":"rolled_back"}}})}}); return v

def test_real_shaped_chain():
 p=plan(); h=http(); u=update(); r=rollback(u); validate_http_receipt(p,h); validate_update_receipt(p,u,h); validate_rollback_receipt(p,r,u)
 reboot=base("headless-native-reboot","2026-09-13T10:06:00Z"); reboot.update({"boot_id_before":BOOT,"boot_id_after":"33333333-3333-3333-3333-333333333333","prior_receipt_sha256":receipt_sha256(r),"after":ident(p.baseline,105,1500),"raw_sources":{"persistent_marker":raw(f"/var/lib/amnezia/release-lab-native-{p.attempt_nonce}.json",{"attempt_nonce":p.attempt_nonce}),"service":raw("systemctl:amneziad.service",{"enabled":"enabled","active":"active"}),"stable_state":raw(UPDATE_STATE,{"state":"rolled_back","lastAppliedVersion":p.baseline.version}),"doctor":raw("cli:doctor",{"ok":True,"result":{"updates":{"state":"rolled_back"}}})}}); validate_reboot_receipt(p,reboot,p.baseline,r)
def test_plan_store_and_owned_outer():
 assert build_acceptance_plan(plan())["profile_store"]=={"path":FIXED_STORE,"uid":0,"gid":0,"mode":"0600","readback_argv":["/usr/local/bin/amnezia-cli","--socket",FIXED_SOCKET,"--json","list-profiles"]}
 p=plan(); bad=NativeUpdatePlan(p.run_id,p.case_id,p.attempt_nonce,p.created_at,OuterBinding(10,20,p.outer_binding.uuid,"/tmp/qmp","/tmp/qga"),p.baseline,p.candidate,p.fixture)
 with pytest.raises(HeadlessAcceptanceError): build_acceptance_plan(bad)
def test_update_storage_paths_match_headless_update_manager_update_root():
 assert UPDATE_STATE=="/var/lib/amnezia/headless-updates.json"
 assert UPDATE_JOURNAL=="/var/lib/amnezia/updates/transaction.json"
 assert ROLLBACK_RECEIPT=="/var/lib/amnezia/updates/rollback-receipt.json"
 built=build_acceptance_plan(plan())["required_product_sources"]
 assert built["journal"]==UPDATE_JOURNAL and built["rollback_receipt"]==ROLLBACK_RECEIPT
def test_http_fixture_binding_and_no_fake_request_nonce():
 v=http(); assert all("attempt_nonce" not in x for x in v["requests"]); validate_http_receipt(plan(),v); v["fixture"]["start_ticks"]=False
 with pytest.raises(HeadlessAcceptanceError): validate_http_receipt(plan(),v)
def test_http_allows_only_exact_timer_manifest_gets_before_artifact():
 v=http(); v["requests"].insert(1,{**v["requests"][0],"observed_at":"2026-09-13T10:00:35Z"}); validate_http_receipt(plan(),v)
 bad=http(); bad["requests"].append({**bad["requests"][0],"observed_at":"2026-09-13T10:00:50Z"})
 with pytest.raises(HeadlessAcceptanceError,match="outside"): validate_http_receipt(plan(),bad)
 bad=http(); bad["requests"][1]["peer"]="10.8.1.11"
 with pytest.raises(HeadlessAcceptanceError,match="peers"): validate_http_receipt(plan(),bad)
def test_raw_hash_and_retirement_fail_closed():
 p=plan(); v=update(); v["raw_sources"]["stable_state"]["sha256"]="0"*64
 with pytest.raises(HeadlessAcceptanceError): validate_update_receipt(p,v,http())
 v=update(); v["raw_sources"]["retired_journal"]=raw(UPDATE_JOURNAL+".absence",{"exists":True})
 with pytest.raises(HeadlessAcceptanceError): validate_update_receipt(p,v,http())
def test_cross_stage_and_bool_fail_closed():
 p=plan(); u=update(); r=rollback(u); r["update_receipt_sha256"]="0"*64
 with pytest.raises(HeadlessAcceptanceError): validate_rollback_receipt(p,r,u)
 u=update(); u["after"]["daemon_pid"]=True
 with pytest.raises(HeadlessAcceptanceError): validate_update_receipt(p,u,http())
