"""Synthetic contract tests only; no guest/runtime acceptance is generated."""
import base64
import hashlib
import json
from copy import deepcopy
from dataclasses import replace
from datetime import datetime

import pytest

from deploy.release_lab import headless_coordinated_rollback_acceptance as c
from deploy.release_lab import test_headless_native_acceptance as fixtures


def raw(path, value, mode="0600"):
    data = value if isinstance(value, bytes) else json.dumps(value, separators=(",", ":")).encode()
    return dict(origin="guest", transport="qga", path=path, uid=0, gid=0, mode=mode,
                nofollow=True, regular=True, nlink=1, stable_identity=True,
                bytes_b64=base64.b64encode(data).decode(), size=len(data), sha256=hashlib.sha256(data).hexdigest())


def absence(path):
    value=raw(path+".absence",{"exists":False})
    value.update(kind="guest-lstat-outcome",inspected_path=path,physical_path="/var/lib/amnezia/.release-lab-test-outcome")
    return value


def decode(value):
    return json.loads(base64.b64decode(value["bytes_b64"]))


def observation(release, pid, state):
    return dict(pair=c.pair(release), version=release.version, daemon_pid=pid, start_ticks=str(pid*10),
                doctor={"ok":True,"result":{"ready":True,"updates":{"state":state,
                    "lastAppliedVersion":release.version,"lastError":"","recoveryRequired":False}}})


PINS={"server_sha256":"1"*64,"wrapper_sha256":"2"*64,"unit_sha256":"3"*64}


def stamp(clock): return datetime.fromisoformat("2026-09-13T"+clock+"+00:00").timestamp()


def rebind_transcript(epoch):
    data=json.dumps(epoch["transcript"]).encode();epoch["transcript_bytes_base64"]=base64.b64encode(data).decode();epoch["transcript_sha256"]=hashlib.sha256(data).hexdigest()


def ledger(plan,boots):
    epochs=[];metadata=[]
    for i,boot in enumerate(boots):
        pid,ticks=400+i,4000+i;name=boot+"-"+str(pid)+"-"+str(ticks)
        directory="/var/lib/amnezia-release-lab/coordinated-http/"+plan.attempt_nonce+"/epochs/"+name
        reset={"ok":True,"run_id":plan.run_id,"attempt_nonce":plan.attempt_nonce,"reset_token":plan.attempt_nonce,
            "log_inode":100+i,"offset":0,"empty_sha256":hashlib.sha256(b"").hexdigest(),"reset_at":stamp(["10:00:00","10:03:00","10:05:00"][i]),
            "cleared_health_request":{"method":"GET","path":"/healthz","status":200,"eof":True,"run_id":plan.run_id,"attempt_nonce":plan.attempt_nonce}}
        row=dict(boot_id=boot,pid=pid,start_ticks=ticks,ready_monotonic_us=1000,epoch=name,request_log=directory+"/requests.jsonl",cursor=directory+"/cursor.json",reset_receipt=reset,address="10.8.1.253",run_id=plan.run_id,attempt_nonce=plan.attempt_nonce,**PINS)
        row["enablement"]={"path":"/etc/systemd/system/multi-user.target.wants/amnezia-lab-http-"+plan.attempt_nonce+".service","target":"../amnezia-lab-http-"+plan.attempt_nonce+".service","uid":0,"unit_sha256":PINS["unit_sha256"]}
        metadata.append(deepcopy(row));epoch=deepcopy(row)
        epoch["transcript"]={"reset_token":plan.attempt_nonce,"log_inode":100+i,"start_offset":0,"rows":[],"log_sha256":hashlib.sha256(b"").hexdigest(),"log_size":0,"finished_at":stamp("10:08:00")};rebind_transcript(epoch)
        daemon_pid,daemon_ticks=[(101,1100),(110,1100),(202,2020)][i]
        props={"MainPID":str(daemon_pid),"ExecMainStartTimestampMonotonic":"2000","ActiveEnterTimestampMonotonic":"3000","ActiveState":"active","SubState":"running","FragmentPath":"/etc/systemd/system/amneziad.service","DropInPaths":"","InvocationID":"id"}
        props_bytes=("\n".join(k+"="+v for k,v in props.items())+"\n").encode()
        observation={"boot_id":boot,"pid":daemon_pid,"start_ticks":daemon_ticks,"observed_monotonic_us":4000,"properties":props,"systemctl_bytes_base64":base64.b64encode(props_bytes).decode(),"systemctl_sha256":hashlib.sha256(props_bytes).hexdigest()}
        data=json.dumps(observation).encode();epoch["daemon_observations"]=[dict(daemon_observation=observation,daemon_observation_bytes_base64=base64.b64encode(data).decode(),daemon_observation_sha256=hashlib.sha256(data).hexdigest())];epochs.append(epoch)
    data=("\n".join(json.dumps(x) for x in metadata)+"\n").encode()
    return dict(schema="amnezia-coordinated-http-ledger-v1",run_id=plan.run_id,case_id=plan.case_id,attempt_nonce=plan.attempt_nonce,endpoint=plan.fixture.endpoint,diagnosticOnly=True,releasePass=False,raw_ledger_bytes_base64=base64.b64encode(data).decode(),raw_ledger_sha256=hashlib.sha256(data).hexdigest(),epochs=epochs)


@pytest.fixture
def chain(monkeypatch):
    retained = b"synthetic CLI bytes!"
    old_plan = fixtures.plan()
    p = replace(old_plan, candidate=replace(old_plan.candidate, cli_sha256=hashlib.sha256(retained).hexdigest(), cli_size=len(retained)))
    monkeypatch.setattr(fixtures, "plan", lambda: p)
    http, update = fixtures.http(), fixtures.update()
    reboot = fixtures.base("headless-coordinated-candidate-reboot", "2026-09-13T10:03:00Z")
    reboot.update(boot_id_before=fixtures.BOOT, boot_id_after="33333333-3333-3333-3333-333333333333",
        prior_receipt_sha256=c.receipt_sha256(update), after=fixtures.ident(p.candidate, 110, 1100),
        raw_sources={"persistent_marker":fixtures.raw(f"/var/lib/amnezia/release-lab-native-{p.attempt_nonce}.json",{"attempt_nonce":p.attempt_nonce}),
          "service":fixtures.raw("systemctl:amneziad.service",{"enabled":"enabled","active":"active"}),
          "stable_state":fixtures.raw(c.UPDATE_STATE,{"state":"no_update","lastAppliedVersion":p.candidate.version,"lastError":""}),
          "doctor":fixtures.raw("cli:doctor",{"ok":True,"result":{"ready":True,"updates":{"state":"no_update","lastAppliedVersion":p.candidate.version,"lastError":"","recoveryRequired":False}}}),"retired_journal":absence(c.UPDATE_JOURNAL)})
    reboot["after_raw"]=fixtures.raw("identity:post-reboot",reboot["after"])
    original = {"version":1,"unknown":{"keep":42},"profiles":[{"id":"one","autoUpdate":True,"url":"preserve"},
        {"id":"two","autoUpdate":False,"unknown":[1,2]}, {"id":"three","autoUpdate":True}]}
    paused = deepcopy(original)
    for profile in paused["profiles"]: profile["autoUpdate"] = False
    state = {"state":"rollback_restart_pending","lastAppliedVersion":p.baseline.version}
    journal = {"phase":"rollback_restart_pending","operation":"rollback","candidateVersion":p.baseline.version,
        "currentVersion":p.baseline.version,"installDirectory":"/usr/local/bin",
        "candidateHashes":{n:v["sha256"] for n,v in c.pair(p.baseline).items()},
        "candidateSizes":{n:v["size"] for n,v in c.pair(p.baseline).items()}}
    stable = {"state":"disabled","lastAppliedVersion":p.baseline.version,"lastError":"","recoveryRequired":False}
    sources = {"original_profiles":raw(c.FIXED_STORE,original),"paused_profiles":raw(c.FIXED_STORE,paused),
        "pending_state":raw(c.UPDATE_STATE,state),"pending_journal":raw(c.UPDATE_JOURNAL,journal),
        "held_state":raw(c.UPDATE_STATE,stable),"held_journal_absence":absence(c.UPDATE_JOURNAL),
        "rollback_stdout":raw("cli:update-rollback",{"ok":True,"result":{"updates":{"state":"rollback_restart_pending"}}}),
        "retained_executable":dict(raw(c.RETAINED,retained,"0500"),kind="guest-descriptor-metadata")}
    unit = ("[Unit]\nDescription=Amnezia rollback-with-pause recovery\nAfter=amneziad.service\n\n"
        "[Service]\nType=oneshot\nUser=root\nUMask=0077\nExecStart="+c.RETAINED+
        " --rollback-coordinator run\nTimeoutStartSec=120\nNoNewPrivileges=true\nPrivateTmp=true\n"
        "ProtectSystem=strict\nReadWritePaths=/var/lib/amnezia /usr/local/bin\n\n[Install]\nWantedBy=multi-user.target\n")
    sources["retained_unit"] = raw(c.UNIT,unit.encode(),"0644")
    observed = observation(p.baseline, 200, "rollback_restart_pending")
    held = dict(schema=1,authority=c.AUTHORITY,operationId="44444444-4444-4444-4444-444444444444",phase="held",
        originalVersion=p.candidate.version, targetVersion=p.baseline.version, originalPair=c.pair(p.candidate),
        targetPair=c.pair(p.baseline), retainedSha256=p.candidate.cli_sha256,
        originalProfilesSha256=sources["original_profiles"]["sha256"], pausedProfilesSha256=sources["paused_profiles"]["sha256"],
        pausedProfileCount=2, originalProfilesBase64=sources["original_profiles"]["bytes_b64"], observed13=observed, final13=observation(p.baseline,201,"disabled"),
        createdAt="2026-09-13T10:04:00Z", updatedAt="2026-09-13T10:04:05Z", acknowledgementAuthority=c.AUTHORITY,
        stopEvidence={"verifiedStopped":True,"observedProcessGone":True,"observedIdentity":observed,"observedAt":"2026-09-13T10:04:01Z"},
        pendingEvidence={"stateBytesBase64":sources["pending_state"]["bytes_b64"],"journalBytesBase64":sources["pending_journal"]["bytes_b64"],"stateSha256":sources["pending_state"]["sha256"],
            "journalSha256":sources["pending_journal"]["sha256"],"capturedAt":"2026-09-13T10:04:02Z"},
        coordinatorAcknowledgement={"authority":c.AUTHORITY,"result":"disabled","returnedSuccessfully":True,
            "completedAt":"2026-09-13T10:04:03Z","postStateSha256":sources["held_state"]["sha256"]})
    sources["held_record"] = raw(c.RECORD,held)
    sources["held_reboot_record"] = raw(c.RECORD,held)
    sources["held_reboot_profiles"] = raw(c.FIXED_STORE,paused)
    sources["held_reboot_journal_absence"] = absence(c.UPDATE_JOURNAL)
    resumed = dict(held,phase="resumed",updatedAt="2026-09-13T10:07:00Z",resumeStoppedService=observation(p.baseline,202,"disabled"),resumeObservedService=observation(p.baseline,203,"no_update"))
    sources["resumed_record"] = raw(c.RECORD,resumed)
    sources["resumed_profiles"] = raw(c.FIXED_STORE,original)
    sources["retired_unit"] = raw(c.UNIT,unit.encode(),"0644")
    sources["retired_unit_state"] = raw("systemctl:amnezia-rollback-coordinator.service",{"enabled":"disabled","active":"inactive"})
    sources["resume_stdout"] = raw("cli:coordinator-resume",{"ok":True,"code":"resumed","coordinator":{"operationId":held["operationId"]}})
    receipt = fixtures.base("headless-coordinated-rollback-with-pause", "2026-09-13T10:08:00Z")
    receipt.update(candidate_reboot_sha256=c.receipt_sha256(reboot),raw_sources=sources,retained_resumed_record=True,
        rollback_process={"pid":300,"start_ticks":3000,"exe":"/usr/local/bin/amnezia-cli","exe_sha256":p.candidate.cli_sha256,
            "argv":["/usr/local/bin/amnezia-cli","--socket",c.FIXED_SOCKET,"--json","update-rollback"],"exit_code":0},
        coordinator_process={"pid":302,"start_ticks":3020,"exe":c.RETAINED,"exe_sha256":p.candidate.cli_sha256,
            "argv":[c.RETAINED,"--rollback-coordinator","run"],"exit_code":0},
        resume_process={"invoked_at":"2026-09-13T10:06:50.200000Z","observed_at":"2026-09-13T10:06:50.800000Z","pid":301,"start_ticks":3010,"exe":c.RETAINED,"exe_sha256":p.candidate.cli_sha256,
            "argv":[c.RETAINED,"--rollback-coordinator","resume"],"exit_code":0},
        held_reboot={"prior_held_record_sha256":sources["held_record"]["sha256"],"boot_id_before":reboot["boot_id_after"],
            "boot_id_after":"55555555-5555-5555-5555-555555555555","after":observation(p.baseline,202,"disabled")})
    receipt["held_reboot"]["native_observation"]={"boot_id_before":receipt["held_reboot"]["boot_id_before"],"boot_id_after":receipt["held_reboot"]["boot_id_after"],
        "after_raw":fixtures.raw("identity:post-reboot",fixtures.ident(p.baseline,202,2020)),
        "raw_sources":{"persistent_marker":fixtures.raw(f"/var/lib/amnezia/release-lab-native-{p.attempt_nonce}.json",{"attempt_nonce":p.attempt_nonce}),
        "service":fixtures.raw("systemctl:amneziad.service",{"enabled":"enabled","active":"active"}),
        "stable_state":fixtures.raw(c.UPDATE_STATE,{"state":"disabled","lastAppliedVersion":p.baseline.version,"lastError":""}),
        "doctor":fixtures.raw("cli:doctor",receipt["held_reboot"]["after"]["doctor"])}}
    receipt["held_http"] = ledger(p, [reboot["boot_id_before"], reboot["boot_id_after"], receipt["held_reboot"]["boot_id_after"]])
    for name in ("rollback_stdout","resume_stdout","retired_unit_state"): sources[name]["kind"]="guest-exec-outcome"
    return p,receipt,update,reboot,http


def validate(chain): return c.validate_coordinated_rollback_chain(*chain, expected_http_sources=PINS)


def test_synthetic_complete_chain_is_distinct_not_legacy_pass(chain):
    result = validate(chain)
    assert result["authority"] == c.AUTHORITY and result["legacy_native_rollback_pass"] is False
    assert result["automatic_publication_approved"] is False


@pytest.mark.parametrize("field",["held_record","retained_executable","retained_unit",
    "held_journal_absence","held_reboot_profiles","held_reboot_record","resumed_profiles","retired_unit","resume_stdout"])
def test_missing_raw_evidence_rejected(chain, field):
    del chain[1]["raw_sources"][field]
    with pytest.raises(c.HeadlessAcceptanceError): validate(chain)


@pytest.mark.parametrize("field,value",[("authority","old13Daemon"),("acknowledgementAuthority","old13Daemon"),
    ("pausedProfileCount",True),("retainedSha256","0"*64),("targetVersion","5.0.0.0"),("phase","rolled_back")])
def test_forged_product_record_rejected(chain, field, value):
    source=chain[1]["raw_sources"]; held=decode(source["held_record"]);held[field]=value
    source["held_record"]=raw(c.RECORD,held)
    with pytest.raises(c.HeadlessAcceptanceError): validate(chain)


@pytest.mark.parametrize("field,value",[("uid",True),("mode","0666"),("nofollow",False),("nlink",2),
    ("stable_identity",False),("sha256","0"*64),("size",True)])
def test_descriptor_and_hash_proof_rejected(chain,field,value):
    chain[1]["raw_sources"]["held_record"][field]=value
    with pytest.raises(c.HeadlessAcceptanceError): validate(chain)


def test_no_enabled_profile_or_unknown_key_loss_allowed(chain):
    source=chain[1]["raw_sources"];p=decode(source["paused_profiles"]);p["profiles"][2]["autoUpdate"]=True
    source["paused_profiles"]=raw(c.FIXED_STORE,p)
    with pytest.raises(c.HeadlessAcceptanceError): validate(chain)


def test_artifact_get_during_hold_rejected(chain):
    p,r,*_=chain;epoch=r["held_http"]["epochs"][2]
    epoch["transcript"]["rows"]=[{"method":"GET","path":p.fixture.artifact_path,"status":200,"observed_at":stamp("10:06:00")}]
    rebind_transcript(epoch)
    with pytest.raises(c.HeadlessAcceptanceError,match="artifact GET"): validate(chain)


def test_reboot_must_change_and_bind_boot(chain):
    chain[1]["held_reboot"]["boot_id_after"]=chain[1]["held_reboot"]["boot_id_before"]
    with pytest.raises(c.HeadlessAcceptanceError,match="real held reboot"): validate(chain)


def test_missing_verified_stop_and_recovered_ack_not_normal_success(chain):
    source=chain[1]["raw_sources"];held=decode(source["held_record"])
    held["coordinatorAcknowledgement"]["returnedSuccessfully"]=False
    source["held_record"]=raw(c.RECORD,held)
    with pytest.raises(c.HeadlessAcceptanceError,match="genuine coordinator ACK"): validate(chain)


def test_terminal_resumed_record_must_be_retained(chain):
    chain[1]["retained_resumed_record"]=False
    with pytest.raises(c.HeadlessAcceptanceError): validate(chain)


@pytest.mark.parametrize("section,field,value",[
    ("stopEvidence","verifiedStopped",False),
    ("stopEvidence","observedProcessGone",False),
    ("coordinatorAcknowledgement","authority","old13Daemon"),
    ("coordinatorAcknowledgement","result","recovered_disabled_poststate"),
    ("pendingEvidence","stateBytesBase64","e30="),
    ("pendingEvidence","journalSha256","0"*64),
])
def test_durable_commit_evidence_is_required(chain,section,field,value):
    source=chain[1]["raw_sources"];held=decode(source["held_record"])
    held[section][field]=value;source["held_record"]=raw(c.RECORD,held)
    with pytest.raises(c.HeadlessAcceptanceError): validate(chain)


def test_duplicate_private_json_rejected(chain):
    chain[1]["raw_sources"]["held_record"]=raw(c.RECORD,b'{"schema":1,"schema":1}')
    with pytest.raises(c.HeadlessAcceptanceError,match="duplicate JSON"):validate(chain)


def test_missing_durable_ack_not_replaced_by_optional_process(chain):
    source=chain[1]["raw_sources"];held=decode(source["held_record"]);held["coordinatorAcknowledgement"]["authority"]="old13Daemon";source["held_record"]=raw(c.RECORD,held)
    with pytest.raises(c.HeadlessAcceptanceError):validate(chain)


def test_profile_resume_conflict_rejected(chain):
    source=chain[1]["raw_sources"];changed=decode(source["resumed_profiles"])
    changed["unknown"]["keep"]=43;source["resumed_profiles"]=raw(c.FIXED_STORE,changed)
    with pytest.raises(c.HeadlessAcceptanceError,match="exact policy"):validate(chain)


def test_http_coverage_gap_is_not_no_download_proof(chain):
    epoch=chain[1]["held_http"]["epochs"][1]
    epoch["reset_receipt"]["reset_at"]=stamp("10:04:06")
    rows=[{k:v for k,v in x.items() if k not in ("transcript","transcript_bytes_base64","transcript_sha256","daemon_observations")} for x in chain[1]["held_http"]["epochs"]]
    raw_ledger=("\n".join(json.dumps(x) for x in rows)+"\n").encode()
    chain[1]["held_http"]["raw_ledger_bytes_base64"]=base64.b64encode(raw_ledger).decode()
    chain[1]["held_http"]["raw_ledger_sha256"]=hashlib.sha256(raw_ledger).hexdigest()
    with pytest.raises(c.HeadlessAcceptanceError,match="start coverage"):validate(chain)


def test_no_reload_after_ack_rejected(chain):
    source=chain[1]["raw_sources"];held=decode(source["held_record"])
    held["final13"]["daemon_pid"]=held["observed13"]["daemon_pid"]
    held["final13"]["start_ticks"]=held["observed13"]["start_ticks"]
    source["held_record"]=raw(c.RECORD,held)
    with pytest.raises(c.HeadlessAcceptanceError,match="reload after ACK"):validate(chain)


def test_injected_or_bool_receipt_rejected(chain):
    chain[1]["schema"]=True
    with pytest.raises(c.HeadlessAcceptanceError):validate(chain)


@pytest.mark.parametrize("gid",[988,0])
def test_real_service_gid_accepted(chain,gid):
    for name in ("held_state","held_record","held_reboot_record","resumed_record"):
        chain[1]["raw_sources"][name]["gid"]=gid
    validate(chain)


@pytest.mark.parametrize("gid",[True,-1,1.5])
def test_non_integer_or_negative_gid_rejected(chain,gid):
    chain[1]["raw_sources"]["held_state"]["gid"]=gid
    with pytest.raises(c.HeadlessAcceptanceError):validate(chain)


def test_saved_original_base64_must_match_exact_private_bytes(chain):
    source=chain[1]["raw_sources"];held=decode(source["held_record"])
    held["originalProfilesBase64"]="e30=";source["held_record"]=raw(c.RECORD,held)
    with pytest.raises(c.HeadlessAcceptanceError,match="saved original"):validate(chain)


def test_unknown_profile_bool_number_change_is_rejected_even_with_all_hashes_updated(chain):
    source=chain[1]["raw_sources"];paused=decode(source["paused_profiles"])
    paused["profiles"][1]["unknown"][0]=True;source["paused_profiles"]=raw(c.FIXED_STORE,paused)
    for name in ("held_record","held_reboot_record","resumed_record"):
        record=decode(source[name]);record["pausedProfilesSha256"]=source["paused_profiles"]["sha256"]
        source[name]=raw(c.RECORD,record)
    with pytest.raises(c.HeadlessAcceptanceError,match="nonpolicy"):validate(chain)


def test_unknown_reboot_record_type_change_rejected(chain):
    source=chain[1]["raw_sources"];held=decode(source["held_record"]);held["unknown"]=1
    source["held_record"]=raw(c.RECORD,held);reboot=deepcopy(held);reboot["unknown"]=True
    source["held_reboot_record"]=raw(c.RECORD,reboot)
    chain[1]["held_reboot"]["prior_held_record_sha256"]=source["held_record"]["sha256"]
    with pytest.raises(c.HeadlessAcceptanceError,match="record changed"):validate(chain)


@pytest.mark.parametrize("key",["held_journal_absence","held_reboot_journal_absence"])
def test_zero_is_not_absence_false(chain,key):
    value=chain[1]["raw_sources"][key];changed=raw(value["path"],{"exists":0})
    changed.update(kind="guest-lstat-outcome",inspected_path=c.UPDATE_JOURNAL)
    chain[1]["raw_sources"][key]=changed
    with pytest.raises(c.HeadlessAcceptanceError):validate(chain)


def test_resumed_record_same_pid_as_held_reboot_cannot_claim_reload(chain):
    source=chain[1]["raw_sources"];record=decode(source["resumed_record"])
    record["resumeObservedService"]=chain[1]["held_reboot"]["after"]
    source["resumed_record"]=raw(c.RECORD,record)
    with pytest.raises(c.HeadlessAcceptanceError,match="did not reload"):validate(chain)


def test_resume_saved_stop_identity_must_match_actual_held_boot(chain):
    source=chain[1]["raw_sources"];record=decode(source["resumed_record"])
    record["resumeStoppedService"]["daemon_pid"]+=1;source["resumed_record"]=raw(c.RECORD,record)
    with pytest.raises(c.HeadlessAcceptanceError,match="did not stop"):validate(chain)


def test_candidate_reboot_no_update_is_distinctly_supported_before_mutation(chain):
    p,r,u,b,h=chain;c.validate_coordinated_candidate_reboot(p,b,u)
    c.validate_coordinated_held(p,r,b,u,h)


def test_actual_official_accepted_pending_is_request_not_ack(chain):
    source=chain[1]["raw_sources"]
    source["rollback_stdout"]=raw("cli:update-rollback",{"ok":True,"result":{
        "state":"rollback_coordinator_accepted_pending","pending":True,
        "authority":"retained14CoordinatorRequest","coordinator":{
            "authority":c.AUTHORITY,"phase":"rollback_requested"}}})
    source["rollback_stdout"]["kind"]="guest-exec-outcome"
    validate(chain)


@pytest.mark.parametrize("mutation",["missing_boot","wrong_source","ledger_hash","missing_daemon","ready_after_daemon","bool_pid"])
def test_boot_http_evidence_cannot_be_inferred_from_healthy_last_epoch(chain,mutation):
    ledger=chain[1]["held_http"]
    if mutation=="missing_boot":ledger["epochs"].pop(1)
    elif mutation=="wrong_source":ledger["epochs"][1]["wrapper_sha256"]="0"*64
    elif mutation=="ledger_hash":ledger["raw_ledger_sha256"]="0"*64
    elif mutation=="missing_daemon":ledger["epochs"][1]["daemon_observations"]=None
    elif mutation=="bool_pid":ledger["epochs"][1]["pid"]=True
    else:
        epoch=ledger["epochs"][1];obs=epoch["daemon_observations"][0]["daemon_observation"];obs["properties"]["ExecMainStartTimestampMonotonic"]="500"
        data=("\n".join(k+"="+v for k,v in obs["properties"].items())+"\n").encode()
        obs["systemctl_bytes_base64"]=base64.b64encode(data).decode();obs["systemctl_sha256"]=hashlib.sha256(data).hexdigest()
        data=json.dumps(obs).encode();epoch["daemon_observations"][0]["daemon_observation_bytes_base64"]=base64.b64encode(data).decode();epoch["daemon_observations"][0]["daemon_observation_sha256"]=hashlib.sha256(data).hexdigest()
    with pytest.raises(c.HeadlessAcceptanceError):validate(chain)


def test_expected_http_hashes_must_come_from_reviewed_external_source_context(chain):
    with pytest.raises(c.HeadlessAcceptanceError,match="external HTTP source"):
        c.validate_coordinated_rollback_chain(*chain,expected_http_sources={})


def test_normal_artifact_get_after_explicit_resume_is_not_held_violation(chain):
    p,r,*_=chain;epoch=r["held_http"]["epochs"][2]
    epoch["transcript"]["rows"]=[{"method":"GET","path":p.fixture.artifact_path,"status":200,"observed_at":stamp("10:07:30")}]
    rebind_transcript(epoch);validate(chain)


def test_held_reboot_raw_observation_is_required_before_resume(chain):
    p,r,u,b,h=chain;del r["held_reboot"]["native_observation"]["after_raw"]
    with pytest.raises(c.HeadlessAcceptanceError):c.validate_coordinated_held_reboot(p,r,b)


def test_retained_binary_body_is_not_required_for_lean_descriptor_proof(chain):
    del chain[1]["raw_sources"]["retained_executable"]["bytes_b64"]
    validate(chain)



def test_http_ready_proof_for_unrelated_incarnation_rejected(chain):
    epoch=chain[1]["held_http"]["epochs"][1];obs=epoch["daemon_observations"][0]["daemon_observation"]
    obs["pid"]+=999;obs["start_ticks"]+=999;obs["properties"]["MainPID"]=str(obs["pid"])
    data=("\n".join(k+"="+v for k,v in obs["properties"].items())+"\n").encode()
    obs["systemctl_bytes_base64"]=base64.b64encode(data).decode();obs["systemctl_sha256"]=hashlib.sha256(data).hexdigest()
    data=json.dumps(obs).encode();epoch["daemon_observations"][0]["daemon_observation_bytes_base64"]=base64.b64encode(data).decode();epoch["daemon_observations"][0]["daemon_observation_sha256"]=hashlib.sha256(data).hexdigest()
    with pytest.raises(c.HeadlessAcceptanceError,match="unrelated daemon"):validate(chain)



def test_baseline_first_checkpoint_does_not_replace_required_actual_candidate(chain):
    captures=chain[1]["held_http"]["epochs"][0]["daemon_observations"]
    earlier=deepcopy(captures[0]);obs=earlier["daemon_observation"]
    obs["pid"]=900;obs["start_ticks"]=9000;obs["properties"]["MainPID"]="900"
    data=("\n".join(k+"="+v for k,v in obs["properties"].items())+"\n").encode()
    obs["systemctl_bytes_base64"]=base64.b64encode(data).decode();obs["systemctl_sha256"]=hashlib.sha256(data).hexdigest()
    data=json.dumps(obs).encode();earlier["daemon_observation_bytes_base64"]=base64.b64encode(data).decode();earlier["daemon_observation_sha256"]=hashlib.sha256(data).hexdigest()
    captures.insert(0,earlier);validate(chain)


def test_duplicate_or_unbounded_checkpoint_list_rejected(chain):
    captures=chain[1]["held_http"]["epochs"][0]["daemon_observations"]
    captures.append(deepcopy(captures[0]))
    with pytest.raises(c.HeadlessAcceptanceError,match="duplicate daemon checkpoint"):validate(chain)
