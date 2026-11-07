import hashlib,json
from pathlib import Path
import pytest
from deploy.release_lab.android_visual_handshake import AndroidVisualHandshakeStore,VisualHandshakeError

PNG=b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"+(100).to_bytes(4,"big")+(200).to_bytes(4,"big")+b"\x08\x06\x00\x00\x00\x00\x00\x00\x00"
RUN="run-1";NONCE="1"*48

def record(now=100,state="operator-unclassified",sequence=1):
 return {"schema":1,"run_id":RUN,"attempt_nonce":NONCE,"sequence":sequence,"kind":"update","state":"operator-unclassified","action":"Update","bounds":None,"display_owner":{"package":"org.amnezia.vpn","activity":"Main","pid":12,"uid":10123},"action_target":{"package":"org.amnezia.vpn","version_code":38,"artifact_sha256":"a"*64,"artifact_size":10},"artifact_sha256":"a"*64,"artifact_size":10,"review_seconds":90,"origin":"guest","transport":"qga-adb"}

def test_request_decision_is_immutable_bound_and_never_touches_run_state(tmp_path):
 state=tmp_path/"state.json";state.write_text('{"sentinel":1}')
 store=AndroidVisualHandshakeStore(tmp_path,clock=lambda:100);ack=store.request(record(),PNG)
 assert Path(ack["request_path"]).exists() and Path(ack["png_path"]).read_bytes()==PNG
 decision=store.decide(RUN,NONCE,ack["request_id"],ack["request_sha256"],"approve",[1,2,11,12])
 assert store.poll(ack)==decision and state.read_text()=='{"sentinel":1}'
 with pytest.raises(FileExistsError):store.decide(RUN,NONCE,ack["request_id"],ack["request_sha256"],"approve",[1,2,11,12])

def test_tamper_expiry_and_state_specific_decisions_fail_closed(tmp_path):
 clock=[100];store=AndroidVisualHandshakeStore(tmp_path,clock=lambda:clock[0]);ack=store.request(record(),PNG)
 with pytest.raises(VisualHandshakeError,match="changed"):store.decide(RUN,NONCE,ack["request_id"],"0"*64,"approve")
 clock[0]=191
 with pytest.raises(VisualHandshakeError,match="expired"):store.decide(RUN,NONCE,ack["request_id"],ack["request_sha256"],"approve")
 clock[0]=100;refresh=store.request(record(sequence=2),PNG)
 with pytest.raises(VisualHandshakeError,match="requires"):store.decide(RUN,NONCE,refresh["request_id"],refresh["request_sha256"],"approve")
 assert store.decide(RUN,NONCE,refresh["request_id"],refresh["request_sha256"],"refresh")["input_only"] is True

def test_request_bytes_or_identity_cannot_be_reused(tmp_path):
 store=AndroidVisualHandshakeStore(tmp_path,clock=lambda:100);ack=store.request(record(),PNG)
 request_path=Path(ack["request_path"]);request_path.chmod(0o600);request_path.write_text("{}")
 with pytest.raises(VisualHandshakeError,match="changed"):store.decide(RUN,NONCE,ack["request_id"],ack["request_sha256"],"approve")
def test_outside_ack_and_out_of_image_bounds_are_rejected(tmp_path):
 store=AndroidVisualHandshakeStore(tmp_path,clock=lambda:100);ack=store.request(record(),PNG)
 with pytest.raises(VisualHandshakeError,match="outside PNG"):store.decide(RUN,NONCE,ack["request_id"],ack["request_sha256"],"approve",[0,0,101,20])
 forged={**ack,"request_path":str(tmp_path/"outside.json")}
 with pytest.raises(VisualHandshakeError,match="path/hash"):store.poll(forged)
def test_symlinked_request_is_rejected_when_supported(tmp_path):
 store=AndroidVisualHandshakeStore(tmp_path,clock=lambda:100);ack=store.request(record(),PNG);path=Path(ack["request_path"]);saved=path.with_suffix(".saved");path.rename(saved)
 try:path.symlink_to(saved)
 except OSError:pytest.skip("symlink creation unavailable")
 with pytest.raises(VisualHandshakeError,match="not regular"):store.poll(ack)

def test_kind_action_and_strict_identity_schema_are_bound(tmp_path):
 store=AndroidVisualHandshakeStore(tmp_path,clock=lambda:100)
 forged=record();forged["action"]="Skip"
 with pytest.raises(VisualHandshakeError,match="invalid visual request"):store.request(forged,PNG)
 forged=record();forged["display_owner"]["pid"]=True
 with pytest.raises(VisualHandshakeError,match="display owner"):store.request(forged,PNG)
