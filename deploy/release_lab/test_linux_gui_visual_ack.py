import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
from deploy.release_lab.linux_gui_visual_ack import create_root_visual_ack, validate_root_visual_ack, VisualAckError

def collect(path: Path) -> dict:
    data=path.read_bytes()
    return {"schema":"amnezia.release-lab.linux-gui-window.v1","phase":"collect","origin":"qga","injected":False,
      "run_id":"run-1","profile":"linux-x64-gui","guest_marker":"amnezia-release-lab:run-1:linux-x64-gui",
      "attempt_nonce":"attempt-123456789","collected_at":"2026-09-13T19:59:00Z","version":"5.0.1.39",
      "artifact_sha256":"a"*64,"helper_sha256":"b"*64,"expected_binary_sha256":"c"*64,
      "session":{"uid":1000,"user":"lab","display":":0","xauthority":"/run/user/1000/gdm/Xauthority"},
      "process":{"pid":22,"start_ticks":33,"uid":1000,"exe":"/opt/AmneziaVPN/bin/AmneziaVPN","installed_binary_sha256":"c"*64},
      "window":{"id":"0x42","title":"AmneziaVPN","map_state":"IsViewable","wm_class":["AmneziaVPN"]},
      "service":{"active":"active","sub_state":"running","main_pid":"12","start_monotonic":"44"},
      "window_ready":True,"visual_review_required":True,"visual_review_passed":False,
      "screenshot":{"expected_version":"5.0.1.39","archive_record":{"path":str(path),"sha256":hashlib.sha256(data).hexdigest(),"size":len(data)}}}

def test_ack_is_immutable_and_rehashes_png(tmp_path):
    png=tmp_path/"window.png"; png.write_bytes(b"\x89PNG\r\n\x1a\n"+b"x"*2048)
    raw=collect(png); dest=tmp_path/"ack"/"visual.json"
    now=datetime.now(timezone.utc); raw["collected_at"]=(now-timedelta(minutes=1)).isoformat().replace("+00:00","Z")
    reviewed=now.isoformat().replace("+00:00","Z")
    ack=create_root_visual_ack(owned_root=tmp_path,destination=dest,collect=raw,
      attempt_nonce="attempt-123456789",reviewed_at=reviewed)
    assert validate_root_visual_ack(owned_root=tmp_path,ack=ack,collect=raw)["decision"]=="accepted"
    with pytest.raises(FileExistsError):
        create_root_visual_ack(owned_root=tmp_path,destination=dest,collect=raw,
          attempt_nonce="attempt-123456789",reviewed_at=reviewed)
    png.write_bytes(b"\x89PNG\r\n\x1a\n"+b"y"*2048)
    with pytest.raises(VisualAckError): validate_root_visual_ack(owned_root=tmp_path,ack=ack,collect=raw)

def test_ack_rejects_forged_process_and_escape(tmp_path):
    png=tmp_path/"window.png"; png.write_bytes(b"\x89PNG\r\n\x1a\n"+b"x"*2048); raw=collect(png)
    raw["process"]["pid"]=True
    with pytest.raises(VisualAckError): create_root_visual_ack(owned_root=tmp_path,destination=tmp_path/"a.json",collect=raw,attempt_nonce="attempt-123456789",reviewed_at="2026-09-13T20:00:00Z")
    raw=collect(png)
    with pytest.raises(VisualAckError): create_root_visual_ack(owned_root=tmp_path,destination=tmp_path.parent/"escape.json",collect=raw,attempt_nonce="attempt-123456789",reviewed_at="2026-09-13T20:00:00Z")

def test_ack_rejects_wrong_attempt_and_incomplete_live_semantics(tmp_path):
    png=tmp_path/"window.png"; png.write_bytes(b"\x89PNG\r\n\x1a\n"+b"x"*2048); raw=collect(png)
    now=datetime.now(timezone.utc); raw["collected_at"]=(now-timedelta(minutes=1)).isoformat().replace("+00:00","Z")
    with pytest.raises(VisualAckError,match="nonce"): create_root_visual_ack(owned_root=tmp_path,destination=tmp_path/"a",collect=raw,attempt_nonce="different-123456789",reviewed_at=now.isoformat().replace("+00:00","Z"))
    raw["service"]["start_monotonic"]="0"
    with pytest.raises(VisualAckError,match="semantics"): create_root_visual_ack(owned_root=tmp_path,destination=tmp_path/"b",collect=raw,attempt_nonce=raw["attempt_nonce"],reviewed_at=now.isoformat().replace("+00:00","Z"))
