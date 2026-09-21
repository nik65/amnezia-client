"""Immutable controller acknowledgement for a human-reviewed Linux GUI PNG."""
from __future__ import annotations

import hashlib, json, os, re, stat
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Mapping

SCHEMA = "amnezia.release-lab.root-visual-review.v1"
SHA = re.compile(r"[0-9a-f]{64}")

class VisualAckError(RuntimeError): pass

def _under(path: Path, root: Path) -> Path:
    root=root.resolve(strict=True); value=path.resolve(strict=False)
    try: value.relative_to(root)
    except ValueError as exc: raise VisualAckError("path escaped owned evidence root") from exc
    if path.is_symlink(): raise VisualAckError("symlinked evidence path is forbidden")
    return value

def _utc(value: str) -> datetime:
    if not isinstance(value,str) or not value.endswith("Z"): raise VisualAckError("review time must be UTC")
    try: return datetime.fromisoformat(value[:-1]+"+00:00")
    except ValueError as exc: raise VisualAckError("invalid review time") from exc

def _canonical(value: Mapping[str,Any]) -> bytes:
    return json.dumps(dict(value),sort_keys=True,separators=(",",":")).encode()

def create_root_visual_ack(*, owned_root: Path, destination: Path, collect: Mapping[str,Any],
                           attempt_nonce: str, reviewed_at: str) -> dict[str,Any]:
    if collect.get("schema")!="amnezia.release-lab.linux-gui-window.v1" or collect.get("phase")!="collect" \
       or collect.get("origin")!="qga" or collect.get("injected") is not False:
        raise VisualAckError("collect receipt is not authentic Linux GUI evidence")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{15,95}",attempt_nonce) or collect.get("attempt_nonce")!=attempt_nonce: raise VisualAckError("invalid attempt nonce binding")
    reviewed=_utc(reviewed_at); collected=_utc(collect.get("collected_at")); process=collect.get("process") or {}; window=collect.get("window") or {}
    if reviewed < collected or reviewed-collected > timedelta(hours=24) or reviewed > datetime.now(timezone.utc)+timedelta(minutes=5): raise VisualAckError("visual review time is stale or out of order")
    session=collect.get("session") or {}; service=collect.get("service") or {}
    if (collect.get("version")!=(collect.get("screenshot") or {}).get("expected_version")
       or session.get("user")!="lab" or isinstance(session.get("uid"),bool) or not isinstance(session.get("uid"),int) or session["uid"]<=0
       or not re.fullmatch(r":[0-9]+(?:\.[0-9]+)?",str(session.get("display","")))
       or not str(session.get("xauthority","")).startswith(f"/run/user/{session.get('uid')}/")
       or process.get("uid")!=session.get("uid") or process.get("exe")!="/opt/AmneziaVPN/bin/AmneziaVPN"
       or process.get("installed_binary_sha256")!=collect.get("expected_binary_sha256")
       or window.get("map_state")!="IsViewable" or not window.get("title")
       or not isinstance(window.get("wm_class"),list) or not any("amnezia" in str(x).lower() for x in window["wm_class"])
       or service.get("active")!="active" or service.get("sub_state")!="running"
       or not str(service.get("main_pid","")).isdigit() or int(service["main_pid"])<=1
       or not str(service.get("start_monotonic","")).isdigit() or int(service["start_monotonic"])<=0
       or collect.get("window_ready") is not True or collect.get("visual_review_required") is not True
       or collect.get("visual_review_passed") is not False): raise VisualAckError("collect receipt lacks full live GUI semantics")
    shot=(collect.get("screenshot") or {}).get("archive_record") or {}
    shot_path=_under(Path(str(shot.get("path",""))),owned_root)
    st=shot_path.lstat()
    if not stat.S_ISREG(st.st_mode): raise VisualAckError("reviewed screenshot is not a regular file")
    data=shot_path.read_bytes(); digest=hashlib.sha256(data).hexdigest()
    if len(data)<=1024 or shot.get("size")!=len(data) or shot.get("sha256")!=digest:
        raise VisualAckError("reviewed PNG differs from controller archive record")
    if not data.startswith(b"\x89PNG\r\n\x1a\n"): raise VisualAckError("reviewed evidence is not a PNG")
    for key in ("artifact_sha256","helper_sha256","expected_binary_sha256"):
        if not SHA.fullmatch(str(collect.get(key,""))): raise VisualAckError("collect binding SHA is invalid")
    if isinstance(process.get("pid"),bool) or not isinstance(process.get("pid"),int) or process["pid"]<=1 \
       or isinstance(process.get("start_ticks"),bool) or not isinstance(process.get("start_ticks"),int) or process["start_ticks"]<=0 \
       or not window.get("id"):
        raise VisualAckError("process/window binding is incomplete")
    value={"schema":SCHEMA,"decision":"accepted","reviewer_role":"root-visual-review",
      "reviewed_at":reviewed_at,"run_id":collect.get("run_id"),"profile":collect.get("profile"),
      "attempt_nonce":attempt_nonce,"guest_marker":collect.get("guest_marker"),"artifact_sha256":collect["artifact_sha256"],
      "helper_sha256":collect["helper_sha256"],"expected_binary_sha256":collect["expected_binary_sha256"],
      "pid":process["pid"],"start_ticks":process["start_ticks"],"window_id":window["id"],
      "screenshot":{"path":str(shot_path),"sha256":digest,"size":len(data)},
      "collect_receipt_sha256":hashlib.sha256(_canonical(collect)).hexdigest()}
    target=_under(destination,owned_root)
    target.parent.mkdir(parents=True,exist_ok=True)
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
    if hasattr(os,"O_NOFOLLOW"): flags|=os.O_NOFOLLOW
    fd=os.open(target,flags,0o600)
    try:
        payload=json.dumps(value,sort_keys=True,indent=2).encode()+b"\n"; os.write(fd,payload); os.fsync(fd)
    finally: os.close(fd)
    return value

def validate_root_visual_ack(*, owned_root: Path, ack: Mapping[str,Any], collect: Mapping[str,Any]) -> dict[str,Any]:
    expected={"schema":SCHEMA,"decision":"accepted","reviewer_role":"root-visual-review",
      "run_id":collect.get("run_id"),"profile":collect.get("profile"),"guest_marker":collect.get("guest_marker"),
      "artifact_sha256":collect.get("artifact_sha256"),"helper_sha256":collect.get("helper_sha256"),
      "expected_binary_sha256":collect.get("expected_binary_sha256"),"pid":(collect.get("process") or {}).get("pid"),
      "start_ticks":(collect.get("process") or {}).get("start_ticks"),"window_id":(collect.get("window") or {}).get("id"),
      "collect_receipt_sha256":hashlib.sha256(_canonical(collect)).hexdigest()}
    if any(ack.get(k)!=v for k,v in expected.items()): raise VisualAckError("visual acknowledgement binding mismatch")
    reviewed=_utc(ack.get("reviewed_at")); collected=_utc(collect.get("collected_at"))
    if reviewed < collected or reviewed-collected > timedelta(hours=24): raise VisualAckError("visual acknowledgement time mismatch")
    shot=ack.get("screenshot") or {}; path=_under(Path(str(shot.get("path",""))),owned_root)
    data=path.read_bytes()
    if shot.get("size")!=len(data) or shot.get("sha256")!=hashlib.sha256(data).hexdigest():
        raise VisualAckError("reviewed PNG changed after acknowledgement")
    return dict(ack)
