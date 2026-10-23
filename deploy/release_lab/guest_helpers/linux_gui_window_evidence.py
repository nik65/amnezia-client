#!/usr/bin/env python3
"""Collect fail-closed Linux GUI window evidence inside an owned lab guest.

The controller owns screenshot capture and durable archival.  This helper only
binds that controller acknowledgement to a still-live, mapped application
window.  Pixel diagnostics are deliberately never treated as UI acceptance.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import selectors
import base64
import stat
import subprocess
import sys
import time
from typing import Any, Callable


SCHEMA = "amnezia.release-lab.linux-gui-window.v1"
PROFILE = "linux-x64-gui"
BINARY = Path("/opt/AmneziaVPN/bin/AmneziaVPN")
SERVICE = "AmneziaVPN.service"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")


class EvidenceError(RuntimeError):
    pass

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.exists():
        raise EvidenceError("immutable evidence phase already exists or is a symlink")
    current = path.parent
    while current != current.parent:
        if current.is_symlink():
            raise EvidenceError("evidence path contains a symlink")
        current = current.parent
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}.{os.urandom(8).hex()}")
    descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(value, sort_keys=True, allow_nan=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        reserved = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(reserved)
        try:
            os.replace(tmp, path)
            if os.name != "nt":
                directory = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except Exception:
            path.unlink(missing_ok=True)
            raise
    finally:
        tmp.unlink(missing_ok=True)


def command(argv: list[str], *, env: dict[str, str] | None = None,
            timeout: float = 15) -> str:
    result = subprocess.run(argv, env=env, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode != 0:
        raise EvidenceError(f"command failed ({result.returncode}): {argv[0]}: {result.stderr.strip()}")
    return result.stdout


def validate_common(args: argparse.Namespace) -> tuple[Path, str]:
    if args.profile != PROFILE or not RUN_RE.fullmatch(args.run_id) or not RUN_RE.fullmatch(args.attempt_nonce) or len(args.attempt_nonce) < 16:
        raise EvidenceError("invalid run/profile identity")
    expected_marker = f"amnezia-release-lab:{args.run_id}:{PROFILE}"
    marker = Path(args.marker_path)
    if marker.is_symlink() or not marker.is_file() or marker.read_text(encoding="utf-8") != expected_marker:
        raise EvidenceError("guest marker identity is missing or mismatched")
    expected_dir = Path("/run/amnezia-release-lab") / args.run_id / PROFILE
    evidence_dir = Path(args.evidence_dir)
    if evidence_dir != expected_dir or evidence_dir.is_symlink():
        raise EvidenceError("evidence directory is outside the owned run/profile path")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    current = Path("/run/amnezia-release-lab")
    for part in (args.run_id, PROFILE):
        current = current / part
        if current.is_symlink() or not current.is_dir():
            raise EvidenceError("evidence directory has an ambiguous parent")
    return evidence_dir, expected_marker


def proc_identity(pid: int) -> dict[str, Any]:
    proc = Path("/proc") / str(pid)
    try:
        stat_text = (proc / "stat").read_text(encoding="utf-8")
        closing = stat_text.rfind(")")
        if closing < 0:
            raise ValueError("invalid proc stat")
        fields_after_comm = stat_text[closing + 2:].split()
        start_ticks = int(fields_after_comm[19])
        exe = (proc / "exe").resolve(strict=True)
        uid = (proc / "status").stat().st_uid
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"application process {pid} is unavailable") from exc
    return {"pid": pid, "start_ticks": start_ticks, "exe": str(exe), "uid": uid,
            "installed_binary_sha256": sha256(exe)}


def exact_binary_pids(uid: int) -> set[int]:
    found: set[int] = set()
    for item in Path("/proc").iterdir():
        if not item.name.isdigit():
            continue
        try:
            if (item / "status").stat().st_uid == uid and (item / "exe").resolve(strict=True) == BINARY:
                found.add(int(item.name))
        except OSError:
            continue
    return found



def require_unlocked_session(session,deadline):
    """Independent logind and GNOME actual state; a mapped window is insufficient."""
    sid=session['session_id'];uid=session['uid']
    if uid!=1000 or session.get('user')!='lab' or not re.fullmatch(r'[a-zA-Z0-9]+',sid):raise EvidenceError('owned session lock binding differs')
    def text(argv):
        raw=status_attempt(argv,remaining(deadline,5))
        if raw['exitcode']!=0 or raw.get('timeout') or raw.get('overflow'):raise EvidenceError('session lock readback failed')
        return raw['stdout'].decode('utf-8',errors='strict').strip()
    props={k:text(['loginctl','show-session',sid,'-p'+k,'--value']) for k in ('Type','Active','State','Class','User','LockedHint')}
    if props!={'Type':'x11','Active':'yes','State':'active','Class':'user','User':'1000','LockedHint':'no'}:raise EvidenceError('owned GUI session is locked or changed')
    prefix=['runuser','-u','lab','--','env','XDG_RUNTIME_DIR=/run/user/1000','DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus','DISPLAY='+session['display'],'XAUTHORITY='+session['xauthority']]
    active=text(prefix+['gdbus','call','--session','--dest','org.gnome.Shell.ScreenShield','--object-path','/org/gnome/ScreenSaver','--method','org.gnome.ScreenSaver.GetActive'])
    if active!='(false,)':raise EvidenceError('GNOME ScreenSaver obscures owned GUI session')
    return {'lockedHint':'no','screenSaverActive':False,'session_id':sid,'observed_at':utc_now()}


def unlocked(args,evidence_dir,marker):
    state=load_launch(args,evidence_dir,marker)
    if not same_process(state['process']):raise EvidenceError('owned process changed before screen capture')
    proof=require_unlocked_session(state['session'],time.monotonic()+args.timeout)
    return {**state,'phase':'unlocked','sessionUnlocked':proof}


def active_x11_session() -> dict[str, Any]:
    import pwd  # Linux guest only; keep the module importable for host contract tests.

    lab = pwd.getpwnam("lab")
    sessions = command(["loginctl", "list-sessions", "--no-legend"])
    matches: list[dict[str, Any]] = []
    for line in sessions.splitlines():
        columns = line.split()
        if len(columns) < 3 or columns[2] != "lab":
            continue
        sid = columns[0]
        props = {}
        for key in ("Type", "Active", "State", "Class", "User"):
            props[key] = command(["loginctl", "show-session", sid, f"-p{key}", "--value"]).strip()
        if props == {"Type": "x11", "Active": "yes", "State": "active", "Class": "user", "User": str(lab.pw_uid)}:
            matches.append({"session_id": sid, "uid": lab.pw_uid, "user": "lab"})
    if len(matches) != 1:
        raise EvidenceError("exactly one active owned lab X11 session is required")

    graphical: list[tuple[str, str]] = []
    for pid in Path("/proc").iterdir():
        if not pid.name.isdigit():
            continue
        try:
            if (pid / "status").stat().st_uid != lab.pw_uid:
                continue
            comm = (pid / "comm").read_text(encoding="utf-8").strip()
            if comm not in {"gnome-shell", "Xorg", "Xwayland"}:
                continue
            values = {}
            for entry in (pid / "environ").read_bytes().split(b"\0"):
                if b"=" in entry:
                    key, value = entry.split(b"=", 1)
                    values[key.decode(errors="ignore")] = value.decode(errors="ignore")
            if values.get("DISPLAY") and values.get("XAUTHORITY"):
                graphical.append((values["DISPLAY"], values["XAUTHORITY"]))
        except OSError:
            continue
    graphical = sorted(set(graphical))
    if len(graphical) != 1:
        raise EvidenceError("unique DISPLAY/XAUTHORITY could not be derived from the owned session")
    display, auth_text = graphical[0]
    auth = Path(auth_text)
    auth_stat = auth.lstat()
    expected_auth_root = Path("/run/user") / str(lab.pw_uid)
    try:
        auth.relative_to(expected_auth_root)
    except ValueError as exc:
        raise EvidenceError("Xauthority escaped the owned runtime directory") from exc
    if (stat.S_ISLNK(auth_stat.st_mode) or not stat.S_ISREG(auth_stat.st_mode)
            or auth_stat.st_uid != lab.pw_uid or stat.S_IMODE(auth_stat.st_mode) & 0o022):
        raise EvidenceError("Xauthority is not an owned regular file")
    if not re.fullmatch(r":[0-9]+(?:\.[0-9]+)?", display):
        raise EvidenceError("DISPLAY is not a local X11 display")
    return {**matches[0], "display": display, "xauthority": str(auth)}


def xenv(session: dict[str, Any]) -> dict[str, str]:
    return {**os.environ, "DISPLAY": session["display"], "XAUTHORITY": session["xauthority"]}


def mapped_windows(pid: int, session: dict[str, Any], *, deadline=None) -> list[dict[str, str]]:
    env = xenv(session)
    root = command(["runuser", "-u", "lab", "--", "xprop", "-root", "_NET_CLIENT_LIST"], env=env, timeout=remaining(deadline))
    ids = re.findall(r"0x[0-9a-fA-F]+", root)
    if len(ids) > 128:
        raise EvidenceError("X11 client list exceeds the bounded window count")
    matches: list[dict[str, str]] = []
    for wid in ids:
        props = command(["runuser", "-u", "lab", "--", "xprop", "-id", wid,
                         "_NET_WM_PID", "_NET_WM_NAME", "WM_NAME", "WM_CLASS", "_NET_WM_STATE"], env=env, timeout=remaining(deadline))
        pid_match = re.search(r"_NET_WM_PID\([^)]*\) = (\d+)", props)
        if not pid_match or int(pid_match.group(1)) != pid:
            continue
        info = command(["runuser", "-u", "lab", "--", "xwininfo", "-id", wid], env=env, timeout=remaining(deadline))
        state = re.search(r"Map State:\s*(\S+)", info)
        if not state or state.group(1) != "IsViewable" or "_NET_WM_STATE_HIDDEN" in props:
            continue
        title_match = re.search(r'(?:_NET_WM_NAME|WM_NAME)\([^)]*\) = "([^"]*)"', props)
        title = title_match.group(1) if title_match else ""
        if not title.strip():
            raise EvidenceError("mapped application window has no title")
        wm_class = re.search(r'WM_CLASS\([^)]*\) = "([^"]*)", "([^"]*)"', props)
        classes = [part for part in wm_class.groups()] if wm_class else []
        if not classes or not any("amnezia" in part.lower() for part in classes):
            raise EvidenceError("mapped window WM_CLASS does not identify Amnezia")
        matches.append({"id": wid.lower(), "title": title, "wm_class": classes, "map_state": "IsViewable"})
    return matches


def remaining(deadline, maximum=15):
    value=maximum if deadline is None else min(maximum,deadline-time.monotonic())
    if value<=0:raise EvidenceError('total GUI launch readiness budget exhausted')
    return value


def status_attempt(argv, timeout, max_bytes=65536):
    """Bound actual stdout/stderr memory and reap only this child process group."""
    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    selector=selectors.DefaultSelector();buffers={'stdout':bytearray(),'stderr':bytearray()};deadline=time.monotonic()+timeout
    result={'exitcode':None,'timeout':False,'overflow':False}
    for name,stream in (('stdout',child.stdout),('stderr',child.stderr)):
        os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
    try:
        while selector.get_map():
            left=deadline-time.monotonic()
            if left<=0:result['timeout']=True;break
            for key,_ in selector.select(min(.1,left)):
                data=os.read(key.fileobj.fileno(),8192)
                if not data:selector.unregister(key.fileobj);continue
                if sum(map(len,buffers.values()))+len(data)>max_bytes:result['overflow']=True;break
                buffers[key.data].extend(data)
            if result['overflow']:break
        if result['timeout'] or result['overflow']:
            if child.poll() is None:os.killpg(child.pid,signal.SIGTERM)
        try:result['exitcode']=child.wait(timeout=max(.01,min(1,deadline-time.monotonic())))
        except subprocess.TimeoutExpired:
            result['timeout']=True
            if child.poll() is None:os.killpg(child.pid,signal.SIGKILL)
            result['exitcode']=child.wait(timeout=1)
        return {**result,**{name:bytes(data) for name,data in buffers.items()}}
    finally:
        if child.poll() is None:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=1)
        selector.close();child.stdout.close();child.stderr.close()


def running_version(session, expected, identity, window, deadline, evidence_dir, renderer_args=()):
    argv=['runuser','-u','lab','--','env',f"DISPLAY={session['display']}",f"XAUTHORITY={session['xauthority']}",*renderer_args,str(BINARY),'--json','--status']
    for attempt in range(1,65):
        if not same_process(identity) or mapped_windows(identity['pid'],session,deadline=deadline)!=[window]:raise EvidenceError('exact process/window changed before operator readiness')
        result=status_attempt(argv,remaining(deadline,30))
        atomic_json(evidence_dir/f'status-attempt-{attempt:03d}.json',{'diagnosticOnly':True,'attempt':attempt,'pid':identity['pid'],'start_ticks':identity['start_ticks'],'exitcode':result['exitcode'],'timeout':result['timeout'],'overflow':result['overflow'],'stdout_base64':base64.b64encode(result['stdout']).decode(),'stderr_base64':base64.b64encode(result['stderr']).decode()})
        if not same_process(identity) or mapped_windows(identity['pid'],session,deadline=deadline)!=[window]:raise EvidenceError('exact process/window changed after operator readiness')
        if result['timeout'] or result['overflow']:raise EvidenceError('bounded operator readiness command failed')
        item=None
        for line in reversed(result['stdout'].decode(errors='replace').splitlines()):
            try:value=json.loads(line)
            except ValueError:continue
            if isinstance(value,dict):item=value;break
        if item is not None:
            if item.get('schema')=='amnezia.operator.status.v1':
                if item.get('version')!=expected or item.get('pid')!=identity['pid']:raise EvidenceError('operator status version or primary PID differs')
                if result['exitcode']==0 and not item.get('error') and item.get('applicationRunning') is True:return expected
                transient=result['exitcode']==4 and item.get('error')=='application_not_ready' and item.get('applicationRunning') is True
            else:
                transient=result['exitcode']==4 and item=={'ok':False,'error':'application_not_ready'}
        else:
            transient=(result['exitcode']==5 and not result['stdout'].strip() and result['stderr'].strip()==b'Timed out waiting for the running Amnezia instance.')
        if transient and item is not None:
            try:whole=json.loads(result['stdout'])
            except (ValueError,UnicodeError):whole=None
            transient=(whole==item and len(result['stdout'])<=1024 and not result['stderr'].strip())
        if not transient:raise EvidenceError('live operator status did not confirm the expected running version')
        time.sleep(min(.5,remaining(deadline,.5)))
    raise EvidenceError('bounded operator readiness attempt count exhausted')


def service_health(*, deadline=None) -> dict[str, str]:
    values = {}
    for prop in ("ActiveState", "SubState", "MainPID", "ExecMainStartTimestampMonotonic"):
        values[prop] = command(["systemctl", "show", SERVICE, f"-p{prop}", "--value"],timeout=remaining(deadline)).strip()
    if values["ActiveState"] != "active" or values["SubState"] != "running" or not values["MainPID"].isdigit() \
            or int(values["MainPID"]) <= 0:
        raise EvidenceError("fresh application service health is not active/running")
    return {"name": SERVICE, "active": values["ActiveState"], "sub_state": values["SubState"],
            "main_pid": values["MainPID"], "start_monotonic": values["ExecMainStartTimestampMonotonic"]}


def same_process(expected: dict[str, Any]) -> bool:
    try:
        current = proc_identity(int(expected["pid"]))
    except EvidenceError:
        return False
    return all(current[key] == expected[key] for key in
               ("pid", "start_ticks", "exe", "uid", "installed_binary_sha256"))


def load_launch(args: argparse.Namespace, evidence_dir: Path, marker: str) -> dict[str, Any]:
    try:
        state = json.loads((evidence_dir / "launch.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError("launch evidence is missing or invalid") from exc
    expected = {"schema": SCHEMA, "phase": "launch", "origin": "qga", "injected": False,
                "run_id": args.run_id, "profile": PROFILE, "guest_marker": marker,
                "attempt_nonce": args.attempt_nonce,
                "artifact_sha256": args.artifact_sha256, "helper_sha256": args.helper_sha256,
                "version": args.expected_version, "expected_binary_sha256": args.expected_binary_sha256}
    if any(state.get(key) != value for key, value in expected.items()):
        raise EvidenceError("launch evidence identity is invalid")
    if not isinstance(state.get("process"), dict) or state["process"].get("installed_binary_sha256") != args.expected_binary_sha256:
        raise EvidenceError("launch evidence binary identity is invalid")
    return state


def launch(args: argparse.Namespace, evidence_dir: Path, marker: str) -> dict[str, Any]:
    if not VERSION_RE.fullmatch(args.expected_version) or not SHA_RE.fullmatch(args.expected_binary_sha256) \
            or not SHA_RE.fullmatch(args.artifact_sha256) or not SHA_RE.fullmatch(args.helper_sha256):
        raise EvidenceError("expected version or SHA-256 input is invalid")
    if BINARY.is_symlink() or not BINARY.is_file() or not os.access(BINARY, os.X_OK):
        raise EvidenceError("exact installed GUI binary is unavailable")
    if sha256(BINARY) != args.expected_binary_sha256:
        raise EvidenceError("installed GUI binary SHA-256 differs from plan")
    if sha256(Path(__file__).resolve()) != args.helper_sha256:
        raise EvidenceError("guest helper SHA-256 differs from controller plan")
    session = active_x11_session()
    if exact_binary_pids(session["uid"]):
        raise EvidenceError("pre-existing exact-binary process prevents ownership proof")
    for output in (evidence_dir / "launch.json", evidence_dir / "application.log"):
        if output.is_symlink() or output.exists():
            raise EvidenceError("launch evidence already exists; refusing guest effects")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    log_fd = os.open(evidence_dir / "application.log", flags, 0o600)
    atomic_json(evidence_dir/'attempt.json',{'run_id':args.run_id,'profile':PROFILE,'attempt_nonce':args.attempt_nonce,'artifact_sha256':args.artifact_sha256,'helper_sha256':args.helper_sha256,'expected_binary_sha256':args.expected_binary_sha256})
    deadline = time.monotonic() + args.timeout
    require_unlocked_session(session,deadline)
    render_args=renderer_arguments(getattr(args,"renderer_policy","default"),deadline)
    launch_start={"realtime_us":time.time_ns()//1000,"monotonic_us":time.clock_gettime_ns(time.CLOCK_MONOTONIC)//1000}
    try:
        subprocess.Popen(["runuser", "-u", "lab", "--", "env", f"DISPLAY={session['display']}",
                          f"XAUTHORITY={session['xauthority']}", *render_args, str(BINARY)], stdout=log_fd,
                         stderr=log_fd, start_new_session=True)
    finally:
        os.close(log_fd)
    identity: dict[str, Any] | None = None
    window: dict[str, str] | None = None
    while time.monotonic() < deadline:
        pids = exact_binary_pids(session["uid"])
        if len(pids) == 1:
            candidate = proc_identity(next(iter(pids)))
            windows = mapped_windows(candidate["pid"], session, deadline=deadline)
            if len(windows) == 1:
                identity, window = candidate, windows[0]
                break
        time.sleep(0.5)
    if identity is None or window is None:
        raise EvidenceError("bounded wait found no unique exact-process mapped window")
    progress={'schema':SCHEMA,'diagnosticOnly':True,'run_id':args.run_id,'profile':PROFILE,'attempt_nonce':args.attempt_nonce,'session':session,'process':identity,'window':window,'crash_binding':crash_binding(identity,launch_start),'rendererPolicy':getattr(args,'renderer_policy','default')}
    try:progress['safeEnvironment']=safe_process_environment(identity)
    except (OSError,EvidenceError) as error:progress['safeEnvironmentGap']=type(error).__name__
    try:progress['mappedLibraries']=process_maps_snapshot(identity)
    except (OSError,EvidenceError) as error:progress['mappedLibrariesGap']=type(error).__name__
    atomic_json(evidence_dir/'launch-progress.json',progress)
    version = running_version(session,args.expected_version,identity,window,deadline-args.dwell,evidence_dir,render_args)
    service = service_health(deadline=deadline-args.dwell)
    remaining(deadline,args.dwell or .001)
    dwell_deadline = time.monotonic() + args.dwell
    if dwell_deadline>deadline:raise EvidenceError('total GUI launch budget cannot include required dwell')
    while time.monotonic() < dwell_deadline:
        if not same_process(identity) or mapped_windows(identity["pid"], session, deadline=deadline) != [window]:
            raise EvidenceError("application crashed or its mapped window changed during dwell")
        time.sleep(min(0.5, max(0.0, dwell_deadline - time.monotonic())))
    session_unlocked=require_unlocked_session(session,deadline)
    remaining(deadline,.001)
    result = {"schema": SCHEMA, "phase": "launch", "origin": "qga", "injected": False,
              "run_id": args.run_id, "profile": PROFILE, "guest_marker": marker,
              "attempt_nonce": args.attempt_nonce, "observed_at": utc_now(),
              "artifact_sha256": args.artifact_sha256, "helper_sha256": args.helper_sha256,
              "expected_binary_sha256": args.expected_binary_sha256,
              "session": session, "sessionUnlocked":session_unlocked, "process": identity, "version": version, "window": window,
              "service": service, "crash_free_dwell_seconds": args.dwell,
              "window_ready": True, "visual_review_required": True}
    atomic_json(evidence_dir / "launch.json", result)
    return result


def collect(args: argparse.Namespace, evidence_dir: Path, marker: str) -> dict[str, Any]:
    launch_state = load_launch(args, evidence_dir, marker)
    session_unlocked=require_unlocked_session(launch_state["session"],time.monotonic()+args.timeout)
    identity = launch_state["process"]
    if launch_state.get("guest_marker") != marker or not same_process(identity):
        raise EvidenceError("launch process binding is no longer live")
    if mapped_windows(identity["pid"], launch_state["session"]) != [launch_state["window"]]:
        raise EvidenceError("owned mapped window is no longer uniquely visible")
    ack_path = Path(args.screenshot_ack)
    expected_ack = evidence_dir / "screenshot-archive-ack.json"
    if ack_path != expected_ack or ack_path.is_symlink() or not ack_path.is_file():
        raise EvidenceError("controller screenshot archive acknowledgement is missing")
    ack = json.loads(ack_path.read_text(encoding="utf-8"))
    required = {"schema": "amnezia.release-lab.controller-screenshot-ack.v1",
                "controller_created": True, "run_id": args.run_id, "profile": PROFILE,
                "attempt_nonce": args.attempt_nonce,
                "guest_marker": marker, "pid": identity["pid"], "start_ticks": identity["start_ticks"],
                "window_id": launch_state["window"]["id"], "artifact_sha256": args.artifact_sha256,
                "helper_sha256": args.helper_sha256, "expected_version": args.expected_version,
                "expected_binary_sha256": args.expected_binary_sha256}
    if any(ack.get(key) != value for key, value in required.items()):
        raise EvidenceError("screenshot acknowledgement differs from live window identity")
    size = ack.get("screenshot_size")
    archive = ack.get("archive_record")
    if (not SHA_RE.fullmatch(str(ack.get("screenshot_sha256", "")))
            or isinstance(size, bool) or not isinstance(size, int) or size <= 1024
            or not isinstance(archive, dict) or archive.get("sha256") != ack.get("screenshot_sha256")
            or archive.get("size") != size or archive.get("kind") != "linux-gui-window"
            or not isinstance(archive.get("path"), str) or not archive["path"]
            or ack.get("final_gate_revalidation_required") is not True):
        raise EvidenceError("screenshot durable archive metadata is incomplete")
    result = {**launch_state, "sessionUnlocked":session_unlocked, "phase": "collect", "service": service_health(),
              "collected_at": utc_now(),
              "screenshot": {**ack, "pixel_diagnostics_are_acceptance": False},
              "visual_review_required": True, "visual_review_passed": False}
    atomic_json(evidence_dir / "collect.json", result)
    return result


def signal_exact_process(identity: dict[str, Any], sig: int) -> None:
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise EvidenceError("pidfd signalling is required for race-safe cleanup")
    descriptor = os.pidfd_open(int(identity["pid"]), 0)
    try:
        if not same_process(identity):
            raise EvidenceError("process identity changed immediately before cleanup signal")
        signal.pidfd_send_signal(descriptor, sig)
    finally:
        os.close(descriptor)


def cleanup(args: argparse.Namespace, evidence_dir: Path, marker: str) -> dict[str, Any]:
    state = load_launch(args, evidence_dir, marker)
    identity = state["process"]
    if state.get("guest_marker") != marker or not same_process(identity):
        raise EvidenceError("refusing cleanup because exact owned process identity changed")
    pid = int(identity["pid"])
    signal_exact_process(identity, signal.SIGTERM)
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline and same_process(identity):
        time.sleep(0.1)
    escalated = False
    if same_process(identity):
        signal_exact_process(identity, signal.SIGKILL)
        escalated = True
        deadline = time.monotonic() + min(args.timeout, 10)
        while time.monotonic() < deadline and same_process(identity):
            time.sleep(0.1)
    if same_process(identity):
        raise EvidenceError("owned application process did not exit")
    result = {"schema": SCHEMA, "phase": "cleanup", "origin": "qga", "injected": False,
              "run_id": args.run_id, "profile": PROFILE, "guest_marker": marker,
              "attempt_nonce": args.attempt_nonce, "observed_at": utc_now(),
              "pid": pid, "start_ticks": identity["start_ticks"], "exe": identity["exe"],
              "terminated": True, "sigkill_escalated": escalated}
    atomic_json(evidence_dir / "cleanup.json", result)
    return result


SAFE_ENV = {b'DISPLAY', b'XAUTHORITY', b'XDG_RUNTIME_DIR', b'DBUS_SESSION_BUS_ADDRESS',
            b'GALLIUM_DRIVER', b'QT_QPA_PLATFORM', b'QT_QUICK_BACKEND',
            b'LIBGL_ALWAYS_SOFTWARE', b'MESA_LOADER_DRIVER_OVERRIDE'}


def bounded_fd_read(fd,maximum,deadline=None):
    """Short procfs reads are not EOF. Retain at most the requested budget."""
    data=bytearray()
    while len(data)<maximum:
        if deadline is not None and time.monotonic()>deadline:raise EvidenceError('bounded procfs read deadline')
        block=os.read(fd,maximum-len(data))
        if not block:break
        data.extend(block)
    return bytes(data)


def process_maps_snapshot(identity):
    if not same_process(identity):raise EvidenceError('application changed before maps snapshot')
    parent=os.open('/proc/'+str(identity['pid']),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        if not same_process(identity):raise EvidenceError('application changed before maps open')
        fd=os.open('maps',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:data=bounded_fd_read(fd,32769)
        finally:os.close(fd)
        if not same_process(identity):raise EvidenceError('application changed during maps snapshot')
        return {'body_base64':base64.b64encode(data[:32768]).decode(),'truncated':len(data)>32768,'complete':len(data)<=32768,'capturedSize':min(len(data),32768)}
    finally:os.close(parent)


def safe_process_environment(identity):
    if not same_process(identity):
        raise EvidenceError('application changed before environment snapshot')
    fd = os.open('/proc/'+str(identity['pid'])+'/environ', os.O_RDONLY|os.O_NOFOLLOW)
    try:
        data = bounded_fd_read(fd, 65537)
    finally:
        os.close(fd)
    if len(data)>65536 or not same_process(identity):
        raise EvidenceError('application environment bounds or identity changed')
    return {k.decode():v.decode(errors='replace') for item in data.split(b'\0')
            if b'=' in item for k,v in [item.split(b'=',1)] if k in SAFE_ENV and len(v)<=1024}


def renderer_arguments(policy, deadline):
    if policy == 'default':
        return []
    if policy != 'softpipe':
        raise EvidenceError('unknown renderer policy')
    path=Path('/run/systemd/system/user@1000.service.d/90-release-lab-softpipe.conf')
    value=private_bytes(path,1024)
    if base64.b64decode(value['body_base64']) != b'[Service]\nEnvironment=GALLIUM_DRIVER=softpipe\n':
        raise EvidenceError('owned softpipe fixture policy differs')
    raw=command(['systemctl','show','user@1000.service','-pEnvironment','--value'],timeout=remaining(deadline,2))
    if 'GALLIUM_DRIVER=softpipe' not in raw.split():
        raise EvidenceError('softpipe fixture environment readback differs')
    return ['GALLIUM_DRIVER=softpipe']


def crash_binding(identity, launch_start):
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot):
        raise EvidenceError('kernel boot identity malformed')
    return {'boot_id':boot,'pid':identity['pid'],'start_ticks':identity['start_ticks'],
            'clock_ticks':os.sysconf('SC_CLK_TCK'),'uid':identity['uid'],'exe':identity['exe'],
            'installed_binary_sha256':identity['installed_binary_sha256'],
            'launch_realtime_us':launch_start['realtime_us'],
            'launch_monotonic_us':launch_start['monotonic_us']}


def fault_records(binding, deadline):
    """Read existing journals only; never retrieve or process a core image."""
    result={'diagnosticOnly':True,'binding':binding,'queries':{},'gaps':[]}
    now_us=time.time_ns()//1000
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    required={'boot_id','pid','start_ticks','clock_ticks','uid','exe','installed_binary_sha256','launch_realtime_us','launch_monotonic_us'}
    if (set(binding)!=required or binding['boot_id']!=boot or type(binding['pid']) is not int
            or binding['pid']<=0 or type(binding['uid']) is not int or binding['uid']!=1000
            or binding['exe']!=str(BINARY) or not SHA_RE.fullmatch(binding['installed_binary_sha256'])
            or any(type(binding[k]) is not int or binding[k]<0 for k in ('start_ticks','clock_ticks','launch_realtime_us','launch_monotonic_us'))
            or binding['clock_ticks']<=0 or not 0<=now_us-binding['launch_realtime_us']<=300_000_000
            or binding['start_ticks']<binding['launch_monotonic_us']*binding['clock_ticks']//1_000_000):
        raise EvidenceError('crash diagnostic historical identity differs')
    fields='MESSAGE,_BOOT_ID,_PID,_UID,_EXE,__MONOTONIC_TIMESTAMP,__REALTIME_TIMESTAMP,COREDUMP_PID,COREDUMP_UID,COREDUMP_EXE,COREDUMP_TIMESTAMP,COREDUMP_SIGNAL,COREDUMP_SIGNAL_NAME,COREDUMP_COMM,COREDUMP_FILENAME,COREDUMP_TRUNCATED,COREDUMP_STACKTRACE'
    common=['journalctl','--no-pager','-q','-o','json','--output-fields='+fields,'-n','64',
            '--boot='+boot.replace('-',''),'--since=@'+str(binding['launch_realtime_us']/1_000_000),
            '--until=@'+str(now_us/1_000_000)]
    queries={'user':['_PID='+str(binding['pid']),'_UID='+str(binding['uid']),'_EXE='+binding['exe']],
             'kernel':['_TRANSPORT=kernel'],
             'coredump':['COREDUMP_PID='+str(binding['pid']),'COREDUMP_UID='+str(binding['uid']),'COREDUMP_EXE='+binding['exe']]}
    for name,matches in queries.items():
        if deadline-time.monotonic()<=.05:
            result['gaps'].append(name+':diagnostic-budget');continue
        try:
            raw=status_attempt(common+matches,remaining(deadline,2),max_bytes=32768)
            record={k:raw[k] for k in ('exitcode','timeout','overflow')}
            record['stderr_base64']=base64.b64encode(raw['stderr'][:4096]).decode()
            record['stdout_size']=len(raw['stdout'])
            record['stdout_sha256']=hashlib.sha256(raw['stdout']).hexdigest()
            record['records']=[]
            if raw['exitcode'] or raw['timeout'] or raw['overflow']:
                result['gaps'].append(name+':command-incomplete')
                record['stdout_base64']=base64.b64encode(raw['stdout']).decode()
            else:
                lines=raw['stdout'].splitlines()
                if len(lines)>64:raise EvidenceError('journal record bounds')
                for line in lines:
                    item=json.loads(line)
                    if not isinstance(item,dict) or item.get('_BOOT_ID')!=boot.replace('-',''):
                        raise EvidenceError('journal boot differs')
                    mono=int(item['__MONOTONIC_TIMESTAMP']);real=int(item['__REALTIME_TIMESTAMP'])
                    if not binding['launch_monotonic_us']<=mono or not binding['launch_realtime_us']<=real<=now_us:
                        raise EvidenceError('journal time differs')
                    if name=='user' and any(item.get(k)!=str(binding[v]) for k,v in (('_PID','pid'),('_UID','uid'),('_EXE','exe'))):
                        raise EvidenceError('journal process differs')
                    if name=='coredump':
                        if any(item.get(k)!=str(binding[v]) for k,v in (('COREDUMP_PID','pid'),('COREDUMP_UID','uid'),('COREDUMP_EXE','exe'))):
                            raise EvidenceError('coredump process differs')
                        stamp=int(item.get('COREDUMP_TIMESTAMP','0'))
                        if not binding['launch_realtime_us']<=stamp<=now_us:raise EvidenceError('coredump time differs')
                    if name=='kernel':
                        # Kernel MESSAGE has no authenticated application identity.
                        # Keep exact PID token hits only as explicitly labelled correlation.
                        message=item.get('MESSAGE','')
                        if not isinstance(message,str) or not re.search(r'(?<!\d)'+str(binding['pid'])+r'(?!\d)',message):continue
                        item={**item,'attribution':'kernel-message-PID-correlation-only'}
                    record['records'].append(item)
                record['empty']=not record['records']
            result['queries'][name]=record
        except (OSError,ValueError,KeyError,EvidenceError) as error:
            result['gaps'].append(name+':'+type(error).__name__)
    result['coreTransferAttempted']=False
    result['debuggerInvoked']=False
    return result


def private_bytes(path, limit, *, tail=False):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:raise EvidenceError('private visual diagnostic file differs')
        if tail:os.lseek(fd,max(0,info.st_size-limit),0)
        elif info.st_size>limit:raise EvidenceError('private visual diagnostic size exceeds bounds')
        data=os.read(fd,limit)
        return {'size':info.st_size,'capturedSize':len(data),'truncated':info.st_size>len(data),'sha256':hashlib.sha256(data).hexdigest(),'body_base64':base64.b64encode(data).decode()}
    finally:os.close(fd)


def bounded_diagnostic_result(result):
    """Keep primary provenance/logs; optional capture omissions are explicit."""
    def size():return len(json.dumps(result).encode())
    if size()>512000 and 'faultRecords' in result:
        value=result['faultRecords'];raw=json.dumps(value,sort_keys=True).encode()
        result['faultRecords']={'diagnosticOnly':True,'omitted':True,'reason':'aggregate-output-budget',
            'serializedSize':len(raw),'serializedSHA256':hashlib.sha256(raw).hexdigest(),
            'binding':value.get('binding'),'gaps':value.get('gaps',[])}
        result['gaps'].append('fault-records:aggregate-output-budget')
    for attempt in result.get('statusAttempts',[]):
        if size()<=512000:break
        value=attempt['record']
        attempt['record']={k:v for k,v in value.items() if k!='body_base64'}
        attempt['record']['bodyOmitted']=True
        result['gaps'].append(attempt['name']+':aggregate-output-budget')
    for name in ('maps','stack','cmdline','status','threads'):
        if size()<=512000:break
        if name in result:
            del result[name];result['gaps'].append(name+':aggregate-output-budget')
    if size()>512000:raise EvidenceError('private visual diagnostic output bounds')
    return result


def diagnose(args,evidence_dir,marker):
    """Bounded private read-only attempt snapshot; never a GUI PASS."""
    deadline=time.monotonic()+10
    result={'schema':SCHEMA,'phase':'diagnose','diagnosticOnly':True,'origin':'qga','injected':False,'run_id':args.run_id,'profile':PROFILE,'attempt_nonce':args.attempt_nonce,'guest_marker':marker,'gaps':[]}
    if sha256(Path(__file__).resolve())!=args.helper_sha256:raise EvidenceError('diagnostic helper differs')
    attempt=evidence_dir/'attempt.json'
    if not attempt.exists():result['gaps'].append('no-owned-attempt');return result
    record=json.loads(base64.b64decode(private_bytes(attempt,4096)['body_base64']))
    expected={'run_id':args.run_id,'profile':PROFILE,'attempt_nonce':args.attempt_nonce,'artifact_sha256':args.artifact_sha256,'helper_sha256':args.helper_sha256,'expected_binary_sha256':args.expected_binary_sha256}
    if record!=expected:raise EvidenceError('private attempt identity differs')
    result['attempt']=record
    for name in ('application.log','launch-progress.json'):
        try:result[name]=private_bytes(evidence_dir/name,65536,tail=name=='application.log')
        except (OSError,EvidenceError) as error:result['gaps'].append(name+':'+type(error).__name__)
    progress=result.get('launch-progress.json')
    if progress:
        value=json.loads(base64.b64decode(progress['body_base64']))
        if value.get('attempt_nonce')!=args.attempt_nonce or value.get('run_id')!=args.run_id:raise EvidenceError('diagnostic process binding differs')
        process=value['process']
        result['historicalProcess']=process
        if value.get('crash_binding'):
            try:
                binding=value['crash_binding']
                if any(binding[k]!=process[k] for k in ('pid','start_ticks','uid','exe','installed_binary_sha256')) or binding['installed_binary_sha256']!=args.expected_binary_sha256:
                    raise EvidenceError('historical crash binding differs from owned process')
                result['crashBinding']=binding
                result['faultRecords']=fault_records(binding,deadline)
            except (OSError,ValueError,KeyError,EvidenceError) as error:result['gaps'].append('fault-records:'+type(error).__name__)
        else:result['gaps'].append('no-historical-crash-binding')
        if same_process(process):
            result['process']=process
            try:proc_fd=os.open('/proc/'+str(process['pid']),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            except OSError as error:proc_fd=None;result['gaps'].append('process-directory:'+type(error).__name__)
            if proc_fd is not None:
                def proc_read(name,limit,parent=proc_fd):
                    if time.monotonic()>deadline:raise EvidenceError('private visual diagnostic10s budget')
                    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                    try:return bounded_fd_read(fd,limit+1,deadline=deadline)
                    finally:os.close(fd)
                try:
                    if not same_process(process):raise EvidenceError('application changed before private snapshot')
                    for name,limit in (('cmdline',8192),('status',8192),('maps',32768),('stack',8192)):
                        try:
                            data=proc_read(name,limit)
                            result[name]={'body_base64':base64.b64encode(data[:limit]).decode(),'truncated':len(data)>limit}
                        except (OSError,EvidenceError) as error:result['gaps'].append(name+':'+type(error).__name__)
                    try:
                        data=proc_read('environ',65536)
                        if len(data)>65536:raise EvidenceError('application environ bounds')
                        allowed={b'DISPLAY',b'XAUTHORITY',b'XDG_RUNTIME_DIR',b'DBUS_SESSION_BUS_ADDRESS',b'GALLIUM_DRIVER',b'QT_QPA_PLATFORM',b'QT_QUICK_BACKEND',b'LIBGL_ALWAYS_SOFTWARE',b'MESA_LOADER_DRIVER_OVERRIDE'}
                        result['safeEnvironment']={k.decode():v.decode(errors='replace') for item in data.split(b'\0') if b'=' in item for k,v in [item.split(b'=',1)] if k in allowed and len(v)<=1024}
                    except (OSError,EvidenceError) as error:result['gaps'].append('safe-env:'+type(error).__name__)
                    result['threads']=[]
                    task=os.open('task',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=proc_fd)
                    try:
                        tids=sorted(name for name in os.listdir(task) if name.isdigit())
                        result['threadsTruncated']=len(tids)>32
                        for tid in tids[:32]:
                            if time.monotonic()>deadline:result['gaps'].append('thread:diagnostic-budget');break
                            thread=None
                            try:
                                thread=os.open(tid,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=task)
                                wchan=proc_read('wchan',256,thread).decode(errors='replace')
                                result['threads'].append({'tid':int(tid),'wchan':wchan[:256]})
                            except (OSError,EvidenceError) as error:result['gaps'].append('thread:'+type(error).__name__)
                            finally:
                                if thread is not None:os.close(thread)
                    finally:os.close(task)
                    if not same_process(process):result['gaps'].append('owned-process-changed-during-snapshot')
                except (OSError,EvidenceError) as error:result['gaps'].append('process-snapshot:'+type(error).__name__)
                finally:os.close(proc_fd)
        else:result['gaps'].append('owned-application-no-longer-live')
    result['statusAttempts']=[]
    paths=sorted(evidence_dir.glob('status-attempt-*.json'))
    if len(paths)>64:raise EvidenceError('private status attempt count bounds')
    attempt_bytes=0
    for path in paths:
        try:
            record=private_bytes(path,100000);attempt_bytes+=len(json.dumps(record).encode())
            if attempt_bytes>262144:raise EvidenceError('private status archive aggregate bounds')
            result['statusAttempts'].append({'name':path.name,'record':record})
        except (OSError,EvidenceError) as error:result['gaps'].append('status-attempt:'+type(error).__name__)
    return bounded_diagnostic_result(result)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("action", choices=("launch", "collect", "cleanup", "diagnose", "unlocked"))
    value.add_argument("--run-id", required=True)
    value.add_argument("--attempt-nonce", required=True)
    value.add_argument("--profile", required=True)
    value.add_argument("--marker-path", default="/tmp/amnezia-release-lab-marker")
    value.add_argument("--evidence-dir", required=True)
    value.add_argument("--timeout", type=float, default=60)
    value.add_argument("--dwell", type=float, default=10)
    value.add_argument("--renderer-policy",choices=("default","softpipe"),default="default")
    value.add_argument("--expected-version")
    value.add_argument("--expected-binary-sha256")
    value.add_argument("--artifact-sha256")
    value.add_argument("--helper-sha256")
    value.add_argument("--screenshot-ack")
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        evidence_dir, marker = validate_common(args)
        if (not math.isfinite(args.timeout) or not math.isfinite(args.dwell)
                or args.timeout <= 0 or args.timeout > 300 or args.dwell < 0 or args.dwell > 120):
            raise EvidenceError("timeouts are outside bounded limits")
        if args.action == "launch":
            result = launch(args, evidence_dir, marker)
        elif args.action == "unlocked":
            result = unlocked(args,evidence_dir,marker)
        elif args.action == "diagnose":
            result = diagnose(args,evidence_dir,marker)
        elif args.action == "collect":
            result = collect(args, evidence_dir, marker)
        else:
            result = cleanup(args, evidence_dir, marker)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (EvidenceError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(json.dumps({"schema": SCHEMA, "status": "FAIL", "reason": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
