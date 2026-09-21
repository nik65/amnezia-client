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


def mapped_windows(pid: int, session: dict[str, Any]) -> list[dict[str, str]]:
    env = xenv(session)
    root = command(["runuser", "-u", "lab", "--", "xprop", "-root", "_NET_CLIENT_LIST"], env=env)
    ids = re.findall(r"0x[0-9a-fA-F]+", root)
    if len(ids) > 128:
        raise EvidenceError("X11 client list exceeds the bounded window count")
    matches: list[dict[str, str]] = []
    for wid in ids:
        props = command(["runuser", "-u", "lab", "--", "xprop", "-id", wid,
                         "_NET_WM_PID", "_NET_WM_NAME", "WM_NAME", "WM_CLASS", "_NET_WM_STATE"], env=env)
        pid_match = re.search(r"_NET_WM_PID\([^)]*\) = (\d+)", props)
        if not pid_match or int(pid_match.group(1)) != pid:
            continue
        info = command(["runuser", "-u", "lab", "--", "xwininfo", "-id", wid], env=env)
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


def running_version(session: dict[str, Any], expected: str) -> str:
    output = command(["runuser", "-u", "lab", "--", "env",
                      f"DISPLAY={session['display']}", f"XAUTHORITY={session['xauthority']}",
                      str(BINARY), "--json", "--status"], timeout=30)
    for line in reversed(output.splitlines()):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("schema") == "amnezia.operator.status.v1" and item.get("version") == expected \
                and not item.get("error"):
            return expected
    raise EvidenceError("live operator status did not confirm the expected running version")


def service_health() -> dict[str, str]:
    values = {}
    for prop in ("ActiveState", "SubState", "MainPID", "ExecMainStartTimestampMonotonic"):
        values[prop] = command(["systemctl", "show", SERVICE, f"-p{prop}", "--value"]).strip()
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
    try:
        subprocess.Popen(["runuser", "-u", "lab", "--", "env", f"DISPLAY={session['display']}",
                          f"XAUTHORITY={session['xauthority']}", str(BINARY)], stdout=log_fd,
                         stderr=log_fd, start_new_session=True)
    finally:
        os.close(log_fd)
    deadline = time.monotonic() + args.timeout
    identity: dict[str, Any] | None = None
    window: dict[str, str] | None = None
    while time.monotonic() < deadline:
        pids = exact_binary_pids(session["uid"])
        if len(pids) == 1:
            candidate = proc_identity(next(iter(pids)))
            windows = mapped_windows(candidate["pid"], session)
            if len(windows) == 1:
                identity, window = candidate, windows[0]
                break
        time.sleep(0.5)
    if identity is None or window is None:
        raise EvidenceError("bounded wait found no unique exact-process mapped window")
    version = running_version(session, args.expected_version)
    service = service_health()
    dwell_deadline = time.monotonic() + args.dwell
    while time.monotonic() < dwell_deadline:
        if not same_process(identity) or mapped_windows(identity["pid"], session) != [window]:
            raise EvidenceError("application crashed or its mapped window changed during dwell")
        time.sleep(min(0.5, max(0.0, dwell_deadline - time.monotonic())))
    result = {"schema": SCHEMA, "phase": "launch", "origin": "qga", "injected": False,
              "run_id": args.run_id, "profile": PROFILE, "guest_marker": marker,
              "attempt_nonce": args.attempt_nonce, "observed_at": utc_now(),
              "artifact_sha256": args.artifact_sha256, "helper_sha256": args.helper_sha256,
              "expected_binary_sha256": args.expected_binary_sha256,
              "session": session, "process": identity, "version": version, "window": window,
              "service": service, "crash_free_dwell_seconds": args.dwell,
              "window_ready": True, "visual_review_required": True}
    atomic_json(evidence_dir / "launch.json", result)
    return result


def collect(args: argparse.Namespace, evidence_dir: Path, marker: str) -> dict[str, Any]:
    launch_state = load_launch(args, evidence_dir, marker)
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
    result = {**launch_state, "phase": "collect", "service": service_health(),
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


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("action", choices=("launch", "collect", "cleanup"))
    value.add_argument("--run-id", required=True)
    value.add_argument("--attempt-nonce", required=True)
    value.add_argument("--profile", required=True)
    value.add_argument("--marker-path", default="/tmp/amnezia-release-lab-marker")
    value.add_argument("--evidence-dir", required=True)
    value.add_argument("--timeout", type=float, default=60)
    value.add_argument("--dwell", type=float, default=10)
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
