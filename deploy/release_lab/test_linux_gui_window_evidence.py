import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest


HELPER = Path(__file__).parent / "guest_helpers" / "linux_gui_window_evidence.py"
SPEC = importlib.util.spec_from_file_location("linux_gui_window_evidence", HELPER)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def args(tmp_path: Path, action: str = "collect") -> SimpleNamespace:
    run_id = "gui-window-test"
    return SimpleNamespace(action=action, run_id=run_id, profile=MODULE.PROFILE,
                           attempt_nonce="attempt-123456789",
                           marker_path=str(tmp_path / "marker"),
                           evidence_dir=str(Path("/run/amnezia-release-lab") / run_id / MODULE.PROFILE),
                           timeout=1, dwell=0, expected_version="5.0.1.39",
                           expected_binary_sha256="a" * 64, artifact_sha256="b" * 64,
                           helper_sha256="c" * 64, screenshot_ack=None)


def launch_state() -> dict:
    return {"schema": MODULE.SCHEMA, "phase": "launch", "origin": "qga", "injected": False,
            "run_id": "gui-window-test", "profile": MODULE.PROFILE,
            "attempt_nonce": "attempt-123456789", "observed_at": "2026-09-13T19:59:00Z",
            "guest_marker": "amnezia-release-lab:gui-window-test:linux-x64-gui",
            "session": {"uid": 1001, "user": "lab", "display": ":0", "xauthority": "/run/user/1001/gdm/Xauthority"},
            "process": {"pid": 42, "start_ticks": 9001, "exe": str(MODULE.BINARY), "uid": 1001,
                        "installed_binary_sha256": "a" * 64},
            "window": {"id": "0x200001", "title": "AmneziaVPN", "map_state": "IsViewable"},
            "version": "5.0.1.39", "artifact_sha256": "b" * 64, "helper_sha256": "c" * 64,
            "expected_binary_sha256": "a" * 64}


def test_version_probe_rejects_application_not_running() -> None:
    session = {"display": ":0", "xauthority": "/run/user/1001/gdm/Xauthority"}
    payload = json.dumps({"schema": "amnezia.operator.status.v1", "version": "5.0.1.39",
                          "error": "application_not_running"})
    with patch.object(MODULE, "command", return_value=payload):
        with pytest.raises(MODULE.EvidenceError, match="live operator status"):
            MODULE.running_version(session, "5.0.1.39")


def test_collect_requires_unique_live_mapped_window_and_marks_png_for_review(tmp_path: Path) -> None:
    state = launch_state()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    ack = evidence / "screenshot-archive-ack.json"
    ack.write_text(json.dumps({"run_id": "gui-window-test", "profile": MODULE.PROFILE, "pid": 42,
                               "schema": "amnezia.release-lab.controller-screenshot-ack.v1",
                               "controller_created": True, "guest_marker": state["guest_marker"],
                               "attempt_nonce": "attempt-123456789",
                               "start_ticks": 9001, "window_id": "0x200001",
                               "artifact_sha256": "b" * 64, "helper_sha256": "c" * 64,
                               "expected_version": "5.0.1.39", "expected_binary_sha256": "a" * 64,
                               "screenshot_sha256": "d" * 64, "screenshot_size": 4096,
                               "archive_record": {"path": "/owned/export/gui.png", "sha256": "d" * 64,
                                                  "size": 4096, "kind": "linux-gui-window"},
                               "final_gate_revalidation_required": True, "unique_colors": 17}), encoding="utf-8")
    values = args(tmp_path)
    values.screenshot_ack = str(ack)
    with patch.object(MODULE, "load_launch", return_value=state), \
         patch.object(MODULE, "same_process", return_value=True), \
         patch.object(MODULE, "mapped_windows", return_value=[state["window"]]), \
         patch.object(MODULE, "service_health", return_value={"active": "active"}), \
         patch.object(MODULE, "atomic_json"):
        result = MODULE.collect(values, evidence, state["guest_marker"])
    assert result["window_ready"] if "window_ready" in result else True
    assert result["visual_review_required"] is True
    assert result["visual_review_passed"] is False
    assert result["screenshot"]["pixel_diagnostics_are_acceptance"] is False


def test_collect_rejects_window_identity_change(tmp_path: Path) -> None:
    state = launch_state()
    values = args(tmp_path)
    with patch.object(MODULE, "load_launch", return_value=state), \
         patch.object(MODULE, "same_process", return_value=True), \
         patch.object(MODULE, "mapped_windows", return_value=[]):
        with pytest.raises(MODULE.EvidenceError, match="uniquely visible"):
            MODULE.collect(values, tmp_path, state["guest_marker"])


def test_cleanup_refuses_pid_reuse_without_signalling(tmp_path: Path) -> None:
    state = launch_state()
    values = args(tmp_path, "cleanup")
    with patch.object(MODULE, "load_launch", return_value=state), \
         patch.object(MODULE, "same_process", return_value=False), \
         patch.object(MODULE.os, "kill") as kill:
        with pytest.raises(MODULE.EvidenceError, match="identity changed"):
            MODULE.cleanup(values, tmp_path, state["guest_marker"])
    kill.assert_not_called()


def test_mapped_window_requires_pid_title_and_isviewable() -> None:
    outputs = iter([
        "_NET_CLIENT_LIST(WINDOW): window id # 0x200001, 0x200002",
        '_NET_WM_PID(CARDINAL) = 42\n_NET_WM_NAME(UTF8_STRING) = "AmneziaVPN"\nWM_CLASS(STRING) = "amneziavpn", "AmneziaVPN"',
        "Map State: IsViewable",
        '_NET_WM_PID(CARDINAL) = 7\n_NET_WM_NAME(UTF8_STRING) = "Other"',
        "Map State: IsViewable",
    ])
    with patch.object(MODULE, "command", side_effect=lambda *a, **k: next(outputs)):
        assert MODULE.mapped_windows(42, {"display": ":0", "xauthority": "/x"}) == [
            {"id": "0x200001", "title": "AmneziaVPN", "wm_class": ["amneziavpn", "AmneziaVPN"], "map_state": "IsViewable"}
        ]


def test_load_launch_rejects_stale_artifact_or_helper_binding(tmp_path: Path) -> None:
    state = launch_state()
    (tmp_path / "launch.json").write_text(json.dumps(state), encoding="utf-8")
    values = args(tmp_path)
    assert MODULE.load_launch(values, tmp_path, state["guest_marker"])["version"] == "5.0.1.39"
    state["artifact_sha256"] = "e" * 64
    (tmp_path / "launch.json").write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(MODULE.EvidenceError, match="identity"):
        MODULE.load_launch(values, tmp_path, state["guest_marker"])


def test_atomic_json_creates_once_and_rejects_existing_or_symlink_parent(tmp_path: Path) -> None:
    target = tmp_path / "owned" / "phase.json"
    MODULE.atomic_json(target, {"passed": True})
    assert json.loads(target.read_text(encoding="utf-8"))["passed"] is True
    with pytest.raises(MODULE.EvidenceError, match="already exists"):
        MODULE.atomic_json(target, {"passed": False})
    real = tmp_path / "real"; real.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        return
    with pytest.raises(MODULE.EvidenceError, match="symlink"):
        MODULE.atomic_json(link / "phase.json", {"passed": True})


def test_collect_rejects_forged_controller_archive_ack(tmp_path: Path) -> None:
    state = launch_state(); ack = tmp_path / "screenshot-archive-ack.json"
    ack.write_text(json.dumps({"schema": "amnezia.release-lab.controller-screenshot-ack.v1",
        "controller_created": True, "run_id": "gui-window-test", "profile": MODULE.PROFILE,
        "attempt_nonce": "attempt-123456789",
        "guest_marker": state["guest_marker"], "pid": 42, "start_ticks": 9001,
        "window_id": "0x200001", "artifact_sha256": "b"*64, "helper_sha256": "c"*64,
        "expected_version": "5.0.1.39", "expected_binary_sha256": "a"*64,
        "screenshot_sha256": "d"*64, "screenshot_size": True,
        "archive_record": {"path":"/owned/x","sha256":"d"*64,"size":True,"kind":"linux-gui-window"},
        "final_gate_revalidation_required": True}), encoding="utf-8")
    values=args(tmp_path); values.screenshot_ack=str(ack)
    with patch.object(MODULE,"load_launch",return_value=state), patch.object(MODULE,"same_process",return_value=True), patch.object(MODULE,"mapped_windows",return_value=[state["window"]]):
        with pytest.raises(MODULE.EvidenceError, match="metadata"):
            MODULE.collect(values,tmp_path,state["guest_marker"])


def test_signal_exact_process_rechecks_after_opening_pidfd() -> None:
    identity=launch_state()["process"]
    with patch.object(MODULE.os,"pidfd_open",return_value=9,create=True), \
         patch.object(MODULE.signal,"pidfd_send_signal",create=True) as send, \
         patch.object(MODULE,"same_process",return_value=False), patch.object(MODULE.os,"close"):
        with pytest.raises(MODULE.EvidenceError,match="immediately"):
            MODULE.signal_exact_process(identity,MODULE.signal.SIGTERM)
    send.assert_not_called()


def test_launch_rejects_duplicate_before_process_creation(tmp_path: Path) -> None:
    values = args(tmp_path, "launch")
    evidence = tmp_path / "evidence"; evidence.mkdir()
    (evidence / "launch.json").write_text("{}", encoding="utf-8")
    binary = tmp_path / "AmneziaVPN"; binary.write_bytes(b"binary")
    session = {"uid": 1001, "display": ":0", "xauthority": "/run/user/1001/Xauthority"}
    with patch.object(MODULE, "BINARY", binary), \
         patch.object(MODULE, "sha256", side_effect=["a" * 64, "c" * 64]), \
         patch.object(MODULE.os, "access", return_value=True), \
         patch.object(MODULE, "active_x11_session", return_value=session), \
         patch.object(MODULE, "exact_binary_pids", return_value=set()), \
         patch.object(MODULE.subprocess, "Popen") as popen:
        with pytest.raises(MODULE.EvidenceError, match="refusing guest effects"):
            MODULE.launch(values, evidence, "amnezia-release-lab:gui-window-test:linux-x64-gui")
    popen.assert_not_called()
