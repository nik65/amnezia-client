from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

try:
    from relay_smoke_controller import RelaySmokeError, build_plan
except ImportError:
    from deploy.release_lab.relay_smoke_controller import RelaySmokeError, build_plan


def _records(root: Path) -> tuple[Path, Path]:
    child = root / "child.json"
    server = root / "server.json"
    child.write_text(json.dumps({"run_id": "run", "case_id": "case", "vm_id": "{11111111-1111-1111-1111-111111111111}", "parent_sha256": "0" * 64, "qmp_socket": "qmp.sock", "qga_socket": "qga.sock", "marker": "amnezia-release-lab:run:windows-x64", "process_pid": 123, "process_uuid": "11111111-1111-1111-1111-111111111111"}), encoding="utf-8")
    server.write_text(json.dumps({"run_id": "run", "profile": "server-router", "qmp_socket": "server.qmp", "qga_socket": "server.qga", "host_bind": "127.0.0.1", "ssh_guest_port": 22, "http_guest_port": 17865}), encoding="utf-8")
    return child, server


def test_build_plan_is_fixed_and_identity_bound(tmp_path: Path) -> None:
    child, server = _records(tmp_path)
    plan = build_plan(run_id="run", case_id="case", vm_id="{11111111-1111-1111-1111-111111111111}", child_record=child, server_record=server, supervisor=tmp_path / "supervisor.exe", relay=tmp_path / "relay.exe", run_root=tmp_path)
    assert plan["relay"]["ssh"]["host_port"] == 22222
    assert plan["relay"]["ssh"]["guest_port"] == 22222
    assert plan["relay"]["http"]["guest_port"] == 17865
    assert plan["server"]["ssh_guest_port"] == 22
    assert plan["host_network_mutation"] is False


def test_build_plan_rejects_wildcard_and_unbound_records(tmp_path: Path) -> None:
    child, server = _records(tmp_path)
    with pytest.raises(RelaySmokeError):
        build_plan(run_id="run", case_id="case", vm_id="{ffffffff-ffff-ffff-ffff-ffffffffffff}", child_record=child, server_record=server, supervisor=tmp_path / "supervisor.exe", relay=tmp_path / "relay.exe", run_root=tmp_path)
    child.write_text(child.read_text(encoding="utf-8").replace('"run_id": "run"', '"run_id": "other"'), encoding="utf-8")
    with pytest.raises(RelaySmokeError):
        build_plan(run_id="run", case_id="case", vm_id="{11111111-1111-1111-1111-111111111111}", child_record=child, server_record=server, supervisor=tmp_path / "supervisor.exe", relay=tmp_path / "relay.exe", run_root=tmp_path)


def test_lab_cli_exposes_read_only_relay_smoke_plan(tmp_path: Path) -> None:
    child, server = _records(tmp_path)
    command = [sys.executable, str(Path(__file__).with_name("lab.py")), "--dry-run", "--json", "relay-smoke-plan", "--run-id", "run", "--case-id", "case", "--vm-id", "{11111111-1111-1111-1111-111111111111}", "--run-root", str(tmp_path), "--child-record", str(child), "--server-record", str(server), "--supervisor", str(tmp_path / "supervisor.exe"), "--relay", str(tmp_path / "relay.exe")]
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["action"] == "relay-smoke-plan"
