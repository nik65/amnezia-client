from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent


def test_smoke_adapter_is_fixed_and_fail_closed() -> None:
    source = (ROOT / "hyperv_relay_smoke.ps1").read_text(encoding="utf-8")
    assert "$SshRelayPort = 22222" in source
    assert "$HttpRelayPort = 17865" in source
    assert "$LinuxSshPort = 22" in source
    assert "$HttpPath = '/healthz'" in source
    assert "Assert-ExactGuid" in source
    assert "Assert-OwnedPath" in source
    assert "qmp_socket" in source and "qga_socket" in source
    assert "process_uuid" in source and "guest_marker" not in source
    assert "host_network_mutation = $false" in source
    assert "target-host" not in source and "target-port" not in source
    assert "New-Net" not in source and "Set-Net" not in source


def test_guest_task_uses_owned_scheduled_task_and_fixed_supervisor_stop() -> None:
    source = (ROOT / "hyperv_relay_guest_task.ps1").read_text(encoding="utf-8")
    assert "Register-ScheduledTask" in source
    assert "Start-ScheduledTask" in source
    assert "Unregister-ScheduledTask" in source
    assert "--channel $Channel" in source
    assert "--stop --run-id" in source
    assert "target-host" not in source and "target-port" not in source
    assert "host_network_mutation = $false" in source


def test_ui_helper_binds_case_marker_path() -> None:
    source = (ROOT / "hyperv_ui_helper.ps1").read_text(encoding="utf-8")
    assert "[string] $CaseId" in source
    assert "windows-x64\\$CaseId\\run-marker.txt" in source
    assert "case_id=$CaseId" in source


def test_hyperv_adapter_captures_ui_from_case_owned_interactive_task() -> None:
    source = (ROOT / "hyperv_adapter.ps1").read_text(encoding="utf-8")
    assert "Invoke-InteractiveUiCapture" in source
    assert "New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive" in source
    assert "interactive UI capture task remained after cleanup" in source
    assert "-CaseId $Case -VmId $Vm" in source
    assert "parameters=@($_.Parameters | ForEach-Object" in source


@pytest.mark.skipif(not (Path(__file__).parents[3] / "Testing" / "focused-hyperv-relay" / "amnezia_hyperv_socket_relay_supervisor.exe").exists(), reason="private relay supervisor is not built")
def test_smoke_powershell_scripts_parse() -> None:
    for script in (ROOT / "hyperv_relay_smoke.ps1", ROOT / "hyperv_relay_guest_task.ps1"):
        command = "$tokens=$null; $e=@(); [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath '" + str(script) + "'),[ref]$tokens,[ref]$e)|Out-Null; if($e.Count){exit 1}"
        result = subprocess.run(["pwsh", "-NoProfile", "-Command", command], capture_output=True, text=True, timeout=5)
        assert result.returncode == 0, result.stderr
