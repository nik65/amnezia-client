from __future__ import annotations

import re
import ctypes
import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "hyperv_socket_relay.cpp"
REGISTRY = ROOT / "hyperv_socket_relay.ps1"


def test_relay_has_only_fixed_channels_and_targets() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    assert "AF_HYPERV" in source
    assert "HV_GUID_PARENT" in source
    assert "SOCKADDR_HV" in source
    assert "kSshPort = 22222" in source
    assert "kHttpPort = 17865" in source
    assert "INADDR_LOOPBACK" in source
    assert "channelFor(L\"tcp\") != nullptr" in source
    assert "options.channel" in source
    assert "--vm-id" in source
    assert "--ownership-file" in source
    assert "--parent-pid" in source
    assert "--parent-start" in source
    assert "helper_sha256" in source
    assert "sha256File" in source
    assert "processStartTime" in source
    assert "GetModuleFileNameW" in source
    assert "relay_pid" in source
    assert "relay_start" in source
    assert "watchParent" in source
    assert "WaitForMultipleObjects" in source
    assert "openVerifiedParent" in source
    assert "stopEvent" in source
    assert "writeReceipt" in source and "MoveFileExW" in source
    assert "kConnectionDeadlineMs" in source
    assert "connectWithDeadline" in source
    assert "setNonBlocking" in source
    assert "context.failed.store(true)" in source
    assert "timeoutContext" in source
    assert "cancelContext" in source
    assert "resetContext" in source
    assert "SO_EXCLUSIVEADDRUSE" in source
    assert "isForbiddenVmId" in source
    assert "target-host" not in source
    assert "target-port" not in source
    assert "system(" not in source


def test_registry_script_only_owns_two_fixed_service_guids() -> None:
    source = REGISTRY.read_text(encoding="utf-8")
    assert "GuestCommunicationServices" in source
    assert "5f2f2a1e-9c3a-4fa9-8f4d-31e9960d7c31" in source
    assert "6f3bdc8b-7b21-4df1-a3f5-6e4aaecf8f42" in source
    assert "host_network_mutation = $false" in source
    assert "ElementName" in source
    assert "AmneziaReleaseLabOwnerRunId" in source
    assert "AmneziaReleaseLabOwnerMarker" in source
    assert "$created" in source
    assert "registry-$RunId.lease" in source
    assert "AmneziaReleaseLab SSH relay" in source
    assert "AmneziaReleaseLab HTTP relay" in source
    assert "Remove-Item" in source
    assert "New-Guid" not in source


def test_supervisor_is_fixed_owned_foreground_controller() -> None:
    source = (ROOT / "hyperv_socket_relay_supervisor.cpp").read_text(encoding="utf-8")
    assert "CreateEventW" in source
    assert "Local\\\\AmneziaReleaseLabRelayStop_" in source
    assert 'line != L"stop"' in source
    assert "CREATE_NO_WINDOW" in source
    assert "sha256File" in source
    assert "quarantineReceipt" in source
    assert "readyTimeoutMs" in source
    assert "system(" not in source


def test_private_helper_runs_bounded_positive_and_negative_loopback_cases() -> None:
    executable = Path(__file__).parents[3] / "Testing" / "focused-hyperv-relay" / "amnezia_hyperv_socket_relay.exe"
    if not executable.exists():
        pytest.skip("focused private relay helper has not been built")
    result = subprocess.run([str(executable), "--self-test"], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr or result.stdout


def test_private_helper_rejects_unknown_duplicate_and_non_decimal_cli_values() -> None:
    executable = Path(__file__).parents[3] / "Testing" / "focused-hyperv-relay" / "amnezia_hyperv_socket_relay.exe"
    if not executable.exists():
        pytest.skip("focused private relay helper has not been built")
    common = [
        "--mode", "guest", "--channel", "ssh", "--vm-id", "{11111111-1111-1111-1111-111111111111}",
        "--run-id", "run", "--case-id", "case", "--ownership-file", "missing", "--receipt-path", "receipt",
        "--helper-sha256", "0" * 64, "--parent-start", "1",
    ]
    cases = [
        [*common, "--unknown", "value", "--parent-pid", "1"],
        [*common, "--parent-pid", "1", "--parent-pid", "2"],
        [*common, "--parent-pid", "12x"],
        [*common, "--parent-pid", "4294967296"],
    ]
    for arguments in cases:
        result = subprocess.run([str(executable), *arguments], capture_output=True, text=True, timeout=2)
        assert result.returncode == 64, (arguments, result.stdout, result.stderr)


def test_owned_supervisor_start_ready_stop_persists_receipt() -> None:
    helper = Path(__file__).parents[3] / "Testing" / "focused-hyperv-relay" / "amnezia_hyperv_socket_relay.exe"
    supervisor = Path(__file__).parents[3] / "Testing" / "focused-hyperv-relay" / "amnezia_hyperv_socket_relay_supervisor.exe"
    if not helper.exists() or not supervisor.exists():
        pytest.skip("focused private relay supervisor has not been built")
    runs = []
    with tempfile.TemporaryDirectory(prefix="relay-supervisor-") as temporary:
        directory = Path(temporary)
        for iteration in range(2):
            receipt = directory / f"receipt-{iteration}.txt"
            lease = directory / f"lease-{iteration}.txt"
            run_id = f"pytest-run-{os.getpid()}-{time.monotonic_ns()}"
            command = [
                str(supervisor), "--relay-exe", str(helper), "--mode", "guest", "--channel", "http",
                "--vm-id", "{11111111-1111-1111-1111-111111111111}", "--run-id", run_id, "--case-id", "pytest-case",
                "--ownership-file", str(lease), "--receipt-path", str(receipt), "--helper-sha256", hashlib.sha256(helper.read_bytes()).hexdigest(),
                "--ready-timeout-ms", "5000", "--loopback-self-test",
            ]
            process = subprocess.Popen(command, stdin=subprocess.PIPE, text=True)
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline and (not receipt.exists() or "state=running" not in receipt.read_text(encoding="utf-8")):
                time.sleep(0.05)
            assert receipt.exists() and "state=running" in receipt.read_text(encoding="utf-8")
            process.stdin.write("stop\n")
            process.stdin.flush()
            assert process.wait(timeout=6) == 0
            final_receipt = receipt.read_text(encoding="utf-8")
            assert final_receipt.endswith("state=stopped\n")
            runs.append({"supervisor_exit": process.returncode, "receipt": final_receipt})
    evidence = Path(__file__).parents[3] / "Testing" / "focused-hyperv-relay" / "test_receipts" / "supervisor_lifecycle_receipt.json"
    evidence.parent.mkdir(exist_ok=True)
    evidence.write_text(json.dumps({"repeat_runs": runs}, indent=2) + "\n", encoding="utf-8")


def test_owned_supervisor_parent_loss_marks_relay_failed() -> None:
    helper = Path(__file__).parents[3] / "Testing" / "focused-hyperv-relay" / "amnezia_hyperv_socket_relay.exe"
    supervisor = Path(__file__).parents[3] / "Testing" / "focused-hyperv-relay" / "amnezia_hyperv_socket_relay_supervisor.exe"
    if not helper.exists() or not supervisor.exists():
        pytest.skip("focused private relay supervisor has not been built")
    with tempfile.TemporaryDirectory(prefix="relay-parent-loss-") as temporary:
        directory = Path(temporary)
        receipt = directory / "receipt.txt"
        run_id = f"parent-loss-{os.getpid()}-{time.monotonic_ns()}"
        command = [
            str(supervisor), "--relay-exe", str(helper), "--mode", "guest", "--channel", "http",
            "--vm-id", "{11111111-1111-1111-1111-111111111111}", "--run-id", run_id, "--case-id", "case",
            "--ownership-file", str(directory / "lease.txt"), "--receipt-path", str(receipt), "--helper-sha256", hashlib.sha256(helper.read_bytes()).hexdigest(),
            "--ready-timeout-ms", "5000", "--loopback-self-test", "--self-test-parent-loss",
        ]
        process = subprocess.Popen(command, stdin=subprocess.PIPE, text=True)
        assert process.wait(timeout=6) == 0
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline and (not receipt.exists() or "state=failed" not in receipt.read_text(encoding="utf-8")):
            time.sleep(0.05)
        assert receipt.exists() and receipt.read_text(encoding="utf-8").endswith("state=failed\n")


def test_shared_exact_run_case_stop_event_stops_concurrent_ssh_and_http_supervisors() -> None:
    helper = Path(__file__).parents[3] / "Testing" / "focused-hyperv-relay" / "amnezia_hyperv_socket_relay.exe"
    supervisor = Path(__file__).parents[3] / "Testing" / "focused-hyperv-relay" / "amnezia_hyperv_socket_relay_supervisor.exe"
    if not helper.exists() or not supervisor.exists():
        pytest.skip("focused private relay supervisor has not been built")
    with tempfile.TemporaryDirectory(prefix="relay-concurrent-") as temporary:
        directory = Path(temporary)
        run_id = f"concurrent-{os.getpid()}-{time.monotonic_ns()}"
        processes = []
        receipts = []
        for channel in ("ssh", "http"):
            receipt = directory / f"{channel}.receipt"
            command = [
                str(supervisor), "--relay-exe", str(helper), "--mode", "guest", "--channel", channel,
                "--vm-id", "{11111111-1111-1111-1111-111111111111}", "--run-id", run_id, "--case-id", "shared-case",
                "--ownership-file", str(directory / f"{channel}.lease"), "--receipt-path", str(receipt), "--helper-sha256", hashlib.sha256(helper.read_bytes()).hexdigest(),
                "--ready-timeout-ms", "5000", "--loopback-self-test",
            ]
            processes.append(subprocess.Popen(command, stdin=subprocess.PIPE, text=True))
            receipts.append(receipt)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and any(not receipt.exists() or "state=running" not in receipt.read_text(encoding="utf-8") for receipt in receipts):
            time.sleep(0.05)
        assert all(receipt.exists() and "state=running" in receipt.read_text(encoding="utf-8") for receipt in receipts)
        time.sleep(0.5)
        stop = subprocess.run([
            str(supervisor), "--stop", "--run-id", run_id, "--case-id", "shared-case",
            "--ownership-file", str(directory / "ssh.lease"),
        ], capture_output=True, text=True, timeout=3)
        assert stop.returncode == 0, stop.stderr
        assert all(process.wait(timeout=8) == 0 for process in processes)
        assert all(receipt.read_text(encoding="utf-8").endswith("state=stopped\n") for receipt in receipts)


def test_supervisor_delayed_not_ready_child_is_bounded_and_reaped() -> None:
    helper = Path(__file__).parents[3] / "Testing" / "focused-hyperv-relay" / "amnezia_hyperv_socket_relay.exe"
    supervisor = Path(__file__).parents[3] / "Testing" / "focused-hyperv-relay" / "amnezia_hyperv_socket_relay_supervisor.exe"
    if not helper.exists() or not supervisor.exists():
        pytest.skip("focused private relay supervisor has not been built")
    with tempfile.TemporaryDirectory(prefix="relay-delayed-ready-") as temporary:
        directory = Path(temporary)
        receipt = directory / "receipt.txt"
        run_id = f"delayed-{os.getpid()}-{time.monotonic_ns()}"
        command = [
            str(supervisor), "--relay-exe", str(helper), "--mode", "guest", "--channel", "http",
            "--vm-id", "{11111111-1111-1111-1111-111111111111}", "--run-id", run_id, "--case-id", "case",
            "--ownership-file", str(directory / "lease.txt"), "--receipt-path", str(receipt), "--helper-sha256", hashlib.sha256(helper.read_bytes()).hexdigest(),
            "--ready-timeout-ms", "100", "--loopback-self-test", "--self-test-delayed-ready",
        ]
        process = subprocess.run(command, capture_output=True, text=True, timeout=6)
        assert process.returncode == 70
        if receipt.exists():
            assert receipt.read_text(encoding="utf-8").splitlines()[-1] in {"state=stopped", "state=failed"}
        process_listing = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "Get-CimInstance Win32_Process | Select-Object -ExpandProperty CommandLine"],
            capture_output=True, text=True, timeout=3,
        )
        assert run_id not in process_listing.stdout


def test_owned_supervisor_rejects_receipt_write_failure_and_stale_parent_without_overwrite() -> None:
    helper = Path(__file__).parents[3] / "Testing" / "focused-hyperv-relay" / "amnezia_hyperv_socket_relay.exe"
    supervisor = Path(__file__).parents[3] / "Testing" / "focused-hyperv-relay" / "amnezia_hyperv_socket_relay_supervisor.exe"
    if not helper.exists() or not supervisor.exists():
        pytest.skip("focused private relay supervisor has not been built")
    with tempfile.TemporaryDirectory(prefix="relay-negative-") as temporary:
        directory = Path(temporary)
        missing_receipt = directory / "missing" / "receipt.txt"
        command = [
            str(supervisor), "--relay-exe", str(helper), "--mode", "guest", "--channel", "http",
            "--vm-id", "{11111111-1111-1111-1111-111111111111}", "--run-id", "write-failure", "--case-id", "case",
            "--ownership-file", str(directory / "lease.txt"), "--receipt-path", str(missing_receipt), "--helper-sha256", hashlib.sha256(helper.read_bytes()).hexdigest(),
            "--ready-timeout-ms", "1000", "--loopback-self-test",
        ]
        assert subprocess.run(command, input="stop\n", text=True, timeout=5).returncode == 70
        run_id, case_id = "stale-parent", "case"
        event_name = f"Local\\AmneziaReleaseLabRelayStop_{run_id}_{case_id}"
        vm_id = "{11111111-1111-1111-1111-111111111111}"
        lease = directory / "stale-lease.txt"
        receipt = directory / "stale-receipt.txt"
        helper_hash = hashlib.sha256(helper.read_bytes()).hexdigest()
        lease.write_text(f"schema=1\nrun_id={run_id}\ncase_id={case_id}\nvm_id={vm_id}\nhelper_sha256={helper_hash}\nparent_pid={os.getpid()}\nparent_start=1\nstop_event={event_name}\nstate=relay-authorized\n", encoding="utf-8")
        original = f"run_id={run_id}\ncase_id={case_id}\nvm_id={vm_id}\nstop_event={event_name}\nstate=stopped\n"
        receipt.write_text(original, encoding="utf-8")
        event = ctypes.windll.kernel32.CreateEventW(None, True, False, event_name)
        assert event
        try:
            helper_command = [
                str(helper), "--mode", "guest", "--channel", "http", "--vm-id", vm_id, "--run-id", run_id, "--case-id", case_id,
                "--ownership-file", str(lease), "--receipt-path", str(receipt), "--helper-sha256", helper_hash,
                "--parent-pid", str(os.getpid()), "--parent-start", "1", "--stop-event-name", event_name, "--self-test-daemon",
            ]
            assert subprocess.run(helper_command, text=True, timeout=2).returncode == 70
        finally:
            ctypes.windll.kernel32.CloseHandle(event)
        assert receipt.read_text(encoding="utf-8") == original
