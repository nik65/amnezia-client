"""Read-only contract checks for the Android release-lab driver.

These tests intentionally do not invoke WSL, the SDK, ADB, an emulator, or an
APK. The live gate is run later by the release controller after final review.
"""

from __future__ import annotations

import json
import base64
import re
import subprocess
import sys
import pytest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "android-lab-profile.json"
DRIVER = ROOT / "android-lab.sh"
README = ROOT / "README.md"
UPGRADE_SCENARIO = ROOT / "scenarios" / "arm64-upgrade.json"
NETWORK_SCENARIO = ROOT / "scenarios" / "network-gate.json"
REFERENCE_MANIFEST = ROOT.parents[2] / "dist" / "selfhosted-release-verification" / "5.0.1.38" / "bundled-selfhosted_updates" / "selfhosted_updates" / "manifest.json"


def test_profile_is_pinned_for_arm_translation() -> None:
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    assert profile["status"] == "ready-for-live-run"
    assert profile["coverage"] == "translated-arm64"
    assert profile["host"]["default_workspace_root"] == "/var/lib/amnezia-release-lab/android"
    assert profile["host"]["emulator_port"] == 5556
    assert profile["host"]["gpu_mode"] == "software"
    assert profile["sdk"]["package_revision_policy"].startswith("resolve-current-official")
    assert profile["guest"]["abi_under_test"] == "arm64-v8a"
    assert profile["guest"]["host_abi"] == "x86_64"
    assert profile["guest"]["native_bridge_required"] is True
    assert profile["guest"]["min_sdk"] == 28
    assert profile["guest"]["target_sdk"] == 36
    assert profile["guest"]["package"] == "org.amnezia.vpn"
    assert profile["artifacts"]["release_version_code"] == 2186
    assert profile["artifacts"]["previous_version_code"] == 2185
    assert re.fullmatch(r"[0-9a-f]{64}", profile["artifacts"]["release_sha256"])
    assert re.fullmatch(r"[0-9a-f]{64}", profile["artifacts"]["previous_sha256"])
    assert profile["sdk"]["command_line_tools"]["sha256"] == (
        "7ec965280a073311c339e571cd5de778b9975026cfcbe79f2b1cdcb1e15317ee"
    )


def test_driver_is_scoped_and_fail_closed() -> None:
    source = DRIVER.read_text(encoding="utf-8")
    assert "ADB_SERVER_SOCKET" in source
    assert "ANDROID_ADB_SERVER_PORT" in source
    assert 'SERIAL="${AMNEZIA_ANDROID_SERIAL:-emulator-' in source
    assert '[[ "$SERIAL" == emulator-* ]]' in source
    assert "qemu.uuid" in source
    assert "verify_network_gate" in source
    assert "run_scenario" in source
    assert "enable_consumer_fixture_network" in source
    assert "10.8.1.0/32" in source
    assert "10.0.2.2" in source
    assert "fixture-network.json" in source
    assert "rules=verified" in source
    assert "iptables -S OUTPUT" in source
    assert "ip6tables -S OUTPUT" in source
    assert "peer_ipv4" in source
    assert "allowlist=loopback,peer-only" in source
    assert "AMNEZIA_ANDROID_LAB_CONTROLLER_RECEIPT" in source
    assert '"run_id": run' in source
    assert '"artifact_sha256": cs' in source
    assert '"steps": [' in source
    assert '"device_identity": {' in source
    assert '"injected": False' in source
    assert "adbServerStarttime" in source
    assert "offlineGuestFirewall" in source
    assert "installer-smoke-pass-real-update-pending" in source
    assert "run requires baseline-apk candidate-apk baseline-manifest candidate-manifest" in source
    assert "ensure_guest_offline" in source
    assert "emulator.starttime" in source
    assert "-qemu -uuid" in source
    assert "GPU_MODE=\"${AMNEZIA_ANDROID_GPU_MODE:-software}\"" in source
    assert "-gpu \"$GPU_MODE\"" in source
    assert "getprop ro.boot.qemu.avd_name" in source
    assert "getprop ro.dalvik.vm.native.bridge" in source
    assert "libndk_translation" in source
    assert "--abi arm64-v8a" in source
    assert "adb kill-server" not in source
    assert "host_routes_or_firewall" in source
    assert "network_gate=pending" in source
    # The update scenario must enter Android's installer rather than use -r.
    update = source[source.index("test_update()") : source.index("collect()")]
    assert "ViewDownloadsActivity" in update
    assert "uiautomator" in source
    assert "input tap" in source
    assert "install -r" not in update
    assert 'expected_code="$(artifact_code release)"' in update
    assert "35.2.10" not in source
    assert "27.2.12479018" not in source
    assert "repository2-3.xml" in source
    assert "platforms;android-" in source
    assert '"checksum_algorithm": algorithm' in source
    assert '"status": "observed-after-prepare"' in source
    assert "sdkmanager-repository-checksum-plus-local-critical-file-sha256" in source
    assert "filesystem-and-host-preflight" in source
    assert "observed-ready" in source


def test_driver_has_no_shell_syntax_errors_when_bash_is_available() -> None:
    # A Windows Python process cannot pass a drive-letter path to WSL bash.
    # The same check runs natively in the Linux CI/release environment.
    if ":" in str(DRIVER):
        return
    bash = "bash"
    try:
        result = subprocess.run([bash, "-n", str(DRIVER)], capture_output=True, text=True)
    except FileNotFoundError:
        return
    assert result.returncode == 0, result.stderr


def test_readme_documents_truthful_pending_gates() -> None:
    readme = README.read_text(encoding="utf-8")
    for phrase in (
        "Native Bridge",
        "adb install -r",
        "pending",
        "system package installer",
        "host network",
    ):
        assert phrase in readme


def test_scenarios_keep_update_and_network_gates_separate() -> None:
    upgrade = json.loads(UPGRADE_SCENARIO.read_text(encoding="utf-8"))
    network = json.loads(NETWORK_SCENARIO.read_text(encoding="utf-8"))
    assert upgrade["status"] == "ready-for-live-installer-smoke"
    assert upgrade["assertions"]["baseline"]["version_code"] == 2185
    assert upgrade["assertions"]["update"]["version_code"] == 2186
    assert upgrade["assertions"]["update"]["install_mode"] == "system-package-installer-ui"
    assert "adb install -r" in upgrade["forbidden_shortcuts"]
    assert upgrade["network"]["required_for_this_scenario"] is False
    assert upgrade["real_app_server_update"] == "pending-controller-flow"
    assert upgrade["controller_receipt"]["origin"] == "guest"
    assert upgrade["controller_receipt"]["transport"] == "android-adapter"
    assert network["status"] == "pending-controller-owned-peer"
    assert network["handoff"]["marker"].endswith("network-gate.ok")
    assert "Windows host route changes" in network["prohibited"]


def test_reference_manifest_artifact_matches_pinned_receipt() -> None:
    if not REFERENCE_MANIFEST.exists():
        return
    doc = json.loads(REFERENCE_MANIFEST.read_text(encoding="utf-8"))
    encoded = doc["payload"] + "=" * (-len(doc["payload"]) % 4)
    payload = json.loads(base64.b64decode(encoded).decode("utf-8"))
    artifact = payload["platforms"]["android-arm64-v8a"]
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    assert artifact["sha256"] == profile["artifacts"]["release_sha256"]
    assert artifact["versionCode"] == profile["artifacts"]["release_version_code"]
    assert payload["version"] == profile["artifacts"]["release_version"]


def test_consumer_fixture_rejects_unsigned_manifest(tmp_path: Path) -> None:
    sys.path.insert(0, str(ROOT))
    try:
        from consumer_fixture_server import load_manifest
        unsigned = tmp_path / "manifest.json"
        unsigned.write_text(json.dumps({"payload": "only"}), encoding="utf-8")
        with pytest.raises(SystemExit):
            load_manifest(unsigned)
    finally:
        sys.path.remove(str(ROOT))
