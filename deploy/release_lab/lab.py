#!/usr/bin/env python3
"""Fail-closed controller for the disposable Amnezia release lab.

Only QEMU/QGA/QMP are used to cross the host/guest boundary.  In particular,
the controller never starts an Amnezia executable on the workstation and
never accepts a host supplied ``PASS``/receipt as guest evidence.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import errno
import functools
import hashlib
import ipaddress
import json
import math
import os
import platform
import stat
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import unquote, urlparse

try:
    from relay_smoke_controller import RelaySmokeError
except ImportError:  # pragma: no cover - package import path
    from .relay_smoke_controller import RelaySmokeError
try:
    from windows_evidence_archive import WindowsEvidenceArchiveError, archive_exact_file, validate_archive_record
except ImportError:  # pragma: no cover - package import path
    from .windows_evidence_archive import WindowsEvidenceArchiveError, archive_exact_file, validate_archive_record
try:
    from publisher_filemap import PublisherFileMapError, canonical_publisher_file_map, validate_observed_file_map
except ImportError:  # pragma: no cover - package import path
    from .publisher_filemap import PublisherFileMapError, canonical_publisher_file_map, validate_observed_file_map
try:
    from nested_cuttlefish_runner import NestedCuttlefishError, validate_app_update_receipt, validate_boot_receipt, validate_cleanup_receipt
    from headless_native_acceptance import validate_http_receipt, validate_update_receipt, validate_rollback_receipt, validate_reboot_receipt
    from linux_gui_visual_ack import validate_root_visual_ack
    from nested_cuttlefish_common_adapter import NestedCuttlefishCommonAdapter
    from nested_cuttlefish_server_fixture_adapter import canonical_android_artifact_path
    from android_visual_handshake import AndroidVisualHandshakeStore
except ImportError:  # pragma: no cover
    from .nested_cuttlefish_runner import NestedCuttlefishError, validate_app_update_receipt, validate_boot_receipt, validate_cleanup_receipt
    from .headless_native_acceptance import validate_http_receipt, validate_update_receipt, validate_rollback_receipt, validate_reboot_receipt
    from .linux_gui_visual_ack import validate_root_visual_ack
    from .nested_cuttlefish_common_adapter import NestedCuttlefishCommonAdapter
    from .nested_cuttlefish_server_fixture_adapter import canonical_android_artifact_path
    from .android_visual_handshake import AndroidVisualHandshakeStore

try:
    import pwd
except ImportError:  # pragma: no cover - Windows test host
    pwd = None
try:
    import fcntl
except ImportError:  # pragma: no cover - Windows test host
    fcntl = None
try:
    import msvcrt
except ImportError:  # pragma: no cover - Linux runtime
    msvcrt = None


SCHEMA_VERSION = 1
DEFAULT_STATE_ROOT = "/var/lib/amnezia-release-lab"
PROFILE_IDS = ("windows-x64", "android-arm64-v8a", "linux-x64-gui", "linux-headless-x64")
ALL_PROFILE_IDS = PROFILE_IDS + ("server-router",)
PROFILE_ARTIFACT_IDS = {
    "windows-x64": "windows-x64",
    "android-arm64-v8a": "android-arm64-v8a",
    "linux-x64-gui": "linux-x64",
    "linux-headless-x64": "linux-headless-x64",
}
HOST_EXECUTABLES = frozenset(("qemu-system-x86_64", "qemu-img", "swtpm", "bash", "openssl"))
HOST_EXECUTABLE_PATHS = {name: f"/usr/bin/{name}" for name in HOST_EXECUTABLES}
RELEASE_PLATFORM_IDS = frozenset(("windows-x64", "android-arm64-v8a", "linux-x64", "linux-headless-x64"))
RECEIPT_REQUIRED = frozenset(("schema", "run_id", "profile", "artifact", "artifact_sha256", "artifact_size", "artifact_role", "artifact_source", "baseline_version", "candidate_version", "guest_marker", "transport", "steps", "observed_at"))
CONSUMER_FIXTURE_GUEST_PORT = 17865
HYPERV_TRANSPORT = "hyperv-powershell-direct"
HYPERV_ADAPTER_RELATIVE = "deploy/release_lab/windows_host/hyperv_adapter.ps1"
HYPERV_UI_HELPER_RELATIVE = "deploy/release_lab/windows_host/hyperv_ui_helper.ps1"
HYPERV_LAUNCHER_RELATIVE = "deploy/release_lab/windows_host/hyperv_interactive_launcher.ps1"
HYPERV_PROFILE_RELATIVE = "deploy/release_lab/windows_host/profile.json"
HYPERV_POWERSHELL_WSL = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
HYPERV_PARENT_ROOT_WINDOWS = "C:/ProgramData/AmneziaReleaseLab/hyperv/windows-x64"
HYPERV_RUNS_ROOT_WINDOWS = "C:/ProgramData/AmneziaReleaseLab/hyperv/runs"
HYPERV_CASE_IDS = ("thin-clean", "thin-upgrade", "thin-reinstall", "outer-clean", "outer-upgrade", "outer-reinstall", "publisher-clean")
ANDROID_WINDOWS_ADAPTER_RELATIVE = "deploy/release_lab/android/android-lab-windows.ps1"
SEMANTIC_HELPER_RELATIVES = (
    "deploy/release_lab/lab.py",
    "deploy/release_lab/nested_cuttlefish_runner.py",
    "deploy/release_lab/nested_cuttlefish_qga_bridge.py",
    "deploy/release_lab/nested_cuttlefish_app_executor.py",
    "deploy/release_lab/android_visual_handshake.py",
    "deploy/release_lab/nested_cuttlefish_server_fixture_adapter.py",
    "deploy/release_lab/nested_cuttlefish_common_adapter.py",
    "deploy/release_lab/nested_cuttlefish_private_link.py",
    "deploy/release_lab/nested_cuttlefish_host_dependencies.py",
    "deploy/release_lab/nested_cuttlefish_wayland_dependency.py",
    "deploy/release_lab/android/consumer_fixture_server.py",
    "deploy/release_lab/headless_native_acceptance.py",
    "deploy/release_lab/headless_native_qga_adapter.py",
    "deploy/release_lab/headless_native_e2e_driver.py",
    "deploy/release_lab/headless_native_fixture_server.py",
    "deploy/release_lab/headless_native_http_fixture.py",
    "deploy/release_lab/headless_native_reboot_collector.py",
    "deploy/release_lab/headless_preexisting_fixture.py",
    "deploy/release_lab/headless_preexisting_fixture_guest.py",
    "deploy/release_lab/guest_helpers/linux_gui_window_evidence.py",
    "deploy/release_lab/linux_gui_visual_ack.py",
)
ANDROID_VULKAN_RELATIVES = {
    "bundle": "dist/release-lab-fixtures/android-cvd-vulkan-noble-amd64-20260913.tar.gz",
    "manifest": "dist/release-lab-fixtures/android-cvd-vulkan-noble-amd64-20260913/bundle-manifest.json",
    "verifier": "dist/release-lab-fixtures/android-cvd-vulkan-noble-amd64-20260913/verifier-receipt.json",
    "deb": "dist/release-lab-fixtures/android-cvd-vulkan-noble-amd64-20260913/libvulkan1_1.3.275.0-1build1_amd64.deb",
}
ANDROID_WAYLAND_RELATIVES = {
    "verifier": "dist/release-lab-fixtures/android-cvd-host-dependencies-noble-amd64-20260913/wayland-verifier-receipt.json",
    "supplement": "dist/release-lab-fixtures/android-cvd-host-dependencies-noble-amd64-20260913/android-cvd-wayland-supplement-3b2a227c.tar",
}
ANDROID_HOST_DEPENDENCY_RELATIVES = {
    name: f"dist/release-lab-fixtures/android-cvd-host-dependencies-noble-amd64-20260913/{name}"
    for name in (
        "bundle-manifest.json", "verifier-receipt.json", "ubuntu-keyring.gpg",
        "noble-InRelease", "noble-Packages", "noble-updates-InRelease", "noble-updates-Packages",
        "noble-security-InRelease", "noble-security-Packages", "google-keyring.gpg",
        "google-cuttlefish-InRelease", "google-cuttlefish-Packages",
    )
}


class LabError(RuntimeError):
    """An expected fail-closed lab error."""


def android_attempt_matches_fixture(
    attempt: Mapping[str, Any], fixture: Mapping[str, Any], run_id: str, profile_id: str
) -> bool:
    """Require every server fixture identity field to match the adapter attempt."""
    nonce = str(attempt.get("nonce") or "")
    return bool(nonce) and fixture.get("fixture_bind") == "127.0.0.1" and attempt.get("run_id") == run_id and attempt.get("profile") == profile_id and (
        attempt.get("guest_endpoint") == fixture.get("guest_endpoint")
        and attempt.get("nonce") == fixture.get("attempt_nonce")
        and attempt.get("fixture_host_port") == fixture.get("host_port")
        and attempt.get("fixture_guest_port") == fixture.get("guest_port")
        and attempt.get("fixture_bind") == fixture.get("fixture_bind")
    )


def validate_publication_evidence(
    evidence: Mapping[str, Any], run: Mapping[str, Any], root: Path
) -> None:
    """Validate immutable self-hosted publication proof before a release gate."""
    if evidence.get("schema") != 1 or evidence.get("controller_created") is not True or evidence.get("live") is not True or evidence.get("run_id") != run.get("run_id") or not re.fullmatch(r"[0-9a-f]{48}", str(evidence.get("attempt_nonce", ""))):
        raise LabError("publication evidence identity is invalid")
    if evidence.get("case_id") not in HYPERV_CASE_IDS:
        raise LabError("publication evidence case is not an allowlisted Hyper-V case")
    outer = run.get("outer_artifact") or {}
    manifest = run.get("manifest") or {}
    if evidence.get("outer_artifact_sha256") != outer.get("sha256") or evidence.get("manifest_sha256") != manifest.get("sha256"):
        raise LabError("publication evidence does not bind the planned outer artifact and manifest")
    child = evidence.get("windows_child") or {}
    server = evidence.get("server") or {}
    for label, item, keys in (("Windows child", child, ("vm_id", "parent_sha256", "process_pid", "process_uuid", "marker")), ("server", server, ("uuid", "qmp_socket", "qga_socket"))):
        if not isinstance(item, Mapping) or any(not item.get(key) for key in keys):
            raise LabError(f"publication evidence lacks {label} identity")
    if not isinstance(child.get("parent_sha256"), str) or not re.fullmatch(r"[0-9a-fA-F]{64}", child["parent_sha256"]):
        raise LabError("publication evidence parent hash is invalid")
    if child.get("marker") != f"amnezia-release-lab:{run.get('run_id')}:windows-x64" or not isinstance(child.get("process_pid"), int) or child.get("process_pid", 0) <= 0 or not re.fullmatch(r"[0-9a-fA-F-]{36}", str(child.get("process_uuid"))):
        raise LabError("publication evidence Windows child marker/process identity is invalid")
    profile = (run.get("profiles") or {}).get("windows-x64") or {}
    cases = profile.get("hyperv_cases") or {}
    case = cases.get(evidence.get("case_id")) if isinstance(cases, Mapping) else None
    if not isinstance(case, Mapping) or case.get("vm_id") != child.get("vm_id") or case.get("parent_sha256") != child.get("parent_sha256") or case.get("state") != "reset":
        raise LabError("publication evidence child does not match the reset controller case")
    observation = run.get("server_observation")
    if not isinstance(observation, Mapping) or observation.get("uuid") != server.get("uuid") or observation.get("qmp_socket") != server.get("qmp_socket") or observation.get("qga_socket") != server.get("qga_socket") or observation.get("qmp_observed") is not True or observation.get("qga_observed") is not True:
        raise LabError("publication evidence server does not match live controller observation")
    acks = evidence.get("client_acknowledgements")
    if not isinstance(acks, Mapping) or any(
        not isinstance(acks.get(phase), Mapping)
        or acks[phase].get("passed") is not True
        or acks[phase].get("run_id") != run.get("run_id")
        or acks[phase].get("origin") != "guest"
        or acks[phase].get("transport") not in {"qga", HYPERV_TRANSPORT}
        for phase in ("prepare", "commit", "finalize")
    ):
        raise LabError("publication evidence lacks complete client acknowledgements")
    phase_names = {"prepare": "prepared", "commit": "committed", "finalize": "finalized"}
    phase_run_ids = {acks[phase].get("publication_run_id") for phase in phase_names}
    if any(not re.fullmatch(r"[0-9a-f]{48}", str(acks[phase].get("publication_run_id", ""))) for phase in phase_names):
        raise LabError("publication acknowledgement run id is not canonical")
    if len(phase_run_ids) != 1 or any(acks[phase].get("phase") != expected_phase or not isinstance(acks[phase].get("durable_record"), Mapping) or acks[phase]["durable_record"].get("phase") != expected_phase or acks[phase]["durable_record"].get("publication_run_id") != acks[phase].get("publication_run_id") or acks[phase]["durable_record"].get("candidate") != manifest.get("sha256") for phase, expected_phase in phase_names.items()):
        raise LabError("publication acknowledgements are not backed by exact durable server phase records")
    http = evidence.get("http_readback")
    if not isinstance(http, Mapping) or http.get("manifest_sha256") != manifest.get("sha256") or http.get("manifest_bytes") != manifest.get("size"):
        raise LabError("publication HTTP manifest readback is incomplete")
    try:
        manifest_path = Path(str(manifest.get("path", "")))
        if not manifest_path.is_file() or manifest_path.is_symlink():
            raise PublisherFileMapError("frozen publication manifest is not a regular file")
        manifest_bytes = manifest_path.read_bytes()
        if len(manifest_bytes) != manifest.get("size") or hashlib.sha256(manifest_bytes).hexdigest() != manifest.get("sha256"):
            raise PublisherFileMapError("frozen publication manifest bytes changed")
        envelope = json.loads(manifest_bytes.decode("utf-8"))
        encoded = str(envelope["payload"])
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8"))
        validate_observed_file_map(canonical_publisher_file_map(run, payload), http.get("artifacts"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, ValueError, TypeError, PublisherFileMapError) as exc:
        raise LabError(f"publication HTTP artifact readback is invalid: {exc}") from exc
    raw_sources = evidence.get("raw_sources")
    if not isinstance(raw_sources, Mapping) or any(
        not isinstance(raw_sources.get(label), Mapping)
        or raw_sources[label].get("origin") != "guest"
        or not re.fullmatch(r"[0-9a-fA-F]{64}", str(raw_sources[label].get("sha256", "")))
        or not isinstance(raw_sources[label].get("size"), int)
        or raw_sources[label].get("size", -1) < 0
        for label in ("client", "server")
    ):
        raise LabError("publication raw guest source hashes are incomplete")
    for label in ("client", "server"):
        source = raw_sources[label]
        archive_path = source.get("archive_path")
        if not isinstance(archive_path, str):
            raise LabError(f"publication {label} raw source archive path is missing")
        source_file = ensure_owned_child(root, Path(archive_path), f"publication {label} raw source")
        observed_sha, observed_size = sha256_file(source_file)
        if (observed_sha, observed_size) != (source.get("sha256"), source.get("size")):
            raise LabError(f"publication {label} raw source hash does not verify")
        try:
            raw_value = json.loads(source_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LabError(f"publication {label} raw source is not structured JSON") from exc
        if not isinstance(raw_value, Mapping) or raw_value.get("origin") != "guest" or raw_value.get("run_id") != run.get("run_id") or raw_value.get("case_id") != evidence.get("case_id") or raw_value.get("attempt_nonce") != evidence.get("attempt_nonce"):
            raise LabError(f"publication {label} raw source identity is not bound to this attempt")
        if label == "client":
            if raw_value.get("transport") != HYPERV_TRANSPORT or raw_value.get("vm_id") != child.get("vm_id") or not isinstance(raw_value.get("raw"), Mapping) or raw_value["raw"].get("passed") is not True or not isinstance(raw_value["raw"].get("raw"), Mapping) or raw_value["raw"]["raw"].get("exit_code") != 0:
                raise LabError("publication client raw source is not a passed guest publisher result")
        elif raw_value.get("transport") != "qga" or raw_value.get("server_uuid") != server.get("uuid") or raw_value.get("qga_socket") != server.get("qga_socket") or raw_value.get("manifest_sha256") != manifest.get("sha256") or raw_value.get("metadata_sha256") != acks["commit"]["durable_record"].get("metadata_sha256") or raw_value.get("attempt_marker") != {"schema": 1, "run_id": run.get("run_id"), "case_id": evidence.get("case_id"), "attempt_nonce": evidence.get("attempt_nonce"), "manifest_sha256": manifest.get("sha256")} or not isinstance(raw_value.get("raw"), Mapping):
            raise LabError("publication server raw source is not bound to the live server readback")
        elif any(str(acks[phase]["durable_record"].get("record", "")) not in str(raw_value["raw"].get("stdout", "")) for phase in phase_names):
            raise LabError("publication server raw source does not contain the acknowledged durable history records")
    cleanup = evidence.get("cleanup")
    if not isinstance(cleanup, Mapping) or any(cleanup.get(key) is not True for key in ("child_reset", "server_reset", "relays_stopped", "relay_registry_unregistered", "ephemeral_key_removed")):
        raise LabError("publication owned cleanup is incomplete")
    if cleanup.get("host_network_mutation") is not False:
        raise LabError("publication evidence reports host network mutation")
    archive = evidence.get("archive")
    if not isinstance(archive, Mapping) or archive.get("origin") != "controller" or archive.get("immutable") is not True:
        raise LabError("publication evidence archive is not immutable guest-origin proof")
    archive_path = archive.get("path")
    if not isinstance(archive_path, str):
        raise LabError("publication evidence archive path is missing")
    archive_file = ensure_owned_child(root, Path(archive_path), "publication evidence archive")
    if not archive_file.is_file() or not re.fullmatch(r"[0-9a-fA-F]{64}", str(archive.get("sha256", ""))) or archive.get("sha256") != sha256_file(archive_file)[0]:
        raise LabError("publication evidence archive hash does not verify")
    try:
        archive_record = json.loads(archive_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LabError("publication evidence archive is invalid") from exc
    if not isinstance(archive_record, Mapping) or archive_record.get("run_id") != run.get("run_id") or archive_record.get("controller_created") is not True:
        raise LabError("publication evidence archive is not controller-created")
    core = {key: value for key, value in evidence.items() if key != "archive"}
    core_sha = hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    if archive_record.get("evidence_sha256") != core_sha:
        raise LabError("publication evidence archive does not bind the controller evidence")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def mutation_operation(method):
    """Hold the state-root mutation lock across a direct API lifecycle."""
    @functools.wraps(method)
    def guarded(self, *args, **kwargs):
        with self.mutation_session(method.__name__):
            return method(self, *args, **kwargs)
    return guarded


def artifact_id_for_profile(profile_id: str) -> str:
    """Map a guest profile to the signed platform artifact it consumes."""
    try:
        return PROFILE_ARTIFACT_IDS[profile_id]
    except KeyError as exc:
        raise LabError(f"profile has no release artifact mapping: {profile_id}") from exc


def expected_artifact_role(action: str) -> str:
    """Return the role represented by one guest runner action."""
    return "baseline" if action == "reinstall" else "candidate"


def artifact_role_for_stage(stage_name: str) -> str:
    """Derive receipt role from the staged artifact identity in a matrix."""
    return "baseline" if stage_name.startswith("baseline-") else "candidate"


def windows_case_specs(planned_run: Mapping[str, Any]) -> dict[str, list[tuple[str, dict[str, Any], str, str]]]:
    thin = planned_run["artifacts"]["windows-x64"]
    baseline_thin = planned_run["baseline_artifacts"]["windows-x64"]
    outer = planned_run["outer_artifact"]
    baseline_outer = planned_run["baseline_outer_artifact"]
    candidate_version = str(planned_run["candidate_version"])
    baseline_version = str(planned_run["baseline_version"])
    return {
        "thin-clean": [("candidate-thin", thin, "reinstall", candidate_version)],
        "thin-upgrade": [("baseline-thin", baseline_thin, "reinstall", baseline_version), ("candidate-thin", thin, "update", candidate_version)],
        "thin-reinstall": [("candidate-thin", thin, "reinstall", candidate_version), ("candidate-thin", thin, "reinstall", candidate_version)],
        "outer-clean": [("candidate-outer", outer, "reinstall", candidate_version)],
        "outer-upgrade": [("baseline-outer", baseline_outer, "reinstall", baseline_version), ("candidate-outer", outer, "update", candidate_version)],
        "outer-reinstall": [("candidate-outer", outer, "reinstall", candidate_version), ("candidate-outer", outer, "reinstall", candidate_version)],
    }


def validate_step_assertion(
    assertion: Mapping[str, Any], *, action: str, profile_id: str,
    artifact: Mapping[str, Any], expected_version: str,
) -> None:
    """Validate the runner's final assertion without imposing new raw fields.

    Older runners expose ``installed_version`` and hash fields under slightly
    different names.  We validate each field when present, while requiring
    the final version for installer/health actions where it is the safety
    boundary.
    """
    if assertion.get("passed") is not True:
        raise LabError(f"guest step {action} assertion did not pass")
    if action != "probe":
        installed = assertion.get("installed_version")
        if not isinstance(installed, str) or not installed:
            raise LabError(f"guest step {action} assertion lacks the installed version")
        if str(installed) != str(expected_version):
            raise LabError(f"guest step {action} installed version differs from expected {expected_version}")
    if action in {"reinstall", "update", "install"} and not any(assertion.get(key) for key in ("artifact_sha256", "artifact_sha256_before", "artifact_sha256_after", "expected_sha256")):
        raise LabError(f"guest step {action} assertion lacks an artifact hash")
    for key in ("artifact_sha256", "artifact_sha256_after", "expected_sha256"):
        value = assertion.get(key)
        if value is not None and str(value).lower() != str(artifact.get("sha256", "")).lower():
            raise LabError(f"guest step {action} {key} differs from the planned artifact")
    asserted_profile = assertion.get("profile")
    if asserted_profile is not None and asserted_profile != profile_id:
        raise LabError(f"guest step {action} profile assertion differs from {profile_id}")


def free_loopback_port() -> int:
    """Reserve a candidate loopback port without changing host networking."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def json_dump(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def immutable_json_dump(path: Path, value: Mapping[str, Any]) -> None:
    """Create a private evidence file once; never overwrite a receipt archive."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError:
        return
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while archiving guest evidence metadata")
            view = view[written:]
        os.fsync(fd)
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def immutable_bytes_dump(path: Path, payload: bytes) -> None:
    """Create a private raw-log archive once; never replace guest evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError:
        return
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while archiving guest evidence")
            view = view[written:]
        os.fsync(fd)
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def state_root_from(value: str | None) -> Path:
    raw = value or os.environ.get("AMNEZIA_RELEASE_LAB_STATE_ROOT") or DEFAULT_STATE_ROOT
    path = Path(raw)
    # `/var/lib/...` is the canonical path when this script is invoked through
    # WSL.  pathlib on Windows does not consider a POSIX path absolute, but it
    # is still a valid portable input and resolves to the WSL-mounted root
    # when the command is actually run there.
    if not path.is_absolute() and not raw.startswith("/"):
        raise LabError("state root must be an absolute path")
    cursor = path
    while True:
        if cursor.is_symlink():
            raise LabError(f"state root path is symlinked: {cursor}")
        if cursor == cursor.parent:
            break
        cursor = cursor.parent
    return Path(os.path.abspath(str(path)))


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def validate_semantic_helper_records(records: object) -> None:
    if not isinstance(records, Mapping) or set(records) != set(SEMANTIC_HELPER_RELATIVES):
        raise LabError("semantic helper closure is missing or noncanonical")
    for relative, planned in records.items():
        expected_path = (repo_root() / relative).resolve()
        if not isinstance(planned, Mapping) or Path(str(planned.get("path", ""))).resolve() != expected_path:
            raise LabError(f"semantic helper path changed after plan: {relative}")
        current = artifact_record(expected_path)
        if (current["sha256"], current["size"]) != (planned.get("sha256"), planned.get("size")):
            raise LabError(f"semantic helper changed after plan: {relative}")

def validate_android_vulkan_records(records: object) -> None:
    if not isinstance(records,Mapping) or set(records)!=set(ANDROID_VULKAN_RELATIVES):
        raise LabError("Android Vulkan dependency closure is missing or noncanonical")
    for label,relative in ANDROID_VULKAN_RELATIVES.items():
        expected=(repo_root()/relative).resolve(); planned=records[label]
        if not isinstance(planned,Mapping) or Path(str(planned.get("path",""))).resolve()!=expected:
            raise LabError(f"Android Vulkan dependency path changed: {label}")
        current=artifact_record(expected)
        if (current["sha256"],current["size"])!=(planned.get("sha256"),planned.get("size")):
            raise LabError(f"Android Vulkan dependency changed after plan: {label}")

def validate_android_host_dependency_records(records: object) -> None:
    if not isinstance(records,Mapping) or set(records)!=set(ANDROID_HOST_DEPENDENCY_RELATIVES):
        raise LabError("Android host dependency verifier closure is missing or noncanonical")
    for label,relative in ANDROID_HOST_DEPENDENCY_RELATIVES.items():
        expected=(repo_root()/relative).resolve();planned=records[label]
        if not isinstance(planned,Mapping) or Path(str(planned.get("path",""))).resolve()!=expected:
            raise LabError(f"Android host dependency path changed: {label}")
        current=artifact_record(expected)
        if (current["sha256"],current["size"])!=(planned.get("sha256"),planned.get("size")):
            raise LabError(f"Android host dependency changed after plan: {label}")

def validate_android_wayland_records(records: object) -> None:
    if not isinstance(records,Mapping) or set(records)!=set(ANDROID_WAYLAND_RELATIVES):raise LabError("Android Wayland closure missing")
    for label,relative in ANDROID_WAYLAND_RELATIVES.items():
        expected=(repo_root()/relative).resolve();planned=records[label]
        if not isinstance(planned,Mapping) or Path(str(planned.get("path",""))).resolve()!=expected:raise LabError("Android Wayland path changed")
        current=artifact_record(expected)
        if (current["sha256"],current["size"])!=(planned.get("sha256"),planned.get("size")):raise LabError("Android Wayland bytes changed")


def windows_path_for_wsl(path: Path) -> str:
    """Convert a /mnt/<drive> path to a stable forward-slash Windows path."""
    raw = Path(os.path.abspath(str(path))).as_posix()
    native = re.fullmatch(r"([A-Za-z]):/(.+)", raw)
    if native:
        return f"{native.group(1).upper()}:/{native.group(2)}"
    match = re.fullmatch(r"/mnt/([A-Za-z])/(.+)", raw)
    if not match:
        raise LabError(f"Hyper-V bridge requires an artifact/script visible through /mnt/<drive>: {path}")
    return f"{match.group(1).upper()}:/{match.group(2)}"


def wsl_path_for_windows_host(raw: str) -> Path:
    """Map an absolute Windows host path returned by the Hyper-V adapter into WSL."""
    match = re.fullmatch(r"([A-Za-z]):[\\/](.+)", str(raw))
    if not match:
        raise LabError(f"Hyper-V adapter returned a non-absolute Windows path: {raw}")
    tail = match.group(2).replace("\\", "/")
    if any(part in ("", ".", "..") for part in tail.split("/")):
        raise LabError("Hyper-V adapter returned a non-canonical Windows path")
    return Path(f"/mnt/{match.group(1).lower()}/{tail}")


def validate_hyperv_interactive_archives(root: Path, receipt: Mapping[str, Any]) -> None:
    attempt = receipt.get("archive_attempt_nonce")
    app_window = receipt.get("installed_app_window")
    hyperv_ui = receipt.get("hyperv_ui")
    if not isinstance(attempt, str) or not isinstance(app_window, Mapping) or not isinstance(hyperv_ui, Mapping):
        raise LabError("Hyper-V interactive durable archive metadata is missing")
    vm_id = str(app_window.get("vm_id") or "")
    app_screenshot = app_window.get("screenshot")
    ui_archive = hyperv_ui.get("screenshot_archive")
    app_archive = app_screenshot.get("archive") if isinstance(app_screenshot, Mapping) else None
    if not isinstance(ui_archive, Mapping) or not isinstance(app_archive, Mapping):
        raise LabError("Hyper-V interactive durable screenshot records are missing")
    try:
        validate_archive_record(root, ui_archive, kind="uac", vm_id=vm_id, case_id="outer-interactive", attempt_nonce=attempt)
        validate_archive_record(root, app_archive, kind="app-window", vm_id=vm_id, case_id="outer-interactive", attempt_nonce=attempt)
    except WindowsEvidenceArchiveError as exc:
        raise LabError(f"Hyper-V interactive durable archive validation failed: {exc}") from exc


def hyperv_adapter_source() -> Path:
    path = (repo_root() / HYPERV_ADAPTER_RELATIVE).resolve()
    try:
        path.relative_to(repo_root())
    except ValueError as exc:
        raise LabError("Hyper-V adapter escaped repository") from exc
    if not path.is_file() or path.is_symlink():
        raise LabError(f"Hyper-V adapter is missing or symlinked: {path}")
    return path


def hyperv_profile_source() -> Path:
    path = (repo_root() / HYPERV_PROFILE_RELATIVE).resolve()
    if not path.is_file() or path.is_symlink():
        raise LabError(f"Hyper-V profile is missing or symlinked: {path}")
    return path


def hyperv_ui_helper_source() -> Path:
    path = (repo_root() / HYPERV_UI_HELPER_RELATIVE).resolve()
    if not path.is_file() or path.is_symlink():
        raise LabError(f"Hyper-V UI helper is missing or symlinked: {path}")
    return path


def hyperv_launcher_source() -> Path:
    path = (repo_root() / HYPERV_LAUNCHER_RELATIVE).resolve()
    if not path.is_file() or path.is_symlink():
        raise LabError(f"Hyper-V interactive launcher is missing or symlinked: {path}")
    return path


def profiles_root() -> Path:
    return Path(__file__).resolve().parent / "profiles"


def load_profiles() -> dict[str, dict[str, Any]]:
    profiles: dict[str, dict[str, Any]] = {}
    for profile_id in ALL_PROFILE_IDS:
        path = profiles_root() / f"{profile_id}.json"
        if not path.is_file():
            raise LabError(f"missing lab profile: {path}")
        try:
            profile = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LabError(f"invalid lab profile {path}: {exc}") from exc
        validate_profile(profile, path)
        profiles[profile_id] = profile
    return profiles


def validate_profile(profile: Mapping[str, Any], path: Path | None = None) -> None:
    label = str(path or profile.get("id", "profile"))
    required = ("id", "platform", "base_image", "guest_agent", "steps", "guest_executables")
    missing = [key for key in required if key not in profile]
    if missing:
        raise LabError(f"{label}: missing fields: {', '.join(missing)}")
    if profile["id"] not in ALL_PROFILE_IDS:
        raise LabError(f"{label}: unsupported profile id {profile['id']!r}")
    if path is not None and path.stem != profile["id"]:
        raise LabError(f"{label}: profile filename does not match id {profile['id']!r}")
    backend = profile.get("backend")
    if backend not in ("qemu-windows", "qemu-linux", "android-adapter"):
        raise LabError(f"{label}: unsupported backend {backend!r}")
    if backend == "android-adapter":
        script = profile.get("adapter_script")
        if not isinstance(script, str) or Path(script).name != "android-lab.sh":
            raise LabError(f"{label}: Android adapter script is not pinned")
        if profile["guest_agent"] != "adapter":
            raise LabError(f"{label}: Android profile must use adapter transport")
    elif profile["guest_agent"] != "qga":
        raise LabError(f"{label}: QEMU profiles must use QGA guest transport")
    elif not isinstance(profile.get("golden_readiness"), str):
        raise LabError(f"{label}: QEMU profile must name a sealed golden readiness receipt")
    if profile.get("id") == "windows-x64" and (not isinstance(profile.get("ovmf_vars_golden"), str) or not isinstance(profile.get("tpm_state_golden"), str) or profile.get("tpm_state_policy") != "sealed-copy-only"):
        raise LabError(f"{label}: Windows profile must use sealed golden OVMF vars and TPM state")
    if profile.get("consumer_fixture") is True:
        if profile.get("id") != "server-router" or profile.get("fixture_guest_http_port") != CONSUMER_FIXTURE_GUEST_PORT or profile.get("fixture_host_bind") != "127.0.0.1" or profile.get("fixture_network") != "qemu-user-restrict-hostfwd-only":
            raise LabError(f"{label}: consumer fixture is only allowed on the restricted server-router lane")
    if not isinstance(profile["steps"], list) or not profile["steps"]:
        raise LabError(f"{label}: steps must be a non-empty list")
    if not isinstance(profile["guest_executables"], list) or not profile["guest_executables"]:
        raise LabError(f"{label}: guest_executables must be a non-empty list")
    allowed = set(profile["guest_executables"])
    for index, step in enumerate(profile["steps"]):
        if not isinstance(step, dict) or not isinstance(step.get("id"), str):
            raise LabError(f"{label}: step {index} has no id")
        if step.get("action") not in ("probe", "reinstall", "update", "service-health"):
            raise LabError(f"{label}: step {step.get('id')!r} has unsupported action")
        executable = step.get("executable")
        windows_guest_path = isinstance(executable, str) and re.fullmatch(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|]+\\)*[^\\/:*?\"<>|]+", executable or "")
        linux_guest_path = isinstance(executable, str) and executable.startswith("/")
        if not isinstance(executable, str) or executable not in allowed or not (linux_guest_path or (backend == "qemu-windows" and windows_guest_path)):
            raise LabError(f"{label}: step {step.get('id')!r} executable is outside guest allowlist")
        if not isinstance(step.get("args", []), list) or not all(isinstance(arg, str) for arg in step.get("args", [])):
            raise LabError(f"{label}: step {step.get('id')!r} args must be a string list")


def ensure_owned_child(root: Path, child: Path, kind: str) -> Path:
    """Resolve a path and prove it remains in the controller-owned root."""
    root = Path(os.path.abspath(str(root)))
    child = Path(os.path.abspath(str(child)))
    try:
        child.relative_to(root)
    except ValueError as exc:
        raise LabError(f"{kind} is outside lab state root: {child}") from exc
    if child == root:
        raise LabError(f"{kind} cannot be the state root")
    current = root
    for part in child.relative_to(root).parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise LabError(f"{kind} path contains a symlink: {current}")
    return child


def assert_lab_identity(root: Path) -> None:
    if not hasattr(os, "geteuid") or pwd is None:
        raise LabError("release lab must run inside Linux WSL as amnezia-lab")
    if os.geteuid() == 0:
        raise LabError("release lab refuses to run as root")
    try:
        username = pwd.getpwuid(os.geteuid()).pw_name
    except KeyError as exc:
        raise LabError("release lab effective UID has no passwd entry") from exc
    if username != "amnezia-lab":
        raise LabError(f"release lab must run as amnezia-lab, got {username}")
    if not root.is_dir() or root.is_symlink():
        raise LabError(f"owned lab state root is missing or symlinked: {root}")
    marker = root / ".amnezia-lab-root"
    if not marker.is_file() or marker.is_symlink():
        raise LabError("owned lab state root marker is missing or symlinked")
    marker_stat = marker.stat()
    if marker_stat.st_uid != os.geteuid() or stat.S_IMODE(marker_stat.st_mode) & 0o022:
        raise LabError("lab state root marker is not owned by amnezia-lab with private permissions")
    st = root.stat()
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o022:
        raise LabError("lab state root is not owned by amnezia-lab with private permissions")
    current = root
    for parent in reversed(root.parents):
        if parent == parent.parent:
            break
        if current.exists() and current.is_symlink():
            raise LabError(f"lab state parent is symlinked: {current}")
        current = parent


def sha256_file(path: Path) -> tuple[str, int]:
    path = Path(os.path.abspath(str(path)))
    if path.is_symlink():
        raise LabError(f"artifact is a symlink: {path}")
    if not path.is_file():
        raise LabError(f"artifact does not exist: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def sha256_tree(path: Path) -> str:
    if not path.is_dir():
        raise LabError(f"TPM state is not a directory: {path}")
    digest = hashlib.sha256()
    for item in sorted((child for child in path.rglob("*") if child.is_file()), key=lambda value: value.relative_to(path).as_posix()):
        relative = item.relative_to(path).as_posix().encode("utf-8")
        file_digest, size = sha256_file(item)
        digest.update(relative + b"\0" + str(size).encode("ascii") + b"\0" + file_digest.encode("ascii") + b"\n")
    return digest.hexdigest()


def artifact_record(path: Path) -> dict[str, Any]:
    path = Path(os.path.abspath(str(path)))
    digest, size = sha256_file(path)
    return {"path": str(path), "sha256": digest, "size": size}


def validate_signed_manifest(path: Path, public_key: Path, *, version: str, artifacts: Mapping[str, Mapping[str, Any]]) -> None:
    if not path.is_file() or path.is_symlink() or not public_key.is_file() or public_key.is_symlink():
        raise LabError("signed manifest/public key must be regular files")
    try:
        sys.path.insert(0, str(repo_root() / "deploy" / "selfhosted_updates"))
        import make_manifest  # type: ignore
        payload, payload_bytes, signature_b64 = make_manifest.decode_manifest_envelope(path.read_bytes())
    except (SystemExit, ValueError, OSError, json.JSONDecodeError) as exc:
        raise LabError(f"signed manifest envelope is invalid: {exc}") from exc
    finally:
        try:
            sys.path.remove(str(repo_root() / "deploy" / "selfhosted_updates"))
        except ValueError:
            pass
    if payload.get("version") != version or payload.get("autoInstall") is not True:
        raise LabError("signed manifest version or autoInstall does not match candidate")
    platforms = payload.get("platforms")
    if not isinstance(platforms, dict) or set(platforms) != set(artifacts):
        raise LabError("signed manifest platform set does not exactly match planned candidate artifacts")
    for platform_id, planned in artifacts.items():
        item = platforms.get(platform_id)
        if not isinstance(item, dict) or item.get("openExternal") is True or item.get("sha256") != planned.get("sha256") or item.get("size") != planned.get("size") or item.get("autoInstall") is not True:
            raise LabError(f"signed manifest metadata does not match candidate artifact {platform_id}")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise LabError("signed manifest signature is not valid base64") from exc
    with tempfile.TemporaryDirectory() as tmp:
        payload_file = Path(tmp) / "payload.json"; sig_file = Path(tmp) / "payload.sig"
        payload_file.write_bytes(payload_bytes); sig_file.write_bytes(signature)
        result = subprocess.run([resolve_host_executable("openssl"), "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public_key), "-in", str(payload_file), "-sigfile", str(sig_file)], shell=False, text=True, capture_output=True)
        if result.returncode != 0:
            raise LabError(f"signed manifest Ed25519 verification failed: {result.stderr[-500:]}")


def headless_runner_inputs(manifest_path: Path, public_key_path: Path, receipt_path: Path, artifact: Mapping[str, Any], expected_version: str) -> dict[str, str]:
    if not manifest_path.is_file() or manifest_path.is_symlink() or not public_key_path.is_file() or public_key_path.is_symlink() or not receipt_path.is_file() or receipt_path.is_symlink():
        raise LabError("headless trust inputs must be regular files")
    try:
        sys.path.insert(0, str(repo_root() / "deploy" / "selfhosted_updates"))
        import make_manifest  # type: ignore
        payload, _, _ = make_manifest.decode_manifest_envelope(manifest_path.read_bytes())
    except (SystemExit, ValueError, OSError, json.JSONDecodeError) as exc:
        raise LabError(f"headless signed manifest is invalid: {exc}") from exc
    finally:
        try:
            sys.path.remove(str(repo_root() / "deploy" / "selfhosted_updates"))
        except ValueError:
            pass
    provisioning = payload.get("headlessProvisioning")
    platform_item = payload.get("platforms", {}).get("linux-headless-x64") if isinstance(payload.get("platforms"), dict) else None
    if payload.get("version") != expected_version or payload.get("autoInstall") is not True or not isinstance(provisioning, dict) or not isinstance(platform_item, dict):
        raise LabError("headless signed manifest version or platform contract is invalid")
    if platform_item.get("sha256") != artifact.get("sha256") or platform_item.get("size") != artifact.get("size") or platform_item.get("autoInstall") is not True:
        raise LabError("headless signed manifest artifact metadata differs from planned artifact")
    parsed_archive = urlparse(str(provisioning.get("url", "")))
    decoded_archive = unquote(parsed_archive.path)
    relative_archive = PurePosixPath(decoded_archive)
    if (parsed_archive.scheme or parsed_archive.netloc or parsed_archive.params or parsed_archive.query or parsed_archive.fragment
            or relative_archive.is_absolute() or not relative_archive.parts
            or any(part in ("", ".", "..") for part in relative_archive.parts)):
        raise LabError("headless provisioning URL is not a safe relative manifest path")
    manifest_root = manifest_path.parent.resolve()
    archive_path = manifest_root.joinpath(*relative_archive.parts).resolve()
    try:
        archive_path.relative_to(manifest_root)
    except ValueError as exc:
        raise LabError("headless provisioning archive escaped the signed manifest tree") from exc
    if not archive_path.is_file() or archive_path.is_symlink():
        raise LabError("headless provisioning archive is missing or symlinked")
    archive = artifact_record(archive_path)
    if archive["sha256"] != provisioning.get("sha256") or archive["size"] != provisioning.get("size"):
        raise LabError("headless provisioning archive differs from signed manifest")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LabError(f"headless verified receipt is invalid: {exc}") from exc
    manifest_sha, _ = sha256_file(manifest_path)
    public_key_sha, _ = sha256_file(public_key_path)
    required = ("schema", "tool", "verified", "manifestSha256", "publicKeySha256", "archiveSha256", "archiveSize", "version", "packageVersion", "packageManifestSha256", "checksumsSha256")
    if any(key not in receipt for key in required) or receipt.get("schema") != 1 or receipt.get("tool") != "amnezia-verify-provisioning-v1" or receipt.get("verified") is not True:
        raise LabError("headless verified receipt is not an official successful verification")
    if receipt.get("manifestSha256") != manifest_sha or receipt.get("publicKeySha256") != public_key_sha or receipt.get("archiveSha256") != provisioning.get("sha256") or receipt.get("archiveSize") != provisioning.get("size") or receipt.get("version") != expected_version or receipt.get("packageVersion") != expected_version or receipt.get("packageManifestSha256") != provisioning.get("packageManifestSha256") or receipt.get("checksumsSha256") != provisioning.get("checksumsSha256"):
        raise LabError("headless verified receipt does not match signed manifest inputs")
    return {"provisioning_path": str(archive_path), "public_key_path": str(public_key_path), "verified_receipt_path": str(receipt_path), "key_sha256": public_key_sha, "package_manifest_sha256": str(provisioning["packageManifestSha256"]), "checksums_sha256": str(provisioning["checksumsSha256"]), "signed_manifest_sha256": manifest_sha}


def golden_readiness(root: Path, profile: Mapping[str, Any]) -> tuple[bool, str]:
    try:
        image = ensure_owned_child(root, root / str(profile["base_image"]), "golden image")
        readiness = ensure_owned_child(root, root / str(profile["golden_readiness"]), "golden readiness")
        if not image.is_file() or not readiness.is_file():
            return False, "provisioned sealed golden image/readiness receipt is missing"
        data = json.loads(readiness.read_text(encoding="utf-8"))
        if data.get("schema") != 1 or data.get("profile") != profile.get("id") or data.get("sealed") is not True or data.get("network_sealed") is not True or data.get("immutable") is not True or data.get("candidate_credentials") is not False or data.get("guest_agent") != "qga":
            return False, "golden readiness receipt is not sealed QGA evidence"
        actual, _ = sha256_file(image)
        if data.get("base_sha256") != actual:
            return False, "golden image hash differs from readiness receipt"
        if profile.get("id") == "windows-x64":
            vars_path = ensure_owned_child(root, root / str(profile.get("ovmf_vars_golden", "")), "golden OVMF vars")
            tpm_path = ensure_owned_child(root, root / str(profile.get("tpm_state_golden", "")), "golden TPM state")
            if not vars_path.is_file() or not tpm_path.is_dir() or profile.get("tpm_state_policy") != "sealed-copy-only":
                return False, "sealed Windows OVMF vars/TPM state bundle is missing"
            vars_sha, _ = sha256_file(vars_path)
            tpm_sha = sha256_tree(tpm_path)
            if data.get("ovmf_vars_sha256") != vars_sha or data.get("tpm_state_sha256") != tpm_sha:
                return False, "Windows golden OVMF vars or TPM state hash differs from readiness receipt"
        return True, str(image)
    except (LabError, OSError, json.JSONDecodeError) as exc:
        return False, str(exc)


def resolve_host_executable(name: str) -> str:
    """Return an allowlisted host binary, never a caller supplied command."""
    if name not in HOST_EXECUTABLES:
        raise LabError(f"host executable is not allowlisted: {name}")
    expected = Path(HOST_EXECUTABLE_PATHS[name])
    if not expected.is_file() or not os.access(expected, os.X_OK):
        raise LabError(f"trusted host executable is unavailable at {expected}")
    return str(expected)


def ensure_repo_adapter(relative_path: Any) -> Path:
    if not isinstance(relative_path, str) or Path(relative_path).is_absolute() or ".." in Path(relative_path).parts:
        raise LabError("adapter path must be a repository-relative path")
    path = (repo_root() / relative_path).resolve()
    try:
        path.relative_to(repo_root())
    except ValueError as exc:
        raise LabError("adapter path escaped repository") from exc
    if path not in {(repo_root() / "deploy/release_lab/android/android-lab.sh").resolve(), (repo_root() / ANDROID_WINDOWS_ADAPTER_RELATIVE).resolve()}:
        raise LabError(f"unrecognized adapter path: {path}")
    if not path.is_file():
        raise LabError(f"adapter script is missing: {path}")
    return path


def proc_start_time_from_stat(stat_text: str) -> str:
    """Read field 22 from /proc/<pid>/stat without splitting comm incorrectly."""
    closing = stat_text.rfind(")")
    if closing < 0:
        raise LabError("/proc stat has no closing comm delimiter")
    fields_after_comm = stat_text[closing + 2 :].split()
    # The suffix starts at field 3 (state); field 22 is index 19.
    if len(fields_after_comm) <= 19:
        raise LabError("/proc stat is truncated before starttime")
    return fields_after_comm[19]


def proc_state_from_stat(stat_text: str) -> str:
    closing = stat_text.rfind(")")
    if closing < 0:
        raise LabError("/proc stat has no closing comm delimiter")
    fields_after_comm = stat_text[closing + 2 :].split()
    if not fields_after_comm:
        raise LabError("/proc stat is truncated before state")
    return fields_after_comm[0]


def proc_start_time(pid: int) -> str:
    try:
        return proc_start_time_from_stat(Path(f"/proc/{pid}/stat").read_text(encoding="utf-8"))
    except (OSError, LabError) as exc:
        raise LabError(f"cannot read owned process start time for pid {pid}") from exc


PROCESS_STOP_TIMEOUT = 30.0


def wait_owned_process_exit(pid: int, expected_start_time: str, label: str, timeout: float | None = None) -> None:
    """Wait for an owned process to exit without accepting PID reuse."""
    if timeout is None:
        timeout = PROCESS_STOP_TIMEOUT
    deadline = time.monotonic() + timeout
    proc_path = Path(f"/proc/{pid}")
    while time.monotonic() < deadline:
        if not proc_path.exists():
            return
        try:
            stat_text = proc_path.joinpath("stat").read_text(encoding="utf-8")
            if proc_state_from_stat(stat_text) == "Z":
                return
            current_start_time = proc_start_time_from_stat(stat_text)
        except LabError:
            if not proc_path.exists():
                return
            raise
        if current_start_time != expected_start_time:
            raise LabError(f"{label} PID was reused while stopping; preserving owned state")
        time.sleep(0.1)
    if proc_path.exists():
        try:
            stat_text = proc_path.joinpath("stat").read_text(encoding="utf-8")
            if proc_state_from_stat(stat_text) == "Z":
                return
            if proc_start_time_from_stat(stat_text) != expected_start_time:
                raise LabError(f"{label} PID was reused while stopping; preserving owned state")
        except LabError:
            if not proc_path.exists():
                return
            raise
        raise LabError(f"{label} did not exit within {timeout:g}s; preserving owned state")


def require_qmp_return(result: Mapping[str, Any], operation: str) -> Mapping[str, Any]:
    if "return" not in result:
        raise LabError(f"QMP {operation} failed: {result}")
    return result


def run_host(argv: Sequence[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    """Run an already validated host command without a shell."""
    if not argv or argv[0] not in HOST_EXECUTABLES:
        raise LabError("host command is not allowlisted")
    executable = resolve_host_executable(argv[0])
    return subprocess.run([executable, *argv[1:]], check=False, shell=False, text=True, capture_output=True, timeout=timeout)


class QmpClient:
    """Small QMP JSON-lines client used only with an owned Unix socket."""

    def __init__(self, socket_path: Path, timeout: float = 5.0):
        self.socket_path = socket_path
        self.timeout = timeout

    def request(self, execute: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if not self.socket_path.exists():
            raise LabError(f"QMP socket is unavailable: {self.socket_path}")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(self.timeout)
            conn.connect(str(self.socket_path))
            self._read_json(conn)  # greeting
            conn.sendall((json.dumps({"execute": "qmp_capabilities"}) + "\r\n").encode())
            self._read_until_return(conn)
            payload: dict[str, Any] = {"execute": execute}
            if arguments:
                payload["arguments"] = dict(arguments)
            conn.sendall((json.dumps(payload) + "\r\n").encode())
            return self._read_until_return(conn)

    @staticmethod
    def _read_json(conn: socket.socket) -> dict[str, Any]:
        data = b""
        while b"\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                raise LabError("QMP/QGA peer closed before a complete JSON response")
            data += chunk
            if len(data) > 1024 * 1024:
                raise LabError("QMP response exceeds safety bound")
        line, _ = data.split(b"\n", 1)
        line = line.strip(b"\xff\r")
        return json.loads(line.decode("utf-8"))

    def _read_until_return(self, conn: socket.socket) -> dict[str, Any]:
        while True:
            result = self._read_json(conn)
            if "return" in result or "error" in result:
                return result


class QgaClient:
    """QGA JSON-lines client; guest evidence is read through this transport."""

    def __init__(self, socket_path: Path, timeout: float = 5.0):
        self.socket_path = socket_path
        self.timeout = timeout

    def request(self, execute: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if not self.socket_path.exists():
            raise LabError(f"QGA socket is unavailable: {self.socket_path}")
        payload: dict[str, Any] = {"execute": execute}
        if arguments:
            payload["arguments"] = dict(arguments)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(self.timeout)
            conn.connect(str(self.socket_path))
            conn.sendall((json.dumps(payload) + "\r\n").encode())
            return QmpClient._read_json(conn)

    @staticmethod
    def _request_on_connection(conn: socket.socket, execute: str,
                               arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Issue one QGA command on an already-owned persistent connection."""
        payload: dict[str, Any] = {"execute": execute}
        if arguments:
            payload["arguments"] = dict(arguments)
        conn.sendall((json.dumps(payload) + "\r\n").encode())
        return QmpClient._read_json(conn)

    @staticmethod
    def _sync_connection(conn: socket.socket) -> None:
        """Discard stale channel replies and establish a fresh command boundary."""
        sync_id = int(time.time_ns() & 0x7FFFFFFF)
        payload = {"execute": "guest-sync-delimited", "arguments": {"id": sync_id}}
        conn.sendall((json.dumps(payload) + "\r\n").encode())
        for _ in range(64):
            response = QmpClient._read_json(conn)
            if response.get("return") == sync_id:
                return
        raise LabError("QGA persistent connection did not reach a fresh sync boundary")

    def sync(self) -> bool:
        result = self.request("guest-sync-delimited", {"id": int(time.time() * 1000) & 0xFFFFFFFF})
        return "return" in result

    def guest_exec(self, executable: str, args: Sequence[str]) -> dict[str, Any]:
        result = self.request("guest-exec", {"path": executable, "arg": list(args), "capture-output": True})
        if "return" not in result or not isinstance(result["return"], dict):
            raise LabError(f"guest-exec failed for {executable}: {result}")
        return result["return"]

    def guest_exec_wait(self, executable: str, args: Sequence[str], timeout: float = 120.0) -> dict[str, Any]:
        """Run a guest command and require its real exit status and assertion."""
        started = self.guest_exec(executable, args)
        guest_pid = started.get("pid")
        if not isinstance(guest_pid, int):
            raise LabError("guest-exec returned no guest PID")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.request("guest-exec-status", {"pid": guest_pid})
            payload = result.get("return", {})
            if payload.get("exited") is True:
                if payload.get("exitcode") != 0:
                    raise LabError(f"guest step exited with {payload.get('exitcode')}: {payload}")
                output = ""
                if payload.get("out-data"):
                    output = base64.b64decode(payload["out-data"]).decode("utf-8", errors="replace")
                return {"pid": guest_pid, "exitcode": 0, "stdout": output, "stderr": payload.get("err-data", "")}
            time.sleep(0.2)
        raise LabError(f"guest step timed out (pid {guest_pid})")

    def read_file(self, path: str) -> bytes:
        opened = self.request("guest-file-open", {"path": path, "mode": "r"})
        handle = opened.get("return")
        if not isinstance(handle, int):
            raise LabError(f"guest-file-open failed: {opened}")
        try:
            chunks: list[bytes] = []
            while True:
                result = self.request("guest-file-read", {"handle": handle, "count": 65536})
                payload = result.get("return", {})
                encoded = payload.get("buf-b64", "")
                if encoded:
                    chunks.append(base64.b64decode(encoded))
                if not payload.get("eof", True):
                    continue
                return b"".join(chunks)
        finally:
            self.request("guest-file-close", {"handle": handle})

    def write_file(self, path: str, data: bytes) -> None:
        if not self.socket_path.exists():
            raise LabError(f"QGA socket is unavailable: {self.socket_path}")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(self.timeout)
            conn.connect(str(self.socket_path))
            self._sync_connection(conn)
            opened = self._request_on_connection(conn, "guest-file-open", {"path": path, "mode": "w"})
            handle = opened.get("return")
            if not isinstance(handle, int) or isinstance(handle, bool):
                raise LabError(f"guest-file-open for write failed: {opened}")
            try:
                # Keep the base64-expanded QGA JSON request below the proven
                # guest-agent frame limit. Reusing one connection avoids a
                # costly connect/close cycle for every 32 KiB chunk.
                for offset in range(0, len(data), 32768):
                    chunk = data[offset:offset + 32768]
                    encoded = base64.b64encode(chunk).decode("ascii")
                    result = self._request_on_connection(
                        conn, "guest-file-write", {"handle": handle, "buf-b64": encoded}
                    )
                    written = result.get("return", {}).get("count") if isinstance(result.get("return"), Mapping) else None
                    if not isinstance(written, int) or isinstance(written, bool) or written != len(chunk):
                        raise LabError(f"guest-file-write returned a short or invalid count: {result}")
                flushed = self._request_on_connection(conn, "guest-file-flush", {"handle": handle})
                if "return" not in flushed:
                    raise LabError(f"guest-file-flush failed: {flushed}")
            finally:
                closed = self._request_on_connection(conn, "guest-file-close", {"handle": handle})
                if "return" not in closed:
                    raise LabError(f"guest-file-close failed: {closed}")

    def write_file_from_path(self, path: str, source: Path, expected_sha256: str, expected_size: int,
                             *, deadline: float, max_size: int) -> None:
        """Stream an exact local file to QGA without materializing it in argv or memory."""
        if (isinstance(deadline,bool) or not isinstance(deadline,(int,float)) or not math.isfinite(deadline)
            or isinstance(max_size,bool) or not isinstance(max_size,int) or expected_size<=0 or expected_size>max_size):raise LabError("invalid QGA streaming bound")
        if not self.socket_path.exists(): raise LabError(f"QGA socket is unavailable: {self.socket_path}")
        def remaining() -> float:
            value=deadline-time.monotonic()
            if value<=0:raise LabError("QGA streaming deadline expired")
            return min(float(self.timeout),value)
        digest=hashlib.sha256();total=0
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(remaining());conn.connect(str(self.socket_path));self._sync_connection(conn);conn.settimeout(remaining())
            opened=self._request_on_connection(conn,"guest-file-open",{"path":path,"mode":"w"});handle=opened.get("return")
            if not isinstance(handle,int) or isinstance(handle,bool):raise LabError(f"guest-file-open for streaming failed: {opened}")
            primary=None
            try:
                with source.open("rb") as stream:
                    for chunk in iter(lambda:stream.read(32768),b""):
                        conn.settimeout(remaining());total+=len(chunk)
                        if total>expected_size or total>max_size:raise LabError("QGA streaming source exceeds exact bound")
                        digest.update(chunk)
                        result=self._request_on_connection(conn,"guest-file-write",{"handle":handle,"buf-b64":base64.b64encode(chunk).decode("ascii")})
                        written=(result.get("return") or {}).get("count") if isinstance(result.get("return"),Mapping) else None
                        if isinstance(written,bool) or written!=len(chunk):raise LabError("guest streaming write returned a short count")
                if total!=expected_size or digest.hexdigest()!=expected_sha256:raise LabError("local fixture bytes changed during streaming")
                conn.settimeout(remaining());flushed=self._request_on_connection(conn,"guest-file-flush",{"handle":handle})
                if "return" not in flushed:raise LabError(f"guest-file-flush failed: {flushed}")
            except BaseException as exc:primary=exc;raise
            finally:
                try:
                    conn.settimeout(max(.1,min(5.0,max(0.1,deadline-time.monotonic()))))
                    closed=self._request_on_connection(conn,"guest-file-close",{"handle":handle})
                    if "return" not in closed:raise LabError(f"guest-file-close failed: {closed}")
                except BaseException as close_error:
                    if primary is None:raise
                    if hasattr(primary,"add_note"):primary.add_note(f"guest-file-close also failed: {close_error!r}")


@dataclass
class LabController:
    root: Path
    dry_run: bool = False
    test_mode: bool = False
    windows_backend: str = "qemu"
    android_backend: str = "linux"
    _mutation_lock_fd: int | None = field(default=None, init=False, repr=False)
    _mutation_lock_depth: int = field(default=0, init=False, repr=False)

    @property
    def mutation_lock_path(self) -> Path:
        return self.root / ".state.mutation.lock"

    def acquire_mutation_lock(self, owner: str = "lab") -> None:
        if self.dry_run or self.test_mode:
            return
        if fcntl is None and msvcrt is None:
            raise LabError("state mutation locking requires a supported platform lock")
        if self._mutation_lock_depth:
            self._mutation_lock_depth += 1
            return
        self.root.mkdir(parents=True, exist_ok=True)
        lock_path = self.mutation_lock_path
        if lock_path.is_symlink() or (lock_path.exists() and not lock_path.is_file()):
            raise LabError("state mutation lock is not a regular file")
        open_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(lock_path, open_flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except (BlockingIOError, OSError) as exc:
                try:
                    detail = os.read(fd, 512).decode("utf-8", errors="replace").strip()
                except OSError:
                    detail = "owner metadata unavailable"
                raise LabError(f"lab busy: state root mutation lock is held ({detail or 'another run is active'})") from exc
            payload = f"pid={os.getpid()}\nowner={owner}\nacquired_at={utc_now()}\n"
            os.ftruncate(fd, 0)
            os.write(fd, payload.encode("utf-8"))
            os.fsync(fd)
            self._mutation_lock_fd = fd
            self._mutation_lock_depth = 1
        except Exception:
            os.close(fd)
            raise

    def release_mutation_lock(self) -> None:
        if self._mutation_lock_depth == 0:
            return
        if self._mutation_lock_depth > 1:
            self._mutation_lock_depth -= 1
            return
        fd = self._mutation_lock_fd
        self._mutation_lock_fd = None
        self._mutation_lock_depth = 0
        if fd is not None:
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                elif msvcrt is not None:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            finally:
                os.close(fd)

    @contextlib.contextmanager
    def mutation_session(self, owner: str = "lab"):
        self.acquire_mutation_lock(owner)
        try:
            yield self
        finally:
            self.release_mutation_lock()

    def assert_mutation_context(self) -> None:
        if not self.test_mode:
            assert_lab_identity(self.root)

    def uses_hyperv(self, run: Mapping[str, Any], profile_id: str) -> bool:
        return profile_id == "windows-x64" and run.get("windows_backend") == "hyperv"

    def _record_hyperv_case(self, run_id: str, profile_id: str, case_id: str, state_name: str, **fields: Any) -> dict[str, Any]:
        """Persist case intent/state before and after each native backend call."""
        run = self.get_run(run_id)
        profile_state = run.setdefault("profiles", {}).setdefault(profile_id, {})
        cases = profile_state.setdefault("hyperv_cases", {})
        current = dict(cases.get(case_id) or {})
        current.update(fields)
        current.update({"case_id": case_id, "state": state_name, "updated_at": utc_now()})
        cases[case_id] = current
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return current

    def _persist_hyperv_case_progress(
        self,
        run_id: str,
        profile_id: str,
        observed_steps: list[dict[str, Any]],
        case_receipts: list[dict[str, Any]],
        last_case_id: str,
    ) -> None:
        """Persist completed CLI evidence before the child is reset."""
        run = self.get_run(run_id)
        profile_state = run.setdefault("profiles", {}).setdefault(profile_id, {})
        profile_state["steps"] = list(observed_steps)
        profile_state["case_receipts"] = list(case_receipts)
        profile_state["last_case_id"] = last_case_id
        state = self.load_state()
        state["runs"][run_id] = run
        self.save_state(state)

    def hyperv_credential(self) -> str:
        raw = os.environ.get("AMNEZIA_HYPERV_CREDENTIAL_FILE")
        if not raw:
            raise LabError("Hyper-V PowerShell Direct requires AMNEZIA_HYPERV_CREDENTIAL_FILE at runtime")
        path = Path(raw).expanduser().resolve()
        if path.is_symlink() or not path.is_file():
            raise LabError("Hyper-V credential file must be a regular runtime-only file")
        if pwd is None or not hasattr(os, "getuid") or not hasattr(os, "getgid"):
            raise LabError("Hyper-V credential ownership cannot be verified on this host")
        expected_uid = os.getuid()
        expected_gid = pwd.getpwnam("amnezia-lab").pw_gid
        metadata = path.stat()
        if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise LabError("Hyper-V credential file must be owned by amnezia-lab with mode 0600")
        secret = path.read_text(encoding="utf-8").rstrip("\r\n")
        if not secret or len(secret) > 512:
            raise LabError("Hyper-V credential file is empty or too large")
        return secret

    def hyperv_call(self, action: str, *, run_id: str | None = None, credential: bool = False, **kwargs: Any) -> dict[str, Any]:
        if not self.dry_run and not self.test_mode and action not in {"plan", "status", "collect", "ui-observe"} and self._mutation_lock_depth == 0:
            raise LabError(f"Hyper-V mutating action {action} requires an active mutation session")
        adapter = hyperv_adapter_source()
        if not Path(HYPERV_POWERSHELL_WSL).is_file() or not os.access(HYPERV_POWERSHELL_WSL, os.X_OK):
            raise LabError(f"pinned Windows PowerShell bridge is unavailable: {HYPERV_POWERSHELL_WSL}")
        argv = [HYPERV_POWERSHELL_WSL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", windows_path_for_wsl(adapter), "-Action", action, "-ParentRoot", HYPERV_PARENT_ROOT_WINDOWS, "-RunsRoot", HYPERV_RUNS_ROOT_WINDOWS]
        if run_id:
            argv += ["-RunId", run_id]
        for key, value in kwargs.items():
            if value is None:
                continue
            if isinstance(value, bool):
                if value:
                    argv.append(f"-{key}")
            else:
                argv += [f"-{key}", str(value)]
        secret = self.hyperv_credential() if credential else None
        if credential:
            argv.append("-CredentialStdin")
        # Keep the controller's adapter deadline above the guest runner's
        # bounded 15 minute installer wait, so the guest can publish its
        # completion/failure receipt before the host bridge times out.
        result = subprocess.run(argv, input=((secret + "\n").encode("utf-8") if secret is not None else None), check=False, shell=False, text=False, capture_output=True, timeout=960)
        stdout = result.stdout.decode("utf-8-sig", errors="replace")
        stderr = result.stderr.decode("utf-8-sig", errors="replace")
        if result.returncode != 0:
            detail = (stderr or stdout)[-1500:]
            raise LabError(f"Hyper-V adapter {action} failed: {detail}")
        try:
            value = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise LabError(f"Hyper-V adapter {action} returned non-JSON output") from exc
        if not isinstance(value, dict):
            raise LabError(f"Hyper-V adapter {action} returned a non-object response")
        return value

    @property
    def state_path(self) -> Path:
        return self.root / "state.json"

    def load_state(self) -> dict[str, Any]:
        if not self.state_path.is_file():
            return {"schema": SCHEMA_VERSION, "lab_id": None, "runs": {}, "updated_at": None}
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LabError(f"invalid lab state: {exc}") from exc
        if state.get("schema") != SCHEMA_VERSION:
            raise LabError("unsupported lab state schema")
        return state

    def save_state(self, state: dict[str, Any]) -> None:
        if self.dry_run:
            return
        if not self.test_mode and self._mutation_lock_depth == 0:
            raise LabError("state save requires an active mutation session")
        self.assert_mutation_context()
        state["updated_at"] = utc_now()
        json_dump(self.state_path, state)

    def preflight(self, selected_profiles: Sequence[str] | None = None) -> dict[str, Any]:
        checks: dict[str, Any] = {}
        if self.test_mode:
            checks["identity"] = {"ready": True, "test_mode": True}
        else:
            try:
                assert_lab_identity(self.root)
                checks["identity"] = {"ready": True, "user": "amnezia-lab", "uid": os.geteuid()}
            except LabError as exc:
                checks["identity"] = {"ready": False, "reason": str(exc)}
        try:
            profiles = load_profiles()
            checks["profiles"] = {"ready": True, "ids": list(profiles)}
        except LabError as exc:
            checks["profiles"] = {"ready": False, "reason": str(exc)}
            profiles = {}
        qemu_checks: dict[str, Any] = {}
        for executable in ("qemu-system-x86_64", "qemu-img", "swtpm"):
            try:
                qemu_checks[executable] = {"ready": True, "path": resolve_host_executable(executable)}
            except LabError as exc:
                qemu_checks[executable] = {"ready": False, "reason": str(exc)}
        checks["host_executables"] = qemu_checks
        checks["kvm"] = {"ready": Path("/dev/kvm").exists(), "path": "/dev/kvm"}
        checks["state_root"] = {"ready": self.root.is_dir() or not self.dry_run, "path": str(self.root)}
        pending_intents: list[str] = []
        runs_root = self.root / "runs"
        if runs_root.is_dir() and not runs_root.is_symlink():
            for intent_path in runs_root.glob("*/**/.qemu-spawn-intent.json"):
                if intent_path.is_file() or intent_path.is_symlink():
                    pending_intents.append(str(intent_path))
        checks["qemu_spawn_intents"] = {"ready": not pending_intents, "pending": pending_intents}
        selected = list(selected_profiles or profiles)
        unknown = sorted(set(selected) - set(profiles))
        if unknown:
            raise LabError(f"unknown preflight profile: {', '.join(unknown)}")
        image_checks = {}
        for profile_id in selected:
            profile = profiles[profile_id]
            if profile.get("backend") == "android-adapter":
                try:
                    script = ensure_repo_adapter(ANDROID_WINDOWS_ADAPTER_RELATIVE if self.android_backend == "windows" else profile.get("adapter_script"))
                    adapter_profile = script.parent / "android-lab-profile.json"
                    image_checks[profile_id] = {"ready": adapter_profile.is_file() and script.is_file(), "adapter": str(script), "profile": str(adapter_profile), "backend": "android-windows" if self.android_backend == "windows" else "android-linux"}
                except LabError as exc:
                    image_checks[profile_id] = {"ready": False, "reason": str(exc)}
            elif profile_id == "windows-x64" and self.windows_backend == "hyperv":
                try:
                    adapter = hyperv_adapter_source(); host_profile = hyperv_profile_source()
                    plan = self.hyperv_call("plan") if not self.dry_run else {"ready": False, "reason": "dry-run"}
                    image_checks[profile_id] = {"ready": plan.get("ready") is True, "backend": "hyperv", "adapter": str(adapter), "profile": str(host_profile), "parent_sha256": plan.get("parent_sha256"), "reason": None if plan.get("ready") is True else plan.get("reason", "Hyper-V parent is not ready")}
                except (LabError, OSError, subprocess.SubprocessError) as exc:
                    image_checks[profile_id] = {"ready": False, "backend": "hyperv", "reason": str(exc)}
            else:
                ready, detail = golden_readiness(self.root, profile)
                image_checks[profile_id] = {"ready": ready, "path": detail if ready else str(self.root / profile.get("base_image", "")), "reason": None if ready else detail}
        checks["base_images"] = image_checks
        runner_checks = {}
        for profile_id in selected:
            profile = profiles[profile_id]
            runner = profile.get("runner")
            if profile_id == "windows-x64" and self.windows_backend == "hyperv":
                try:
                    runner_path = (repo_root() / str(runner)).resolve()
                    runner_checks[profile_id] = {"ready": runner_path.is_file() and hyperv_adapter_source().is_file() and hyperv_ui_helper_source().is_file() and hyperv_launcher_source().is_file(), "path": str(runner_path), "adapter": str(hyperv_adapter_source()), "ui_helper": str(hyperv_ui_helper_source()), "launcher": str(hyperv_launcher_source()), "transport": HYPERV_TRANSPORT}
                except LabError as exc:
                    runner_checks[profile_id] = {"ready": False, "reason": str(exc)}
                continue
            if profile.get("backend") == "android-adapter":
                runner_checks[profile_id] = {"ready": True, "adapter": str(ANDROID_WINDOWS_ADAPTER_RELATIVE if self.android_backend == "windows" else profile.get("adapter_script")), "backend": "android-windows" if self.android_backend == "windows" else "android-linux"}
                continue
            runner_path = (repo_root() / str(runner)).resolve() if isinstance(runner, str) else Path("")
            runner_checks[profile_id] = {"ready": runner_path.is_file(), "path": str(runner_path)}
        checks["guest_runners"] = runner_checks
        server_profile = profiles_root() / "server-router.env"
        checks["lab_server_profile"] = {"ready": server_profile.is_file(), "path": str(server_profile), "role": "isolated-test-server-router"}
        qemu_required = any(profile_id != "windows-x64" for profile_id in selected)
        ready = (
            checks["identity"].get("ready", False)
            and checks["profiles"].get("ready", False)
            and (not qemu_required or all(item.get("ready", False) for item in qemu_checks.values()))
            and (not qemu_required or checks["kvm"].get("ready", False))
            and all(item.get("ready", False) for item in image_checks.values())
            and all(item.get("ready", False) for item in runner_checks.values())
            and checks["qemu_spawn_intents"].get("ready", False)
            and ("server-router" not in selected or checks["lab_server_profile"].get("ready", False))
            and not self.dry_run
        )
        return {"schema": SCHEMA_VERSION, "ready": ready, "dry_run": self.dry_run, "checks": checks, "release_passed": False}

    @mutation_operation
    def create(self, lane: str, artifacts: Mapping[str, Path], outer_artifact: Path | None = None, run_id: str | None = None, manifest: Path | None = None, baseline_artifacts: Mapping[str, Path] | None = None, baseline_version: str | None = None, candidate_version: str | None = None, manifest_public_key: Path | None = None, baseline_manifest: Path | None = None, headless_baseline_receipt: Path | None = None, headless_candidate_receipt: Path | None = None, baseline_outer_artifact: Path | None = None) -> dict[str, Any]:
        self.assert_mutation_context()
        profiles = load_profiles()
        if lane not in ("candidate", "release", "publisher-diagnostic"):
            raise LabError("lane must be candidate, release, or publisher-diagnostic")
        if self.windows_backend not in ("qemu", "hyperv"):
            raise LabError("Windows backend must be qemu or hyperv")
        if self.android_backend not in ("linux", "windows"):
            raise LabError("Android backend must be linux or windows")
        if lane != "publisher-diagnostic" and not artifacts:
            raise LabError("at least one artifact is required")
        if outer_artifact is None:
            raise LabError("candidate/release runs require the explicit outer self-hosted wrapper artifact")
        records = {name: artifact_record(path) for name, path in artifacts.items()}
        unknown_artifacts = set(records) - set(RELEASE_PLATFORM_IDS)
        if unknown_artifacts:
            raise LabError(f"unsupported planned artifact platform(s): {', '.join(sorted(unknown_artifacts))}")
        baseline_artifacts = baseline_artifacts or {}
        if lane != "publisher-diagnostic" and not baseline_artifacts:
            raise LabError("run requires explicit baseline artifacts; metadata-only upgrade tests are forbidden")
        if lane != "publisher-diagnostic" and set(baseline_artifacts) != set(records):
            raise LabError("candidate/release lane requires an explicit N-1 baseline artifact for every candidate platform")
        if lane == "release" and set(records) != set(RELEASE_PLATFORM_IDS):
            raise LabError("release lane requires every signed release platform artifact")
        if lane == "release" and baseline_outer_artifact is None:
            raise LabError("release lane requires an explicit N-1 baseline outer artifact")
        if lane != "publisher-diagnostic" and (not baseline_version or not candidate_version):
            raise LabError("run requires immutable baseline and candidate versions")
        if lane == "publisher-diagnostic":
            if not candidate_version:
                raise LabError("publisher diagnostic requires a candidate version")
            baseline_version = baseline_version or candidate_version
        if lane != "publisher-diagnostic" and not all(
            ("linux-x64" if profile_id == "linux-x64-gui" else profile_id) in records
            for profile_id in (PROFILE_IDS if lane == "release" else ["linux-x64-gui"] if "linux-x64" in records else [])
        ):
            raise LabError("planned guest profiles do not have matching platform artifacts")
        if manifest is None or manifest_public_key is None:
            raise LabError("run requires a signed manifest and its public key")
        if "linux-headless-x64" in records:
            if baseline_manifest is None and manifest is not None:
                derived = manifest.parent.parent / str(baseline_version) / manifest.name
                if derived.is_file():
                    baseline_manifest = derived
            if baseline_manifest is None or headless_baseline_receipt is None or headless_candidate_receipt is None:
                raise LabError("headless run requires baseline manifest and verified baseline/candidate provisioning receipts")
        baseline_records = {name: artifact_record(path) for name, path in baseline_artifacts.items()}
        baseline_outer_record = artifact_record(baseline_outer_artifact) if baseline_outer_artifact else None
        if lane != "publisher-diagnostic" and self.windows_backend == "hyperv" and outer_artifact is not None and baseline_outer_artifact is None:
            raise LabError("Hyper-V Windows run requires an explicit baseline outer artifact")
        profile_records = {profile_id: artifact_record(profiles_root() / f"{profile_id}.json") for profile_id in profiles}
        semantic_helper_records = {relative: artifact_record(repo_root() / relative) for relative in SEMANTIC_HELPER_RELATIVES}
        android_vulkan_records = {label: artifact_record(repo_root() / relative) for label, relative in ANDROID_VULKAN_RELATIVES.items()}
        validate_android_vulkan_records(android_vulkan_records)
        android_host_dependency_records = {label: artifact_record(repo_root() / relative) for label, relative in ANDROID_HOST_DEPENDENCY_RELATIVES.items()}
        validate_android_host_dependency_records(android_host_dependency_records)
        android_wayland_records = {label: artifact_record(repo_root() / relative) for label, relative in ANDROID_WAYLAND_RELATIVES.items()}
        validate_android_wayland_records(android_wayland_records)
        runner_records = {profile_id: artifact_record(repo_root() / profile["runner"]) for profile_id, profile in profiles.items() if isinstance(profile.get("runner"), str)}
        hyperv_records = None
        if self.windows_backend == "hyperv":
            hyperv_records = {"adapter": artifact_record(hyperv_adapter_source()), "profile": artifact_record(hyperv_profile_source()), "ui_helper": artifact_record(hyperv_ui_helper_source()), "launcher": artifact_record(hyperv_launcher_source())}
        outer = artifact_record(outer_artifact) if outer_artifact else None
        if not isinstance(outer, dict) or outer.get("size", 0) <= 0:
            raise LabError("candidate/release outer artifact must be non-empty")
        if lane != "publisher-diagnostic" and "windows-x64" in records and baseline_outer_record is None and not (self.test_mode or self.dry_run):
            raise LabError("Windows candidate/release run requires an explicit N-1 baseline outer artifact")
        manifest_record = artifact_record(manifest) if manifest else None
        baseline_manifest_record = artifact_record(baseline_manifest) if baseline_manifest else None
        headless_receipt_records = {
            "baseline": artifact_record(headless_baseline_receipt),
            "candidate": artifact_record(headless_candidate_receipt),
        } if headless_baseline_receipt and headless_candidate_receipt else None
        run_id = run_id or f"run-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
        run_dir = ensure_owned_child(self.root, self.root / "runs" / run_id, "run directory")
        if run_dir.exists():
            raise LabError(f"run already exists: {run_id}")
        if not self.dry_run:
            run_dir.mkdir(parents=True)
            for profile_id in profiles:
                profile_dir = run_dir / profile_id
                profile_dir.mkdir()
                overlay = ensure_owned_child(self.root, profile_dir / "overlay.qcow2", "overlay")
                (profile_dir / ".owned-overlay.json").write_text(json.dumps({"run_id": run_id, "profile": profile_id, "overlay": str(overlay)}, sort_keys=True) + "\n", encoding="utf-8")
        state = self.load_state()
        state["lab_id"] = state.get("lab_id") or f"lab-{uuid.uuid4().hex}"
        expected_profiles = []
        for artifact_id in records:
            mapped = "linux-x64-gui" if artifact_id == "linux-x64" else artifact_id
            if mapped in profiles:
                expected_profiles.append(mapped)
        if lane == "release":
            expected_profiles = list(PROFILE_IDS)
        elif lane == "publisher-diagnostic":
            expected_profiles = ["windows-x64"]
        state.setdefault("runs", {})[run_id] = {
            "run_id": run_id, "lane": lane, "dry_run": self.dry_run, "test_mode": self.test_mode,
            "created_at": utc_now(), "artifacts": records, "baseline_artifacts": baseline_records, "outer_artifact": outer, "baseline_outer_artifact": baseline_outer_record,
            "baseline_version": baseline_version, "candidate_version": candidate_version,
            "manifest": manifest_record,
            "baseline_manifest": baseline_manifest_record,
            "headless_verified_receipts": headless_receipt_records,
            "manifest_public_key": artifact_record(manifest_public_key), "windows_backend": self.windows_backend, "android_backend": self.android_backend,
            "hyperv_records": hyperv_records,
            "profile_records": profile_records, "runner_records": runner_records,
            "semantic_helper_records": semantic_helper_records,
            "android_vulkan_records": android_vulkan_records,
            "android_host_dependency_records": android_host_dependency_records,
            "android_wayland_records": android_wayland_records,
            "server_observation": None,
            "expected_profiles": list(dict.fromkeys(expected_profiles)),
            "profiles": {profile_id: {"status": "created", "evidence": None, "vm": None} for profile_id in profiles},
        }
        self.save_state(state)
        return state["runs"][run_id]

    def get_run(self, run_id: str) -> dict[str, Any]:
        run = self.load_state().get("runs", {}).get(run_id)
        if not isinstance(run, dict):
            raise LabError(f"unknown lab run: {run_id}")
        return run

    def _qemu_spawn_intent_path(self, run_id: str, profile_id: str) -> Path:
        run_dir = ensure_owned_child(self.root, self.root / "runs" / run_id / profile_id, "QEMU run directory")
        return ensure_owned_child(self.root, run_dir / ".qemu-spawn-intent.json", "QEMU spawn intent")

    @staticmethod
    def _read_qemu_spawn_intent(path: Path, run_id: str, profile_id: str) -> dict[str, Any]:
        if path.is_symlink() or not path.is_file():
            raise LabError(f"QEMU spawn intent is not a regular file: {path}")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LabError(f"QEMU spawn intent is invalid: {path}") from exc
        if not isinstance(value, dict) or value.get("schema") != 1 or value.get("backend") not in {"qemu-linux", "qemu-windows"} or value.get("run_id") != run_id or value.get("profile") != profile_id:
            raise LabError("QEMU spawn intent identity mismatch")
        for key in ("vm_uuid", "overlay", "qmp_socket", "qga_socket"):
            if not isinstance(value.get(key), str) or not value[key]:
                raise LabError(f"QEMU spawn intent lacks {key}")
        if not isinstance(value.get("argv"), list) or not value["argv"] or value["argv"][0] != "qemu-system-x86_64" or not all(isinstance(item, str) for item in value["argv"]):
            raise LabError("QEMU spawn intent argv is invalid")
        return value

    def _remove_owned_socket(self, path: Path, label: str) -> None:
        """Remove only an actual socket owned by this run; preserve surprises."""
        path = ensure_owned_child(self.root, path, label)
        if not path.exists() and not path.is_symlink():
            return
        if path.is_symlink() or not stat.S_ISSOCK(path.stat().st_mode):
            raise LabError(f"refusing to remove non-socket {label}: {path}")
        # A stale Unix socket file is safe only when no listener accepts it.
        # An accepting/blocked endpoint may belong to a foreign process whose
        # PID is not visible in the intent, so preserve it fail-closed.
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.25)
                probe.connect(str(path))
        except ConnectionRefusedError:
            pass
        except OSError as exc:
            if exc.errno not in {errno.ENOENT, errno.ECONNREFUSED}:
                raise LabError(f"cannot prove {label} is an unowned stale socket: {path}") from exc
        else:
            raise LabError(f"{label} is still accepting connections; preserving recovery state: {path}")
        if not self.dry_run:
            path.unlink()

    def _remove_owned_overlay(self, path: Path) -> None:
        path = ensure_owned_child(self.root, path, "overlay")
        if not path.exists() and not path.is_symlink():
            return
        if path.is_symlink() or not path.is_file():
            raise LabError(f"refusing to remove non-regular overlay: {path}")
        if not self.dry_run:
            path.unlink()

    def _remove_owned_generated_path(self, path: Path, label: str) -> None:
        path = ensure_owned_child(self.root, path, label)
        if not path.exists() and not path.is_symlink():
            return
        if path.is_symlink():
            raise LabError(f"refusing to remove symlinked {label}: {path}")
        if path.is_dir():
            if any(item.is_symlink() for item in path.rglob("*")):
                raise LabError(f"refusing to remove {label} containing symlinks: {path}")
            if not self.dry_run:
                shutil.rmtree(path)
        elif path.is_file():
            if not self.dry_run:
                path.unlink()
        else:
            raise LabError(f"refusing to remove special {label}: {path}")

    def _qemu_process_for_intent(self, intent: Mapping[str, Any]) -> tuple[int, str] | None:
        candidates: Iterable[Path]
        raw_pid = intent.get("pid")
        if isinstance(raw_pid, int) and raw_pid > 0:
            candidates = (Path(f"/proc/{raw_pid}"),)
        else:
            candidates = Path("/proc").glob("[0-9]*")
        expected = ("-uuid", str(intent["vm_uuid"]), str(Path(intent["qmp_socket"]).resolve()), str(Path(intent["qga_socket"]).resolve()))
        for proc_path in candidates:
            cmdline_path = proc_path / "cmdline"
            try:
                cmdline = cmdline_path.read_bytes().decode(errors="replace").replace("\x00", " ")
                pid = int(proc_path.name)
                start_time = proc_start_time(pid)
            except (OSError, LabError, ValueError):
                continue
            if "qemu-system-x86_64" not in Path(str(intent["argv"][0])).name or not all(token in cmdline for token in expected):
                continue
            recorded_start = intent.get("proc_start_time")
            if recorded_start is not None and recorded_start != start_time:
                continue
            return pid, start_time
        return None

    def _recover_qemu_spawn_intent(self, run_id: str, profile_id: str) -> None:
        """Recover an interrupted QEMU launch without guessing ownership.

        A matching live process is adopted into state.  A stale intent is
        cleaned only after proving there is no matching QEMU and every target
        is the exact marker-owned overlay/socket path.
        """
        intent_path = self._qemu_spawn_intent_path(run_id, profile_id)
        if not intent_path.exists() and not intent_path.is_symlink():
            return
        intent = self._read_qemu_spawn_intent(intent_path, run_id, profile_id)
        run = self.get_run(run_id)
        profile_state = run.setdefault("profiles", {}).setdefault(profile_id, {})
        existing_vm = profile_state.get("vm")
        if isinstance(existing_vm, dict):
            if existing_vm.get("uuid") != intent.get("vm_uuid") or existing_vm.get("qmp_socket") != intent.get("qmp_socket") or existing_vm.get("qga_socket") != intent.get("qga_socket"):
                raise LabError("QEMU spawn intent conflicts with the recorded VM")
            if intent_path.is_symlink():
                raise LabError("QEMU spawn intent is symlinked")
            if not self.dry_run:
                intent_path.unlink()
            return
        process = self._qemu_process_for_intent(intent)
        if process is not None:
            pid, start_time = process
            intent.update({"pid": pid, "proc_start_time": start_time})
            vm = {key: intent[key] for key in ("pid", "proc_start_time", "uid", "vm_uuid", "qmp_socket", "qga_socket", "vnc_socket", "argv", "started_at") if key in intent}
            vm["uuid"] = vm.pop("vm_uuid")
            vm["backend"] = intent.get("backend")
            if intent.get("consumer_fixture") is True:
                vm.update({key: intent[key] for key in ("consumer_fixture", "fixture_host_port", "fixture_guest_port", "fixture_bind") if key in intent})
            if "tpm_pid" in intent:
                vm.update({key: intent[key] for key in ("tpm_pid", "tpm_proc_start_time", "tpm_socket", "tpm_state", "ovmf_vars") if key in intent})
            profile_state.update(status="started", vm=vm, spawn_recovered_at=utc_now())
            state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
            raise LabError("QEMU spawn intent recovered a live owned process; continue with probe or reset")
        # A process with the same UUID/socket path is foreign even if its PID
        # was not recorded before the controller interruption.
        for pid_path in Path("/proc").glob("[0-9]*"):
            cmdline_path = pid_path / "cmdline"
            try:
                cmdline = cmdline_path.read_bytes().decode(errors="replace").replace("\x00", " ")
            except OSError:
                continue
            if "qemu-system-x86_64" in cmdline and any(token in cmdline for token in (str(intent["vm_uuid"]), str(Path(intent["qmp_socket"]).resolve()), str(Path(intent["qga_socket"]).resolve()))):
                raise LabError("QEMU spawn intent found a foreign matching process; preserving owned recovery state")
        tpm_pid = intent.get("tpm_pid")
        tpm_start = intent.get("tpm_proc_start_time")
        if isinstance(tpm_pid, int) and tpm_pid > 0 and Path(f"/proc/{tpm_pid}").exists():
            if not isinstance(tpm_start, str) or proc_start_time(tpm_pid) != tpm_start:
                raise LabError("QEMU spawn intent TPM PID identity is ambiguous; preserving recovery state")
            cmdline = Path(f"/proc/{tpm_pid}/cmdline").read_bytes().decode(errors="replace").replace("\x00", " ")
            required = ("swtpm", str(intent.get("tpm_socket", "")), str(intent.get("tpm_state", "")))
            if not all(token and token in cmdline for token in required):
                raise LabError("QEMU spawn intent TPM argv ownership is ambiguous; preserving recovery state")
            try:
                os.kill(tpm_pid, 15)
            except ProcessLookupError:
                pass
            wait_owned_process_exit(tpm_pid, tpm_start, "TPM")
        self._remove_owned_socket(Path(intent["qmp_socket"]), "QMP socket")
        self._remove_owned_socket(Path(intent["qga_socket"]), "QGA socket")
        if intent.get("vnc_socket"):
            self._remove_owned_socket(Path(str(intent["vnc_socket"])), "VNC socket")
        if intent.get("tpm_socket"):
            self._remove_owned_socket(Path(str(intent["tpm_socket"])), "TPM socket")
        self._remove_owned_overlay(Path(intent["overlay"]))
        for key, label in (("ovmf_vars", "OVMF vars"), ("tpm_state", "TPM state")):
            if intent.get(key):
                self._remove_owned_generated_path(Path(str(intent[key])), label)
        if intent_path.is_symlink():
            raise LabError("QEMU spawn intent became symlinked during recovery")
        if not self.dry_run:
            intent_path.unlink()

    @mutation_operation
    def start(self, run_id: str, profile_id: str) -> dict[str, Any]:
        self.assert_mutation_context()
        profiles = load_profiles()
        if profile_id not in profiles:
            raise LabError(f"unknown lab profile: {profile_id}")
        run = self.get_run(run_id)
        if self.dry_run or run.get("dry_run"):
            raise LabError("dry-run cannot start a VM")
        profile = profiles[profile_id]
        if profile.get("backend") == "android-adapter":
            return self._run_android_adapter(run_id, profile_id, "start")
        if self.uses_hyperv(run, profile_id):
            self._record_hyperv_case(run_id, profile_id, "control", "intended")
            try:
                child = self.hyperv_call("create-child", run_id=run_id, CaseId="control")
            except Exception as exc:
                self._record_hyperv_case(run_id, profile_id, "control", "unsafe", error=str(exc))
                raise
            vm = dict(child.get("child") or {})
            vm.update({"backend": "hyperv", "case_id": "control", "vm_id": vm.get("vm_id"), "parent_sha256": vm.get("parent_sha256"), "transport": HYPERV_TRANSPORT, "adapter": str(hyperv_adapter_source())})
            self._record_hyperv_case(run_id, profile_id, "control", "created", vm_id=vm.get("vm_id"), parent_sha256=vm.get("parent_sha256"), run_root=vm.get("run_root"), child_vhdx=vm.get("child_vhdx"))
            try:
                started = self.hyperv_call("start", run_id=run_id, CaseId="control", credential=True)
            except Exception as exc:
                self._record_hyperv_case(run_id, profile_id, "control", "unsafe", error=str(exc))
                raise
            vm.update(started.get("child") or {})
            self._record_hyperv_case(run_id, profile_id, "control", "running", vm_id=vm.get("vm_id"), parent_sha256=vm.get("parent_sha256"), run_root=vm.get("run_root"), child_vhdx=vm.get("child_vhdx"))
            run = self.get_run(run_id)
            run["profiles"][profile_id].update(status="started", vm=vm)
            state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
            return vm
        # Resolve an interrupted prior launch before inspecting/reusing its
        # overlay.  This either adopts the exact live QEMU or removes only
        # marker-owned stale resources.
        self._recover_qemu_spawn_intent(run_id, profile_id)
        run_dir = ensure_owned_child(self.root, self.root / "runs" / run_id / profile_id, "run directory")
        golden_ok, golden_detail = golden_readiness(self.root, profile)
        if not golden_ok:
            raise LabError(f"profile {profile_id} is not backed by a verified sealed golden: {golden_detail}")
        base = ensure_owned_child(self.root, self.root / profile["base_image"], "base image")
        overlay = ensure_owned_child(self.root, run_dir / "overlay.qcow2", "overlay")
        qmp = ensure_owned_child(self.root, run_dir / "qmp.sock", "QMP socket")
        qga = ensure_owned_child(self.root, run_dir / "qga.sock", "QGA socket")
        vnc = ensure_owned_child(self.root, run_dir / "vnc.sock", "VNC socket")
        tpm = None
        proc = None
        if not base.is_file():
            raise LabError(f"base image is missing: {base}")
        if overlay.exists():
            raise LabError(f"owned overlay already exists; reset run before retry: {overlay}")
        img = run_host(("qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(overlay)))
        if img.returncode != 0:
            raise LabError(f"qemu-img failed: {img.stderr[-1000:]}")
        vm_uuid = str(uuid.uuid4())
        disk_args = ("-drive", f"file={overlay},if=ide,format=qcow2") if profile.get("backend") == "qemu-windows" else ("-drive", f"file={overlay},if=virtio,format=qcow2")
        display_args = ("-vnc", f"unix:{vnc}") if profile.get("display") == "vnc-unix" else ("-nographic",)
        # Noble's cloud image has no usable DRM device with QEMU's default
        # 1234:1111 VGA adapter.  The GUI lane needs an explicit virtio GPU
        # so Xorg/modesetting can expose a real desktop over VNC.
        video_args = ("-vga", "virtio") if profile_id == "linux-x64-gui" else ()
        fixture_host_port = None
        if profile_id == "server-router" and profile.get("consumer_fixture") is True:
            if os.environ.get("AMNEZIA_LAB_RELAY_FIXED_ENDPOINTS") == "1":
                fixture_host_port = CONSUMER_FIXTURE_GUEST_PORT
                network_args = ("-netdev", f"user,id=labnet,restrict=on,hostfwd=tcp:127.0.0.1:22222-:22,hostfwd=tcp:127.0.0.1:{CONSUMER_FIXTURE_GUEST_PORT}-:{CONSUMER_FIXTURE_GUEST_PORT}", "-device", "e1000,netdev=labnet,id=labnet-device")
            else:
                fixture_host_port = free_loopback_port()
                network_args = ("-netdev", f"user,id=labnet,restrict=on,hostfwd=tcp:127.0.0.1:{fixture_host_port}-:{CONSUMER_FIXTURE_GUEST_PORT}", "-device", "e1000,netdev=labnet,id=labnet-device")
        else:
            network_args = ("-nic", "none")
        private_link_root_port = profile_id in {"server-router", "linux-headless-x64"}
        root_port_args = ("-device", "pcie-root-port,id=amnezia-link-rp,chassis=31,slot=30") if private_link_root_port else ()
        argv = ("qemu-system-x86_64", "-uuid", vm_uuid, "-machine", str(profile.get("machine", "q35")), "-cpu", "host", "-accel", "kvm", "-name", f"amnezia-release-lab-{run_id}-{profile_id}", "-m", str(profile.get("memory_mb", 2048)), "-smp", str(profile.get("cpus", 2)), *disk_args, *root_port_args, *network_args, "-qmp", f"unix:{qmp},server=on,wait=off", "-chardev", f"socket,path={qga},server=on,wait=off,id=qga0", "-device", "virtio-serial", "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0", *video_args, *display_args)
        intent_path = self._qemu_spawn_intent_path(run_id, profile_id)
        intent: dict[str, Any] = {
            "schema": 1, "state": "prepared", "backend": profile.get("backend"),
            "run_id": run_id, "profile": profile_id, "vm_uuid": vm_uuid,
            "overlay": str(overlay), "qmp_socket": str(qmp), "qga_socket": str(qga),
            "vnc_socket": str(vnc) if profile.get("display") == "vnc-unix" else None,
            "argv": list(argv), "uid": os.getuid() if hasattr(os, "getuid") else None,
            "started_at": utc_now(),
        }
        if fixture_host_port is not None:
            intent.update({"consumer_fixture": True, "fixture_host_port": fixture_host_port, "fixture_guest_port": CONSUMER_FIXTURE_GUEST_PORT, "fixture_bind": "127.0.0.1"})
        if private_link_root_port:
            intent.update({"private_link_root_port": "amnezia-link-rp", "private_link_root_port_chassis": 31, "private_link_root_port_slot": 30})
        json_dump(intent_path, intent)
        if profile.get("uefi"):
            env_profile = profiles_root() / str(profile.get("profile_env", ""))
            if not env_profile.is_file():
                raise LabError(f"Windows UEFI profile contract is missing: {env_profile}")
            # Normal runs clone the sealed firmware state. Distribution OVMF
            # vars and an empty TPM state belong only to bootstrap, never to a
            # release test that could silently lose Boot Manager/BitLocker.
            vars_golden = ensure_owned_child(self.root, self.root / str(profile["ovmf_vars_golden"]), "golden OVMF vars")
            tpm_golden = ensure_owned_child(self.root, self.root / str(profile["tpm_state_golden"]), "golden TPM state")
            code = Path(str(profile.get("ovmf_code")))
            if not code.is_file() or not vars_golden.is_file() or not tpm_golden.is_dir():
                raise LabError("Windows release run requires the sealed OVMF vars and TPM state bundle")
            vars_copy = run_dir / "OVMF_VARS.fd"
            shutil.copyfile(vars_golden, vars_copy)
            tpm_dir = run_dir / "tpm-state"
            shutil.copytree(tpm_golden, tpm_dir)
            tpm_socket = run_dir / "swtpm.sock"
            intent.update({"state": "tpm-prepared", "tpm_socket": str(tpm_socket), "tpm_state": str(tpm_dir), "ovmf_vars": str(vars_copy)})
            json_dump(intent_path, intent)
            swtpm = resolve_host_executable("swtpm")
            tpm_log = (run_dir / "swtpm.log").open("ab")
            tpm = subprocess.Popen([swtpm, "socket", "--tpm2", "--tpmstate", f"dir={tpm_dir}", "--ctrl", f"type=unixio,path={tpm_socket}"], stdout=tpm_log, stderr=subprocess.STDOUT, shell=False, start_new_session=True)
            tpm_log.close()
            intent.update({"state": "tpm-spawned", "tpm_pid": tpm.pid, "tpm_proc_start_time": proc_start_time(tpm.pid)})
            json_dump(intent_path, intent)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not tpm_socket.exists():
                if tpm.poll() is not None:
                    raise LabError("swtpm exited before creating its owned control socket")
                time.sleep(0.1)
            if not tpm_socket.exists():
                tpm.terminate()
                raise LabError("swtpm did not create its owned control socket")
            argv += ("-drive", f"if=pflash,format=raw,readonly=on,file={code}", "-drive", f"if=pflash,format=raw,file={vars_copy}", "-chardev", f"socket,id=chrtpm,path={tpm_socket}", "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis,tpmdev=tpm0")
        else:
            tpm = None
        executable = resolve_host_executable(argv[0])
        log_path = run_dir / "qemu.log"
        if tpm is not None:
            intent.update({"tpm_pid": tpm.pid, "tpm_proc_start_time": proc_start_time(tpm.pid), "tpm_socket": str(tpm_socket), "tpm_state": str(tpm_dir), "ovmf_vars": str(vars_copy)})
        log = log_path.open("ab")
        try:
            # Persist the launch intent before Popen.  If the controller dies
            # after Popen and before state save, reset/preflight can still
            # prove exactly which resources belong to this run.
            json_dump(intent_path, intent)
            proc = subprocess.Popen([executable, *argv[1:]], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, shell=False, close_fds=True, start_new_session=True)
            if proc.poll() is not None:
                raise LabError(f"QEMU exited during startup with code {proc.returncode}")
            intent.update({"state": "spawned", "pid": proc.pid, "proc_start_time": proc_start_time(proc.pid)})
            json_dump(intent_path, intent)
        except Exception:
            for owned_process in (proc, tpm):
                if owned_process is not None and owned_process.poll() is None:
                    owned_process.terminate()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and any(item is not None and item.poll() is None for item in (proc, tpm)):
                time.sleep(0.1)
            if any(item is not None and item.poll() is None for item in (proc, tpm)):
                raise LabError("startup process did not exit; preserving owned overlay and firmware copies for recovery")
            self._remove_owned_socket(qmp, "QMP socket")
            self._remove_owned_socket(qga, "QGA socket")
            self._remove_owned_socket(vnc, "VNC socket")
            self._remove_owned_overlay(overlay)
            for generated in (run_dir / "OVMF_VARS.fd", run_dir / "tpm-state"):
                if generated.is_dir():
                    shutil.rmtree(generated)
                elif generated.exists():
                    generated.unlink()
            if intent_path.is_symlink():
                raise LabError("QEMU spawn intent became symlinked during startup cleanup")
            if intent_path.exists():
                intent_path.unlink()
            raise
        log.close()
        vm = {"pid": proc.pid, "proc_start_time": proc_start_time(proc.pid), "uuid": vm_uuid, "uid": os.getuid() if hasattr(os, "getuid") else None, "qmp_socket": str(qmp), "qga_socket": str(qga), "vnc_socket": str(vnc) if profile.get("display") == "vnc-unix" else None, "argv": list(argv), "started_at": utc_now()}
        if fixture_host_port is not None:
            vm.update({"consumer_fixture": True, "fixture_host_port": fixture_host_port, "fixture_guest_port": CONSUMER_FIXTURE_GUEST_PORT, "fixture_bind": "127.0.0.1"})
        if tpm is not None:
            vm["tpm_pid"] = tpm.pid; vm["tpm_proc_start_time"] = proc_start_time(tpm.pid); vm["tpm_socket"] = str(tpm_socket); vm["tpm_state"] = str(tpm_dir); vm["ovmf_vars"] = str(vars_copy)
        run["profiles"][profile_id].update(status="started", vm=vm)
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        if intent_path.is_symlink():
            raise LabError("QEMU spawn intent became symlinked before commit")
        if intent_path.exists():
            intent_path.unlink()
        return vm

    def _run_android_adapter(self, run_id: str, profile_id: str, command: str, *args: str) -> dict[str, Any]:
        profile = load_profiles()[profile_id]
        run = self.get_run(run_id)
        native_windows = self.android_backend == "windows"
        script = ensure_repo_adapter(ANDROID_WINDOWS_ADAPTER_RELATIVE if native_windows else profile.get("adapter_script"))
        if native_windows:
            native_root_raw = os.environ.get("AMNEZIA_ANDROID_WINDOWS_LAB_ROOT_WSL", "").strip()
            native_root_windows = os.environ.get("AMNEZIA_ANDROID_WINDOWS_LAB_ROOT", "").strip()
            native_sdk_windows = os.environ.get("AMNEZIA_ANDROID_WINDOWS_SDK_ROOT", "").strip()
            native_sdk_wsl = os.environ.get("AMNEZIA_ANDROID_WINDOWS_SDK_ROOT_WSL", "").strip()
            native_root = Path(native_root_raw).resolve()
            if (not native_root_raw.startswith(("/mnt/", "/var/lib/amnezia-release-lab/")) or not native_root_windows or not native_sdk_windows or not native_sdk_wsl):
                raise LabError("native Windows Android backend requires private Windows SDK/root paths")
            if native_root_raw.startswith("/mnt/") and windows_path_for_wsl(Path(native_root_raw)).lower().rstrip("/") != native_root_windows.replace("\\", "/").lower().rstrip("/"):
                raise LabError("native Windows Android root mappings disagree")
            if not native_sdk_wsl.startswith("/mnt/") or windows_path_for_wsl(Path(native_sdk_wsl)).lower().rstrip("/") != native_sdk_windows.replace("\\", "/").lower().rstrip("/"):
                raise LabError("native Windows Android SDK mappings disagree")
            if not native_root_raw.startswith("/var/lib/amnezia-release-lab/"):
                if not (native_root_raw.startswith("/mnt/") and native_root.name == "android-release-lab-native"):
                    raise LabError("native Windows Android root must stay under the controller-owned state root or fixed private workspace root")
            adapter_root = ensure_owned_child(native_root, native_root / run_id, "native Windows Android adapter root")
            native_root_windows = native_root_windows.replace("\\", "/")
            native_sdk_windows = native_sdk_windows.replace("\\", "/")
        else:
            native_root_windows = ""
            native_sdk_windows = ""
            adapter_root = ensure_owned_child(self.root, self.root / "android" / run_id, "Android adapter root")
        env = os.environ.copy()
        env["AMNEZIA_ANDROID_LAB_ROOT"] = str(adapter_root)
        env["AMNEZIA_ANDROID_LAB_RUN_ID"] = run_id
        env["AMNEZIA_ANDROID_LAB_PROFILE_ID"] = profile_id
        env["AMNEZIA_ANDROID_SDK_ROOT"] = str(self.root / "android" / "sdk")
        env["AMNEZIA_ANDROID_SDK_LOCK"] = str(self.root / "android" / "work" / "sdk-lock-api35-tools13114758.json")
        lane_nonce = int(hashlib.sha256(f"{run_id}:{profile_id}".encode()).hexdigest()[:8], 16)
        env["AMNEZIA_ANDROID_ADB_PORT"] = str(5040 + 2 * (lane_nonce % 30))
        env["AMNEZIA_ANDROID_EMULATOR_PORT"] = str(5556 + 2 * (lane_nonce % 60))
        env["AMNEZIA_ANDROID_LAB_CONTROLLER_RECEIPT"] = str(adapter_root / "receipts" / "controller" / run_id / f"{profile_id}.json")
        if native_windows:
            env["AMNEZIA_ANDROID_WINDOWS_LAB_ROOT"] = native_root_windows
            env["AMNEZIA_ANDROID_WINDOWS_SDK_ROOT"] = native_sdk_windows
        run = self.get_run(run_id)
        if native_windows:
            env["AMNEZIA_ANDROID_BASELINE_VERSION"] = str(run["baseline_version"])
            env["AMNEZIA_ANDROID_RELEASE_VERSION"] = str(run["candidate_version"])
        if isinstance(run.get("manifest"), dict):
            env["AMNEZIA_ANDROID_RELEASE_MANIFEST"] = str(run["manifest"]["path"])
        if isinstance(run.get("baseline_manifest"), dict):
            env["AMNEZIA_ANDROID_BASELINE_MANIFEST"] = str(run["baseline_manifest"]["path"])
        if command == "test-update":
            fixture = run.get("server_fixture") or {}
            endpoint = str(fixture.get("guest_endpoint") or os.environ.get("AMNEZIA_LAB_SERVER_ENDPOINT", "")).strip()
            if not endpoint:
                raise LabError("Android update requires the planned server-router fixture guest endpoint")
            attempt = run.get("android_update_attempt") or {}
            attempt_nonce = str(attempt.get("nonce") or "")
            if (attempt_nonce != str(fixture.get("attempt_nonce") or "")
                    or not android_attempt_matches_fixture(attempt, fixture, run_id, profile_id)
                    or attempt.get("guest_endpoint") != endpoint):
                raise LabError("Android update fixture and adapter attempt context are not the same planned run")
            env["AMNEZIA_ANDROID_FIXTURE_GUEST_ENDPOINT"] = endpoint
            env["AMNEZIA_ANDROID_UPDATE_ATTEMPT_NONCE"] = attempt_nonce
            host_port = fixture.get("host_port")
            if not isinstance(host_port, int) or not (1024 <= host_port <= 65535):
                raise LabError("Android update fixture has no bounded host port")
            env["AMNEZIA_ANDROID_FIXTURE_HOST_PORT"] = str(host_port)
        command_outputs = []
        if native_windows:
            launcher = os.environ.get("AMNEZIA_ANDROID_WINDOWS_POWERSHELL_WSL", HYPERV_POWERSHELL_WSL)
            if not launcher.startswith("/mnt/") or not Path(launcher).is_file():
                raise LabError("native Windows Android backend requires a pinned Windows PowerShell executable")
            base_command = [launcher, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", windows_path_for_wsl(script)]
            native_controller_receipt = f"{native_root_windows}/{run_id}/receipts/controller/{run_id}/{profile_id}.json"
            release_manifest_windows = ""
            if isinstance(run.get("manifest"), dict):
                release_manifest_windows = windows_path_for_wsl(Path(str(run["manifest"]["path"])))
            base_command += ["-LabRoot", native_root_windows, "-SdkRoot", native_sdk_windows, "-RunId", run_id, "-ApiLevel", env.get("AMNEZIA_ANDROID_API_LEVEL", "35"), "-AdbPort", env["AMNEZIA_ANDROID_ADB_PORT"], "-EmulatorPort", env["AMNEZIA_ANDROID_EMULATOR_PORT"], "-GpuMode", env.get("AMNEZIA_ANDROID_GPU_MODE", "swangle"), "-ControllerReceiptPath", native_controller_receipt, "-BaselineVersion", str(run["baseline_version"]), "-ReleaseVersion", str(run["candidate_version"]), "-ProductGo", env.get("AMNEZIA_ANDROID_NATIVE_PRODUCT_GO", ""), "-ExpectedVersionCode", env.get("AMNEZIA_ANDROID_EXPECTED_VERSION_CODE", "0"), "-ExpectedReleaseVersionCode", env.get("AMNEZIA_ANDROID_RELEASE_VERSION_CODE", "0"), "-FixtureHostPort", env.get("AMNEZIA_ANDROID_FIXTURE_HOST_PORT", "0"), "-ReleaseManifestPath", release_manifest_windows]
        else:
            launcher = resolve_host_executable("bash")
            base_command = [launcher, str(script)]
        action_args = list(args)
        if native_windows:
            action_args = [windows_path_for_wsl(Path(arg)) if str(arg).startswith("/mnt/") else str(arg) for arg in action_args]
        if command == "start":
            create_result = subprocess.run(base_command + ["create"], cwd=str(repo_root()), env=env, shell=False, text=False, capture_output=True, timeout=900, start_new_session=True)
            if create_result.returncode != 0:
                raise LabError(f"Android adapter create failed: {create_result.stderr.decode('utf-8-sig', errors='replace')[-1500:]}")
            command_outputs.append(create_result.stdout.decode('utf-8-sig', errors='replace'))
        if native_windows and command == "start":
            adapter_work = adapter_root / "work"
            adapter_work.mkdir(parents=True, exist_ok=True)
            start_stdout_path = adapter_work / "controller.start.stdout.log"
            start_stderr_path = adapter_work / "controller.start.stderr.log"
            ownership_path = adapter_root / "ownership.json"
            with start_stdout_path.open("wb") as start_stdout, start_stderr_path.open("wb") as start_stderr:
                native_command = [command, "-Arguments", *action_args] if action_args else [command]
                process = subprocess.Popen(base_command + native_command, cwd=str(repo_root()), env=env, shell=False, stdout=start_stdout, stderr=start_stderr, start_new_session=True)
                deadline = time.monotonic() + 300
                native_result = None
                while time.monotonic() < deadline:
                    if ownership_path.is_file() and not ownership_path.is_symlink():
                        try:
                            candidate = json.loads(ownership_path.read_text(encoding="utf-8"))
                        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                            candidate = None
                        if isinstance(candidate, dict) and candidate.get("state") == "running":
                            native_result = candidate
                            break
                    if process.poll() is not None and process.returncode != 0:
                        error_text = start_stderr_path.read_text(encoding="utf-8", errors="replace")[-1500:]
                        raise LabError(f"Android adapter start failed: {error_text}")
                    time.sleep(1)
                if native_result is None:
                    raise LabError("Android adapter start timed out waiting for the owned native run marker; preserving owned state")
            result_stdout = json.dumps(native_result, sort_keys=True)
            result = subprocess.CompletedProcess(base_command + ([command, "-Arguments", *action_args] if action_args else [command]), 0, stdout=result_stdout.encode(), stderr=b"")
        else:
            native_command = [command, "-Arguments", *action_args] if native_windows and action_args else [command, *action_args]
            result = subprocess.run(base_command + native_command, cwd=str(repo_root()), env=env, shell=False, text=False, capture_output=True, timeout=900, start_new_session=True)
            if result.returncode != 0:
                raise LabError(f"Android adapter {command} failed: {result.stderr.decode('utf-8-sig', errors='replace')[-1500:]}")
        run = self.get_run(run_id)
        if not native_windows or command != "start":
            result_stdout = result.stdout.decode('utf-8-sig', errors='replace')
        native_result = None
        if native_windows:
            try:
                native_result = json.loads(result_stdout)
            except json.JSONDecodeError as exc:
                raise LabError(f"native Windows Android adapter returned invalid JSON: {exc}") from exc
            self._validate_native_android_result(native_result, run_id, profile_id, command)
        native_vm = {"backend": "android-windows-adapter", "root": str(adapter_root), "script": str(script), "native_result": native_result} if native_windows and (command == "start" or not isinstance(run["profiles"][profile_id].get("vm"), dict)) else None
        run["profiles"][profile_id].update(status="started" if command == "start" else "tested", vm=native_vm if native_vm is not None else run["profiles"][profile_id].get("vm"), adapter_output=("\n".join(command_outputs) + result_stdout)[-4000:])
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return {"backend": "android-windows-adapter" if native_windows else "android-adapter", "command": command, "stdout": result_stdout[-4000:], "root": str(adapter_root)}

    def _validate_native_android_result(self, result: Mapping[str, Any], run_id: str, profile_id: str, command: str) -> None:
        product_receipt = None
        if command in {"install-baseline", "test-update", "collect"}:
            product_receipt = result.get("product_receipt")
            if (result.get("schema") != 1 or result.get("run_id") != run_id or result.get("profile") != profile_id
                    or result.get("backend") != "android-windows" or result.get("transport") != "android-adapter"
                    or result.get("origin") != "guest" or result.get("injected") is not False
                    or not isinstance(result.get("native_probe"), dict) or not isinstance(product_receipt, dict)):
                raise LabError("native Android product result envelope is incomplete")
            result = result["native_probe"]
        if (result.get("schema") != 1 or result.get("run_id") != run_id or result.get("profile") != profile_id
                or result.get("backend") != "android-windows" or result.get("transport") != "android-adapter"
                or result.get("origin") != "guest" or result.get("injected") is not False):
            raise LabError("native Android adapter result is not bound guest-origin evidence")
        if command == "reset":
            if result.get("state") != "reset":
                raise LabError("native Android reset result is not a confirmed reset")
            return
        marker = result if command == "start" else result.get("marker")
        if not isinstance(marker, dict) or marker.get("run_id") != run_id or marker.get("profile") != profile_id or marker.get("backend") != "android-windows":
            raise LabError("native Android ownership marker identity mismatch")
        serial = result.get("serial")
        avd_name = result.get("avd_name")
        if not isinstance(serial, str) or not re.fullmatch(r"emulator-\d+", serial) or not isinstance(avd_name, str) or not avd_name:
            raise LabError("native Android serial or AVD identity is invalid")
        for field in ("emulator", "qemu", "adb_server"):
            identity = result.get(field)
            if (not isinstance(identity, dict) or not isinstance(identity.get("pid"), int)
                    or not isinstance(identity.get("start_time_utc_ticks"), int)
                    or not isinstance(identity.get("executable"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", str(identity.get("executable_sha256", "")))
                    or not isinstance(identity.get("command_line"), str)):
                raise LabError(f"native Android {field} process identity is incomplete")
        if "-avd" not in result["emulator"]["command_line"] or avd_name not in result["emulator"]["command_line"] or "-port" not in result["emulator"]["command_line"]:
            raise LabError("native Android emulator command is not bound to the planned AVD/port")
        if "-avd" not in result["qemu"]["command_line"] or avd_name not in result["qemu"]["command_line"] or "-port" not in result["qemu"]["command_line"]:
            raise LabError("native Android QEMU command is not bound to the planned AVD/port")
        if "-L" not in result["adb_server"]["command_line"]:
            raise LabError("native Android ADB command is not dedicated")
        if command == "probe":
            nonce = marker.get("identity_nonce")
            expected_marker = f"amnezia-release-lab:{run_id}:{profile_id}:{nonce}"
            if result.get("guest_marker") != expected_marker:
                raise LabError("native Android guest marker is not bound to this run/profile/nonce")
            if result.get("qemu_uuid") and result.get("qemu_uuid_source") != "guest-property":
                raise LabError("native Android QEMU UUID source is inconsistent")
            if not result.get("qemu_uuid") and result.get("qemu_launch_uuid") != nonce:
                raise LabError("native Android launch UUID fallback is not bound")
            if "x86_64" not in str(result.get("abi_list", "")) or "arm64-v8a" not in str(result.get("abi_list", "")):
                raise LabError("native Android ABI readback lacks x86_64 and arm64-v8a")
        if product_receipt is not None:
            planned = (self.get_run(run_id).get("baseline_artifacts", {}) if command == "install-baseline" else self.get_run(run_id).get("artifacts", {})).get("android-arm64-v8a") or {}
            identity = product_receipt.get("device_identity") or {}
            if (product_receipt.get("schema") != 1 or product_receipt.get("run_id") != run_id or product_receipt.get("profile") != profile_id
                    or product_receipt.get("transport") != "android-adapter" or product_receipt.get("origin") != "guest"
                    or product_receipt.get("injected") is not False or product_receipt.get("guest_marker") != f"amnezia-release-lab:{run_id}:{profile_id}"
                    or product_receipt.get("nonce") != identity.get("launchUuid")
                    or product_receipt.get("artifact_sha256") != planned.get("sha256") or product_receipt.get("artifact_size") != planned.get("size")
                    or not isinstance(product_receipt.get("steps"), list) or any(not isinstance(step, dict) or not isinstance(step.get("passed"), bool) for step in product_receipt["steps"])):
                raise LabError("native Android product receipt is not bound to the live probe/planned artifact")

    def owned_vm(self, run_id: str, profile_id: str) -> dict[str, Any]:
        vm = self.get_run(run_id)["profiles"].get(profile_id, {}).get("vm")
        if not isinstance(vm, dict):
            raise LabError("profile VM has not been started")
        pid = int(vm["pid"]); cmdline_path = Path(f"/proc/{pid}/cmdline")
        if not cmdline_path.is_file():
            raise LabError("owned QEMU process is not running")
        if vm.get("proc_start_time") != proc_start_time(pid):
            raise LabError("QEMU PID was reused by another process")
        if vm.get("uid") is not None and hasattr(os, "getuid") and vm.get("uid") != os.getuid():
            raise LabError("QEMU process owner changed")
        cmdline = cmdline_path.read_bytes().decode(errors="replace").replace("\x00", " ")
        required_tokens = [f"-uuid {vm['uuid']}", str(Path(vm["qmp_socket"]).resolve()), str(Path(vm["qga_socket"]).resolve()), "-accel kvm", "-cpu host"]
        if vm.get("consumer_fixture") is True:
            required_tokens.extend(("-netdev user,id=labnet,restrict=on", f"hostfwd=tcp:127.0.0.1:{int(vm['fixture_host_port'])}-:{CONSUMER_FIXTURE_GUEST_PORT}", "-device e1000,netdev=labnet,id=labnet-device"))
        else:
            required_tokens.append("-nic none")
        if vm.get("private_link_root_port") is not None:
            if (vm.get("private_link_root_port"), vm.get("private_link_root_port_chassis"), vm.get("private_link_root_port_slot")) != ("amnezia-link-rp", 31, 30):
                raise LabError("owned QEMU lacks the frozen private-link root port")
            required_tokens.append("-device pcie-root-port,id=amnezia-link-rp,chassis=31,slot=30")
        if "qemu-system-x86_64" not in Path(vm["argv"][0]).name or any(token not in cmdline for token in required_tokens):
            raise LabError("QEMU identity does not match owned PID/UUID/QMP socket")
        if vm.get("vnc_socket") and str(Path(vm["vnc_socket"]).resolve()) not in cmdline:
            raise LabError("QEMU VNC socket is not bound to the owned process")
        return vm

    @mutation_operation
    def guest_probe(self, run_id: str, profile_id: str) -> dict[str, Any]:
        profile = load_profiles()[profile_id]
        if profile.get("backend") == "android-adapter":
            return self._run_android_adapter(run_id, profile_id, "probe")
        run = self.get_run(run_id)
        if self.uses_hyperv(run, profile_id):
            case_id = (run.get("profiles", {}).get(profile_id, {}).get("vm") or {}).get("case_id", "control")
            result = self.hyperv_call("probe", run_id=run_id, CaseId=case_id, credential=True)
            if result.get("transport") != HYPERV_TRANSPORT or result.get("origin") != "guest" or result.get("injected") is True:
                raise LabError("Hyper-V readiness probe is not guest-origin PowerShell Direct evidence")
            return result
        vm = self.owned_vm(run_id, profile_id)
        qmp = QmpClient(Path(vm["qmp_socket"]))
        qga = QgaClient(Path(vm["qga_socket"]))
        deadline = time.monotonic() + 180
        last_error = "QGA sync failed"
        while time.monotonic() < deadline:
            try:
                require_qmp_return(qmp.request("query-status"), "query-status")
                if qga.sync():
                    return {"profile": profile_id, "transport": "qga", "qmp_status": True, "guest_sync": True, "observed_at": utc_now()}
            except (LabError, OSError, socket.timeout) as exc:
                last_error = str(exc)
            time.sleep(2)
        raise LabError(last_error)

    @mutation_operation
    def nested_android_probe(self, run_id: str) -> dict[str, Any]:
        """Probe nested Android prerequisites in an owned Linux guest only.

        This deliberately stops at an OS capability check.  It does not stage
        an APK, start Cuttlefish, or alter networking; a later nested backend
        may proceed only from this immutable guest-origin result.
        """
        profile_id = "linux-headless-x64"
        run = self.get_run(run_id)
        if profile_id not in run.get("profiles", {}):
            raise LabError("nested Android probe requires the owned Linux headless profile record")
        profile = load_profiles()[profile_id]
        if profile.get("backend") != "qemu-linux" or profile.get("guest_agent") != "qga":
            raise LabError("nested Android probe requires a QGA Linux guest")
        if not isinstance(run["profiles"][profile_id].get("vm"), dict):
            self.start(run_id, profile_id)
        vm = self.owned_vm(run_id, profile_id)
        qga_socket = Path(vm["qga_socket"])
        qga = QgaClient(qga_socket)
        deadline = time.monotonic() + 120
        qga_errors: list[str] = []
        while time.monotonic() < deadline:
            try:
                if qga.sync():
                    break
            except (LabError, OSError, socket.timeout) as exc:
                qga_errors.append(str(exc))
            time.sleep(2)
        else:
            result = {
                "schema": 1, "run_id": run_id, "profile": profile_id,
                "nested_profile": "android-arm64-v8a", "transport": "qga",
                "origin": "guest", "injected": False, "passed": False,
                "status": "blocked", "guest_binding": {
                    "uuid": vm.get("uuid"), "pid": vm.get("pid"),
                    "proc_start_time": vm.get("proc_start_time"),
                    "qmp_socket": vm.get("qmp_socket"), "qga_socket": str(qga_socket),
                },
                "probe": {"passed": False, "reason": "QGA readiness timeout", "errors": qga_errors[-10:]},
                "observed_at": utc_now(),
            }
            run = self.get_run(run_id)
            run["profiles"][profile_id]["nested_android_probe"] = result
            state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
            return result
        # This marker is a controller-owned, non-artifact probe input.  The
        # APK and all nested runtime payloads remain intentionally unstaged.
        qga.write_file("/tmp/amnezia-release-lab-marker", f"amnezia-release-lab:{run_id}:{profile_id}".encode())
        marker = qga.read_file("/tmp/amnezia-release-lab-marker").decode("utf-8", errors="strict")
        expected_marker = f"amnezia-release-lab:{run_id}:{profile_id}"
        if marker != expected_marker:
            raise LabError("nested Android OS probe guest marker is not bound to this run/profile")
        command = """set -eu
config=/boot/config-$(uname -r)
vhost=absent; virtio=absent
if [ -r "$config" ]; then
  vhost=$(sed -n 's/^CONFIG_VHOST_VSOCK=//p' "$config" | head -n1)
  virtio=$(sed -n 's/^CONFIG_VIRTIO_VSOCKETS=//p' "$config" | head -n1)
  [ -n "$vhost" ] || vhost=absent
  [ -n "$virtio" ] || virtio=absent
fi
loaded=false; [ -d /sys/module/vhost_vsock ] && loaded=true
module_load_attempted=false
module_load_error=
if [ "$vhost" = m ] && [ "$loaded" = false ]; then
  module_load_attempted=true
  modprobe vhost_vsock 2>/tmp/amnezia-vhost-vsock-modprobe.err || module_load_error=$(tr '\n\r\"' '   ' </tmp/amnezia-vhost-vsock-modprobe.err | head -c 512)
  [ -d /sys/module/vhost_vsock ] && loaded=true
fi
device=false; [ -c /dev/vhost-vsock ] && device=true
passed=false
if { [ "$vhost" = y ] || { [ "$vhost" = m ] && [ "$loaded" = true ]; }; } && { [ "$virtio" = y ] || [ "$virtio" = m ]; } && [ "$device" = true ]; then passed=true; fi
printf '{\"uname\":\"%s\",\"kernel_config\":\"%s\",\"config_vhost_vsock\":\"%s\",\"config_virtio_vsockets\":\"%s\",\"module_load_attempted\":%s,\"module_load_error\":\"%s\",\"vhost_vsock_module_loaded\":%s,\"vhost_vsock_device\":%s,\"passed\":%s}\\n' "$(uname -sr)" "$config" "$vhost" "$virtio" "$module_load_attempted" "$module_load_error" "$loaded" "$device" "$passed"
"""
        try:
            response = qga.guest_exec_wait("/bin/sh", ["-c", command], timeout=30)
            probe = json.loads(response.get("stdout", ""))
        except (LabError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            probe = {"passed": False, "reason": str(exc)}
        if not isinstance(probe, dict) or probe.get("passed") is not True:
            result = {"schema": 1, "run_id": run_id, "profile": profile_id, "nested_profile": "android-arm64-v8a", "transport": "qga", "origin": "guest", "injected": False, "guest_marker": marker, "guest_binding": {"uuid": vm.get("uuid"), "pid": vm.get("pid"), "proc_start_time": vm.get("proc_start_time"), "qmp_socket": vm.get("qmp_socket"), "qga_socket": vm.get("qga_socket")}, "probe": probe, "passed": False, "status": "blocked", "observed_at": utc_now()}
        else:
            result = {"schema": 1, "run_id": run_id, "profile": profile_id, "nested_profile": "android-arm64-v8a", "transport": "qga", "origin": "guest", "injected": False, "guest_marker": marker, "guest_binding": {"uuid": vm.get("uuid"), "pid": vm.get("pid"), "proc_start_time": vm.get("proc_start_time"), "qmp_socket": vm.get("qmp_socket"), "qga_socket": vm.get("qga_socket")}, "probe": probe, "passed": True, "status": "ready-for-reviewed-nested-runtime", "observed_at": utc_now()}
        run = self.get_run(run_id)
        run["profiles"][profile_id]["nested_android_probe"] = result
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return result

    @mutation_operation
    def start_consumer_fixture(self, run_id: str, manifest_path: Path, apk_path: Path) -> dict[str, Any]:
        """Upload the planned signed candidate to an owned server-router guest."""
        self.assert_mutation_context()
        profile = load_profiles().get("server-router")
        if not isinstance(profile, dict) or profile.get("consumer_fixture") is not True:
            raise LabError("consumer fixture is disabled outside server-router")
        run = self.get_run(run_id)
        vm = self.owned_vm(run_id, "server-router")
        guest_endpoint = str(os.environ.get("AMNEZIA_LAB_SERVER_ENDPOINT", "")).strip()
        try:
            endpoint_ip = ipaddress.ip_address(guest_endpoint)
        except ValueError as exc:
            raise LabError("consumer fixture requires an IPv4 lab endpoint") from exc
        if endpoint_ip.version != 4 or not endpoint_ip.is_private:
            raise LabError("consumer fixture endpoint must be a private IPv4 lab address")
        if isinstance(run.get("server_fixture"), dict) and not run["server_fixture"].get("stopped_at"):
            raise LabError("consumer fixture is already running for this run")
        artifact = run.get("artifacts", {}).get("android-arm64-v8a")
        if not isinstance(artifact, dict):
            raise LabError("consumer fixture requires the planned Android ARM64 candidate")
        manifest_path = Path(os.path.abspath(str(manifest_path)))
        apk_path = Path(os.path.abspath(str(apk_path)))
        candidate = artifact_record(apk_path)
        if candidate.get("sha256") != artifact.get("sha256"):
            raise LabError("fixture APK differs from the planned candidate digest")
        planned_manifest = run.get("manifest") or {}
        if not isinstance(planned_manifest, dict) or artifact_record(manifest_path).get("sha256") != planned_manifest.get("sha256"):
            raise LabError("fixture manifest differs from the planned signed manifest")
        public_key = run.get("manifest_public_key") or {}
        if not isinstance(public_key, dict):
            raise LabError("fixture requires the planned manifest public key")
        validate_signed_manifest(manifest_path, Path(public_key["path"]), version=str(run["candidate_version"]), artifacts=run.get("artifacts", {}))
        qga = QgaClient(Path(vm["qga_socket"]))
        if not qga.sync():
            raise LabError("server-router QGA is not responsive for fixture upload")
        script_source = repo_root() / "deploy" / "release_lab" / "android" / "consumer_fixture_server.py"
        if not script_source.is_file():
            raise LabError("consumer fixture server helper is missing")
        guest_script = "/tmp/amnezia-consumer-fixture.py"
        guest_manifest = "/tmp/amnezia-consumer-fixture-manifest.json"
        guest_apk = "/tmp/amnezia-consumer-fixture.apk"
        qga.write_file(guest_script, script_source.read_bytes())
        qga.write_file(guest_manifest, manifest_path.read_bytes())
        qga.write_file(guest_apk, apk_path.read_bytes())
        request_log = "/tmp/amnezia-consumer-fixture-requests.jsonl"
        attempt_nonce = secrets.token_hex(24)
        started = qga.guest_exec("/usr/bin/python3", [guest_script, "--manifest", guest_manifest, "--apk", guest_apk, "--manifest-sha256", planned_manifest["sha256"], "--apk-sha256", artifact["sha256"], "--run-id", run_id, "--attempt-nonce", attempt_nonce, "--port", str(CONSUMER_FIXTURE_GUEST_PORT), "--request-log", request_log])
        fixture_pid = started.get("pid")
        if not isinstance(fixture_pid, int):
            raise LabError("fixture server guest-exec returned no PID")
        host_port = int(vm["fixture_host_port"])
        health_url = f"http://127.0.0.1:{host_port}/healthz"
        deadline = time.monotonic() + 30
        health = None
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(health_url, timeout=2) as response:
                    health = json.loads(response.read().decode("utf-8"))
                if health.get("status") == "ok" and health.get("run_id") == run_id:
                    break
            except (OSError, ValueError, json.JSONDecodeError):
                time.sleep(0.5)
        if not isinstance(health, dict) or health.get("status") != "ok" or health.get("run_id") != run_id:
            raise LabError("consumer fixture did not become reachable through owned loopback hostfwd")
        with urllib.request.urlopen(f"http://127.0.0.1:{host_port}/manifest.json", timeout=5) as response:
            manifest_bytes = response.read()
        if hashlib.sha256(manifest_bytes).hexdigest() != planned_manifest["sha256"]:
            raise LabError("fixture manifest HTTP bytes differ from signed planned manifest")
        fixture_bind = str(vm.get("fixture_bind") or "")
        run["android_update_attempt"] = {"nonce": attempt_nonce, "guest_endpoint": guest_endpoint, "run_id": run_id, "profile": "android-arm64-v8a", "fixture_host_port": host_port, "fixture_guest_port": CONSUMER_FIXTURE_GUEST_PORT, "fixture_bind": fixture_bind, "created_at": utc_now()}
        run["server_fixture"] = {"pid": fixture_pid, "guest_request_log": request_log, "host_port": host_port, "guest_port": CONSUMER_FIXTURE_GUEST_PORT, "fixture_bind": fixture_bind, "guest_endpoint": guest_endpoint, "attempt_nonce": attempt_nonce, "run_id": run_id, "manifest_sha256": planned_manifest["sha256"], "artifact_sha256": artifact["sha256"], "artifact_size": artifact["size"], "health": health, "transport": "qga-upload-http-hostfwd", "consumer_fixture": True, "observed_at": utc_now()}
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return run["server_fixture"]

    @mutation_operation
    def stop_consumer_fixture(self, run_id: str) -> dict[str, Any]:
        self.assert_mutation_context()
        run = self.get_run(run_id)
        fixture = run.get("server_fixture") or {}
        pid = fixture.get("pid")
        if not isinstance(pid, int):
            raise LabError("consumer fixture has no owned guest PID")
        vm = self.owned_vm(run_id, "server-router")
        qga = QgaClient(Path(vm["qga_socket"]))
        qga.guest_exec_wait("/bin/kill", ["-TERM", str(pid)], timeout=10)
        run["server_fixture"]["stopped_at"] = utc_now()
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return {"run_id": run_id, "pid": pid, "stopped": True}

    @mutation_operation
    def archive_consumer_fixture_evidence(self, run_id: str) -> dict[str, Any]:
        """Archive the fixture request log while its owned server VM is live."""
        self.assert_mutation_context()
        run = self.get_run(run_id)
        fixture = run.get("server_fixture") or {}
        if not fixture:
            return {}
        existing = fixture.get("evidence_archive")
        if isinstance(existing, str) and Path(existing).is_file():
            return json.loads(Path(existing).read_text(encoding="utf-8"))
        vm = self.owned_vm(run_id, "server-router")
        request_log = fixture.get("guest_request_log")
        if not isinstance(request_log, str) or not request_log.startswith("/tmp/"):
            raise LabError("consumer fixture request log path is not a guest-private path")
        qga = QgaClient(Path(vm["qga_socket"]))
        size_response = qga.guest_exec_wait("/usr/bin/stat", ["-c", "%s", request_log], timeout=30)
        try:
            log_size = int(str(size_response.get("stdout", "")).strip())
        except ValueError as exc:
            raise LabError("consumer fixture request log size is invalid") from exc
        if log_size < 0 or log_size > 8 * 1024 * 1024:
            raise LabError("consumer fixture request log exceeds the archive bound")
        log_bytes = qga.read_file(request_log)
        archive_root = ensure_owned_child(self.root, self.root / "exports" / run_id / "server-router" / "consumer-fixture", "consumer fixture evidence")
        archive_root.mkdir(parents=True, exist_ok=True)
        log_destination = ensure_owned_child(self.root, archive_root / "requests.jsonl", "consumer fixture request log")
        immutable_bytes_dump(log_destination, log_bytes)
        log_sha, log_size_readback = sha256_file(log_destination)
        record = {
            "schema": 1, "run_id": run_id, "profile": "server-router", "origin": "guest", "injected": False,
            "transport": "qga", "captured_at": utc_now(),
            "artifact_sha256": fixture.get("artifact_sha256"), "artifact_size": fixture.get("artifact_size"), "manifest_sha256": fixture.get("manifest_sha256"),
            "guest_binding": {key: vm.get(key) for key in ("pid", "proc_start_time", "uid", "uuid", "qmp_socket", "qga_socket", "started_at")},
            "request_log": {"guest_path": request_log, "archive_path": str(log_destination), "sha256": log_sha, "size": log_size_readback},
            "fixture": {key: fixture.get(key) for key in ("host_port", "guest_port", "guest_endpoint", "attempt_nonce", "run_id", "consumer_fixture")},
        }
        archive_path = ensure_owned_child(self.root, archive_root / "evidence.json", "consumer fixture evidence receipt")
        immutable_json_dump(archive_path, record)
        run["server_fixture"]["evidence_archive"] = str(archive_path)
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return record

    @mutation_operation
    def cleanup_auxiliary_resources(self, run_id: str, profile_id: str) -> None:
        """Close Android's separately-started server fixture before guest reset."""
        if profile_id != "android-arm64-v8a":
            return
        run = self.get_run(run_id)
        if not run.get("server_fixture"):
            if run.get("profiles", {}).get("server-router", {}).get("vm"):
                self.reset(run_id, "server-router")
            return
        self.archive_consumer_fixture_evidence(run_id)
        fixture = self.get_run(run_id).get("server_fixture") or {}
        if not fixture.get("stopped_at"):
            self.stop_consumer_fixture(run_id)
        if self.get_run(run_id).get("profiles", {}).get("server-router", {}).get("vm"):
            self.reset(run_id, "server-router")

    @mutation_operation
    def observe_server(self, run_id: str, ssh_host_key_pin: str) -> dict[str, Any]:
        """Register only live QMP/QGA observations for the isolated test server."""
        run = self.get_run(run_id)
        vm = self.owned_vm(run_id, "server-router")
        expected_pin = os.environ.get("AMNEZIA_LAB_SSH_HOST_KEY_PIN", "")
        if not expected_pin or ssh_host_key_pin != expected_pin or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", ssh_host_key_pin):
            raise LabError("server observation requires the configured canonical lab SSH host-key pin")
        require_qmp_return(QmpClient(Path(vm["qmp_socket"])).request("query-status"), "query-status")
        qga = QgaClient(Path(vm["qga_socket"]))
        if not qga.sync():
            raise LabError("server QGA observation failed")
        observation = {"schema": 1, "role": "isolated-test-server-router", "run_id": run_id, "uuid": vm["uuid"], "qmp_observed": True, "qga_observed": True, "publication_verified": False, "consumer_fixture": bool(vm.get("consumer_fixture")), "outer_artifact_sha256": (run.get("outer_artifact") or {}).get("sha256"), "manifest_sha256": (run.get("manifest") or {}).get("sha256"), "ssh_host_key_pin": ssh_host_key_pin, "endpoint": os.environ.get("AMNEZIA_LAB_SERVER_ENDPOINT", "10.8.1.0"), "observed_at": utc_now()}
        run["server_observation"] = observation
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return observation

    @mutation_operation
    def capture_hyperv_failure(self, run_id: str, profile_id: str, case_id: str, phase: str, artifact: Mapping[str, Any] | None, error: Exception) -> dict[str, Any]:
        """Read back a failed guest before reset; never turn it into a pass."""
        diagnostic: dict[str, Any] = {
            "schema": 1, "status": "failed", "run_id": run_id, "profile": profile_id,
            "case_id": case_id, "phase": phase, "error": str(error),
            "artifact": dict(artifact or {}), "transport": HYPERV_TRANSPORT,
            "origin": "controller-failure-capture", "injected": False, "captured_at": utc_now(),
        }
        collect_error: Exception | None = None
        for attempt in range(3):
            try:
                diagnostic["guest_collect"] = self.hyperv_call("collect", run_id=run_id, CaseId=case_id, credential=True)
                diagnostic["guest_collect_status"] = "readback-complete"
                diagnostic["guest_collect_attempts"] = attempt + 1
                break
            except Exception as current_error:
                collect_error = current_error
                if attempt < 2:
                    time.sleep(5)
        else:
            diagnostic["guest_collect_status"] = "readback-failed"
            diagnostic["guest_collect_attempts"] = 3
            diagnostic["guest_collect_error"] = str(collect_error)
        export_root = ensure_owned_child(self.root, self.root / "exports" / run_id / profile_id / case_id, "Hyper-V failure export")
        export_path = export_root / f"{phase}.json"
        json_dump(export_path, diagnostic)
        run = self.get_run(run_id)
        run.setdefault("profiles", {}).setdefault(profile_id, {}).setdefault("failure_diagnostics", []).append({"case_id": case_id, "phase": phase, "path": str(export_path), "status": "failed", "captured_at": diagnostic["captured_at"]})
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return diagnostic

    @mutation_operation
    def run_steps(self, run_id: str, profile_id: str, selected: Iterable[str] | None = None, preserve_failed_guest: bool = False) -> dict[str, Any]:
        self.assert_mutation_context()
        profiles = load_profiles(); profile = profiles[profile_id]
        artifact_id = artifact_id_for_profile(profile_id)
        planned_run = self.get_run(run_id)
        artifact = planned_run.get("outer_artifact") if profile_id == "windows-x64" else planned_run.get("artifacts", {}).get(artifact_id)
        if not isinstance(artifact, dict):
            raise LabError(f"no planned artifact for guest profile {profile_id}")
        baseline = planned_run.get("baseline_artifacts", {}).get(artifact_id)
        if not isinstance(baseline, dict):
            raise LabError(f"no planned N-1 baseline artifact for guest profile {profile_id}")
        if self.uses_hyperv(planned_run, profile_id):
            if preserve_failed_guest and (selected is None or len(set(selected)) != 1):
                raise LabError("preserve-failed-guest requires exactly one selected Hyper-V case")
            # Validate the runtime-only credential before creating any child
            # disk/VM intent.  The value is consumed again by each PowerShell
            # Direct call and is never persisted in the run record.
            self.hyperv_credential()
            if isinstance(planned_run.get("profiles", {}).get(profile_id, {}).get("vm"), dict):
                try:
                    reset_result = self.hyperv_call("reset", run_id=run_id, CaseId="control", credential=False)
                    if reset_result.get("removed_child") is not True or reset_result.get("parent_sha256_before") != reset_result.get("parent_sha256_after"):
                        raise LabError("Hyper-V control reset did not confirm owned child removal and unchanged parent")
                    self._record_hyperv_case(run_id, profile_id, "control", "reset", reset_result=reset_result)
                    planned_run = self.get_run(run_id)
                except Exception as exc:
                    self._record_hyperv_case(run_id, profile_id, "control", "unsafe", error=str(exc))
                    raise
            runner = profile.get("runner")
            runner_source = (repo_root() / str(runner)).resolve()
            runner_record = planned_run.get("runner_records", {}).get(profile_id) or {}
            if not runner_source.is_file() or runner_record.get("sha256") != sha256_file(runner_source)[0]:
                raise LabError("Hyper-V runner changed after planning")
            thin_candidate = planned_run["artifacts"][artifact_id]
            outer_candidate = planned_run.get("outer_artifact")
            outer_baseline = planned_run.get("baseline_outer_artifact")
            if not isinstance(outer_candidate, dict) or not isinstance(outer_baseline, dict):
                raise LabError("Hyper-V matrix requires candidate and baseline outer artifacts")
            case_specs = windows_case_specs(planned_run)
            profile_progress = planned_run.get("profiles", {}).get(profile_id, {})
            observed_steps = list(profile_progress.get("steps") or [])
            case_receipts = list(profile_progress.get("case_receipts") or [])
            known_case_ids: set[str] = set()
            for prior_receipt in case_receipts:
                prior_case_id = str(prior_receipt.get("case_id") or "") if isinstance(prior_receipt, Mapping) else ""
                if not prior_case_id or prior_case_id in known_case_ids:
                    raise LabError("stored Hyper-V case receipts contain a missing or duplicate case identity")
                known_case_ids.add(prior_case_id)
            case_ids = list(case_specs)
            interactive_only = selected is not None and set(selected) == {"outer-interactive"}
            if selected is not None and not interactive_only:
                requested_cases = set(selected)
                unknown_cases = requested_cases.difference(case_specs)
                if unknown_cases:
                    raise LabError(f"unsupported Hyper-V matrix step(s): {', '.join(sorted(unknown_cases))}")
                case_ids = [case_id for case_id in case_ids if case_id in requested_cases]
            if interactive_only:
                case_ids = []
            conflicts = known_case_ids.intersection(case_ids)
            if conflicts:
                raise LabError(f"Hyper-V case receipt conflict for {sorted(conflicts)[0]}; use a fresh run ID")
            if interactive_only and isinstance(profile_progress.get("interactive_receipt"), Mapping):
                raise LabError("Hyper-V interactive receipt already exists; use a fresh run ID")
            for case_id in case_ids:
                case_created = False
                case_reset = False
                case_failed = False
                current_phase = "create-child"
                current_artifact: Mapping[str, Any] | None = None
                self._record_hyperv_case(run_id, profile_id, case_id, "intended")
                try:
                    child = self.hyperv_call("create-child", run_id=run_id, CaseId=case_id)
                    case_created = True
                    child_record = child.get("child") or {}
                    self._record_hyperv_case(run_id, profile_id, case_id, "created", vm_id=child_record.get("vm_id"), parent_sha256=child_record.get("parent_sha256"), run_root=child_record.get("run_root"), child_vhdx=child_record.get("child_vhdx"))
                    current_phase = "start"
                    started = self.hyperv_call("start", run_id=run_id, CaseId=case_id, credential=True)
                    started_child = started.get("child") or child_record
                    self._record_hyperv_case(run_id, profile_id, case_id, "running", vm_id=started_child.get("vm_id"), parent_sha256=started.get("parent_sha256") or started_child.get("parent_sha256"), run_root=started_child.get("run_root"), child_vhdx=started_child.get("child_vhdx"))
                    case_vm = started.get("child") or child.get("child") or {}
                    current_phase = "probe"
                    probe = self.hyperv_call("probe", run_id=run_id, CaseId=case_id, credential=True)
                    if probe.get("transport") != HYPERV_TRANSPORT or probe.get("origin") != "guest" or probe.get("injected") is not False or probe.get("vm_id") != str(case_vm.get("vm_id") or case_vm.get("Id")) or not probe.get("parent_sha256"):
                        raise LabError(f"Hyper-V {case_id} probe is not bound guest evidence")
                    observed_steps.append({"id": "probe", "case_id": case_id, "action": "probe", "passed": True, "probe": probe})
                    if case_id.endswith("-clean"):
                        current_phase = "precondition"
                        self.hyperv_call("precondition", run_id=run_id, CaseId=case_id, credential=True)
                    case_steps: list[dict[str, Any]] = []
                    for stage_name, selected_artifact, action, expected_version in case_specs[case_id]:
                        current_artifact = selected_artifact
                        selected_role = artifact_role_for_stage(stage_name)
                        current_phase = f"stage:{stage_name}"
                        staged = self.hyperv_call("stage", run_id=run_id, CaseId=case_id, credential=True, ArtifactPath=windows_path_for_wsl(Path(selected_artifact["path"])), ArtifactSha256=selected_artifact["sha256"], ArtifactSize=selected_artifact["size"], Stage=stage_name)
                        if staged.get("guest", {}).get("sha256") != selected_artifact.get("sha256"):
                            raise LabError(f"Hyper-V guest artifact hash mismatch for {case_id}/{stage_name}")
                        current_phase = f"run:{action}:{stage_name}"
                        ran = self.hyperv_call("run", run_id=run_id, CaseId=case_id, credential=True, GuestAction=action, ExpectedArtifactRole=selected_role, ExpectedSha256=selected_artifact["sha256"], ExpectedVersion=expected_version, BaselineVersion=str(planned_run["baseline_version"]), CandidateVersion=str(planned_run["candidate_version"]), RunnerPath=windows_path_for_wsl(runner_source), RunnerSha256=runner_record["sha256"])
                        result = ran.get("result", {}); readback = result.get("readback", {}) if isinstance(result, dict) else {}
                        try: receipt = json.loads(str(readback.get("receipt", "")))
                        except json.JSONDecodeError as exc: raise LabError(f"Hyper-V {case_id}/{stage_name} returned no guest receipt") from exc
                        if receipt.get("transport") != HYPERV_TRANSPORT or receipt.get("origin") != "guest" or receipt.get("injected") is True or receipt.get("case_id") != case_id:
                            raise LabError(f"Hyper-V {case_id} receipt is not bound guest-origin evidence")
                        validate_receipt(receipt, run_id=run_id, profile_id=profile_id, artifact=selected_artifact, case_id=case_id, baseline_version=str(planned_run["baseline_version"]), candidate_version=str(planned_run["candidate_version"]), expected_role=selected_role)
                        if not all(step.get("passed") is True for step in receipt.get("steps", [])): raise LabError(f"Hyper-V guest step failed for {case_id}/{stage_name}")
                        case_steps.append({"stage": stage_name, "action": action, "passed": True, "guest_receipt": receipt, "vm_id": result.get("vm_id"), "parent_sha256": result.get("parent_sha256")})
                        observed_steps.append({"id": action, "case_id": case_id, "stage": stage_name, "action": action, "passed": True, "guest_receipt": receipt, "transport": HYPERV_TRANSPORT, "vm_id": result.get("vm_id"), "parent_sha256": result.get("parent_sha256")})
                    final_artifact = case_specs[case_id][-1][1]
                    current_artifact = final_artifact
                    current_phase = "run:service-health"
                    health = self.hyperv_call("run", run_id=run_id, CaseId=case_id, credential=True, GuestAction="service-health", ExpectedArtifactRole="candidate", ExpectedSha256=final_artifact["sha256"], ExpectedVersion=str(planned_run["candidate_version"]), BaselineVersion=str(planned_run["baseline_version"]), CandidateVersion=str(planned_run["candidate_version"]), RunnerPath=windows_path_for_wsl(runner_source), RunnerSha256=runner_record["sha256"])
                    health_result = health.get("result", {}); health_readback = (health_result.get("readback") or {})
                    try: health_receipt = json.loads(str(health_readback.get("receipt", "")))
                    except json.JSONDecodeError as exc: raise LabError(f"Hyper-V {case_id} service-health returned no receipt") from exc
                    validate_receipt(health_receipt, run_id=run_id, profile_id=profile_id, artifact=final_artifact, case_id=case_id, baseline_version=str(planned_run["baseline_version"]), candidate_version=str(planned_run["candidate_version"]), expected_role="candidate")
                    case_receipts.append({"case_id": case_id, "steps": case_steps, "service_health": health_receipt, "vm_id": health_result.get("vm_id"), "parent_sha256": health_result.get("parent_sha256")})
                    known_case_ids.add(case_id)
                    self._persist_hyperv_case_progress(
                        run_id, profile_id, observed_steps, case_receipts, case_id
                    )
                except Exception as case_error:
                    case_failed = True
                    self._record_hyperv_case(run_id, profile_id, case_id, "unsafe", error=str(case_error))
                    if case_created:
                        self.capture_hyperv_failure(run_id, profile_id, case_id, current_phase, current_artifact, case_error)
                    raise
                finally:
                    if case_created and not case_reset and preserve_failed_guest and case_failed:
                        self._record_hyperv_case(run_id, profile_id, case_id, "preserved-diagnostic", error="explicit preserve-failed-guest retained owned child after captured failure")
                    elif case_created and not case_reset:
                        try:
                            reset_result = self.hyperv_call("reset", run_id=run_id, CaseId=case_id, credential=False)
                            if reset_result.get("removed_child") is not True or reset_result.get("parent_sha256_before") != reset_result.get("parent_sha256_after"):
                                raise LabError(f"Hyper-V {case_id} reset did not confirm owned child removal and unchanged parent")
                            self._record_hyperv_case(run_id, profile_id, case_id, "reset", reset_result=reset_result)
                            case_reset = True
                        except Exception as cleanup_exc:
                            planned_run = self.get_run(run_id)
                            planned_run["profiles"][profile_id].setdefault("unsafe_cases", []).append({"case_id": case_id, "error": str(cleanup_exc), "preserved": True, "observed_at": utc_now()})
                            state = self.load_state(); state["runs"][run_id] = planned_run; self.save_state(state)
                            if sys.exc_info()[0] is None:
                                raise LabError(f"Hyper-V {case_id} reset failed; child preserved for recovery: {cleanup_exc}") from cleanup_exc
            planned_run = self.get_run(run_id)
            if selected is not None and not interactive_only:
                return self.get_run(run_id)
            interactive_case = "outer-interactive"
            interactive_receipt = None
            interactive_started = False
            interactive_unsafe = False
            interactive_attempt = secrets.token_hex(16)
            self._record_hyperv_case(run_id, profile_id, interactive_case, "intended")
            planned_hyperv = planned_run.get("hyperv_records") or {}
            planned_ui = planned_hyperv.get("ui_helper") or {}
            planned_launcher = planned_hyperv.get("launcher") or {}
            ui_source = hyperv_ui_helper_source()
            launcher_source = hyperv_launcher_source()
            if not ui_source.is_file() or not launcher_source.is_file() or planned_ui.get("path") != str(ui_source) or planned_launcher.get("path") != str(launcher_source) or sha256_file(ui_source)[0] != planned_ui.get("sha256") or sha256_file(launcher_source)[0] != planned_launcher.get("sha256"):
                raise LabError("Hyper-V interactive helper/launcher changed after plan")
            try:
                interactive_created = self.hyperv_call("create-child", run_id=run_id, CaseId=interactive_case)
                interactive_child = interactive_created.get("child") or {}
                self._record_hyperv_case(run_id, profile_id, interactive_case, "created", vm_id=interactive_child.get("vm_id"), parent_sha256=interactive_child.get("parent_sha256"), run_root=interactive_child.get("run_root"), child_vhdx=interactive_child.get("child_vhdx"))
                interactive_started_result = self.hyperv_call("start", run_id=run_id, CaseId=interactive_case, credential=True)
                interactive_started_child = interactive_started_result.get("child") or interactive_child
                self._record_hyperv_case(run_id, profile_id, interactive_case, "running", vm_id=interactive_started_child.get("vm_id"), parent_sha256=interactive_started_result.get("parent_sha256") or interactive_started_child.get("parent_sha256"), run_root=interactive_started_child.get("run_root"), child_vhdx=interactive_started_child.get("child_vhdx"))
                interactive_started = True
                interactive_probe = self.hyperv_call("probe", run_id=run_id, CaseId=interactive_case, credential=True)
                expected_interactive_vm = str(interactive_started_child.get("vm_id") or interactive_started_child.get("Id") or "")
                if (interactive_probe.get("transport") != HYPERV_TRANSPORT
                        or interactive_probe.get("origin") != "guest"
                        or interactive_probe.get("injected") is not False
                        or (expected_interactive_vm and str(interactive_probe.get("vm_id")) != expected_interactive_vm)
                        or not interactive_probe.get("parent_sha256")):
                    raise LabError("Hyper-V interactive probe is not bound to the fresh child VM")
                self._record_hyperv_case(
                    run_id, profile_id, interactive_case, "probed",
                    vm_id=interactive_probe.get("vm_id"),
                    parent_sha256=interactive_probe.get("parent_sha256"),
                )
                self.hyperv_call("prepare-interactive", run_id=run_id, CaseId=interactive_case, credential=True)
                staged = self.hyperv_call("stage", run_id=run_id, CaseId=interactive_case, credential=True, ArtifactPath=windows_path_for_wsl(Path(outer_candidate["path"])), ArtifactSha256=outer_candidate["sha256"], ArtifactSize=outer_candidate["size"], Stage="candidate-outer")
                if staged.get("guest", {}).get("sha256") != outer_candidate.get("sha256"):
                    raise LabError("Hyper-V interactive stage hash differs from planned outer candidate")
                interactive_run = self.hyperv_call("run", run_id=run_id, CaseId=interactive_case, credential=True, GuestAction="interactive-start", ExpectedArtifactRole="candidate", ExpectedSha256=outer_candidate["sha256"], ExpectedVersion=str(planned_run["candidate_version"]), BaselineVersion=str(planned_run["baseline_version"]), CandidateVersion=str(planned_run["candidate_version"]), RunnerPath=windows_path_for_wsl(runner_source), RunnerSha256=runner_record["sha256"], UiHelperPath=windows_path_for_wsl(ui_source), UiHelperSha256=planned_ui["sha256"], LauncherPath=windows_path_for_wsl(launcher_source), LauncherSha256=planned_launcher["sha256"])
                if (interactive_run.get("result") or {}).get("transport") != HYPERV_TRANSPORT:
                    raise LabError("Hyper-V interactive-start did not return guest transport evidence")
                ui_observe = None
                observe_error: Exception | None = None
                observe_deadline = time.monotonic() + 90
                while time.monotonic() < observe_deadline:
                    try:
                        candidate_observation = self.hyperv_call("ui-observe", run_id=run_id, CaseId=interactive_case, credential=True, ExpectedArtifactSha256=outer_candidate["sha256"])
                        candidate_consent = candidate_observation.get("consent") if isinstance(candidate_observation, dict) else None
                        if isinstance(candidate_consent, dict) and candidate_consent.get("expected_consent") is True:
                            ui_observe = candidate_observation
                            break
                    except Exception as exc:
                        observe_error = exc
                    time.sleep(1)
                if ui_observe is None:
                    if observe_error is not None:
                        raise LabError(f"Hyper-V UI consent did not become observable within 90 seconds: {observe_error}") from observe_error
                    raise LabError("Hyper-V UI consent did not become observable within 90 seconds")
                observed_consent = ui_observe.get("consent") if isinstance(ui_observe, dict) else None
                if not isinstance(observed_consent, dict) or observed_consent.get("expected_consent") is not True:
                    raise LabError("Hyper-V UI observation did not prove the guest consent process")
                ui_confirm = self.hyperv_call("ui-confirm", run_id=run_id, CaseId=interactive_case, credential=True, ExpectedArtifactSha256=outer_candidate["sha256"])
                confirmed_consent = ui_confirm.get("consent") if isinstance(ui_confirm, dict) else None
                if not isinstance(confirmed_consent, dict) or confirmed_consent.get("expected_consent") is not True:
                    raise LabError("Hyper-V UI confirmation lost the guest consent binding")
                interactive_collect = self.hyperv_call("run", run_id=run_id, CaseId=interactive_case, credential=True, GuestAction="interactive-collect", ExpectedArtifactRole="candidate", ExpectedSha256=outer_candidate["sha256"], ExpectedVersion=str(planned_run["candidate_version"]), BaselineVersion=str(planned_run["baseline_version"]), CandidateVersion=str(planned_run["candidate_version"]), RunnerPath=windows_path_for_wsl(runner_source), RunnerSha256=runner_record["sha256"], UiHelperPath=windows_path_for_wsl(ui_source), UiHelperSha256=planned_ui["sha256"], LauncherPath=windows_path_for_wsl(launcher_source), LauncherSha256=planned_launcher["sha256"])
                readback = ((interactive_collect.get("result") or {}).get("readback") or {})
                interactive_receipt = json.loads(str(readback.get("receipt", "")))
                validate_receipt(interactive_receipt, run_id=run_id, profile_id=profile_id, artifact=outer_candidate, case_id=interactive_case, baseline_version=str(planned_run["baseline_version"]), candidate_version=str(planned_run["candidate_version"]))
                if interactive_receipt.get("interactive_verified") is not True or interactive_receipt.get("assertion", {}).get("interactive_passed") is not True:
                    raise LabError("Hyper-V interactive receipt does not prove guest UI/UAC acceptance")
                installer_evidence = interactive_receipt.get("assertion", {}).get("interactive_evidence", {})
                if not isinstance(installer_evidence, dict) or installer_evidence.get("interactive_token") is not True:
                    raise LabError("Hyper-V interactive receipt lacks guest interactive-token evidence")
                screenshot_sha = str(installer_evidence.get("screenshot_sha256") or "")
                ui_export = self.hyperv_call("export-ui", run_id=run_id, CaseId=interactive_case, credential=True, ExpectedScreenshotSha256=screenshot_sha)
                bound_consent = confirmed_consent
                completion = interactive_receipt.get("assertion", {}).get("installer_completion")
                expected_vm_id = str((interactive_run.get("result") or {}).get("vm_id") or "")
                completion_exit = completion.get("exit_code") if isinstance(completion, dict) else None
                if (bound_consent.get("run_id") != run_id or bound_consent.get("case_id") != interactive_case or (expected_vm_id and str(bound_consent.get("vm_id")) != expected_vm_id) or not isinstance(completion, dict) or int(completion.get("installer_pid") or 0) <= 0 or not completion.get("installer_start_time") or completion.get("state") != "completed" or not completion.get("completed_at") or completion.get("fresh_logs") is not True or isinstance(completion_exit, bool) or not isinstance(completion_exit, int) or completion_exit != 0):
                    raise LabError("Hyper-V interactive receipt lacks bound consent/installer completion evidence")
                ui_host_path = str(ui_export.get("host_path") or "")
                expected_evidence_root = f"{HYPERV_RUNS_ROOT_WINDOWS}/{run_id}/windows-x64/cases/{interactive_case}/evidence/".lower()
                if not ui_host_path.replace("\\", "/").lower().startswith(expected_evidence_root):
                    raise LabError("Hyper-V UAC screenshot escaped the owned case evidence root")
                ui_archive = archive_exact_file(
                    self.root, wsl_path_for_windows_host(ui_host_path),
                    self.root / "exports" / run_id / profile_id / interactive_case,
                    expected_sha256=str(ui_export.get("sha256") or ""), expected_size=ui_export.get("size"),
                    kind="uac", vm_id=expected_vm_id, case_id=interactive_case,
                    attempt_nonce=interactive_attempt,
                )
                interactive_receipt["hyperv_ui"] = {
                    "observe": ui_observe,
                    "confirm": ui_confirm,
                    "consent_pid": bound_consent.get("process_id"),
                    "consent_start_time": bound_consent.get("creation_time"),
                    "consent_session_id": bound_consent.get("session_id"),
                    "launcher_pid": bound_consent.get("launcher_pid"),
                    "launcher_start_time": bound_consent.get("launcher_start_time"),
                    "screenshot": ui_export,
                    "screenshot_archive": ui_archive,
                    "launcher_session_id": confirmed_consent.get("launcher_session_id"),
                    "installer_pid": confirmed_consent.get("installer_pid"),
                    "installer_path": confirmed_consent.get("installer_path"),
                    "installer_completion": completion,
                }
                checkpoint_run = self.get_run(run_id)
                checkpoint_run["profiles"][profile_id]["interactive_installer_receipt"] = interactive_receipt
                checkpoint_state = self.load_state(); checkpoint_state["runs"][run_id] = checkpoint_run; self.save_state(checkpoint_state)
                app_window = self.hyperv_call(
                    "app-window", run_id=run_id, CaseId=interactive_case, credential=True,
                    ExpectedVersion=str(planned_run["candidate_version"]),
                    UiHelperPath=windows_path_for_wsl(ui_source), UiHelperSha256=planned_ui["sha256"],
                )
                app_evidence = app_window.get("evidence") if isinstance(app_window, dict) else None
                app_screenshot = app_window.get("screenshot") if isinstance(app_window, dict) else None
                if (not isinstance(app_evidence, dict) or not isinstance(app_screenshot, dict)
                        or app_evidence.get("action") != "launch-app"
                        or (app_evidence.get("app") or {}).get("visible") is not True
                        or str(app_evidence.get("run_id")) != run_id
                        or str(app_evidence.get("case_id")) != interactive_case
                        or str(app_window.get("vm_id")) != expected_vm_id
                        or not app_screenshot.get("host_path") or not app_screenshot.get("sha256")):
                    raise LabError("Hyper-V installed application window evidence is incomplete or unbound")
                screenshot_host_path = str(app_screenshot["host_path"])
                expected_case_root = (
                    f"{HYPERV_RUNS_ROOT_WINDOWS}/{run_id}/windows-x64/cases/{interactive_case}/evidence/"
                ).lower()
                if not screenshot_host_path.replace("\\", "/").lower().startswith(expected_case_root):
                    raise LabError("Hyper-V application screenshot escaped the owned case evidence root")
                screenshot_source = wsl_path_for_windows_host(screenshot_host_path)
                if not screenshot_source.is_file() or screenshot_source.is_symlink():
                    raise LabError("Hyper-V application screenshot disappeared before durable archive")
                durable = archive_exact_file(
                    self.root, screenshot_source,
                    self.root / "exports" / run_id / profile_id / interactive_case,
                    expected_sha256=str(app_screenshot["sha256"]), expected_size=app_screenshot["size"],
                    kind="app-window", vm_id=expected_vm_id, case_id=interactive_case,
                    attempt_nonce=interactive_attempt,
                )
                app_screenshot["archive"] = durable
                interactive_receipt["archive_attempt_nonce"] = interactive_attempt
                interactive_receipt["installed_app_window"] = app_window
                # Persist the complete, hash-bound receipt and durable image
                # while the owned child still exists.  Reset is cleanup after
                # evidence commit and must never be the first durable boundary.
                checkpoint_run = self.get_run(run_id)
                checkpoint_profile = checkpoint_run["profiles"][profile_id]
                checkpoint_profile["interactive_receipt"] = interactive_receipt
                checkpoint_profile["interactive_status"] = "verified_guest_ui_uac_evidence_archived"
                checkpoint_profile["interactive_case_id"] = interactive_case
                checkpoint_state = self.load_state(); checkpoint_state["runs"][run_id] = checkpoint_run; self.save_state(checkpoint_state)
            except Exception as interactive_error:
                # A failed UI/reboot/cleanup path may leave a guest that is
                # unreachable or still holding installer state. Preserve it
                # for recovery rather than claiming a clean reset.
                interactive_unsafe = True
                self._record_hyperv_case(run_id, profile_id, interactive_case, "unsafe", error=str(interactive_error))
                raise
            finally:
                if interactive_started and not interactive_unsafe:
                    try:
                        reset_result = self.hyperv_call("reset", run_id=run_id, CaseId=interactive_case, credential=False)
                        if reset_result.get("removed_child") is not True or reset_result.get("parent_sha256_before") != reset_result.get("parent_sha256_after"):
                            raise LabError("Hyper-V interactive reset did not confirm owned child removal and unchanged parent")
                        self._record_hyperv_case(run_id, profile_id, interactive_case, "reset", reset_result=reset_result)
                    except Exception as cleanup_exc:
                        self._record_hyperv_case(run_id, profile_id, interactive_case, "unsafe", error=str(cleanup_exc))
                        raise
                elif interactive_started:
                    self._record_hyperv_case(run_id, profile_id, interactive_case, "unsafe", error="interactive flow failed before safe cleanup proof")
                    planned_run = self.get_run(run_id)
                    planned_run["profiles"][profile_id].setdefault("unsafe_cases", []).append({"case_id": interactive_case, "error": "interactive flow failed before safe cleanup proof", "preserved": True, "observed_at": utc_now()})
                    state = self.load_state(); state["runs"][run_id] = planned_run; self.save_state(state)
            planned_run = self.get_run(run_id)
            final_case_id = case_ids[-1] if case_ids else interactive_case
            planned_run["profiles"][profile_id].update(status="tested", steps=observed_steps, case_receipts=case_receipts, last_case_id=final_case_id)
            planned_run["profiles"][profile_id]["matrix_status"] = "independent-child-matrix"
            planned_run["profiles"][profile_id]["interactive_status"] = "verified_guest_ui_uac"
            planned_run["profiles"][profile_id]["interactive_case_id"] = interactive_case
            planned_run["profiles"][profile_id]["interactive_receipt"] = interactive_receipt
            state = self.load_state(); state["runs"][run_id] = planned_run; self.save_state(state)
            return {"run_id": run_id, "profile": profile_id, "steps": observed_steps, "transport": HYPERV_TRANSPORT, "dry_run": self.dry_run}
        if profile.get("backend") == "android-adapter":
            artifact_path = artifact.get("path")
            if not artifact_path:
                raise LabError("Android adapter requires the planned arm64 APK")
            wanted = set(selected or ())
            existing_vm = (planned_run.get("profiles", {}).get(profile_id, {}).get("vm") or {})
            existing_root = Path(str(existing_vm.get("root", "")))
            existing_baseline_proof = existing_root.parent / "proofs" / run_id / "baseline-receipt.json"
            if (not wanted or "reinstall" in wanted) and not (wanted == {"reinstall"} and existing_baseline_proof.is_file()):
                self._run_android_adapter(run_id, profile_id, "install-baseline", baseline["path"])
            if not wanted or "update" in wanted:
                baseline_for_update = existing_baseline_proof
                if not baseline_for_update.is_file():
                    raise LabError("Android update requires an immutable baseline product receipt")
                try:
                    baseline_receipt = json.loads(baseline_for_update.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise LabError("Android update baseline receipt is invalid") from exc
                if baseline_receipt.get("status") != "baseline-install-pass" or not all(
                    isinstance(step, Mapping) and step.get("passed") is True for step in baseline_receipt.get("steps", [])
                ):
                    raise LabError("Android update is blocked by failed baseline install/UI/crash gate")
                self._run_android_adapter(run_id, profile_id, "test-update", artifact_path)
            if not wanted or "collect" in wanted:
                self._run_android_adapter(run_id, profile_id, "collect")
            run_after = self.get_run(run_id)
            adapter_root = Path(str((run_after.get("profiles", {}).get(profile_id, {}).get("vm") or {}).get("root", "")))
            # A clean diagnostic/reinstall has a deliberately separate
            # baseline receipt; an update flow ends with the common receipt.
            if wanted and "reinstall" in wanted and "update" not in wanted:
                receipt_path = adapter_root.parent / "proofs" / run_id / "baseline-receipt.json"
                receipt_label = "Android baseline receipt"
            else:
                receipt_path = adapter_root / "receipts" / "controller" / run_id / f"{profile_id}.json"
                receipt_label = "Android receipt"
            # Native Windows evidence is intentionally retained beside the
            # private Windows adapter root, outside the WSL controller state;
            # bind it to that already validated private root instead.
            receipt_path = ensure_owned_child(adapter_root.parent, receipt_path, receipt_label)
            if not receipt_path.is_file():
                raise LabError("Android adapter did not emit the expected product receipt")
            try:
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise LabError(f"Android adapter receipt is invalid after update/collect: {exc}") from exc
            observed_steps = receipt.get("steps") if isinstance(receipt.get("steps"), list) else []
            expected_status = "baseline-install-pass" if wanted == {"reinstall"} else "app-selfhosted-update-pass"
            passed = receipt.get("status") == expected_status and bool(observed_steps) and all(step.get("passed") is True for step in observed_steps if isinstance(step, dict))
            run_after["profiles"][profile_id].update(status="tested", steps=observed_steps, adapter_receipt_status=receipt.get("status"), product_receipt_path=str(receipt_path))
            state = self.load_state(); state["runs"][run_id] = run_after; self.save_state(state)
            return {"run_id": run_id, "profile": profile_id, "adapter": True, "steps": observed_steps, "passed": passed, "receipt_status": receipt.get("status")}
        vm = self.owned_vm(run_id, profile_id)
        qga = QgaClient(Path(vm["qga_socket"]))
        runner = profile.get("runner")
        if not isinstance(runner, str):
            raise LabError(f"profile {profile_id} has no reviewed guest runner")
        runner_source = (repo_root() / runner).resolve()
        try:
            runner_source.relative_to(repo_root())
        except ValueError as exc:
            raise LabError("guest runner escaped repository") from exc
        if not runner_source.is_file():
            raise LabError(f"guest runner is missing: {runner_source}")
        if profile.get("backend") == "qemu-windows":
            qga.write_file(r"C:\ProgramData\AmneziaLab\release-lab.ps1", runner_source.read_bytes())
            artifact_target = r"C:\ProgramData\AmneziaLab\current.exe"
            runner_path = r"C:\ProgramData\AmneziaLab\release-lab.ps1"
            qga.write_file(r"C:\ProgramData\AmneziaLab\run-marker.txt", f"amnezia-release-lab:{run_id}:{profile_id}".encode())
            candidate_target = r"C:\ProgramData\AmneziaLab\current.exe"
            guest_receipt_path = rf"C:\ProgramData\AmneziaLab\runs\{run_id}\receipt.json"
        else:
            qga.write_file("/tmp/amnezia-release-lab-runner.sh", runner_source.read_bytes())
            artifact_name = Path(artifact["path"]).name
            artifact_target = "/tmp/amnezia-release-lab-artifact" + "".join(Path(artifact_name).suffixes)
            runner_path = "/tmp/amnezia-release-lab-runner.sh"
            qga.write_file("/tmp/amnezia-release-lab-marker", f"amnezia-release-lab:{run_id}:{profile_id}".encode())
            candidate_target = artifact_target
            guest_receipt_path = f"/run/amnezia-release-lab/{run_id}/{profile_id}/receipt.json"
        # The reviewed runner API deliberately accepts one guarded artifact
        # path. Reinstall stages N-1 there first; update overwrites that same
        # path with N and verifies its new expected identity.
        wanted = set(selected or ())
        canonical_steps = list(profile["steps"])
        canonical_by_id: dict[str, Mapping[str, Any]] = {}
        for canonical in canonical_steps:
            step_id = canonical.get("id") if isinstance(canonical, Mapping) else None
            if not isinstance(step_id, str) or not step_id or step_id in canonical_by_id:
                raise LabError(f"profile {profile_id} has missing or duplicate canonical step IDs")
            canonical_by_id[step_id] = canonical
        unknown_selected = wanted.difference(canonical_by_id)
        if unknown_selected:
            raise LabError(f"unknown selected profile step: {sorted(unknown_selected)[0]}")
        results: list[dict[str, Any]] = []
        current_guest_binding = {"pid": vm.get("pid"), "proc_start_time": str(vm.get("proc_start_time")),
                                 "uuid": vm.get("uuid"), "qga_socket": str(vm.get("qga_socket"))}
        if wanted:
            stored = planned_run.get("profiles", {}).get(profile_id, {}).get("steps") or []
            if not isinstance(stored, list):
                raise LabError("stored profile steps are malformed")
            stored_by_id: dict[str, dict[str, Any]] = {}
            for prior in stored:
                if not isinstance(prior, dict) or not isinstance(prior.get("id"), str):
                    raise LabError("stored profile step lacks a canonical identity")
                step_id = prior["id"]
                canonical = canonical_by_id.get(step_id)
                if canonical is None:
                    raise LabError(f"stored profile step is unknown: {step_id}")
                if step_id in stored_by_id:
                    raise LabError(f"stored profile step is duplicated: {step_id}")
                if prior.get("passed") is not True:
                    raise LabError(f"stored profile step did not pass: {step_id}")
                if prior.get("action") != canonical.get("action") or prior.get("executable") != canonical.get("executable"):
                    raise LabError(f"stored profile step differs from canonical profile: {step_id}")
                if prior.get("guest_binding") != current_guest_binding:
                    raise LabError(f"stored profile step belongs to a different guest incarnation: {step_id}")
                planned_for_role = baseline if prior.get("artifact_role") == "baseline" else artifact if prior.get("artifact_role") == "candidate" else None
                if (not isinstance(planned_for_role, Mapping)
                        or prior.get("artifact_sha256") != planned_for_role.get("sha256")
                        or prior.get("artifact_size") != planned_for_role.get("size")):
                    raise LabError(f"stored profile step differs from the current planned artifact: {step_id}")
                stored_by_id[step_id] = prior
            conflicts = wanted.intersection(stored_by_id)
            if conflicts:
                raise LabError(f"selected profile step already has immutable evidence: {sorted(conflicts)[0]}")
            # Retain the original assertion/QGA objects byte-for-byte in the
            # controller state, but normalize their list order to the profile.
            results = [stored_by_id[step["id"]] for step in canonical_steps if step["id"] in stored_by_id]
        for step in profile["steps"]:
            if wanted and step["id"] not in wanted:
                continue
            step_args = list(step.get("args", []))
            selected = baseline if step["action"] == "reinstall" else artifact
            selected_target = candidate_target
            expected_version = planned_run.get("baseline_version") if step["action"] == "reinstall" else planned_run.get("candidate_version")
            headless_args: list[str] = []
            if profile_id == "linux-headless-x64":
                trust = planned_run.get("headless_verified_receipts") or {}
                manifest_record = planned_run.get("baseline_manifest") if step["action"] == "reinstall" else planned_run.get("manifest")
                receipt_record = trust.get("baseline") if step["action"] == "reinstall" else trust.get("candidate")
                if not isinstance(manifest_record, dict) or not isinstance(receipt_record, dict):
                    raise LabError("headless step is missing its signed manifest or verified provisioning receipt")
                inputs = headless_runner_inputs(Path(manifest_record["path"]), Path(planned_run["manifest_public_key"]["path"]), Path(receipt_record["path"]), selected, str(expected_version))
                provisioning_target = "/tmp/amnezia-release-lab-provisioning.tar.gz"
                public_key_target = "/tmp/amnezia-release-lab-update-public-key.pem"
                receipt_target = "/tmp/amnezia-release-lab-verified-receipt.json"
                qga.write_file(provisioning_target, Path(inputs["provisioning_path"]).read_bytes())
                qga.write_file(public_key_target, Path(inputs["public_key_path"]).read_bytes())
                qga.write_file(receipt_target, Path(inputs["verified_receipt_path"]).read_bytes())
                headless_args = ["--provisioning-artifact-path", provisioning_target, "--public-key", public_key_target, "--key-sha256", inputs["key_sha256"], "--package-manifest-sha256", inputs["package_manifest_sha256"], "--checksums-sha256", inputs["checksums_sha256"], "--signed-manifest-sha256", inputs["signed_manifest_sha256"], "--verified-receipt", receipt_target]
            if profile.get("backend") == "qemu-windows":
                step_args = ["-NoProfile", "-File", runner_path, step["action"], profile_id, "-RunId", run_id, "-ExpectedVersion", str(expected_version), "-ExpectedArtifactRole", expected_artifact_role(step["action"]), "-BaselineVersion", str(planned_run["baseline_version"]), "-CandidateVersion", str(planned_run["candidate_version"]), "-ExpectedSha256", selected["sha256"], "-ArtifactPath", selected_target, "-ReceiptPath", guest_receipt_path]
            else:
                selected_role = expected_artifact_role(step["action"])
                if (profile_id == "linux-headless-x64" and step["action"] == "reinstall"
                        and planned_run.get("baseline_version") == planned_run.get("candidate_version")
                        and baseline.get("sha256") == artifact.get("sha256")):
                    selected_role = "candidate"
                step_args = [runner_path, step["action"], profile_id, "--run-id", run_id, "--baseline-version", str(planned_run["baseline_version"]), "--candidate-version", str(planned_run["candidate_version"]), "--expected-version", str(expected_version), "--expected-sha256", selected["sha256"], "--expected-artifact-role", selected_role, "--artifact-path", selected_target, "--receipt-path", guest_receipt_path,
                             "--guest-pid", str(vm["pid"]), "--guest-start", str(vm["proc_start_time"]),
                             "--guest-uuid", str(vm["uuid"]), "--guest-qga", str(vm["qga_socket"]), *headless_args]
            qga.write_file(selected_target, Path(selected["path"]).read_bytes())
            response = qga.guest_exec_wait(step["executable"], step_args)
            try:
                assertion = json.loads(response.get("stdout", ""))
            except json.JSONDecodeError as exc:
                raise LabError(f"guest step {step['id']} returned no JSON assertion: {exc}") from exc
            validate_step_assertion(assertion, action=step["action"], profile_id=profile_id, artifact=selected, expected_version=str(expected_version))
            results.append({"id": step["id"], "action": step["action"], "executable": step["executable"], "qga_response": response, "assertion": assertion, "passed": True, "guest_binding": dict(current_guest_binding),
                            "artifact_sha256": selected["sha256"], "artifact_size": selected["size"],
                            "artifact_role": selected_role, "artifact_source": {"transport":"qga","kind":"qga-upload","hash_verified":True,"path":selected_target}})
            results.sort(key=lambda item: list(canonical_by_id).index(item["id"]))
            # Persist every completed guest mutation before starting the next
            # step so a later health/UI failure cannot erase authentic install
            # or update evidence from this same owned VM.
            progress = self.get_run(run_id)
            progress["profiles"][profile_id].update(
                status="testing", steps=list(results), last_completed_step=step["id"]
            )
            state = self.load_state(); state["runs"][run_id] = progress; self.save_state(state)
        if not results:
            raise LabError("no selected profile steps")
        run = self.get_run(run_id); run["profiles"][profile_id].update(status="tested", steps=results)
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return {"run_id": run_id, "profile": profile_id, "steps": results, "dry_run": self.dry_run}

    @mutation_operation
    def collect(self, run_id: str, profile_id: str, case_id: str | None = None) -> dict[str, Any]:
        profile = load_profiles()[profile_id]
        if profile.get("backend") == "android-adapter":
            vm = self.get_run(run_id)["profiles"][profile_id].get("vm") or {}
            receipt_path = Path(str(vm.get("root", ""))) / "receipts" / "controller" / run_id / f"{profile_id}.json"
            receipt_path = ensure_owned_child(self.root, receipt_path, "Android receipt")
            if not receipt_path.is_file():
                raise LabError("Android adapter did not emit the common receipt; refusing to infer a pass")
            try:
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise LabError(f"Android adapter receipt is invalid: {exc}") from exc
            run = self.get_run(run_id)
            artifact = run.get("artifacts", {}).get(profile_id)
            pending = receipt.get("status") in {"baseline-abi-blocked", "app-selfhosted-update-pending"}
            validate_receipt(receipt, run_id=run_id, profile_id=profile_id, artifact=artifact, baseline_version=str(run["baseline_version"]), candidate_version=str(run["candidate_version"]), allow_pending=pending, expected_role=None if pending else "candidate")
            run["profiles"][profile_id].update(status="evidence-collected", evidence=receipt)
            state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
            return receipt
        run = self.get_run(run_id)
        if self.uses_hyperv(run, profile_id):
            if case_id:
                diagnostic = self.hyperv_call("collect", run_id=run_id, CaseId=case_id, credential=True)
                return {"run_id": run_id, "profile": profile_id, "case_id": case_id, "diagnostic": diagnostic, "release_passed": False}
            case_id = (run.get("profiles", {}).get(profile_id, {}).get("last_case_id") or (run.get("profiles", {}).get(profile_id, {}).get("vm") or {}).get("case_id") or "control")
            archived = next((item for item in (run.get("profiles", {}).get(profile_id, {}).get("case_receipts") or []) if item.get("case_id") == case_id), None)
            if not isinstance(archived, dict) or not isinstance(archived.get("service_health"), dict):
                raise LabError("Hyper-V collect has no archived guest receipt for the final case")
            receipt = dict(archived["service_health"])
            artifact = run.get("outer_artifact") or run.get("artifacts", {}).get(profile_id)
            validate_receipt(receipt, run_id=run_id, profile_id=profile_id, artifact=artifact, case_id=case_id, baseline_version=str(run["baseline_version"]), candidate_version=str(run["candidate_version"]))
            receipt["hyperv_binding"] = {"vm_id": archived.get("vm_id"), "case_id": case_id, "parent_sha256": archived.get("parent_sha256"), "transport": HYPERV_TRANSPORT, "archived": True}
            if not receipt["hyperv_binding"]["vm_id"] or not receipt["hyperv_binding"]["parent_sha256"]:
                raise LabError("Hyper-V archived receipt lacks child VM/parent binding")
            interactive = run.get("profiles", {}).get(profile_id, {}).get("interactive_receipt")
            if isinstance(interactive, dict):
                validate_hyperv_interactive_archives(self.root, interactive)
                receipt["interactive_verified"] = interactive.get("interactive_verified") is True and interactive.get("assertion", {}).get("interactive_passed") is True
                receipt["interactive_receipt"] = interactive
            run["profiles"][profile_id].update(status="evidence-collected", evidence=receipt)
            state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
            return receipt
        run = self.get_run(run_id); vm = self.owned_vm(run_id, profile_id)
        qga = QgaClient(Path(vm["qga_socket"]))
        artifact = run.get("outer_artifact") if profile_id == "windows-x64" else (run.get("artifacts", {}).get(profile_id) or run.get("artifacts", {}).get(profile_id.replace("-gui", "")))
        marker_path = r"C:\ProgramData\AmneziaLab\run-marker.txt" if profile_id == "windows-x64" else "/tmp/amnezia-release-lab-marker"
        marker = qga.read_file(marker_path).decode("utf-8", errors="strict")
        expected_marker = f"amnezia-release-lab:{run_id}:{profile_id}"
        if marker != expected_marker:
            raise LabError("guest run marker was not read back through QGA")
        steps = run["profiles"][profile_id].get("steps")
        if not isinstance(steps, list) or not steps or any(step.get("passed") is not True for step in steps):
            raise LabError("no completed guest step assertions are available")
        receipt_guest_path = rf"C:\ProgramData\AmneziaLab\runs\{run_id}\receipt.json" if profile_id == "windows-x64" else f"/run/amnezia-release-lab/{run_id}/{profile_id}/receipt.json"
        try:
            receipt = json.loads(qga.read_file(receipt_guest_path).decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LabError(f"guest runner receipt is invalid or missing: {exc}") from exc
        receipt = dict(receipt)
        if profile.get("backend") == "qemu-linux":
            artifact_id = artifact_id_for_profile(profile_id)
            validate_linux_receipt_incarnation(
                receipt, vm, profile, run_id, profile_id, steps,
                {"candidate": run.get("artifacts", {}).get(artifact_id),
                 "baseline": run.get("baseline_artifacts", {}).get(artifact_id)},
            )
        validate_receipt(receipt, run_id=run_id, profile_id=profile_id, artifact=artifact, baseline_version=str(run["baseline_version"]), candidate_version=str(run["candidate_version"]), expected_role="candidate")
        run["profiles"][profile_id].update(status="evidence-collected", evidence=receipt)
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return receipt

    @mutation_operation
    def archive_guest_evidence(self, run_id: str, profile_id: str, error: Exception | None = None) -> dict[str, Any]:
        """Persist guest-origin receipts/logs before any VM reset."""
        self.assert_mutation_context()
        run = self.get_run(run_id)
        profile = load_profiles()[profile_id]
        archive_root = ensure_owned_child(self.root, self.root / "exports" / run_id / profile_id, "guest evidence archive")
        archive_root.mkdir(parents=True, exist_ok=True)
        archive_path = ensure_owned_child(self.root, archive_root / "evidence.json", "guest evidence receipt")
        planned_artifact = run.get("outer_artifact") if profile_id == "windows-x64" else (run.get("artifacts", {}).get(profile_id) or run.get("artifacts", {}).get(profile_id.replace("-gui", "")) or {})
        record: dict[str, Any] = {
            "schema": 1, "run_id": run_id, "profile": profile_id,
            "captured_at": utc_now(), "origin": "guest", "injected": False,
            "transport": "android-adapter" if profile.get("backend") == "android-adapter" else "qga",
            "artifact": dict(planned_artifact),
            "artifact_sha256": planned_artifact.get("sha256"),
            "artifact_size": planned_artifact.get("size"),
            "error": str(error) if error else None, "receipt": None, "raw_logs": [],
        }
        receipt: dict[str, Any] | None = None
        receipt_bytes: bytes | None = None
        if profile.get("backend") == "android-adapter":
            vm = (run.get("profiles", {}).get(profile_id, {}).get("vm") or {})
            adapter_root = str(vm.get("root", "")).strip()
            if adapter_root:
                receipt_path = Path(adapter_root) / "receipts" / "controller" / run_id / f"{profile_id}.json"
                receipt_path = ensure_owned_child(self.root, receipt_path, "Android guest receipt")
                if receipt_path.is_file() and not receipt_path.is_symlink():
                    receipt_bytes = receipt_path.read_bytes()
        elif self.uses_hyperv(run, profile_id):
            diagnostics = run.get("profiles", {}).get(profile_id, {}).get("failure_diagnostics") or []
            record["failure_diagnostics"] = list(diagnostics)
            receipt = run.get("profiles", {}).get(profile_id, {}).get("evidence")
            if isinstance(receipt, dict):
                receipt_bytes = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
                record["transport"] = HYPERV_TRANSPORT
                record["guest_binding"] = receipt.get("hyperv_binding") or {}
        else:
            vm = self.owned_vm(run_id, profile_id)
            record["guest_binding"] = {key: vm.get(key) for key in ("pid", "proc_start_time", "uid", "uuid", "qmp_socket", "qga_socket", "started_at")}
            qga = QgaClient(Path(vm["qga_socket"]))
            receipt_guest_path = f"/run/amnezia-release-lab/{run_id}/{profile_id}/receipt.json"
            try:
                receipt_bytes = qga.read_file(receipt_guest_path)
            except (OSError, LabError):
                receipt_bytes = None
            if receipt_bytes is not None:
                try:
                    receipt = json.loads(receipt_bytes.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    receipt = None
            failure_path = ((receipt.get("failure") or {}).get("fresh_log_path") if isinstance(receipt, dict) and isinstance(receipt.get("failure"), dict) else None)
            log_paths = [failure_path] if isinstance(failure_path, str) and failure_path else []
            try:
                listing = qga.guest_exec_wait("/bin/sh", ["-c", "find /tmp -maxdepth 1 -type f -name 'amnezia-release-lab*' -printf '%p\\n' 2>/dev/null || true"], timeout=30)
                log_paths.extend(line.strip() for line in listing.get("stdout", "").splitlines() if line.strip().endswith(".log") or line.strip().endswith(".reason"))
            except (LabError, OSError):
                pass
            # Preserve bounded diagnostics even when a crash happened before
            # the runner could publish its common receipt.
            for guest_path in dict.fromkeys(log_paths):
                try:
                    size_response = qga.guest_exec_wait("/usr/bin/stat", ["-c", "%s", guest_path], timeout=30)
                    size = int(size_response.get("stdout", "0").strip())
                    if size < 0 or size > 8 * 1024 * 1024:
                        continue
                    data = qga.read_file(guest_path)
                except (LabError, OSError, ValueError):
                    continue
                safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(guest_path).name)[:96]
                destination = ensure_owned_child(self.root, archive_root / "logs" / safe_name, "guest raw log archive")
                immutable_bytes_dump(destination, data)
                digest, byte_count = sha256_file(destination)
                record["raw_logs"].append({"guest_path": guest_path, "archive_path": str(destination), "sha256": digest, "size": byte_count})
        if receipt_bytes is not None:
            try:
                receipt = json.loads(receipt_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                receipt = None
            if profile.get("backend") == "android-adapter" and isinstance(receipt, dict):
                identity = receipt.get("device_identity") or {}
                record["guest_binding"] = {
                    "transport": "android-adapter",
                    "serial": identity.get("serial"),
                    "qemu_uuid": identity.get("qemu_uuid") or identity.get("qemuUuid"),
                }
            receipt_destination = ensure_owned_child(self.root, archive_root / "receipt.json", "guest receipt archive")
            immutable_bytes_dump(receipt_destination, receipt_bytes)
            receipt_sha, receipt_size = sha256_file(receipt_destination)
            record["receipt"] = {"archive_path": str(receipt_destination), "sha256": receipt_sha, "size": receipt_size}
            if receipt is not None:
                record["receipt"]["value"] = receipt
        if receipt is None and record.get("error") is None:
            record["error"] = "guest receipt was unavailable before cleanup"
        immutable_json_dump(archive_path, record)
        record["archive_path"] = str(archive_path)
        profile_state = run["profiles"][profile_id]
        profile_state["evidence_archive"] = str(archive_path)
        profile_state["archive_status"] = "captured" if record.get("receipt") else "incomplete"
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return record

    @mutation_operation
    def run_suite(self, lane: str, artifacts: Mapping[str, Path], outer_artifact: Path | None, run_id: str | None = None, manifest: Path | None = None, baseline_artifacts: Mapping[str, Path] | None = None, baseline_version: str | None = None, candidate_version: str | None = None, manifest_public_key: Path | None = None, baseline_manifest: Path | None = None, headless_baseline_receipt: Path | None = None, headless_candidate_receipt: Path | None = None, baseline_outer_artifact: Path | None = None) -> dict[str, Any]:
        """Create and execute every selected real guest, then return evidence summary."""
        run = self.create(lane, artifacts, outer_artifact, run_id, manifest, baseline_artifacts, baseline_version, candidate_version, manifest_public_key, baseline_manifest, headless_baseline_receipt, headless_candidate_receipt, baseline_outer_artifact)
        run_id = run["run_id"]
        expected = run.get("expected_profiles") or list(PROFILE_IDS)
        completed: list[str] = []
        if "android-arm64-v8a" in expected:
            try:
                manifest_record = run.get("manifest") or {}
                android_artifact = run.get("artifacts", {}).get("android-arm64-v8a") or {}
                if not isinstance(manifest_record, dict) or not android_artifact.get("path"):
                    raise LabError("Android fixture startup requires the planned signed manifest and APK")
                self.start(run_id, "server-router")
                self.guest_probe(run_id, "server-router")
                self.start_consumer_fixture(run_id, Path(manifest_record["path"]), Path(android_artifact["path"]))
            except Exception as exc:
                try:
                    self.cleanup_auxiliary_resources(run_id, "android-arm64-v8a")
                except Exception as cleanup_exc:
                    raise LabError(f"Android fixture startup failed and cleanup was incomplete: {cleanup_exc}") from exc
                raise
        for profile_id in expected:
            archive_error: Exception | None = None
            try:
                self.start(run_id, profile_id)
                self.guest_probe(run_id, profile_id)
                self.run_steps(run_id, profile_id)
                self.collect(run_id, profile_id)
                completed.append(profile_id)
            except Exception as exc:
                archive_error = exc
                try:
                    self.archive_guest_evidence(run_id, profile_id, exc)
                except Exception as archive_exc:
                    run = self.get_run(run_id)
                    run["profiles"][profile_id]["archive_error"] = str(archive_exc)
                    state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
                    raise LabError(f"guest evidence archive failed; preserving owned guest: {archive_exc}") from exc
                raise
            else:
                try:
                    self.archive_guest_evidence(run_id, profile_id)
                except Exception as archive_exc:
                    archive_error = archive_exc
                    raise LabError(f"guest evidence archive failed; preserving owned guest: {archive_exc}") from archive_exc
            finally:
                current = self.get_run(run_id)["profiles"][profile_id]
                if profile_id == "android-arm64-v8a":
                    # The server fixture is an auxiliary owned resource.  Its
                    # cleanup must run even when Android failed before the
                    # adapter recorded a VM or its evidence archive failed.
                    try:
                        self.cleanup_auxiliary_resources(run_id, profile_id)
                    except Exception as auxiliary_exc:
                        run = self.get_run(run_id)
                        run["profiles"][profile_id]["cleanup_error"] = str(auxiliary_exc)
                        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
                        if archive_error is None:
                            raise LabError(f"auxiliary server cleanup failed; preserving owned guests: {auxiliary_exc}") from auxiliary_exc
                if archive_error is None or current.get("evidence_archive"):
                    try:
                        self.reset(run_id, profile_id)
                    except Exception as reset_exc:
                        run = self.get_run(run_id)
                        run["profiles"][profile_id]["cleanup_error"] = str(reset_exc)
                        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
                        raise
        return {"run_id": run_id, "lane": lane, "completed_profiles": completed, "release_passed": False, "next": "gate"}

    @mutation_operation
    def reset(self, run_id: str, profile_id: str | None = None) -> dict[str, Any]:
        self.assert_mutation_context()
        run = self.get_run(run_id)
        targets = [profile_id] if profile_id else list(run.get("profiles", {}))
        removed = []
        for current in targets:
            if current not in run["profiles"]:
                raise LabError(f"unknown profile in run: {current}")
            if self.uses_hyperv(run, current):
                profile_state = run["profiles"][current]
                tracked = profile_state.get("hyperv_cases") if isinstance(profile_state.get("hyperv_cases"), dict) else {}
                if tracked:
                    case_ids = [case for case, detail in tracked.items() if isinstance(detail, dict) and detail.get("state") != "reset"]
                else:
                    case_ids = [((profile_state.get("vm") or {}).get("case_id") or "control")]
                for case_id in case_ids:
                    detail = tracked.get(case_id) if isinstance(tracked, dict) else None
                    try:
                        result = self.hyperv_call("reset", run_id=run_id, CaseId=case_id, credential=False)
                        if result.get("removed_child") is not True or result.get("parent_sha256_before") != result.get("parent_sha256_after"):
                            raise LabError(f"Hyper-V reset did not confirm removal and unchanged parent for {case_id}")
                        if isinstance(tracked, dict):
                            self._record_hyperv_case(run_id, current, case_id, "reset", reset_result=result)
                    except Exception as exc:
                        if isinstance(tracked, dict):
                            self._record_hyperv_case(run_id, current, case_id, "unsafe", error=str(exc))
                        raise
                run = self.get_run(run_id)
                prior = dict(run["profiles"].get(current, {}))
                prior.update(status="reset", vm=None)
                run["profiles"][current] = prior
                removed.append(f"hyperv-child:{run_id}:{current}")
                continue
            profile_dir = ensure_owned_child(self.root, self.root / "runs" / run_id / current, "profile directory")
            marker = profile_dir / ".owned-overlay.json"
            overlay = profile_dir / "overlay.qcow2"
            if not marker.is_file():
                raise LabError(f"refusing reset without ownership marker: {marker}")
            metadata = json.loads(marker.read_text(encoding="utf-8"))
            if metadata.get("run_id") != run_id or metadata.get("profile") != current or Path(metadata.get("overlay", "")).resolve() != overlay.resolve():
                raise LabError("overlay ownership marker mismatch")
            # A controller crash can leave a QEMU spawn intent before the VM
            # record was committed.  Recover it first; this is deliberately
            # fail-closed when a live/foreign process or non-socket target is
            # encountered.
            self._recover_qemu_spawn_intent(run_id, current)
            vm = run["profiles"][current].get("vm")
            if isinstance(vm, dict) and vm.get("backend") in {"android-adapter", "android-windows-adapter"}:
                self._run_android_adapter(run_id, current, "reset")
            if isinstance(vm, dict) and vm.get("backend") not in {"android-adapter", "android-windows-adapter"}:
                try:
                    owned = self.owned_vm(run_id, current)
                except LabError:
                    # A dead owned process is already reset. A reused PID is
                    # safe to clean only when the live process is not the
                    # recorded QEMU identity; a foreign QEMU still blocks.
                    pid = int(vm.get("pid", 0))
                    proc_path = Path(f"/proc/{pid}")
                    if proc_path.exists():
                        cmdline = proc_path.joinpath("cmdline").read_bytes().decode(errors="replace").replace("\x00", " ")
                        qmp_token = str(vm.get("qmp_socket", ""))
                        qga_token = str(vm.get("qga_socket", ""))
                        if "qemu-system-x86_64" in cmdline or qmp_token in cmdline or qga_token in cmdline:
                            raise
                else:
                    pid = int(owned["pid"])
                    try:
                        os.kill(pid, 15)
                    except ProcessLookupError:
                        pass
                    wait_owned_process_exit(pid, str(owned["proc_start_time"]), "QEMU")
                tpm_pid = vm.get("tpm_pid")
                if isinstance(tpm_pid, int) and Path(f"/proc/{tpm_pid}").exists():
                    tpm_start_time = vm.get("tpm_proc_start_time")
                    if not isinstance(tpm_start_time, str) or tpm_start_time != proc_start_time(tpm_pid):
                        raise LabError("refusing to stop reused TPM PID")
                    cmdline = Path(f"/proc/{tpm_pid}/cmdline").read_bytes().decode(errors="replace").replace("\x00", " ")
                    if "swtpm" not in cmdline or str(vm.get("tpm_socket")) not in cmdline:
                        raise LabError("refusing to stop foreign TPM process")
                    try:
                        os.kill(tpm_pid, 15)
                    except ProcessLookupError:
                        pass
                    wait_owned_process_exit(tpm_pid, tpm_start_time, "TPM")
                for generated_name in ("ovmf_vars", "tpm_state"):
                    generated = vm.get(generated_name)
                    if generated:
                        generated_path = ensure_owned_child(self.root, Path(str(generated)), f"owned {generated_name}")
                        if generated_path.is_dir() and not self.dry_run:
                            shutil.rmtree(generated_path)
                        elif generated_path.exists() and not self.dry_run:
                            generated_path.unlink()
            if overlay.exists() and not self.dry_run:
                self._remove_owned_overlay(overlay)
                removed.append(str(overlay))
            for socket_path, label in ((profile_dir / "qmp.sock", "QMP socket"), (profile_dir / "qga.sock", "QGA socket"), (profile_dir / "vnc.sock", "VNC socket"), (profile_dir / "swtpm.sock", "TPM socket")):
                self._remove_owned_socket(socket_path, label)
            intent_path = profile_dir / ".qemu-spawn-intent.json"
            if intent_path.is_symlink():
                raise LabError("refusing to remove symlinked QEMU spawn intent")
            if intent_path.exists():
                if not intent_path.is_file():
                    raise LabError("refusing to remove non-regular QEMU spawn intent")
                if not self.dry_run:
                    intent_path.unlink()
            prior = dict(run["profiles"].get(current, {}))
            prior.update(status="reset", vm=None)
            run["profiles"][current] = prior
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return {"run_id": run_id, "reset_profiles": targets, "removed_overlays": removed, "release_passed": False}

    @mutation_operation
    def _register_full4(self, run_id: str, kind: str, value: Mapping[str, Any]) -> dict[str, Any]:
        if kind not in {"android", "headless", "linux-visual"}:
            raise LabError("unsupported full4 semantic evidence kind")
        run = self.get_run(run_id); root = ensure_owned_child(self.root,self.root / "runs" / run_id / "full4-semantic","full4 semantic directory"); root.mkdir(parents=True, exist_ok=True)
        path = root / f"{kind}.json"
        if path.exists() or path.is_symlink():
            raise LabError("full4 semantic evidence is immutable")
        bound_value=dict(value);bound_value["_controller_binding"]={"run_id":run_id,"outer_sha256":(run.get("outer_artifact") or {}).get("sha256"),"manifest_sha256":(run.get("manifest") or {}).get("sha256"),"candidate_artifacts":{k:{"sha256":v.get("sha256"),"size":v.get("size")} for k,v in (run.get("artifacts") or {}).items()},"semantic_helpers":{k:{"sha256":v.get("sha256"),"size":v.get("size")} for k,v in (run.get("semantic_helper_records") or {}).items()}}
        payload = (json.dumps(bound_value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as stream: stream.write(payload); stream.flush(); os.fsync(stream.fileno())
        except BaseException:
            path.unlink(missing_ok=True); raise
        digest, size = sha256_file(path); record = {"path": str(path), "sha256": digest, "size": size, "run_id": run_id, "kind": kind,
            "outer_sha256": (run.get("outer_artifact") or {}).get("sha256"), "manifest_sha256": (run.get("manifest") or {}).get("sha256")}
        run.setdefault("full4_semantic", {})[kind] = record; state=self.load_state();state["runs"][run_id]=run;self.save_state(state);return record

    def register_android_semantic(self, run_id: str, plan: Any, boot: Mapping[str, Any], app: Mapping[str, Any], cleanup: Mapping[str, Any], link: Mapping[str, Any], link_cleanup: Mapping[str, Any]) -> dict[str, Any]:
        run=self.get_run(run_id);planned=(run.get("artifacts") or {}).get("android-arm64-v8a") or {};owner=getattr(plan,"ownership",None);apk=getattr(plan,"apk",None);vm=((run.get("profiles") or {}).get("linux-headless-x64") or {}).get("vm") or {}
        if (getattr(owner,"run_id",None)!=run_id or getattr(owner,"profile",None)!="linux-headless-x64" or getattr(apk,"sha256",None)!=planned.get("sha256") or getattr(apk,"size",None)!=planned.get("size") or getattr(owner,"pid",None)!=vm.get("pid") or str(getattr(owner,"start_ticks",None))!=str(vm.get("proc_start_time")) or getattr(owner,"uuid",None)!=vm.get("uuid") or getattr(owner,"qmp_socket",None)!=vm.get("qmp_socket") or getattr(owner,"qga_socket",None)!=vm.get("qga_socket")):raise LabError("Android semantic plan differs from current run/artifact/outer binding")
        validate_boot_receipt(plan, boot); validate_app_update_receipt(plan, boot, app); validate_cleanup_receipt(plan, cleanup, boot)
        server_vm=((run.get("profiles") or {}).get("server-router") or {}).get("vm") or {}
        def expected_link_binding(source: Mapping[str, Any], profile: str) -> dict[str, Any]:
            return {"run_id":run_id,"profile":profile,"marker":f"amnezia-release-lab:{run_id}:{profile}",
                "pid":source.get("pid"),"start_ticks":str(source.get("proc_start_time")),"uid":source.get("uid"),
                "uuid":source.get("uuid"),"qmp_socket":source.get("qmp_socket"),"qga_socket":source.get("qga_socket")}
        outer_expected=expected_link_binding(vm,"linux-headless-x64");server_expected=expected_link_binding(server_vm,"server-router")
        application_links=link.get("application_links");application_cleanup=link_cleanup.get("application_cleanup")
        if (link.get("run_id")!=run_id or link.get("attempt_nonce")!=getattr(owner,"attempt_nonce",None) or link.get("ready") is not True
            or link.get("outer_ownership")!=outer_expected or link.get("server_ownership")!=server_expected
            or link_cleanup.get("run_id")!=run_id or link_cleanup.get("attempt_nonce")!=getattr(owner,"attempt_nonce",None)
            or link_cleanup.get("clean") is not True or link_cleanup.get("outer_ownership")!=outer_expected
            or link_cleanup.get("server_ownership")!=server_expected or (link_cleanup.get("socket") or {}).get("exists") is not False
            or not isinstance(application_links,Mapping) or set(application_links)!={"server","outer"}
            or any((application_links.get(role) or {}).get("application_address")!="10.8.1.0/32" or (application_links.get(role) or {}).get("present") is not True for role in ("server","outer"))
            or not isinstance(application_cleanup,Mapping) or set(application_cleanup)!={"server","outer"}
            or any((application_cleanup.get(role) or {}).get("application_address")!="10.8.1.0/32" or (application_cleanup.get(role) or {}).get("present") is not False for role in ("server","outer"))):
            raise LabError("Android private-link receipt differs from current owned guests/run/attempt")
        probes=link.get("http"); expected_http={(run.get("manifest") or {}).get("sha256"):(run.get("manifest") or {}).get("size"),planned.get("sha256"):planned.get("size")}
        if (not isinstance(probes,list) or len(probes)!=2 or {x.get("sha256"):x.get("bytes") for x in probes if isinstance(x,Mapping)}!=expected_http):
            raise LabError("Android private-link HTTP probe differs from manifest/candidate bytes")
        return self._register_full4(run_id, "android", {"boot": dict(boot), "app": dict(app), "cleanup": dict(cleanup),"private_link":dict(link),"private_link_cleanup":dict(link_cleanup)})

    def _preflight_nested_android_inputs(self, run_id: str, plan: Any, fixture_adapter: Any, private_link: Any, baseline: Any) -> dict[str, Any]:
        run = self.get_run(run_id)
        planned = (run.get("artifacts") or {}).get("android-arm64-v8a") or {}
        planned_baseline = (run.get("baseline_artifacts") or {}).get("android-arm64-v8a") or {}
        manifest = run.get("manifest") or {}
        fixture_helper = (run.get("semantic_helper_records") or {}).get("deploy/release_lab/android/consumer_fixture_server.py") or {}
        vulkan = (run.get("android_vulkan_records") or {}).get("deb") or {}
        profiles = run.get("profiles") or {}
        outer_vm = (profiles.get("linux-headless-x64") or {}).get("vm") or {}
        server_vm = (profiles.get("server-router") or {}).get("vm") or {}
        owner = getattr(plan, "ownership", None)
        fp = getattr(fixture_adapter, "plan", None); lp = getattr(private_link, "p", None)
        if not callable(getattr(private_link,"failure_archive",None)):raise LabError("nested Android private link lacks controller failure archive")
        def full_binding(source: Mapping[str, Any], profile: str) -> dict[str, Any]:
            return {"run_id":run_id,"profile":profile,"marker":f"amnezia-release-lab:{run_id}:{profile}",
                "pid":source.get("pid"),"start_ticks":str(source.get("proc_start_time")),"uid":source.get("uid"),
                "uuid":source.get("uuid"),"qmp_socket":source.get("qmp_socket"),"qga_socket":source.get("qga_socket")}
        outer_bound=full_binding(outer_vm,"linux-headless-x64");server_bound=full_binding(server_vm,"server-router")
        server_core={k:server_bound[k] for k in ("pid","start_ticks","uuid","qmp_socket","qga_socket")}
        http_objects=getattr(lp,"http_objects",())
        expected_http={(manifest.get("sha256"),manifest.get("size")),(planned.get("sha256"),planned.get("size"))}
        actual_http={(getattr(item,"sha256",None),getattr(item,"size",None)) for item in http_objects}
        try:
            canonical_artifact_path=canonical_android_artifact_path(Path(str(manifest.get("path",""))).read_bytes(),str(planned.get("sha256","")),planned.get("size"),Path(str(planned.get("path",""))).name)
        except (OSError,NestedCuttlefishError) as exc:
            raise LabError(f"nested Android signed artifact path is invalid: {exc}") from exc
        def normalized_link_binding(value: object) -> dict[str, Any]:
            source=value if isinstance(value,Mapping) else {}
            return {**{k:source.get(k) for k in ("run_id","profile","marker","pid","uid","uuid","qmp_socket","qga_socket")},
                    "start_ticks":str(source.get("start_ticks",source.get("proc_start_time")))}
        if (getattr(owner,"run_id",None)!=run_id or getattr(owner,"attempt_nonce",None) is None
            or getattr(baseline,"sha256",None)!=planned_baseline.get("sha256") or getattr(baseline,"size",None)!=planned_baseline.get("size")
            or getattr(baseline,"source_path",None)!=planned_baseline.get("path") or getattr(baseline,"name",None)!=Path(str(planned_baseline.get("path",""))).name
            or getattr(baseline,"package",None)!=getattr(getattr(plan,"apk",None),"package",None)
            or getattr(plan,"vulkan_deb_path",None)!=vulkan.get("path") or getattr(plan,"vulkan_deb_sha256",None)!=vulkan.get("sha256")
            or getattr(plan,"vulkan_deb_size",None)!=vulkan.get("size")
            or getattr(fp,"run_id",None)!=run_id or getattr(fp,"attempt_nonce",None)!=owner.attempt_nonce
            or getattr(fp,"marker",None)!=server_bound["marker"] or getattr(fp,"outer_ownership",None)!=server_core
            or getattr(fp,"script_sha256",None)!=fixture_helper.get("sha256") or getattr(fp,"script_size",None)!=fixture_helper.get("size")
            or PurePosixPath(str(getattr(fp,"script_path",""))).name!="consumer_fixture_server.py"
            or getattr(fp,"manifest_sha256",None)!=manifest.get("sha256") or getattr(fp,"manifest_size",None)!=manifest.get("size")
            or getattr(fp,"apk_sha256",None)!=planned.get("sha256") or getattr(fp,"apk_size",None)!=planned.get("size")
            or getattr(fp,"artifact_path",None)!=canonical_artifact_path
            or getattr(lp,"run_id",None)!=run_id or getattr(lp,"attempt_nonce",None)!=owner.attempt_nonce
            or normalized_link_binding(getattr(lp,"outer_binding",None))!=outer_bound
            or normalized_link_binding(getattr(lp,"server_binding",None))!=server_bound
            or getattr(lp,"endpoint",None)!="http://10.8.1.0:17865" or getattr(fp,"endpoint",None)!=getattr(lp,"endpoint",None)
            or getattr(lp,"application_address",None)!="10.8.1.0/32" or actual_http!=expected_http
            or {getattr(item,"path",None) for item in http_objects}!={"/manifest.json",canonical_artifact_path}):
            raise LabError("nested Android fixture/private-link plan differs from current run/VM/artifact/manifest")
        expected_stage=[{"path":getattr(fp,key),"sha256":sha,"size":size,"uid":0,"mode":"0600"} for key,sha,size in (
            ("script_path",getattr(fp,"script_sha256",None),getattr(fp,"script_size",None)),
            ("manifest_path",getattr(fp,"manifest_sha256",None),getattr(fp,"manifest_size",None)),
            ("apk_path",getattr(fp,"apk_sha256",None),getattr(fp,"apk_size",None)))]
        return {"run":run,"planned":planned,"manifest":manifest,"fixture_helper":fixture_helper,"fixture_plan":fp,"expected_stage":expected_stage,"server_core":server_core}

    def archive_nested_link_failure(self, run_id: str, record: Mapping[str, Any]) -> dict[str, Any]:
        """Durably preserve bounded private-link evidence before fixture cleanup."""
        self.assert_mutation_context();self.get_run(run_id)
        if (not isinstance(record,Mapping) or record.get("schema")!=1 or record.get("operation")!="nested-private-qemu-link-failure"
                or record.get("run_id")!=run_id or not re.fullmatch(r"[0-9a-f]{48}",str(record.get("attempt_nonce","")))):
            raise LabError("nested private-link failure identity")
        data=(json.dumps(dict(record),sort_keys=True,separators=(",",":"))+"\n").encode()
        if len(data)>65536:raise LabError("nested private-link failure record exceeds bound")
        directory=ensure_owned_child(self.root,self.root/"runs"/run_id/"controller","nested private-link controller archive");directory.mkdir(parents=True,exist_ok=True)
        out=ensure_owned_child(self.root,directory/f"private-link-failure-{record['attempt_nonce']}.json","nested private-link failure archive")
        fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_BINARY",0),0o600)
        try:
            view=memoryview(data)
            while view:
                count=os.write(fd,view)
                if count<=0:raise OSError("short nested private-link archive write")
                view=view[count:]
            os.fsync(fd)
        finally:os.close(fd)
        if os.name != "nt":
            dirfd=os.open(directory,os.O_RDONLY|getattr(os,"O_DIRECTORY",0));os.fsync(dirfd);os.close(dirfd)
        observed=out.read_bytes()
        if observed!=data:raise LabError("nested private-link archive readback differs")
        return {"origin":"controller","immutable":True,"path":str(out),"sha256":hashlib.sha256(observed).hexdigest(),"size":len(observed)}

    def archive_nested_vulkan_failure(self, run_id: str, record: Mapping[str, Any]) -> dict[str, Any]:
        """Persist bounded guest Vulkan diagnostics before prelaunch cleanup."""
        self.assert_mutation_context(); run=self.get_run(run_id)
        if (not isinstance(record,Mapping) or record.get("schema")!=1 or record.get("outer_failure")!="vulkan-runtime-probe"
                or record.get("run_id")!=run_id or not re.fullmatch(r"[0-9a-f]{48}",str(record.get("attempt_nonce","")))
                or not isinstance(record.get("outer_ownership"),Mapping) or not isinstance(record.get("diagnostic"),Mapping)):
            raise LabError("nested Vulkan failure identity")
        vm=(((run.get("profiles") or {}).get("linux-headless-x64") or {}).get("vm") or {})
        expected_outer={"run_id":run_id,"profile":"linux-headless-x64","attempt_nonce":record.get("attempt_nonce"),
            "pid":vm.get("pid"),"start_ticks":int(vm.get("proc_start_time")) if str(vm.get("proc_start_time","")).isdigit() else vm.get("proc_start_time"),
            "uuid":vm.get("uuid"),"qmp_socket":vm.get("qmp_socket"),"qga_socket":vm.get("qga_socket")}
        if dict(record["outer_ownership"])!=expected_outer:
            raise LabError("nested Vulkan failure outer ownership differs from current VM")
        data=(json.dumps(dict(record),sort_keys=True,separators=(",",":"))+"\n").encode()
        if len(data)>16384: raise LabError("nested Vulkan failure record exceeds bound")
        directory=ensure_owned_child(self.root,self.root/"runs"/run_id/"controller","nested Vulkan failure archive");directory.mkdir(parents=True,exist_ok=True)
        out=ensure_owned_child(self.root,directory/f"vulkan-failure-{record['attempt_nonce']}.json","nested Vulkan failure archive")
        fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_BINARY",0),0o600)
        try:
            view=memoryview(data)
            while view:
                count=os.write(fd,view)
                if count<=0: raise OSError("short nested Vulkan archive write")
                view=view[count:]
            os.fsync(fd)
        finally: os.close(fd)
        if os.name != "nt":
            dirfd=os.open(directory,os.O_RDONLY|getattr(os,"O_DIRECTORY",0));os.fsync(dirfd);os.close(dirfd)
        observed=out.read_bytes()
        if observed!=data: raise LabError("nested Vulkan archive readback differs")
        return {"origin":"controller","immutable":True,"path":str(out),"sha256":hashlib.sha256(observed).hexdigest(),"size":len(observed)}

    def archive_nested_boot_failure(self, run_id: str, record: Mapping[str, Any], screenshot: bytes | None = None) -> dict[str, Any]:
        """Persist one bounded boot state-machine failure before exact cleanup."""
        self.assert_mutation_context();run=self.get_run(run_id)
        current=((run.get("profiles") or {}).get("linux-headless-x64") or {}).get("vm") or {}
        expected={"run_id":run_id,"profile":"linux-headless-x64","attempt_nonce":record.get("attempt_nonce"),
            "pid":current.get("pid"),"start_ticks":int(current.get("proc_start_time",0)),"uuid":current.get("uuid"),
            "qmp_socket":current.get("qmp_socket"),"qga_socket":current.get("qga_socket")}
        if (not isinstance(record,Mapping) or record.get("schema")!=1 or record.get("outer_failure")!="nested-boot"
                or record.get("run_id")!=run_id or not re.fullmatch(r"[0-9a-f]{48}",str(record.get("attempt_nonce","")))
                or record.get("outer_ownership")!=expected or not isinstance(record.get("last_probe"),Mapping)
                or not isinstance(record.get("qemu_seen"),bool) or not isinstance(record.get("phase"),str)):
            raise LabError("nested boot failure identity")
        data=(json.dumps(dict(record),sort_keys=True,separators=(",",":"))+"\n").encode()
        app_focus=str(record.get("phase","")).startswith("app-")
        observations=(record.get("last_probe") or {}).get("focus_observations")
        if app_focus and observations is not None:
            if not isinstance(observations,list) or len(observations)>56:raise LabError("nested app focus observation bound")
            for observation in observations:
                raw=observation.get("raw") if isinstance(observation,Mapping) else None
                if (not isinstance(raw,Mapping) or raw.get("origin")!="guest" or raw.get("transport")!="qga-adb" or raw.get("path")!="adb:activity-top-resumed"
                        or not isinstance(raw.get("size"),int) or isinstance(raw.get("size"),bool) or not 0<=raw["size"]<=6144
                        or not re.fullmatch(r"[0-9a-f]{64}",str(raw.get("sha256",""))) or not isinstance(raw.get("bytes_b64"),str)):
                    raise LabError("nested app focus raw identity")
                try:raw_bytes=base64.b64decode(raw["bytes_b64"],validate=True)
                except Exception as exc:raise LabError("nested app focus raw encoding") from exc
                if len(raw_bytes)!=raw["size"] or hashlib.sha256(raw_bytes).hexdigest()!=raw["sha256"]:raise LabError("nested app focus raw readback")
        network_failure=str(record.get("phase",""))=="android-network"
        if network_failure:
            probe=record.get("last_probe") or {};guest_network=probe.get("guest_network")
            if (not isinstance(guest_network,Mapping) or len(guest_network)>12
                    or isinstance(probe.get("raw_size"),bool) or not isinstance(probe.get("raw_size"),int)
                    or not 0<probe["raw_size"]<=131072 or not re.fullmatch(r"[0-9a-f]{64}",str(probe.get("raw_sha256","")))):
                raise LabError("nested network boot failure payload identity")
            raw_probe={key:value for key,value in probe.items() if key not in {"raw_size","raw_sha256","processes_sha256"}}
            raw_bytes=json.dumps(raw_probe,sort_keys=True,separators=(",",":")).encode()
            if len(raw_bytes)!=probe["raw_size"] or hashlib.sha256(raw_bytes).hexdigest()!=probe["raw_sha256"]:
                raise LabError("nested network boot failure raw binding")
            for row in guest_network.values():
                if (not isinstance(row,Mapping) or not isinstance(row.get("argv"),list) or len(row["argv"])>32
                        or any(not isinstance(arg,str) or len(arg)>4096 for arg in row["argv"])
                        or isinstance(row.get("exit_code"),bool) or not isinstance(row.get("exit_code"),int)
                        or not isinstance(row.get("stdout"),str) or len(row["stdout"])>4096
                        or not isinstance(row.get("stderr"),str) or len(row["stderr"])>4096):
                    raise LabError("nested network boot failure command bound")
        failure_bound=786432 if app_focus else (196608 if network_failure else 16384)
        if len(data)>failure_bound:raise LabError("nested boot failure record exceeds bound")
        directory=ensure_owned_child(self.root,self.root/"runs"/run_id/"controller","nested boot failure archive");directory.mkdir(parents=True,exist_ok=True)
        screenshot_ack=None
        if app_focus:
            shot=(record.get("last_probe") or {}).get("screencap")
            if isinstance(shot,Mapping) and shot.get("png_signature") is True:
                png=screenshot
                if (not isinstance(png,bytes) or not png.startswith(b"\x89PNG\r\n\x1a\n") or len(png)!=shot.get("size") or len(png)>4194304
                        or hashlib.sha256(png).hexdigest()!=shot.get("sha256")):raise LabError("nested app failure screenshot identity")
                image=ensure_owned_child(self.root,directory/f"nested-app-focus-{record['attempt_nonce']}.png","nested app failure screenshot")
                image_fd=os.open(image,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_BINARY",0),0o600)
                try:
                    view=memoryview(png)
                    while view:
                        count=os.write(image_fd,view)
                        if count<=0:raise OSError("short nested app screenshot write")
                        view=view[count:]
                    os.fsync(image_fd)
                finally:os.close(image_fd)
                screenshot_ack={"path":str(image),"sha256":hashlib.sha256(png).hexdigest(),"size":len(png),"immutable":True}
        out=ensure_owned_child(self.root,directory/f"nested-boot-failure-{record['attempt_nonce']}.json","nested boot failure archive")
        fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_BINARY",0),0o600)
        try:
            view=memoryview(data)
            while view:
                count=os.write(fd,view)
                if count<=0:raise OSError("short nested boot archive write")
                view=view[count:]
            os.fsync(fd)
        finally:os.close(fd)
        if os.name!="nt":
            dirfd=os.open(directory,os.O_RDONLY|getattr(os,"O_DIRECTORY",0));os.fsync(dirfd);os.close(dirfd)
        observed=out.read_bytes()
        if observed!=data:raise LabError("nested boot archive readback differs")
        ack={"origin":"controller","immutable":True,"path":str(out),"sha256":hashlib.sha256(observed).hexdigest(),"size":len(observed)}
        if screenshot_ack is not None:ack["screenshot"]=screenshot_ack
        return ack

    def archive_nested_host_dependency_failure(self, run_id: str, record: Mapping[str, Any]) -> dict[str, Any]:
        self.assert_mutation_context();run=self.get_run(run_id)
        if (not isinstance(record,Mapping) or record.get("schema")!=1 or record.get("run_id")!=run_id
                or record.get("profile")!="linux-headless-x64" or not re.fullmatch(r"[0-9a-f]{48}",str(record.get("attempt_nonce","")))
                or record.get("verifier_sha256")!="742b5e27241e308995a4a245828a07aeff72928bb49a9f74db35a96212572fa6"):
            raise LabError("nested host dependency failure identity")
        current=((run.get("profiles") or {}).get("linux-headless-x64") or {}).get("vm") or {}
        expected={"run_id":run_id,"profile":"linux-headless-x64","attempt_nonce":record["attempt_nonce"],"pid":current.get("pid"),"start_ticks":int(current.get("proc_start_time",0)),"uuid":current.get("uuid"),"qmp_socket":current.get("qmp_socket"),"qga_socket":current.get("qga_socket")}
        if record.get("outer")!=expected:raise LabError("nested host dependency outer identity")
        data=(json.dumps(dict(record),sort_keys=True,separators=(",",":"))+"\n").encode()
        if len(data)>16384:raise LabError("nested host dependency failure exceeds bound")
        directory=ensure_owned_child(self.root,self.root/"runs"/run_id/"controller","nested dependency archive");directory.mkdir(parents=True,exist_ok=True)
        out=ensure_owned_child(self.root,directory/f"host-dependency-failure-{record['attempt_nonce']}.json","nested dependency archive")
        fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_BINARY",0),0o600)
        try:
            view=memoryview(data)
            while view:
                n=os.write(fd,view)
                if n<=0:raise OSError("short dependency archive write")
                view=view[n:]
            os.fsync(fd)
        finally:os.close(fd)
        observed=out.read_bytes()
        if observed!=data:raise LabError("nested dependency archive readback differs")
        return {"origin":"controller","immutable":True,"path":str(out),"sha256":hashlib.sha256(observed).hexdigest(),"size":len(observed)}

    def archive_nested_host_dependency_success(self, run_id: str, record: Mapping[str, Any]) -> dict[str, Any]:
        self.assert_mutation_context();run=self.get_run(run_id)
        if (not isinstance(record,Mapping) or record.get("schema")!=1 or record.get("run_id")!=run_id
                or not re.fullmatch(r"[0-9a-f]{48}",str(record.get("attempt_nonce",""))) or record.get("origin")!="guest"
                or record.get("transport")!="qga" or record.get("injected") is not False
                or (record.get("signed_index_verifier") or {}).get("sha256")!="742b5e27241e308995a4a245828a07aeff72928bb49a9f74db35a96212572fa6"):
            raise LabError("nested host dependency success identity")
        vm=((run.get("profiles") or {}).get("linux-headless-x64") or {}).get("vm") or {}
        expected={"run_id":run_id,"profile":"linux-headless-x64","attempt_nonce":record["attempt_nonce"],"pid":vm.get("pid"),"start_ticks":int(vm.get("proc_start_time",0)),"uuid":vm.get("uuid"),"qmp_socket":vm.get("qmp_socket"),"qga_socket":vm.get("qga_socket")}
        if record.get("outer")!=expected:raise LabError("nested host dependency success outer identity")
        data=(json.dumps(dict(record),sort_keys=True,separators=(",",":"))+"\n").encode()
        if len(data)>131072:raise LabError("nested host dependency success exceeds bound")
        directory=ensure_owned_child(self.root,self.root/"runs"/run_id/"controller","nested dependency archive");directory.mkdir(parents=True,exist_ok=True)
        out=ensure_owned_child(self.root,directory/f"host-dependency-success-{record['attempt_nonce']}.json","nested dependency archive")
        immutable_bytes_dump(out,data);observed=out.read_bytes()
        if observed!=data:raise LabError("nested dependency success archive readback differs")
        return {"origin":"controller","immutable":True,"path":str(out),"sha256":hashlib.sha256(observed).hexdigest(),"size":len(observed)}

    @mutation_operation
    def install_nested_android_host_dependencies(self, run_id: str, installer: Any, timeout: float = 1200) -> dict[str, Any]:
        """Install the frozen signed Noble dependency closure before large Android staging."""
        self.assert_mutation_context();run=self.get_run(run_id);validate_semantic_helper_records(run.get("semantic_helper_records"));validate_android_host_dependency_records(run.get("android_host_dependency_records"))
        try:from .nested_cuttlefish_host_dependencies import HostDependencyInstaller
        except ImportError:from nested_cuttlefish_host_dependencies import HostDependencyInstaller
        if not isinstance(installer,HostDependencyInstaller):raise LabError("nested host dependency installer type is not canonical")
        for callback,name in ((getattr(installer,"archive",None),"archive_nested_host_dependency_failure"),(getattr(installer,"success_archive",None),"archive_nested_host_dependency_success")):
            if getattr(callback,"__self__",None) is not self or getattr(callback,"__name__","")!=name:raise LabError("nested host dependency archive callback is not controller-owned")
        plan=getattr(installer,"p",None)
        if plan is None or plan.run_id!=run_id or plan.profile!="linux-headless-x64":raise LabError("nested host dependency plan differs from run")
        vm=((run.get("profiles") or {}).get("linux-headless-x64") or {}).get("vm") or {}
        expected={"run_id":run_id,"profile":"linux-headless-x64","attempt_nonce":plan.attempt_nonce,"pid":vm.get("pid"),"start_ticks":int(vm.get("proc_start_time",0)),"uuid":vm.get("uuid"),"qmp_socket":vm.get("qmp_socket"),"qga_socket":vm.get("qga_socket")}
        if dict(plan.outer)!=expected:raise LabError("nested host dependency plan outer identity differs")
        receipt=installer.install(timeout=timeout)
        ack=receipt.get("controller_success_archive") or {};ack_path=ensure_owned_child(self.root,Path(str(ack.get("path",""))),"nested dependency success archive");expected_ack=ensure_owned_child(self.root,self.root/"runs"/run_id/"controller"/f"host-dependency-success-{plan.attempt_nonce}.json","nested dependency success archive")
        if ack_path!=expected_ack:raise LabError("nested dependency success archive path is noncanonical")
        ack_actual=artifact_record(ack_path)
        try:ack_payload=json.loads(ack_path.read_text(encoding="utf-8"))
        except (OSError,UnicodeDecodeError,json.JSONDecodeError) as exc:raise LabError("nested dependency success archive unreadable") from exc
        expected_archived={k:v for k,v in receipt.items() if k!="controller_success_archive"}
        if ack.get("origin")!="controller" or ack.get("immutable") is not True or (ack_actual["sha256"],ack_actual["size"])!=(ack.get("sha256"),ack.get("size")) or ack_payload!=expected_archived:
            raise LabError("nested dependency success archive differs from guest receipt")
        out=ensure_owned_child(self.root,self.root/"runs"/run_id/"controller"/f"host-dependencies-{plan.attempt_nonce}.json","nested dependency receipt")
        out.parent.mkdir(parents=True,exist_ok=True);immutable_json_dump(out,receipt);record=artifact_record(out)
        state=self.load_state();target=state["runs"][run_id];target["nested_android_host_dependencies"]={**record,"attempt_nonce":plan.attempt_nonce,"verifier_sha256":receipt["signed_index_verifier"]["sha256"],"success_archive":{"path":str(ack_path),"sha256":ack_actual["sha256"],"size":ack_actual["size"]}};self.save_state(state)
        return receipt

    def _archive_nested_wayland(self,run_id:str,record:Mapping[str,Any],kind:str)->dict[str,Any]:
        self.assert_mutation_context();run=self.get_run(run_id)
        if not isinstance(record,Mapping) or record.get("run_id")!=run_id or not re.fullmatch(r"[0-9a-f]{48}",str(record.get("attempt_nonce",""))):raise LabError("nested Wayland archive identity")
        vm=((run.get("profiles") or {}).get("linux-headless-x64") or {}).get("vm") or {}
        expected={"run_id":run_id,"profile":"linux-headless-x64","attempt_nonce":record["attempt_nonce"],"pid":vm.get("pid"),"start_ticks":int(vm.get("proc_start_time",0)),"uuid":vm.get("uuid"),"qmp_socket":vm.get("qmp_socket"),"qga_socket":vm.get("qga_socket")}
        if record.get("outer")!=expected:raise LabError("nested Wayland outer identity")
        data=(json.dumps(dict(record),sort_keys=True,separators=(",",":"))+"\n").encode()
        if len(data)>262144:raise LabError("nested Wayland archive exceeds bound")
        out=ensure_owned_child(self.root,self.root/"runs"/run_id/"controller"/f"wayland-{kind}-{record['attempt_nonce']}.json","nested Wayland archive")
        out.parent.mkdir(parents=True,exist_ok=True);immutable_bytes_dump(out,data);observed=out.read_bytes()
        if observed!=data:raise LabError("nested Wayland archive readback differs")
        return {"origin":"controller","immutable":True,"path":str(out),"sha256":hashlib.sha256(observed).hexdigest(),"size":len(observed)}

    def archive_nested_wayland_failure(self,run_id:str,record:Mapping[str,Any])->dict[str,Any]:return self._archive_nested_wayland(run_id,record,"failure")
    def archive_nested_wayland_success(self,run_id:str,record:Mapping[str,Any])->dict[str,Any]:return self._archive_nested_wayland(run_id,record,"success")

    @mutation_operation
    def install_nested_android_wayland_dependency(self,run_id:str,installer:Any,timeout:float=300)->dict[str,Any]:
        self.assert_mutation_context();run=self.get_run(run_id);validate_semantic_helper_records(run.get("semantic_helper_records"));validate_android_wayland_records(run.get("android_wayland_records"))
        try:from .nested_cuttlefish_wayland_dependency import WaylandDependencyInstaller
        except ImportError:from nested_cuttlefish_wayland_dependency import WaylandDependencyInstaller
        if not isinstance(installer,WaylandDependencyInstaller):raise LabError("nested Wayland installer type is not canonical")
        for callback,name in ((installer.failure_archive,"archive_nested_wayland_failure"),(installer.success_archive,"archive_nested_wayland_success")):
            if getattr(callback,"__self__",None) is not self or getattr(callback,"__name__","")!=name:raise LabError("nested Wayland archive callback is not controller-owned")
        plan=installer.plan;vm=((run.get("profiles") or {}).get("linux-headless-x64") or {}).get("vm") or {};expected={"run_id":run_id,"profile":"linux-headless-x64","attempt_nonce":plan.attempt_nonce,"pid":vm.get("pid"),"start_ticks":int(vm.get("proc_start_time",0)),"uuid":vm.get("uuid"),"qmp_socket":vm.get("qmp_socket"),"qga_socket":vm.get("qga_socket")}
        if plan.run_id!=run_id or dict(plan.outer)!=expected:raise LabError("nested Wayland plan differs")
        receipt=installer.install(timeout);out=ensure_owned_child(self.root,self.root/"runs"/run_id/"controller"/f"wayland-install-{plan.attempt_nonce}.json","nested Wayland receipt");out.parent.mkdir(parents=True,exist_ok=True);immutable_json_dump(out,receipt);rec=artifact_record(out)
        state=self.load_state();state["runs"][run_id]["nested_android_wayland"]={**rec,"attempt_nonce":plan.attempt_nonce,"archive":receipt.get("controller_archive")};self.save_state(state);return receipt

    @mutation_operation
    def stage_nested_android_fixture(self, run_id: str, plan: Any, fixture_adapter: Any, private_link: Any, baseline: Any, timeout: float = 900) -> dict[str, Any]:
        """Stage exact fixture bytes only after authoritative controller preflight."""
        self.assert_mutation_context(); ctx=self._preflight_nested_android_inputs(run_id,plan,fixture_adapter,private_link,baseline);fp=ctx["fixture_plan"];qga=fixture_adapter.qga
        if isinstance(timeout,bool) or not isinstance(timeout,(int,float)) or not math.isfinite(timeout) or timeout<=0 or timeout>1800:raise LabError("invalid nested fixture staging deadline")
        deadline=time.monotonic()+timeout
        def identity_fence() -> None:
            if fixture_adapter.snapshot()!=ctx["server_core"] or str(getattr(qga,"socket_path",""))!=str(ctx["server_core"]["qga_socket"]):raise LabError("server-router identity/QGA changed during fixture staging")
        def fence() -> None:
            identity_fence()
            if time.monotonic()>=deadline:raise LabError("nested fixture staging deadline expired")
        fence()
        sources=((Path(ctx["fixture_helper"]["path"]),fp.script_path,fp.script_sha256,fp.script_size),(Path(ctx["manifest"]["path"]),fp.manifest_path,fp.manifest_sha256,fp.manifest_size),(Path(ctx["planned"]["path"]),fp.apk_path,fp.apk_sha256,fp.apk_size))
        guest_root=str(PurePosixPath(fp.script_path).parent)
        expected_root=str(PurePosixPath("/var/lib/amnezia-release-lab/fixture")/plan.ownership.attempt_nonce)
        out=ensure_owned_child(self.root,self.root/"runs"/run_id/"controller"/"nested-fixture-stage.json","nested fixture stage receipt")
        if out.exists() or out.is_symlink():raise LabError("nested fixture stage receipt already exists")
        if guest_root!=expected_root or any(PurePosixPath(dst).parent!=PurePosixPath(guest_root) for _,dst,_,_ in sources):raise LabError("fixture staging paths do not share the exact owned guest root")
        mkdir_code="""import json,os,stat,sys
parts=('var','lib','amnezia-release-lab');fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
for part in parts:
 try:n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
 except FileNotFoundError:
  if part!='amnezia-release-lab':raise
  os.mkdir(part,0o700,dir_fd=fd);n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
 os.close(fd);fd=n;s=os.fstat(fd)
 if s.st_uid!=0 or (s.st_mode&0o022):raise SystemExit('unsafe owned ancestry')
try:n=os.open('fixture',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
except FileNotFoundError:os.mkdir('fixture',0o700,dir_fd=fd);n=os.open('fixture',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
os.close(fd);fd=n;s=os.fstat(fd)
if s.st_uid!=0 or (s.st_mode&0o022):raise SystemExit('unsafe fixture parent')
os.mkdir(sys.argv[1],0o700,dir_fd=fd);child=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);cs=os.fstat(child);os.close(child);os.close(fd)
print(json.dumps({'root_inode':cs.st_ino,'uid':cs.st_uid,'mode':oct(cs.st_mode&0o777)}))"""
        mkdir=None;root_inode=0
        try:
            mkdir=qga.guest_exec_wait("/usr/bin/python3",["-c",mkdir_code,plan.ownership.attempt_nonce],timeout=min(30,max(1,deadline-time.monotonic())))
            fence()
            if mkdir.get("exitcode")!=0:raise LabError("fixture guest root exclusive creation failed")
            try:mkdir_receipt=json.loads(mkdir.get("stdout",""));root_inode=mkdir_receipt["root_inode"]
            except (KeyError,TypeError,ValueError,json.JSONDecodeError) as exc:raise LabError("fixture guest root receipt missing") from exc
            if isinstance(root_inode,bool) or not isinstance(root_inode,int) or root_inode<=0 or mkdir_receipt.get("uid")!=0 or mkdir_receipt.get("mode")!="0o700":raise LabError("fixture guest root ownership receipt invalid")
            for src,dst,sha,size in sources:
                fence()
                actual=artifact_record(src)
                if actual["sha256"]!=sha or actual["size"]!=size:raise LabError("fixture local bytes changed after preflight")
                qga.write_file_from_path(dst,src,sha,size,deadline=deadline,max_size=128*1024*1024);fence()
            code="""import hashlib,json,os,pathlib,sys
rows=[]
for p,h,n in zip(sys.argv[1::3],sys.argv[2::3],sys.argv[3::3]):
 q=pathlib.Path(p);os.chmod(q,0o600);b=q.read_bytes();s=q.stat()
 if s.st_uid!=0 or (s.st_mode&0o777)!=0o600 or hashlib.sha256(b).hexdigest()!=h or len(b)!=int(n):raise SystemExit('staged file mismatch')
 rows.append({'path':p,'sha256':h,'size':len(b),'uid':s.st_uid,'mode':'0600'})
print(json.dumps({'files':rows},separators=(',',':')))"""
            raw=qga.guest_exec_wait("/usr/bin/python3",["-c",code,*[str(x) for row in sources for x in row[1:]]],timeout=min(60,max(1,deadline-time.monotonic())));fence()
            if raw.get("exitcode")!=0:raise LabError("fixture staged receipt command failed")
            receipt=json.loads(raw.get("stdout",""));expected=ctx["expected_stage"]
            if receipt.get("files")!=expected:raise LabError("fixture staged receipt differs from exact bytes/owner/mode")
        except BaseException as primary:
            try:
                identity_fence();cleanup_code="""import os,stat,sys
nonce=sys.argv[1];ino=int(sys.argv[2]);fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
for part in ('var','lib','amnezia-release-lab','fixture'):
 n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=n
parent=fd;child=os.open(nonce,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);s=os.fstat(child)
if (ino and s.st_ino!=ino) or s.st_uid!=0 or (s.st_mode&0o777)!=0o700:raise SystemExit('staging root identity changed')
for name in os.listdir(child):
 st=os.stat(name,dir_fd=child,follow_symlinks=False)
 if not stat.S_ISREG(st.st_mode):raise SystemExit('unexpected staging entry')
 os.unlink(name,dir_fd=child)
os.close(child);os.rmdir(nonce,dir_fd=parent);os.close(parent)"""
                qga.guest_exec_wait("/usr/bin/python3",["-c",cleanup_code,plan.ownership.attempt_nonce,str(root_inode)],timeout=20);identity_fence()
            except BaseException as cleanup:
                if hasattr(primary,"add_note"):primary.add_note(f"fixture staging cleanup also failed: {cleanup!r}")
                failure_path=ensure_owned_child(self.root,self.root/"runs"/run_id/"controller"/f"nested-fixture-stage-failure-{plan.ownership.attempt_nonce}.json","nested fixture staging failure")
                if not failure_path.exists():
                    failure_path.parent.mkdir(parents=True,exist_ok=True);immutable_json_dump(failure_path,{"schema":1,"run_id":run_id,"attempt_nonce":plan.ownership.attempt_nonce,"guest_root":guest_root,"observed_root_inode":root_inode or None,"cleanup_required":True,"reason":type(cleanup).__name__,"recorded_at":utc_now()})
            raise
        payload={"schema":1,"run_id":run_id,"attempt_nonce":plan.ownership.attempt_nonce,"guest_root":guest_root,"guest_root_inode":root_inode,"files":expected,"origin":"guest","transport":"qga","injected":False}
        out.parent.mkdir(parents=True,exist_ok=True);immutable_json_dump(out,payload);record=artifact_record(out)
        run=self.get_run(run_id);run["nested_android_fixture_stage"]={**record,"attempt_nonce":plan.ownership.attempt_nonce};state=self.load_state();state["runs"][run_id]=run;self.save_state(state);return payload

    def request_nested_android_visual(self, run_id: str, record: Mapping[str, Any], png: bytes) -> dict[str, Any]:
        """Publish immutable visual evidence while the semantic run owns the mutation lock."""
        self.get_run(run_id)
        if record.get("run_id") != run_id:
            raise LabError("nested Android visual request run mismatch")
        ack = AndroidVisualHandshakeStore(self.root).request(record, png)
        print(json.dumps({"milestone":"android-visual-request", "request_path":ack["request_path"],
                          "png_path":ack["png_path"], "request_sha256":ack["request_sha256"],
                          "request_id":ack["request_id"], "expires_at":ack["expires_at"],
                          "action":record.get("action"), "state":record.get("state"), "bounds":record.get("bounds")},
                         sort_keys=True, separators=(",", ":")), flush=True)
        return ack

    def poll_nested_android_visual(self, run_id: str, ack: Mapping[str, Any]) -> Mapping[str, Any] | None:
        """Read an operator decision without acquiring or nesting the mutation lock."""
        self.get_run(run_id)
        return AndroidVisualHandshakeStore(self.root).poll(ack)

    def decide_nested_android_visual(self, run_id: str, attempt_nonce: str, request_id: str,
                                     request_sha256: str, decision: str, bounds: Sequence[int] | None = None) -> dict[str, Any]:
        """External decision API; input only and intentionally outside mutation state."""
        self.get_run(run_id)
        return AndroidVisualHandshakeStore(self.root).decide(run_id, attempt_nonce, request_id, request_sha256, decision, bounds)

    @mutation_operation
    def run_nested_android_semantic(self, run_id: str, plan: Any, bridge: Any, fixture_adapter: Any, private_link: Any, baseline: Any, outer_live_snapshot: Any, visual_request: Any, visual_poll: Any) -> dict[str, Any]:
        """Run the reviewed nested lifecycle and durably archive its canonical receipt."""
        self.assert_mutation_context()
        run = self.get_run(run_id)
        archive_root = ensure_owned_child(self.root, self.root / "exports" / run_id / "android-arm64-v8a", "nested Android archive")
        receipt_path = ensure_owned_child(self.root, archive_root / "receipt.json", "nested Android common receipt")
        archive_path = ensure_owned_child(self.root, archive_root / "evidence.json", "nested Android evidence")
        if receipt_path.exists() or receipt_path.is_symlink() or archive_path.exists() or archive_path.is_symlink():
            raise LabError("nested Android archive attempt already exists")
        if not callable(getattr(bridge, "boot_failure_archive", None)):
            raise LabError("nested Android bridge lacks controller boot failure archive")
        if not callable(visual_request) or not callable(visual_poll):
            raise LabError("nested Android visual callbacks are missing")
        ctx=self._preflight_nested_android_inputs(run_id,plan,fixture_adapter,private_link,baseline);run=ctx["run"];planned=ctx["planned"]
        deps=run.get("nested_android_host_dependencies") or {};dep_path=ensure_owned_child(self.root,Path(str(deps.get("path",""))),"nested dependency receipt")
        dep_actual=artifact_record(dep_path)
        try:dep_payload=json.loads(dep_path.read_text(encoding="utf-8"))
        except (OSError,UnicodeDecodeError,json.JSONDecodeError) as exc:raise LabError("nested host dependency receipt unreadable") from exc
        success=deps.get("success_archive") or {};success_path=ensure_owned_child(self.root,Path(str(success.get("path",""))),"nested dependency success archive");expected_success_path=ensure_owned_child(self.root,self.root/"runs"/run_id/"controller"/f"host-dependency-success-{plan.ownership.attempt_nonce}.json","nested dependency success archive")
        if success_path!=expected_success_path:raise LabError("nested dependency early archive path is noncanonical")
        success_actual=artifact_record(success_path)
        try:success_payload=json.loads(success_path.read_text(encoding="utf-8"))
        except (OSError,UnicodeDecodeError,json.JSONDecodeError) as exc:raise LabError("nested dependency early success archive unreadable") from exc
        expected_success={k:v for k,v in dep_payload.items() if k!="controller_success_archive"}
        if (dep_actual.get("sha256")!=deps.get("sha256") or dep_actual.get("size")!=deps.get("size")
                or deps.get("attempt_nonce")!=plan.ownership.attempt_nonce or deps.get("verifier_sha256")!="742b5e27241e308995a4a245828a07aeff72928bb49a9f74db35a96212572fa6"
                or dep_payload.get("run_id")!=run_id or dep_payload.get("attempt_nonce")!=plan.ownership.attempt_nonce
                or (dep_payload.get("signed_index_verifier") or {}).get("sha256")!=deps.get("verifier_sha256")
                or getattr(bridge,"host_dependency_receipt",None)!=dep_payload
                or (success_actual.get("sha256"),success_actual.get("size"))!=(success.get("sha256"),success.get("size"))
                or success_payload!=expected_success or dep_payload.get("outer")!=dict(plan.ownership.__dict__)):
            raise LabError("nested host dependency receipt is missing, stale, or tampered")
        validate_android_wayland_records(run.get("android_wayland_records"));way=run.get("nested_android_wayland") or {}
        way_path=ensure_owned_child(self.root,Path(str(way.get("path",""))),"nested Wayland receipt");way_actual=artifact_record(way_path)
        try:way_payload=json.loads(way_path.read_text(encoding="utf-8"))
        except (OSError,UnicodeDecodeError,json.JSONDecodeError) as exc:raise LabError("nested Wayland receipt unreadable") from exc
        way_installer=getattr(bridge,"wayland_installer",None);way_plan=getattr(way_installer,"plan",None);way_records=run.get("android_wayland_records") or {}
        if ((way_actual.get("sha256"),way_actual.get("size"))!=(way.get("sha256"),way.get("size")) or way.get("attempt_nonce")!=plan.ownership.attempt_nonce
                or way_payload.get("run_id")!=run_id or way_payload.get("attempt_nonce")!=plan.ownership.attempt_nonce or way_payload.get("outer")!=dict(plan.ownership.__dict__)
                or getattr(bridge,"wayland_install_receipt",None)!=way_payload or way_plan is None or way_plan.run_id!=run_id or way_plan.attempt_nonce!=plan.ownership.attempt_nonce
                or dict(way_plan.outer)!=dict(plan.ownership.__dict__) or way_plan.qemu_sha256!=plan.qemu_aarch64_sha256
                or Path(way_plan.supplement_path).resolve()!=Path(way_records["supplement"]["path"]).resolve() or Path(way_plan.verifier_path).resolve()!=Path(way_records["verifier"]["path"]).resolve()):raise LabError("nested Wayland receipt is missing, stale, or tampered")
        way_ack=way_payload.get("controller_archive") or {};way_ack_path=ensure_owned_child(self.root,Path(str(way_ack.get("path",""))),"nested Wayland success archive");expected_way_ack=ensure_owned_child(self.root,self.root/"runs"/run_id/"controller"/f"wayland-success-{plan.ownership.attempt_nonce}.json","nested Wayland success archive")
        if way_ack_path!=expected_way_ack:raise LabError("nested Wayland success archive path is noncanonical")
        way_ack_actual=artifact_record(way_ack_path)
        try:way_ack_payload=json.loads(way_ack_path.read_text(encoding="utf-8"))
        except (OSError,UnicodeDecodeError,json.JSONDecodeError) as exc:raise LabError("nested Wayland success archive unreadable") from exc
        if (way_ack.get("origin")!="controller" or way_ack.get("immutable") is not True or (way_ack_actual["sha256"],way_ack_actual["size"])!=(way_ack.get("sha256"),way_ack.get("size")) or way_ack_payload!={k:v for k,v in way_payload.items() if k!="controller_archive"}):raise LabError("nested Wayland success archive differs")
        staged=run.get("nested_android_fixture_stage") or {};stage_path=ensure_owned_child(self.root,Path(str(staged.get("path",""))),"nested fixture stage receipt");actual=artifact_record(stage_path)
        try:stage_payload=json.loads(stage_path.read_text(encoding="utf-8"))
        except (OSError,UnicodeDecodeError,json.JSONDecodeError) as exc:raise LabError("nested fixture stage receipt is unreadable") from exc
        if (actual.get("sha256")!=staged.get("sha256") or actual.get("size")!=staged.get("size") or staged.get("attempt_nonce")!=plan.ownership.attempt_nonce
            or isinstance(stage_payload.get("guest_root_inode"),bool) or not isinstance(stage_payload.get("guest_root_inode"),int) or stage_payload.get("guest_root_inode",0)<=0
            or {k:v for k,v in stage_payload.items() if k!="guest_root_inode"}!={"schema":1,"run_id":run_id,"attempt_nonce":plan.ownership.attempt_nonce,"guest_root":str(PurePosixPath(ctx["fixture_plan"].script_path).parent),"files":ctx["expected_stage"],"origin":"guest","transport":"qga","injected":False}):raise LabError("nested fixture stage receipt is missing, stale, or tampered")
        common = NestedCuttlefishCommonAdapter(plan, bridge, baseline,
            str(run["baseline_version"]), str(run["candidate_version"]), fixture_adapter, private_link, outer_live_snapshot,
            visual_request=visual_request,visual_poll=visual_poll).run()
        validate_receipt(common, run_id=run_id, profile_id="android-arm64-v8a", artifact=planned,
                         baseline_version=str(run["baseline_version"]), candidate_version=str(run["candidate_version"]),
                         expected_role="candidate")
        raw = common["semantic"]
        archive_root.mkdir(parents=True, exist_ok=True)
        receipt_bytes = (json.dumps(common, sort_keys=True, separators=(",", ":")) + "\n").encode()
        immutable_bytes_dump(receipt_path, receipt_bytes)
        receipt_sha, receipt_size = sha256_file(receipt_path)
        if receipt_sha != hashlib.sha256(receipt_bytes).hexdigest() or receipt_size != len(receipt_bytes):
            raise LabError("nested Android immutable receipt write did not preserve exact bytes")
        identity = common["device_identity"]
        archive = {
            "schema": 1, "run_id": run_id, "profile": "android-arm64-v8a", "captured_at": utc_now(),
            "origin": "guest", "injected": False, "transport": "nested-qga",
            "artifact": dict(planned), "artifact_sha256": planned.get("sha256"), "artifact_size": planned.get("size"),
            "error": None, "raw_logs": [],
            "guest_binding": {"serial": identity["serial"], "qemu_uuid": identity["qemu_uuid"],
                              "outer_ownership": identity["outer_ownership"], "attempt_nonce": identity["attempt_nonce"]},
            "receipt": {"archive_path": str(receipt_path), "sha256": receipt_sha, "size": receipt_size},
        }
        immutable_json_dump(archive_path, archive)
        archive_sha, archive_size = sha256_file(archive_path)
        if archive_sha != hashlib.sha256(archive_path.read_bytes()).hexdigest() or archive_size <= 0:
            raise LabError("nested Android evidence archive write did not preserve exact bytes")
        self.register_android_semantic(run_id, plan, raw["boot"], raw["app"], raw["cleanup"],raw["private_link"],raw["private_link_cleanup"])
        run = self.get_run(run_id)
        run["profiles"]["android-arm64-v8a"].update(status="evidence-collected", steps=common["steps"], evidence=common, nested_transport="qga",
            evidence_archive=str(archive_path), archive_status="captured", nested_cleanup=raw["cleanup"])
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return {"receipt": common, "archive": {**archive, "archive_path": str(archive_path)}}

    def register_headless_semantic(self, run_id: str, plan: Any, http: Mapping[str, Any], update: Mapping[str, Any], rollback: Mapping[str, Any], reboot: Mapping[str, Any], cleanup: Mapping[str, Any]) -> dict[str, Any]:
        run=self.get_run(run_id);planned=(run.get("artifacts") or {}).get("linux-headless-x64") or {};baseline_planned=(run.get("baseline_artifacts") or {}).get("linux-headless-x64") or {};manifest=run.get("manifest") or {};key=run.get("manifest_public_key") or {};outer=getattr(plan,"outer_binding",None);candidate=getattr(plan,"candidate",None);baseline=getattr(plan,"baseline",None);vm=((run.get("profiles") or {}).get("linux-headless-x64") or {}).get("vm") or {}
        if (getattr(plan,"run_id",None)!=run_id or getattr(candidate,"tar_sha256",None)!=planned.get("sha256") or getattr(candidate,"tar_size",None)!=planned.get("size") or getattr(candidate,"manifest_sha256",None)!=manifest.get("sha256") or getattr(candidate,"key_sha256",None)!=key.get("sha256") or getattr(baseline,"tar_sha256",None)!=baseline_planned.get("sha256") or getattr(baseline,"tar_size",None)!=baseline_planned.get("size") or getattr(baseline,"version",None)!=run.get("baseline_version") or getattr(outer,"pid",None)!=vm.get("pid") or str(getattr(outer,"start_ticks",None))!=str(vm.get("proc_start_time")) or getattr(outer,"uuid",None)!=vm.get("uuid") or getattr(outer,"qmp_socket",None)!=vm.get("qmp_socket") or getattr(outer,"qga_socket",None)!=vm.get("qga_socket")):raise LabError("headless semantic plan differs from current run/artifact/manifest/key/outer binding")
        validate_http_receipt(plan,http);validate_update_receipt(plan,update,http);validate_rollback_receipt(plan,rollback,update);validate_reboot_receipt(plan,reboot,plan.baseline,rollback)
        if cleanup.get("stopped") is not True or cleanup.get("listener_closed") is not True or cleanup.get("unknown_survivors") != []: raise LabError("headless fixture cleanup is incomplete")
        return self._register_full4(run_id,"headless",{"http":dict(http),"update":dict(update),"rollback":dict(rollback),"reboot":dict(reboot),"cleanup":dict(cleanup)})

    def register_linux_visual(self, run_id: str, ack: Mapping[str, Any], collect: Mapping[str, Any]) -> dict[str, Any]:
        validate_root_visual_ack(owned_root=self.root,ack=ack,collect=collect)
        return self._register_full4(run_id,"linux-visual",{"ack":dict(ack),"collect":dict(collect)})

    def gate(self, run_id: str, lane: str, artifact_dir: Path | None = None, outer_artifact: Path | None = None) -> dict[str, Any]:
        self.assert_mutation_context()
        run = self.get_run(run_id)
        if lane not in ("candidate", "release"):
            raise LabError("lane must be candidate or release")
        if run.get("lane") != lane:
            raise LabError("gate lane does not match the planned run lane")
        if self.dry_run or run.get("dry_run"):
            return {"run_id": run_id, "lane": lane, "candidate_passed": False, "release_passed": False, "reason": "dry-run cannot pass a release gate"}
        if run.get("test_mode") is True:
            return {"run_id": run_id, "lane": lane, "candidate_passed": False, "release_passed": False, "reason": "test_mode cannot pass a release gate"}
        profiles = run.get("profiles")
        if not isinstance(profiles, Mapping):
            raise LabError("gate requires the complete profile state record")
        expected_profiles = run.get("expected_profiles")
        if not isinstance(expected_profiles, list) or not expected_profiles or any(profile_id not in PROFILE_IDS for profile_id in expected_profiles):
            raise LabError("gate requires an explicit non-empty release profile set")
        if lane == "release":
            if set(expected_profiles) != set(PROFILE_IDS) or set(run.get("artifacts", {})) != set(RELEASE_PLATFORM_IDS) or set(run.get("baseline_artifacts", {})) != set(RELEASE_PLATFORM_IDS):
                raise LabError("release gate requires all release profiles and candidate/baseline artifact records")
        for profile_id in expected_profiles:
            artifact_id = artifact_id_for_profile(profile_id)
            planned_guest_artifact = run.get("outer_artifact") if profile_id == "windows-x64" else (run.get("artifacts", {}).get(artifact_id) or run.get("artifacts", {}).get(profile_id) or {})
            if not isinstance(planned_guest_artifact, Mapping) or not isinstance(planned_guest_artifact.get("path"), str) or not re.fullmatch(r"[0-9a-fA-F]{64}", str(planned_guest_artifact.get("sha256", ""))) or not isinstance(planned_guest_artifact.get("size"), int) or planned_guest_artifact.get("size", -1) < 0:
                raise LabError(f"gate artifact record is incomplete for {profile_id}")
            if lane == "release":
                baseline_guest_artifact = run.get("baseline_outer_artifact") if profile_id == "windows-x64" else (run.get("baseline_artifacts", {}).get(artifact_id) or {})
                if not isinstance(baseline_guest_artifact, Mapping) or not isinstance(baseline_guest_artifact.get("path"), str) or not re.fullmatch(r"[0-9a-fA-F]{64}", str(baseline_guest_artifact.get("sha256", ""))) or not isinstance(baseline_guest_artifact.get("size"), int) or baseline_guest_artifact.get("size", -1) < 0:
                    raise LabError(f"gate baseline artifact record is incomplete for {profile_id}")
        profile_records = run.get("profile_records")
        if lane == "release" and (not isinstance(profile_records, Mapping) or set(profile_records) != set(ALL_PROFILE_IDS)):
            raise LabError("release gate requires immutable records for every lab profile")
        if lane == "release":
            try:
                publication = run.get("publication_evidence")
                if not isinstance(publication, Mapping):
                    raise LabError("release publication requires complete self-hosted client-flow evidence")
                validate_publication_evidence(publication, run, self.root)
            except (LabError, OSError, ValueError, TypeError) as exc:
                return {"run_id": run_id, "lane": lane, "candidate_passed": False, "release_passed": False, "reason": str(exc), "publication_verified": False}
        if lane == "release" and not isinstance(run.get("outer_artifact"), dict):
            raise LabError("release lane requires the final bundled outer artifact")
        if not isinstance(run.get("outer_artifact"), dict):
            raise LabError("candidate/release gate requires the final outer artifact")
        if not isinstance(run.get("manifest"), dict):
            raise LabError("gate requires a planned signed manifest artifact")
        if lane == "release" and not isinstance(run.get("server_observation"), dict):
            raise LabError("release gate requires live owned server VM QMP/QGA observation")
        if artifact_dir and not artifact_dir.is_dir():
            raise LabError(f"artifact directory is missing: {artifact_dir}")
        for artifact_id, planned in run.get("artifacts", {}).items():
            current_path = Path(planned["path"])
            if artifact_dir and current_path.parent != artifact_dir.resolve():
                raise LabError(f"planned artifact path is outside the declared artifact directory: {artifact_id}")
            current = artifact_record(current_path)
            if (current["sha256"], current["size"]) != (planned.get("sha256"), planned.get("size")):
                raise LabError(f"artifact changed after guest testing: {artifact_id}")
        for artifact_id, planned in run.get("baseline_artifacts", {}).items():
            current = artifact_record(Path(planned["path"]))
            if (current["sha256"], current["size"]) != (planned.get("sha256"), planned.get("size")):
                raise LabError(f"baseline artifact changed after guest testing: {artifact_id}")
        if isinstance(run.get("baseline_outer_artifact"), dict):
            planned_baseline_outer = run["baseline_outer_artifact"]
            current_baseline_outer = artifact_record(Path(planned_baseline_outer["path"]))
            if (current_baseline_outer["sha256"], current_baseline_outer["size"]) != (planned_baseline_outer.get("sha256"), planned_baseline_outer.get("size")):
                raise LabError("baseline outer artifact changed after guest testing")
        if not outer_artifact:
            raise LabError("gate requires the exact planned outer artifact path")
        outer = artifact_record(outer_artifact)
        planned = run.get("outer_artifact") or {}
        if Path(planned.get("path", "")).resolve() != outer_artifact.resolve() or planned.get("sha256") != outer["sha256"] or planned.get("size") != outer["size"]:
            raise LabError("outer artifact changed or path changed after plan; rebuild after testing is forbidden")
        for label in ("manifest", "baseline_manifest", "manifest_public_key"):
            planned = run.get(label)
            if not isinstance(planned, dict):
                continue
            current = artifact_record(Path(planned["path"]))
            if (current["sha256"], current["size"]) != (planned.get("sha256"), planned.get("size")):
                raise LabError(f"{label} changed after guest testing")
        for role, planned_receipt in (run.get("headless_verified_receipts") or {}).items():
            if not isinstance(planned_receipt, dict):
                raise LabError(f"headless verified receipt record is invalid: {role}")
            current_receipt = artifact_record(Path(planned_receipt["path"]))
            if (current_receipt["sha256"], current_receipt["size"]) != (planned_receipt.get("sha256"), planned_receipt.get("size")):
                raise LabError(f"headless verified receipt changed after guest testing: {role}")
        for label in ("profile_records", "runner_records"):
            for item_id, planned in run.get(label, {}).items():
                current = artifact_record(Path(planned["path"]))
                if (current["sha256"], current["size"]) != (planned.get("sha256"), planned.get("size")):
                    raise LabError(f"{label} changed after plan: {item_id}")
        planned_helpers = run.get("semantic_helper_records")
        if lane == "release":
            validate_semantic_helper_records(planned_helpers)
            validate_android_vulkan_records(run.get("android_vulkan_records"))
            validate_android_host_dependency_records(run.get("android_host_dependency_records"))
            validate_android_wayland_records(run.get("android_wayland_records"))
        for item_id, planned in (run.get("hyperv_records") or {}).items():
            current = artifact_record(Path(planned["path"]))
            if (current["sha256"], current["size"]) != (planned.get("sha256"), planned.get("size")):
                raise LabError(f"hyperv_records changed after plan: {item_id}")
        validate_signed_manifest(Path(run["manifest"]["path"]), Path(run["manifest_public_key"]["path"]), version=str(run["candidate_version"]), artifacts=run.get("artifacts", {}))
        if isinstance(run.get("baseline_manifest"), dict):
            validate_signed_manifest(Path(run["baseline_manifest"]["path"]), Path(run["manifest_public_key"]["path"]), version=str(run["baseline_version"]), artifacts=run.get("baseline_artifacts", {}))
        if lane == "release":
            observation = run.get("server_observation")
            publication = run.get("publication_evidence") or {}
            publication_server = publication.get("server") if isinstance(publication, Mapping) else None
            current_server_vm = (run.get("profiles", {}).get("server-router", {}).get("vm") or {})
            expected_server_uuid = current_server_vm.get("uuid") or (publication_server or {}).get("uuid")
            if not isinstance(observation, dict) or observation.get("role") != "isolated-test-server-router" or observation.get("run_id") != run_id or observation.get("qmp_observed") is not True or observation.get("qga_observed") is not True or observation.get("uuid") != expected_server_uuid or observation.get("outer_artifact_sha256") != run["outer_artifact"].get("sha256") or observation.get("manifest_sha256") != run["manifest"].get("sha256"):
                raise LabError("release gate server observation is incomplete or not bound to this run")
            if current_server_vm:
                self.observe_server(run_id, str(observation.get("ssh_host_key_pin", "")))
            elif not (isinstance(publication.get("cleanup"), Mapping) and publication["cleanup"].get("server_reset") is True):
                raise LabError("release gate cannot re-observe a server that was reset without publication cleanup proof")
        archived_evidence: dict[str, dict[str, Any]] = {}
        for profile_id in expected_profiles:
            profile_state = profiles.get(profile_id, {})
            archive_path = profile_state.get("evidence_archive")
            if isinstance(archive_path, str):
                archive = ensure_owned_child(self.root, Path(archive_path), "archived guest evidence")
                if archive.is_file() and not archive.is_symlink():
                    try:
                        archive_value = json.loads(archive.read_text(encoding="utf-8"))
                        receipt_ref = archive_value.get("receipt") or {}
                        receipt_path = ensure_owned_child(self.root, Path(str(receipt_ref.get("archive_path", ""))), "archived guest receipt")
                        receipt_bytes = receipt_path.read_bytes()
                        digest, size = sha256_file(receipt_path)
                        planned = run.get("outer_artifact") if profile_id == "windows-x64" else (run.get("artifacts", {}).get(profile_id) or run.get("artifacts", {}).get(profile_id.replace("-gui", "")) or {})
                        expected_transport = ("nested-qga" if profile_id == "android-arm64-v8a" and profile_state.get("nested_transport") == "qga"
                            else "android-adapter" if load_profiles()[profile_id].get("backend") == "android-adapter"
                            else HYPERV_TRANSPORT if self.uses_hyperv(run, profile_id) else "qga")
                        archive_binding = archive_value.get("guest_binding")
                        receipt_value = json.loads(receipt_bytes.decode("utf-8"))
                        if (digest != receipt_ref.get("sha256") or size != receipt_ref.get("size")
                                or archive_value.get("run_id") != run_id or archive_value.get("profile") != profile_id
                                or archive_value.get("artifact_sha256") != planned.get("sha256")
                                or archive_value.get("artifact_size") != planned.get("size")
                                or archive_value.get("error") is not None
                                or archive_value.get("origin") != "guest"
                                or archive_value.get("injected") is not False
                                or archive_value.get("transport") != expected_transport
                                or not isinstance(archive_binding, dict)):
                            raise LabError("archived guest evidence integrity mismatch")
                        if receipt_value.get("transport") != expected_transport:
                            raise LabError("archived guest receipt transport differs from controller archive")
                        if profile_id == "android-arm64-v8a":
                            identity = receipt_value.get("device_identity") or {}
                            if (archive_binding.get("serial") != identity.get("serial")
                                    or archive_binding.get("qemu_uuid") != (identity.get("qemu_uuid") or identity.get("qemuUuid"))):
                                raise LabError("archived Android guest binding differs from receipt identity")
                        elif self.uses_hyperv(run, profile_id):
                            hyperv_binding = receipt_value.get("hyperv_binding") or {}
                            if (archive_binding.get("vm_id") != hyperv_binding.get("vm_id")
                                    or archive_binding.get("parent_sha256") != hyperv_binding.get("parent_sha256")
                                    or archive_binding.get("archived") is not True):
                                raise LabError("archived Hyper-V guest binding differs from receipt identity")
                        elif not archive_binding.get("qga_socket") or not archive_binding.get("uuid"):
                            raise LabError("archived QGA guest binding is incomplete")
                        elif load_profiles()[profile_id].get("backend") == "qemu-linux":
                            projected={key:archive_binding.get(key) for key in ("pid","proc_start_time","uuid","qga_socket")}
                            if (projected != receipt_value.get("guest_binding")
                                    or isinstance(archive_binding.get("uid"),bool) or not isinstance(archive_binding.get("uid"),int)
                                    or archive_binding.get("uid",-1)<0 or not archive_binding.get("qmp_socket")
                                    or not archive_binding.get("started_at")):
                                raise LabError("archived Linux guest binding differs from receipt")
                            artifact_id=artifact_id_for_profile(profile_id)
                            validate_linux_receipt_incarnation(receipt_value,
                                projected,
                                load_profiles()[profile_id],run_id,profile_id,None,
                                {"candidate":run.get("artifacts",{}).get(artifact_id),"baseline":run.get("baseline_artifacts",{}).get(artifact_id)})
                        archived_evidence[profile_id] = receipt_value
                        validate_receipt(archived_evidence[profile_id], run_id=run_id, profile_id=profile_id, artifact=planned, baseline_version=str(run["baseline_version"]), candidate_version=str(run["candidate_version"]))
                    except (OSError, UnicodeDecodeError, json.JSONDecodeError, LabError) as exc:
                        raise LabError(f"archived guest evidence is invalid for {profile_id}: {exc}") from exc
        if lane == "release":
            publication = run.get("publication_evidence") or {}
            expected_archive_hashes = {}
            captured_times = []
            for profile_id in expected_profiles:
                archive_path=(profiles.get(profile_id) or {}).get("evidence_archive")
                if isinstance(archive_path,str):
                    p=ensure_owned_child(self.root,Path(archive_path),"canonical guest archive");expected_archive_hashes[profile_id]=sha256_file(p)[0]
                    try:captured_times.append(datetime.fromisoformat(str(json.loads(p.read_text()).get("captured_at")).replace("Z","+00:00")))
                    except (ValueError,TypeError,json.JSONDecodeError) as exc:raise LabError("canonical guest archive timestamp is invalid") from exc
            if publication.get("guest_archive_hashes") != expected_archive_hashes:
                raise LabError("publication evidence is not bound to canonical guest archives")
            try:published=datetime.fromisoformat(str(publication.get("prepared_at") or publication.get("observed_at")).replace("Z","+00:00"))
            except (ValueError,TypeError) as exc:raise LabError("publication evidence timestamp is invalid") from exc
            if captured_times and published <= max(captured_times):raise LabError("publication evidence predates canonical guest archives")
        missing = []
        for profile_id in expected_profiles:
            profile_state = profiles.get(profile_id, {})
            if profile_state.get("status") not in {"evidence-collected", "reset"} or not isinstance(profile_state.get("evidence_archive"), str) or profile_id not in archived_evidence or profile_state.get("cleanup_error") or profile_state.get("archive_status") not in {"captured", None}:
                missing.append(f"{profile_id}-archive")
            declared = {step.get("id") for step in load_profiles()[profile_id].get("steps", [])}
            evidence = archived_evidence.get(profile_id) or profiles.get(profile_id, {}).get("evidence") or {}
            observed_steps = profiles.get(profile_id, {}).get("steps", [])
            if profile_id in archived_evidence:
                # After reset the archive is the sole source of step truth;
                # cached controller steps may be stale or over-complete.
                observed_steps = archived_evidence[profile_id].get("steps", [])
            elif not observed_steps and isinstance(evidence, dict):
                observed_steps = evidence.get("steps", [])
            observed = {step.get("id") for step in observed_steps if isinstance(step, dict) and step.get("passed") is True}
            if not declared.issubset(observed):
                missing.append(f"{profile_id}-steps")
        if "android-arm64-v8a" in expected_profiles:
            fixture = run.get("server_fixture") or {}
            fixture_archive_path = fixture.get("evidence_archive")
            fixture_ok = isinstance(fixture_archive_path, str) and bool(fixture.get("stopped_at"))
            if fixture_ok:
                try:
                    fixture_archive = ensure_owned_child(self.root, Path(fixture_archive_path), "consumer fixture evidence")
                    fixture_value = json.loads(fixture_archive.read_text(encoding="utf-8"))
                    log_ref = fixture_value.get("request_log") or {}
                    log_path = ensure_owned_child(self.root, Path(str(log_ref.get("archive_path", ""))), "consumer fixture request log")
                    log_digest, log_size = sha256_file(log_path)
                    planned_apk = run.get("artifacts", {}).get("android-arm64-v8a") or {}
                    planned_manifest = run.get("manifest") or {}
                    binding = fixture_value.get("guest_binding") or {}
                    attempt = run.get("android_update_attempt") or {}
                    attempt_binding_ok = android_attempt_matches_fixture(
                        attempt, fixture, run_id, "android-arm64-v8a"
                    )
                    fixture_ok = (fixture_value.get("run_id") == run_id
                                  and fixture_value.get("profile") == "server-router"
                                  and fixture_value.get("origin") == "guest"
                                  and fixture_value.get("injected") is False
                                  and fixture_value.get("transport") == "qga"
                                  and fixture_value.get("artifact_sha256") == planned_apk.get("sha256")
                                  and fixture_value.get("artifact_size") == planned_apk.get("size")
                                  and fixture_value.get("manifest_sha256") == planned_manifest.get("sha256")
                                  and attempt_binding_ok
                                  and log_digest == log_ref.get("sha256")
                                  and log_size == log_ref.get("size")
                                  and binding.get("qga_socket") and binding.get("uuid")
                                  and profiles.get("server-router", {}).get("status") == "reset"
                                  and profiles.get("server-router", {}).get("vm") is None)
                except (OSError, UnicodeDecodeError, json.JSONDecodeError, LabError, ValueError):
                    fixture_ok = False
            if not fixture_ok:
                missing.append("android-arm64-v8a-consumer-fixture-cleanup-archive")
        if self.uses_hyperv(run, "windows-x64"):
            # The immutable controller archive is authoritative after reset;
            # cached profile evidence is only a fallback for pre-reset use.
            evidence = archived_evidence.get("windows-x64") or profiles["windows-x64"].get("evidence") or {}
            binding = evidence.get("hyperv_binding") if isinstance(evidence, dict) else None
            case_id = profiles["windows-x64"].get("last_case_id") or "control"
            # reset clears the live child VM record.  The immutable receipt
            # archive is the post-reset source for the sealed-parent binding.
            archived_binding = (archived_evidence.get("windows-x64") or {}).get("hyperv_binding")
            parent_sha = (archived_binding or binding or {}).get("parent_sha256") if isinstance(archived_binding or binding, dict) else None
            if not isinstance(binding, dict) or binding.get("case_id") != case_id or not binding.get("vm_id") or binding.get("parent_sha256") != parent_sha or binding.get("transport") != HYPERV_TRANSPORT or binding.get("archived") is not True:
                missing.append("windows-x64-hyperv-parent-vmid-binding")
            if profiles["windows-x64"].get("matrix_status") != "independent-child-matrix":
                missing.append("windows-x64-hyperv-independent-child-matrix")
            if profiles["windows-x64"].get("interactive_status") != "verified_guest_ui_uac":
                missing.append("windows-x64-hyperv-interactive-ui-uac-pending")
            try:
                validate_hyperv_interactive_archives(self.root, profiles["windows-x64"].get("interactive_receipt") or {})
            except LabError:
                missing.append("windows-x64-hyperv-interactive-durable-archives")
        if self.uses_hyperv(run, "windows-x64") and (archived_evidence.get("windows-x64") or profiles.get("windows-x64", {}).get("evidence") or {}).get("interactive_verified") is not True:
            missing.append("windows-x64-interactive-uac")
        if missing:
            return {"run_id": run_id, "lane": lane, "candidate_passed": False, "release_passed": False, "reason": "missing real guest evidence", "missing_profiles": missing}
        if lane == "release":
            semantic = run.get("full4_semantic") or {}
            for kind in ("android", "headless", "linux-visual"):
                record = semantic.get(kind) if isinstance(semantic, Mapping) else None
                if not isinstance(record, Mapping): raise LabError(f"release gate lacks {kind} semantic evidence")
                path=ensure_owned_child(self.root,Path(str(record.get("path",""))),f"{kind} semantic evidence");digest,size=sha256_file(path)
                if (digest!=record.get("sha256") or size!=record.get("size") or record.get("run_id")!=run_id
                    or record.get("outer_sha256")!=(run.get("outer_artifact") or {}).get("sha256")
                    or record.get("manifest_sha256")!=(run.get("manifest") or {}).get("sha256")):
                    raise LabError(f"release gate {kind} semantic evidence binding mismatch")
                semantic_value=json.loads(path.read_text(encoding="utf-8"))
                expected_binding={"run_id":run_id,"outer_sha256":(run.get("outer_artifact") or {}).get("sha256"),"manifest_sha256":(run.get("manifest") or {}).get("sha256"),"candidate_artifacts":{k:{"sha256":v.get("sha256"),"size":v.get("size")} for k,v in (run.get("artifacts") or {}).items()},"semantic_helpers":{k:{"sha256":v.get("sha256"),"size":v.get("size")} for k,v in (run.get("semantic_helper_records") or {}).items()}}
                if semantic_value.get("_controller_binding")!=expected_binding:raise LabError(f"release gate {kind} canonical payload binding mismatch")
                if kind=="android":
                    app=semantic_value.get("app") or {};package=app.get("package_installer") or {};planned=(run.get("artifacts") or {}).get("android-arm64-v8a") or {};planned_baseline=(run.get("baseline_artifacts") or {}).get("android-arm64-v8a") or {};baseline=(semantic_value.get("baseline") or {}).get("artifact") or {}
                    link=semantic_value.get("private_link") or {};link_cleanup=semantic_value.get("private_link_cleanup") or {};boot=semantic_value.get("boot") or {}
                    application_links=link.get("application_links") or {};application_cleanup=link_cleanup.get("application_cleanup") or {}
                    outer=(boot.get("outer_ownership") or {}); link_outer=link.get("outer_ownership") or {};clean_outer=link_cleanup.get("outer_ownership") or {}
                    core=("pid","uuid","qmp_socket","qga_socket")
                    if (app.get("run_id")!=run_id or package.get("artifact_sha256")!=planned.get("sha256") or package.get("artifact_size")!=planned.get("size")
                        or baseline.get("sha256")!=planned_baseline.get("sha256") or baseline.get("size")!=planned_baseline.get("size")
                        or baseline.get("source_path")!=planned_baseline.get("path") or baseline.get("name")!=Path(str(planned_baseline.get("path",""))).name
                        or (semantic_value.get("cleanup") or {}).get("passed") is not True or link.get("run_id")!=run_id
                        or link.get("attempt_nonce")!=outer.get("attempt_nonce") or link.get("ready") is not True
                        or any(link_outer.get(k)!=outer.get(k) for k in core) or str(link_outer.get("start_ticks"))!=str(outer.get("start_ticks"))
                        or link_cleanup.get("run_id")!=run_id or link_cleanup.get("attempt_nonce")!=link.get("attempt_nonce")
                        or link_cleanup.get("clean") is not True or link_cleanup.get("server_ownership")!=link.get("server_ownership")
                        or any(clean_outer.get(k)!=link_outer.get(k) for k in (*core,"start_ticks"))
                        or (link_cleanup.get("socket") or {}).get("exists") is not False
                        or set(application_links)!={"server","outer"} or set(application_cleanup)!={"server","outer"}
                        or any((application_links.get(role) or {}).get("application_address")!="10.8.1.0/32" or (application_links.get(role) or {}).get("present") is not True for role in ("server","outer"))
                        or any((application_cleanup.get(role) or {}).get("application_address")!="10.8.1.0/32" or (application_cleanup.get(role) or {}).get("present") is not False for role in ("server","outer"))):raise LabError("release gate Android semantic payload differs from current plan/private link")
                elif kind=="headless":
                    update=semantic_value.get("update") or {};after=update.get("after") or {};planned=(run.get("artifacts") or {}).get("linux-headless-x64") or {}
                    if update.get("run_id")!=run_id or after.get("version")!=run.get("candidate_version") or (semantic_value.get("cleanup") or {}).get("stopped") is not True:raise LabError("release gate headless semantic payload differs from current plan")
                elif (semantic_value.get("ack") or {}).get("run_id")!=run_id:raise LabError("release gate visual ACK differs from current run")
        result = {"run_id": run_id, "lane": lane, "candidate_passed": True, "release_passed": lane == "release", "artifact_sha256": (run.get("outer_artifact") or {}).get("sha256"), "tested_at": utc_now()}
        if lane == "release":
            marker = ensure_owned_child(self.root, self.root / "exports" / run_id / "publishable.json", "publication marker")
            json_dump(marker, {"schema": 1, "run_id": run_id, "release_passed": True, "artifact_sha256": result["artifact_sha256"], "created_at": utc_now(), "evidence": "qga-real-guest"})
            result["publishable_marker"] = str(marker)
        return result


def validate_receipt(receipt: Mapping[str, Any], *, run_id: str, profile_id: str, artifact: Mapping[str, Any] | None, case_id: str | None = None, baseline_version: str | None = None, candidate_version: str | None = None, allow_pending: bool = False, expected_role: str | None = None) -> None:
    missing = sorted(RECEIPT_REQUIRED - set(receipt))
    if missing:
        raise LabError(f"guest receipt missing fields: {', '.join(missing)}")
    if receipt.get("schema") != 1 or receipt.get("run_id") != run_id or receipt.get("profile") != profile_id:
        raise LabError("guest receipt identity mismatch")
    if case_id is not None and receipt.get("case_id") != case_id:
        raise LabError("guest receipt case identity mismatch")
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", str(receipt.get("baseline_version", ""))) or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", str(receipt.get("candidate_version", ""))):
        raise LabError("guest receipt has invalid baseline/candidate versions")
    allowed_transports = {"android-adapter", "nested-qga"} if profile_id == "android-arm64-v8a" else ({"qga", HYPERV_TRANSPORT} if profile_id == "windows-x64" else {"qga"})
    if receipt.get("transport") not in allowed_transports or receipt.get("origin") != "guest" or receipt.get("injected") is not False:
        raise LabError("guest receipt is not real guest-transport evidence")
    if baseline_version is not None and str(receipt.get("baseline_version")) != str(baseline_version):
        raise LabError("guest receipt baseline version differs from the planned N-1 version")
    if candidate_version is not None and str(receipt.get("candidate_version")) != str(candidate_version):
        raise LabError("guest receipt candidate version differs from the planned candidate version")
    marker = receipt.get("guest_marker")
    if not isinstance(marker, str) or marker != f"amnezia-release-lab:{run_id}:{profile_id}":
        raise LabError("guest marker is missing or does not identify this run/profile")
    if not isinstance(receipt.get("steps"), list) or not receipt["steps"] or any(not isinstance(step, dict) or not isinstance(step.get("passed"), bool) for step in receipt["steps"]):
        raise LabError("guest receipt has no fully passed steps")
    if not allow_pending and any(step.get("passed") is not True for step in receipt["steps"]):
        raise LabError("guest receipt has an incomplete or failed step")
    if artifact and receipt.get("artifact_sha256") != artifact.get("sha256"):
        raise LabError("guest receipt artifact digest differs from planned artifact")
    if artifact and receipt.get("artifact_size") != artifact.get("size"):
        raise LabError("guest receipt artifact size differs from planned artifact")
    role = receipt.get("artifact_role")
    if role not in {"baseline", "candidate", "outer-baseline", "outer-candidate"}:
        raise LabError("guest receipt artifact role is missing or invalid")
    if profile_id != "windows-x64" and role.startswith("outer-"):
        raise LabError("outer artifact role is only valid for the Windows platform")
    if expected_role is not None:
        allowed_roles = {expected_role}
        if profile_id == "windows-x64":
            allowed_roles.update({f"outer-{expected_role}"})
        if role not in allowed_roles:
            raise LabError("guest receipt artifact role does not match the executed step")
    source = receipt.get("artifact_source")
    if not isinstance(source, dict) or source.get("transport") != receipt.get("transport") or source.get("hash_verified") is not True:
        raise LabError("guest receipt artifact source proof is incomplete")
    if not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("artifact_sha256", ""))):
        raise LabError("guest receipt artifact digest is not SHA-256")
    assertion = receipt.get("assertion")
    step_names = {str(step.get("id") or step.get("name") or "").lower() for step in receipt["steps"]}
    action = str(receipt.get("action", "")).lower()
    requires_product_final = action in {"install", "reinstall", "update", "health"} or any(
        any(token in name for token in ("install", "update", "health", "versionreadback", "candidate-version-readback"))
        for name in step_names
    )
    if not allow_pending and requires_product_final and profile_id != "android-arm64-v8a" and (not isinstance(assertion, Mapping) or assertion.get("passed") is not True):
        raise LabError("guest receipt lacks a passed final assertion")
    if isinstance(assertion, Mapping):
        installed = assertion.get("installed_version")
        expected = assertion.get("expected_version")
        if installed is not None and expected is not None and str(installed) != str(expected):
            raise LabError("guest receipt assertion version differs from its expected version")
        after_hash = assertion.get("artifact_sha256_after")
        if after_hash is not None and str(after_hash).lower() != str(receipt.get("artifact_sha256", "")).lower():
            raise LabError("guest receipt assertion artifact hash differs from receipt")
        if profile_id != "android-arm64-v8a" and not allow_pending:
            if not isinstance(installed, str) or not installed:
                raise LabError("guest receipt final assertion lacks installed version")
            hashes = [assertion.get(key) for key in ("artifact_sha256", "artifact_sha256_before", "artifact_sha256_after", "expected_sha256")]
            if not any(isinstance(value, str) and value.lower() == str(receipt.get("artifact_sha256", "")).lower() for value in hashes):
                raise LabError("guest receipt final assertion lacks the tested artifact hash")
    if profile_id == "android-arm64-v8a":
        if requires_product_final and not allow_pending:
            candidate = receipt.get("candidate")
            nested = receipt.get("transport") == "nested-qga"
            final_names = ({"service-health"} if nested else
                           {"candidateversionreadback", "candidate-version-readback"})
            final_steps = [step for step in receipt["steps"] if str(step.get("id") or step.get("name") or "").lower() in final_names]
            if (not isinstance(candidate, Mapping) or candidate.get("version") != receipt.get("candidate_version")
                    or candidate.get("sha256") != receipt.get("artifact_sha256")
                    or not final_steps or final_steps[-1].get("passed") is not True):
                raise LabError("Android receipt lacks final candidate version/hash readback")
            if nested:
                raw = final_steps[-1].get("raw_assertion")
                package = raw.get("package_installer") if isinstance(raw, Mapping) else None
                ui = raw.get("ui") if isinstance(raw, Mapping) else None
                logcat = raw.get("logcat") if isinstance(raw, Mapping) else None
                if (not isinstance(package, Mapping) or not isinstance(ui, Mapping)
                        or not isinstance(logcat, Mapping)
                        or package.get("artifact_sha256") != receipt.get("artifact_sha256")
                        or package.get("artifact_size") != receipt.get("artifact_size")
                        or package.get("version_code") != candidate.get("version_code")
                        or ui.get("version_code") != candidate.get("version_code")
                        or logcat.get("crashes") != []):
                    raise LabError("nested Android final service-health assertion is incomplete")
        identity = receipt.get("device_identity")
        qemu_uuid = ((identity.get("qemu_uuid") or identity.get("qemuUuid")) if isinstance(identity, dict) else None)
        launch_uuid = identity.get("launchUuid") or identity.get("launch_uuid") if isinstance(identity, dict) else None
        nonce = receipt.get("nonce")
        nested = receipt.get("transport") == "nested-qga"
        if (not isinstance(identity, dict) or (not nested and not identity.get("serial", "").startswith("emulator-"))
                or (nested and (not identity.get("serial") or not qemu_uuid or not isinstance(identity.get("outer_ownership"), Mapping)))
                or (not nested and not qemu_uuid and (not launch_uuid or launch_uuid != nonce))):
            raise LabError("Android receipt lacks the owned emulator serial and live launch UUID/nonce binding")


def validate_linux_receipt_incarnation(receipt: Mapping[str, Any], vm: Mapping[str, Any],
                                       profile: Mapping[str, Any], run_id: str, profile_id: str,
                                       controller_steps: Sequence[Mapping[str, Any]] | None = None,
                                       planned_artifacts: Mapping[str, Mapping[str, Any] | None] | None = None) -> None:
    expected = {"pid": vm.get("pid"), "proc_start_time": str(vm.get("proc_start_time")),
                "uuid": vm.get("uuid"), "qga_socket": str(vm.get("qga_socket"))}
    if receipt.get("guest_binding") != expected:
        raise LabError("Linux guest receipt is not bound to the current owned VM incarnation")
    canonical = [str(item.get("id")) for item in profile.get("steps", [])]
    steps = receipt.get("steps")
    if not isinstance(steps, list) or not steps:
        raise LabError("Linux guest receipt has no immutable per-step records")
    ids = [item.get("id") for item in steps if isinstance(item, Mapping)]
    if len(ids) != len(steps) or len(set(ids)) != len(ids) or any(value not in canonical for value in ids):
        raise LabError("Linux guest receipt step identities are missing, duplicate, or noncanonical")
    if ids != [value for value in canonical if value in ids]:
        raise LabError("Linux guest receipt steps are outside canonical order")
    prior: datetime | None = None
    for item in steps:
        if (item.get("run_id") != run_id or item.get("profile") != profile_id
                or item.get("guest_binding") != expected or not isinstance(item.get("raw_assertion"), Mapping)):
            raise LabError("Linux guest step crossed run/profile/VM incarnation")
        observed = item.get("observed_at")
        try:
            stamp = datetime.fromisoformat(str(observed).replace("Z", "+00:00"))
        except ValueError as exc:
            raise LabError("Linux guest step timestamp is invalid") from exc
        if prior is not None and stamp < prior:
            raise LabError("Linux guest step temporal chain is out of order")
        prior = stamp
        if planned_artifacts is not None:
            role = item.get("artifact_role")
            planned = planned_artifacts.get(role) if isinstance(role, str) else None
            if (not isinstance(planned, Mapping)
                    or item.get("artifact_sha256") != planned.get("sha256")
                    or item.get("artifact_size") != planned.get("size")):
                raise LabError("Linux guest step differs from the current planned artifact")
    if controller_steps is not None:
        by_id = {item.get("id"): item for item in controller_steps if isinstance(item, Mapping)}
        if len(by_id) != len(controller_steps) or set(by_id) != set(ids):
            raise LabError("controller/guest Linux step set differs")
        for guest_step in steps:
            controller_step = by_id[guest_step["id"]]
            if (controller_step.get("guest_binding") != expected
                    or guest_step.get("raw_assertion") != controller_step.get("assertion")):
                raise LabError("controller/guest Linux raw assertion or incarnation differs")
            for key in ("artifact_sha256", "artifact_size", "artifact_role", "artifact_source"):
                if guest_step.get(key) != controller_step.get(key):
                    raise LabError(f"controller/guest Linux {key} differs")


def parse_artifacts(values: Sequence[str]) -> dict[str, Path]:
    artifacts: dict[str, Path] = {}
    for value in values:
        name, sep, raw = value.partition("=")
        if not sep or name not in RELEASE_PLATFORM_IDS:
            raise LabError(f"artifact must be platform=path for a supported platform: {value}")
        if name in artifacts:
            raise LabError(f"duplicate planned artifact platform: {name}")
        path = Path(raw).expanduser().resolve()
        artifacts[name] = path
    return artifacts


def emit(value: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, indent=2, sort_keys=True))
    elif isinstance(value, Mapping):
        print(json.dumps(value, indent=2, sort_keys=True))
    else:
        print(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Amnezia disposable QEMU release lab")
    parser.add_argument("--state-root", default=None)
    parser.add_argument("--windows-backend", choices=("qemu", "hyperv"), default="qemu")
    parser.add_argument("--android-backend", choices=("linux", "windows"), default="linux")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true", dest="as_json")
    sub = parser.add_subparsers(dest="command", required=True)
    preflight = sub.add_parser("preflight")
    preflight.add_argument("--profile", action="append", default=[])
    sub.add_parser("status")
    plan = sub.add_parser("plan")
    plan.add_argument("--lane", choices=("candidate", "release", "publisher-diagnostic"), default="release")
    plan.add_argument("--artifact", action="append", default=[])
    plan.add_argument("--outer-artifact")
    plan.add_argument("--baseline-outer-artifact")
    plan.add_argument("--manifest")
    plan.add_argument("--manifest-public-key")
    plan.add_argument("--baseline-manifest")
    plan.add_argument("--headless-baseline-receipt")
    plan.add_argument("--headless-candidate-receipt")
    plan.add_argument("--baseline-artifact", action="append", default=[])
    plan.add_argument("--baseline-version", required=True)
    plan.add_argument("--candidate-version", required=True)
    create = sub.add_parser("create")
    create.add_argument("--lane", choices=("candidate", "release", "publisher-diagnostic"), default="release")
    create.add_argument("--artifact", action="append", default=[])
    create.add_argument("--outer-artifact")
    create.add_argument("--baseline-outer-artifact")
    create.add_argument("--manifest")
    create.add_argument("--manifest-public-key")
    create.add_argument("--baseline-manifest")
    create.add_argument("--headless-baseline-receipt")
    create.add_argument("--headless-candidate-receipt")
    create.add_argument("--baseline-artifact", action="append", default=[])
    create.add_argument("--baseline-version", required=True)
    create.add_argument("--candidate-version", required=True)
    create.add_argument("--run-id")
    for name in ("start", "guest-probe", "run", "collect"):
        command = sub.add_parser(name)
        command.add_argument("--run-id", required=True)
        command.add_argument("--profile", required=True, choices=ALL_PROFILE_IDS)
        if name == "run":
            command.add_argument("--step", action="append", default=[])
            command.add_argument("--preserve-failed-guest", action="store_true")
        if name == "collect": command.add_argument("--case-id")
    nested_probe = sub.add_parser("nested-android-probe")
    nested_probe.add_argument("--run-id", required=True)
    visual_decide = sub.add_parser("android-visual-decide")
    visual_decide.add_argument("--run-id", required=True)
    visual_decide.add_argument("--attempt-nonce", required=True)
    visual_decide.add_argument("--request-id", required=True)
    visual_decide.add_argument("--request-sha256", required=True)
    visual_decide.add_argument("--decision", required=True, choices=("approve", "refresh", "reject"))
    visual_decide.add_argument("--bounds", nargs=4, type=int)
    suite = sub.add_parser("run-suite")
    suite.add_argument("--lane", choices=("candidate", "release"), default="release")
    suite.add_argument("--artifact", action="append", default=[])
    suite.add_argument("--outer-artifact")
    suite.add_argument("--baseline-outer-artifact")
    suite.add_argument("--manifest")
    suite.add_argument("--manifest-public-key")
    suite.add_argument("--baseline-manifest")
    suite.add_argument("--headless-baseline-receipt")
    suite.add_argument("--headless-candidate-receipt")
    suite.add_argument("--baseline-artifact", action="append", default=[])
    suite.add_argument("--baseline-version", required=True)
    suite.add_argument("--candidate-version", required=True)
    suite.add_argument("--run-id")
    reset = sub.add_parser("reset")
    reset.add_argument("--run-id", required=True); reset.add_argument("--profile", choices=ALL_PROFILE_IDS)
    gate = sub.add_parser("gate")
    gate.add_argument("--run-id", required=True); gate.add_argument("--lane", choices=("candidate", "release"), default="release")
    gate.add_argument("--artifact-dir"); gate.add_argument("--outer-artifact")
    observe = sub.add_parser("server-observe")
    observe.add_argument("--run-id", required=True); observe.add_argument("--ssh-host-key-pin", required=True)
    fixture = sub.add_parser("fixture-start")
    fixture.add_argument("--run-id", required=True)
    fixture.add_argument("--manifest", required=True)
    fixture.add_argument("--artifact", required=True)
    fixture_stop = sub.add_parser("fixture-stop")
    fixture_stop.add_argument("--run-id", required=True)
    relay_plan = sub.add_parser("relay-smoke-plan")
    relay_plan.add_argument("--run-id", required=True)
    relay_plan.add_argument("--case-id", required=True)
    relay_plan.add_argument("--vm-id", required=True)
    relay_plan.add_argument("--run-root", required=True)
    relay_plan.add_argument("--child-record", required=True)
    relay_plan.add_argument("--server-record", required=True)
    relay_plan.add_argument("--supervisor", required=True)
    relay_plan.add_argument("--relay", required=True)
    publication_validate = sub.add_parser("publication-validate")
    publication_validate.add_argument("--run-id", required=True)
    publish = sub.add_parser("publish-validation")
    publish.add_argument("--run-id", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    controller = LabController(state_root_from(args.state_root), dry_run=args.dry_run, windows_backend=args.windows_backend, android_backend=args.android_backend)
    mutating_commands = {"plan", "create", "start", "guest-probe", "run", "collect", "nested-android-probe", "run-suite", "reset", "gate", "server-observe", "fixture-start", "fixture-stop", "publish-validation"}
    mutation_lock_held = False
    try:
        if args.command in mutating_commands:
            controller.acquire_mutation_lock(args.command)
            mutation_lock_held = True
        if args.command == "preflight": result = controller.preflight(args.profile or None)
        elif args.command == "status": result = controller.load_state()
        elif args.command in ("plan", "create"):
            result = controller.create(args.lane, parse_artifacts(args.artifact), Path(args.outer_artifact).resolve() if args.outer_artifact else None, getattr(args, "run_id", None), Path(args.manifest).resolve() if args.manifest else None, parse_artifacts(args.baseline_artifact), args.baseline_version, args.candidate_version, Path(args.manifest_public_key).resolve() if args.manifest_public_key else None, Path(args.baseline_manifest).resolve() if args.baseline_manifest else None, Path(args.headless_baseline_receipt).resolve() if args.headless_baseline_receipt else None, Path(args.headless_candidate_receipt).resolve() if args.headless_candidate_receipt else None, Path(args.baseline_outer_artifact).resolve() if args.baseline_outer_artifact else None)
        elif args.command == "start": result = controller.start(args.run_id, args.profile)
        elif args.command == "guest-probe": result = controller.guest_probe(args.run_id, args.profile)
        elif args.command == "nested-android-probe": result = controller.nested_android_probe(args.run_id)
        elif args.command == "android-visual-decide": result = controller.decide_nested_android_visual(args.run_id, args.attempt_nonce, args.request_id, args.request_sha256, args.decision, args.bounds)
        elif args.command == "run": result = controller.run_steps(args.run_id, args.profile, args.step or None, args.preserve_failed_guest)
        elif args.command == "collect": result = controller.collect(args.run_id, args.profile, args.case_id)
        elif args.command == "run-suite": result = controller.run_suite(args.lane, parse_artifacts(args.artifact), Path(args.outer_artifact).resolve() if args.outer_artifact else None, args.run_id, Path(args.manifest).resolve() if args.manifest else None, parse_artifacts(args.baseline_artifact), args.baseline_version, args.candidate_version, Path(args.manifest_public_key).resolve() if args.manifest_public_key else None, Path(args.baseline_manifest).resolve() if args.baseline_manifest else None, Path(args.headless_baseline_receipt).resolve() if args.headless_baseline_receipt else None, Path(args.headless_candidate_receipt).resolve() if args.headless_candidate_receipt else None, Path(args.baseline_outer_artifact).resolve() if args.baseline_outer_artifact else None)
        elif args.command == "reset": result = controller.reset(args.run_id, args.profile)
        elif args.command == "gate": result = controller.gate(args.run_id, args.lane, Path(args.artifact_dir).resolve() if args.artifact_dir else None, Path(args.outer_artifact).resolve() if args.outer_artifact else None)
        elif args.command == "server-observe": result = controller.observe_server(args.run_id, args.ssh_host_key_pin)
        elif args.command == "fixture-start": result = controller.start_consumer_fixture(args.run_id, Path(args.manifest).resolve(), Path(args.artifact).resolve())
        elif args.command == "fixture-stop": result = controller.stop_consumer_fixture(args.run_id)
        elif args.command == "relay-smoke-plan":
            try:
                from relay_smoke_controller import build_plan
            except ImportError:  # pragma: no cover - package import path
                from .relay_smoke_controller import build_plan
            result = build_plan(run_id=args.run_id, case_id=args.case_id, vm_id=args.vm_id, child_record=Path(args.child_record), server_record=Path(args.server_record), supervisor=Path(args.supervisor), relay=Path(args.relay), run_root=Path(args.run_root))
        elif args.command == "publication-validate":
            run = controller.get_run(args.run_id)
            publication = run.get("publication_evidence")
            if not isinstance(publication, Mapping):
                raise LabError("publication evidence is missing")
            validate_publication_evidence(publication, run, controller.root)
            result = {"run_id": args.run_id, "publication_verified": True, "release_passed": False}
        elif args.command == "publish-validation":
            publish_run = controller.get_run(args.run_id)
            if not controller.uses_hyperv(publish_run, "windows-x64"):
                raise LabError("publish-validation requires the owned Hyper-V Windows backend")
            if publish_run.get("dry_run") or publish_run.get("test_mode"):
                raise LabError("publish-validation cannot run in dry-run or test_mode")
            try:
                from .publisher_controller import ConcretePublisherOps, ControllerPublisher
            except ImportError:
                from publisher_controller import ConcretePublisherOps, ControllerPublisher
            result = ControllerPublisher(controller, ConcretePublisherOps(controller)).run(args.run_id)
        else: raise LabError(f"unsupported command: {args.command}")
        emit(result, args.as_json)
        if args.command == "preflight" and not result.get("ready", False): return 2
        if args.command == "gate" and not (result.get("release_passed") or result.get("candidate_passed")): return 3
        return 0
    except (LabError, RelaySmokeError, WindowsEvidenceArchiveError, OSError, subprocess.SubprocessError) as exc:
        emit({"ok": False, "error": str(exc), "release_passed": False}, args.as_json)
        return 1
    finally:
        if mutation_lock_held:
            controller.release_mutation_lock()


if __name__ == "__main__":
    raise SystemExit(main())
