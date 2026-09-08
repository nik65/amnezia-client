#!/usr/bin/env python3
"""Fail-closed controller for the disposable Amnezia release lab.

Only QEMU/QGA/QMP are used to cross the host/guest boundary.  In particular,
the controller never starts an Amnezia executable on the workstation and
never accepts a host supplied ``PASS``/receipt as guest evidence.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import stat
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse

try:
    import pwd
except ImportError:  # pragma: no cover - Windows test host
    pwd = None


SCHEMA_VERSION = 1
DEFAULT_STATE_ROOT = "/var/lib/amnezia-release-lab"
PROFILE_IDS = ("windows-x64", "android-arm64-v8a", "linux-x64-gui", "linux-headless-x64")
ALL_PROFILE_IDS = PROFILE_IDS + ("server-router",)
HOST_EXECUTABLES = frozenset(("qemu-system-x86_64", "qemu-img", "swtpm", "bash", "openssl"))
HOST_EXECUTABLE_PATHS = {name: f"/usr/bin/{name}" for name in HOST_EXECUTABLES}
RELEASE_PLATFORM_IDS = frozenset(("windows-x64", "android-arm64-v8a", "linux-x64", "linux-headless-x64"))
RECEIPT_REQUIRED = frozenset(("schema", "run_id", "profile", "artifact", "artifact_sha256", "baseline_version", "candidate_version", "guest_marker", "transport", "steps", "observed_at"))
CONSUMER_FIXTURE_GUEST_PORT = 17865


class LabError(RuntimeError):
    """An expected fail-closed lab error."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def free_loopback_port() -> int:
    """Reserve a candidate loopback port without changing host networking."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def json_dump(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


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
    archive_name = Path(urlparse(str(provisioning.get("url", ""))).path).name
    archive_path = Path(str(artifact["path"])).parent / archive_name
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
    if path != (repo_root() / "deploy/release_lab/android/android-lab.sh").resolve():
        raise LabError(f"unrecognized adapter path: {path}")
    if not path.is_file():
        raise LabError(f"adapter script is missing: {path}")
    return path


def proc_start_time(pid: int) -> str:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()
        return fields[21]
    except (OSError, IndexError) as exc:
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
            current_start_time = proc_start_time(pid)
        except LabError:
            if not proc_path.exists():
                return
            raise
        if current_start_time != expected_start_time:
            raise LabError(f"{label} PID was reused while stopping; preserving owned state")
        time.sleep(0.1)
    if proc_path.exists():
        try:
            if proc_start_time(pid) != expected_start_time:
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
            data += conn.recv(65536)
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
        opened = self.request("guest-file-open", {"path": path, "mode": "w"})
        handle = opened.get("return")
        if not isinstance(handle, int):
            raise LabError(f"guest-file-open for write failed: {opened}")
        try:
            for offset in range(0, len(data), 49152):
                encoded = base64.b64encode(data[offset:offset + 49152]).decode("ascii")
                result = self.request("guest-file-write", {"handle": handle, "buf-b64": encoded})
                if "return" not in result:
                    raise LabError(f"guest-file-write failed: {result}")
        finally:
            self.request("guest-file-close", {"handle": handle})


@dataclass
class LabController:
    root: Path
    dry_run: bool = False
    test_mode: bool = False

    def assert_mutation_context(self) -> None:
        if not self.test_mode:
            assert_lab_identity(self.root)

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
        selected = list(selected_profiles or profiles)
        unknown = sorted(set(selected) - set(profiles))
        if unknown:
            raise LabError(f"unknown preflight profile: {', '.join(unknown)}")
        image_checks = {}
        for profile_id in selected:
            profile = profiles[profile_id]
            if profile.get("backend") == "android-adapter":
                try:
                    script = ensure_repo_adapter(profile.get("adapter_script"))
                    adapter_profile = script.parent / "android-lab-profile.json"
                    image_checks[profile_id] = {"ready": adapter_profile.is_file(), "adapter": str(script), "profile": str(adapter_profile)}
                except LabError as exc:
                    image_checks[profile_id] = {"ready": False, "reason": str(exc)}
            else:
                ready, detail = golden_readiness(self.root, profile)
                image_checks[profile_id] = {"ready": ready, "path": detail if ready else str(self.root / profile.get("base_image", "")), "reason": None if ready else detail}
        checks["base_images"] = image_checks
        runner_checks = {}
        for profile_id in selected:
            profile = profiles[profile_id]
            runner = profile.get("runner")
            if profile.get("backend") == "android-adapter":
                runner_checks[profile_id] = {"ready": True, "adapter": str(profile.get("adapter_script"))}
                continue
            runner_path = (repo_root() / str(runner)).resolve() if isinstance(runner, str) else Path("")
            runner_checks[profile_id] = {"ready": runner_path.is_file(), "path": str(runner_path)}
        checks["guest_runners"] = runner_checks
        server_profile = profiles_root() / "server-router.env"
        checks["lab_server_profile"] = {"ready": server_profile.is_file(), "path": str(server_profile), "role": "isolated-test-server-router"}
        ready = (
            checks["identity"].get("ready", False)
            and checks["profiles"].get("ready", False)
            and all(item.get("ready", False) for item in qemu_checks.values())
            and checks["kvm"].get("ready", False)
            and all(item.get("ready", False) for item in image_checks.values())
            and all(item.get("ready", False) for item in runner_checks.values())
            and ("server-router" not in selected or checks["lab_server_profile"].get("ready", False))
            and not self.dry_run
        )
        return {"schema": SCHEMA_VERSION, "ready": ready, "dry_run": self.dry_run, "checks": checks, "release_passed": False}

    def create(self, lane: str, artifacts: Mapping[str, Path], outer_artifact: Path | None = None, run_id: str | None = None, manifest: Path | None = None, baseline_artifacts: Mapping[str, Path] | None = None, baseline_version: str | None = None, candidate_version: str | None = None, manifest_public_key: Path | None = None, baseline_manifest: Path | None = None, headless_baseline_receipt: Path | None = None, headless_candidate_receipt: Path | None = None) -> dict[str, Any]:
        self.assert_mutation_context()
        profiles = load_profiles()
        if lane not in ("candidate", "release"):
            raise LabError("lane must be candidate or release")
        if not artifacts:
            raise LabError("at least one artifact is required")
        records = {name: artifact_record(path) for name, path in artifacts.items()}
        baseline_artifacts = baseline_artifacts or {}
        if not baseline_artifacts:
            raise LabError("run requires explicit baseline artifacts; metadata-only upgrade tests are forbidden")
        if lane == "release" and set(baseline_artifacts) != set(records):
            raise LabError("release lane requires an explicit N-1 baseline artifact for every candidate platform")
        if not baseline_version or not candidate_version:
            raise LabError("run requires immutable baseline and candidate versions")
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
        profile_records = {profile_id: artifact_record(profiles_root() / f"{profile_id}.json") for profile_id in profiles}
        runner_records = {profile_id: artifact_record(repo_root() / profile["runner"]) for profile_id, profile in profiles.items() if isinstance(profile.get("runner"), str)}
        outer = artifact_record(outer_artifact) if outer_artifact else None
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
        state.setdefault("runs", {})[run_id] = {
            "run_id": run_id, "lane": lane, "dry_run": self.dry_run,
            "created_at": utc_now(), "artifacts": records, "baseline_artifacts": baseline_records, "outer_artifact": outer,
            "baseline_version": baseline_version, "candidate_version": candidate_version,
            "manifest": manifest_record,
            "baseline_manifest": baseline_manifest_record,
            "headless_verified_receipts": headless_receipt_records,
            "manifest_public_key": artifact_record(manifest_public_key),
            "profile_records": profile_records, "runner_records": runner_records,
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
            fixture_host_port = free_loopback_port()
            network_args = ("-netdev", f"user,id=labnet,restrict=on,hostfwd=tcp:127.0.0.1:{fixture_host_port}-:{CONSUMER_FIXTURE_GUEST_PORT}", "-device", "e1000,netdev=labnet,id=labnet-device")
        else:
            network_args = ("-nic", "none")
        argv = ("qemu-system-x86_64", "-uuid", vm_uuid, "-machine", str(profile.get("machine", "q35")), "-cpu", "host", "-accel", "kvm", "-name", f"amnezia-release-lab-{run_id}-{profile_id}", "-m", str(profile.get("memory_mb", 2048)), "-smp", str(profile.get("cpus", 2)), *disk_args, *network_args, "-qmp", f"unix:{qmp},server=on,wait=off", "-chardev", f"socket,path={qga},server=on,wait=off,id=qga0", "-device", "virtio-serial", "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0", *video_args, *display_args)
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
            swtpm = resolve_host_executable("swtpm")
            tpm_log = (run_dir / "swtpm.log").open("ab")
            tpm = subprocess.Popen([swtpm, "socket", "--tpm2", "--tpmstate", f"dir={tpm_dir}", "--ctrl", f"type=unixio,path={tpm_socket}"], stdout=tpm_log, stderr=subprocess.STDOUT, shell=False, start_new_session=True)
            tpm_log.close()
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
        log = log_path.open("ab")
        try:
            proc = subprocess.Popen([executable, *argv[1:]], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, shell=False, close_fds=True, start_new_session=True)
            if proc.poll() is not None:
                raise LabError(f"QEMU exited during startup with code {proc.returncode}")
        except Exception:
            for owned_process in (proc, tpm):
                if owned_process is not None and owned_process.poll() is None:
                    owned_process.terminate()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and any(item is not None and item.poll() is None for item in (proc, tpm)):
                time.sleep(0.1)
            if any(item is not None and item.poll() is None for item in (proc, tpm)):
                raise LabError("startup process did not exit; preserving owned overlay and firmware copies for recovery")
            if overlay.exists():
                overlay.unlink()
            for generated in (run_dir / "OVMF_VARS.fd", run_dir / "tpm-state"):
                if generated.is_dir():
                    shutil.rmtree(generated)
                elif generated.exists():
                    generated.unlink()
            raise
        log.close()
        vm = {"pid": proc.pid, "proc_start_time": proc_start_time(proc.pid), "uuid": vm_uuid, "uid": os.getuid() if hasattr(os, "getuid") else None, "qmp_socket": str(qmp), "qga_socket": str(qga), "vnc_socket": str(vnc) if profile.get("display") == "vnc-unix" else None, "argv": list(argv), "started_at": utc_now()}
        if fixture_host_port is not None:
            vm.update({"consumer_fixture": True, "fixture_host_port": fixture_host_port, "fixture_guest_port": CONSUMER_FIXTURE_GUEST_PORT, "fixture_bind": "127.0.0.1"})
        if tpm is not None:
            vm["tpm_pid"] = tpm.pid; vm["tpm_proc_start_time"] = proc_start_time(tpm.pid); vm["tpm_socket"] = str(tpm_socket); vm["tpm_state"] = str(tpm_dir); vm["ovmf_vars"] = str(vars_copy)
        run["profiles"][profile_id].update(status="started", vm=vm)
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return vm

    def _run_android_adapter(self, run_id: str, profile_id: str, command: str, *args: str) -> dict[str, Any]:
        profile = load_profiles()[profile_id]
        script = ensure_repo_adapter(profile.get("adapter_script"))
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
        run = self.get_run(run_id)
        if isinstance(run.get("manifest"), dict):
            env["AMNEZIA_ANDROID_RELEASE_MANIFEST"] = str(run["manifest"]["path"])
        if isinstance(run.get("baseline_manifest"), dict):
            env["AMNEZIA_ANDROID_BASELINE_MANIFEST"] = str(run["baseline_manifest"]["path"])
        command_outputs = []
        if command == "start":
            create_result = subprocess.run([resolve_host_executable("bash"), str(script), "create"], cwd=str(repo_root()), env=env, shell=False, text=True, capture_output=True, timeout=900, start_new_session=True)
            if create_result.returncode != 0:
                raise LabError(f"Android adapter create failed: {create_result.stderr[-1500:]}")
            command_outputs.append(create_result.stdout)
        result = subprocess.run([resolve_host_executable("bash"), str(script), command, *args], cwd=str(repo_root()), env=env, shell=False, text=True, capture_output=True, timeout=900, start_new_session=True)
        if result.returncode != 0:
            raise LabError(f"Android adapter {command} failed: {result.stderr[-1500:]}")
        run = self.get_run(run_id)
        run["profiles"][profile_id].update(status="started" if command == "start" else "tested", vm={"backend": "android-adapter", "root": str(adapter_root), "script": str(script)} if command == "start" else run["profiles"][profile_id].get("vm"), adapter_output=("\n".join(command_outputs) + result.stdout)[-4000:])
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return {"backend": "android-adapter", "command": command, "stdout": result.stdout[-4000:], "root": str(adapter_root)}

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
        if "qemu-system-x86_64" not in Path(vm["argv"][0]).name or any(token not in cmdline for token in required_tokens):
            raise LabError("QEMU identity does not match owned PID/UUID/QMP socket")
        if vm.get("vnc_socket") and str(Path(vm["vnc_socket"]).resolve()) not in cmdline:
            raise LabError("QEMU VNC socket is not bound to the owned process")
        return vm

    def guest_probe(self, run_id: str, profile_id: str) -> dict[str, Any]:
        profile = load_profiles()[profile_id]
        if profile.get("backend") == "android-adapter":
            return self._run_android_adapter(run_id, profile_id, "probe")
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

    def start_consumer_fixture(self, run_id: str, manifest_path: Path, apk_path: Path) -> dict[str, Any]:
        """Upload the planned signed candidate to an owned server-router guest."""
        self.assert_mutation_context()
        profile = load_profiles().get("server-router")
        if not isinstance(profile, dict) or profile.get("consumer_fixture") is not True:
            raise LabError("consumer fixture is disabled outside server-router")
        run = self.get_run(run_id)
        vm = self.owned_vm(run_id, "server-router")
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
        started = qga.guest_exec("/usr/bin/python3", [guest_script, "--manifest", guest_manifest, "--apk", guest_apk, "--manifest-sha256", planned_manifest["sha256"], "--apk-sha256", artifact["sha256"], "--run-id", run_id, "--port", str(CONSUMER_FIXTURE_GUEST_PORT), "--request-log", request_log])
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
        run["server_fixture"] = {"pid": fixture_pid, "guest_request_log": request_log, "host_port": host_port, "guest_port": CONSUMER_FIXTURE_GUEST_PORT, "run_id": run_id, "manifest_sha256": planned_manifest["sha256"], "artifact_sha256": artifact["sha256"], "health": health, "transport": "qga-upload-http-hostfwd", "consumer_fixture": True, "observed_at": utc_now()}
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return run["server_fixture"]

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

    def run_steps(self, run_id: str, profile_id: str, selected: Iterable[str] | None = None) -> dict[str, Any]:
        self.assert_mutation_context()
        profiles = load_profiles(); profile = profiles[profile_id]
        artifact_id = "android-arm64-v8a" if profile_id == "android-arm64-v8a" else ("linux-x64" if profile_id == "linux-x64-gui" else profile_id)
        planned_run = self.get_run(run_id)
        artifact = planned_run.get("outer_artifact") if profile_id == "windows-x64" else planned_run.get("artifacts", {}).get(artifact_id)
        if not isinstance(artifact, dict):
            raise LabError(f"no planned artifact for guest profile {profile_id}")
        baseline = planned_run.get("baseline_artifacts", {}).get(artifact_id)
        if not isinstance(baseline, dict):
            raise LabError(f"no planned N-1 baseline artifact for guest profile {profile_id}")
        if profile.get("backend") == "android-adapter":
            artifact_path = artifact.get("path")
            if not artifact_path:
                raise LabError("Android adapter requires the planned arm64 APK")
            self._run_android_adapter(run_id, profile_id, "install-baseline", baseline["path"])
            self._run_android_adapter(run_id, profile_id, "test-update", artifact_path)
            self._run_android_adapter(run_id, profile_id, "collect")
            return {"run_id": run_id, "profile": profile_id, "adapter": True, "steps": ["install-baseline", "test-update", "collect"], "passed": True}
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
        results = []
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
                step_args = ["-NoProfile", "-File", runner_path, step["action"], profile_id, "-RunId", run_id, "-ExpectedVersion", str(expected_version), "-ExpectedSha256", selected["sha256"], "-ArtifactPath", selected_target, "-ReceiptPath", guest_receipt_path]
            else:
                step_args = [runner_path, step["action"], profile_id, "--run-id", run_id, "--expected-version", str(expected_version), "--expected-sha256", selected["sha256"], "--artifact-path", selected_target, "--receipt-path", guest_receipt_path, *headless_args]
            qga.write_file(selected_target, Path(selected["path"]).read_bytes())
            response = qga.guest_exec_wait(step["executable"], step_args)
            try:
                assertion = json.loads(response.get("stdout", ""))
            except json.JSONDecodeError as exc:
                raise LabError(f"guest step {step['id']} returned no JSON assertion: {exc}") from exc
            if assertion.get("passed") is not True:
                raise LabError(f"guest step {step['id']} assertion did not pass")
            results.append({"id": step["id"], "action": step["action"], "executable": step["executable"], "qga_response": response, "assertion": assertion, "passed": True})
        if not results:
            raise LabError("no selected profile steps")
        run = self.get_run(run_id); run["profiles"][profile_id].update(status="tested", steps=results)
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return {"run_id": run_id, "profile": profile_id, "steps": results, "dry_run": self.dry_run}

    def collect(self, run_id: str, profile_id: str) -> dict[str, Any]:
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
            validate_receipt(receipt, run_id=run_id, profile_id=profile_id, artifact=artifact)
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
        receipt.setdefault("baseline_version", run.get("baseline_version"))
        receipt.setdefault("candidate_version", run.get("candidate_version"))
        receipt.setdefault("guest_marker", marker)
        receipt.setdefault("transport", "qga")
        receipt.setdefault("origin", "guest")
        receipt.setdefault("injected", False)
        receipt.setdefault("interactive_verified", bool(receipt.get("assertion", {}).get("interactive_passed") is True))
        validate_receipt(receipt, run_id=run_id, profile_id=profile_id, artifact=artifact)
        run["profiles"][profile_id].update(status="evidence-collected", evidence=receipt)
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return receipt

    def run_suite(self, lane: str, artifacts: Mapping[str, Path], outer_artifact: Path | None, run_id: str | None = None, manifest: Path | None = None, baseline_artifacts: Mapping[str, Path] | None = None, baseline_version: str | None = None, candidate_version: str | None = None, manifest_public_key: Path | None = None, baseline_manifest: Path | None = None, headless_baseline_receipt: Path | None = None, headless_candidate_receipt: Path | None = None) -> dict[str, Any]:
        """Create and execute every selected real guest, then return evidence summary."""
        run = self.create(lane, artifacts, outer_artifact, run_id, manifest, baseline_artifacts, baseline_version, candidate_version, manifest_public_key, baseline_manifest, headless_baseline_receipt, headless_candidate_receipt)
        run_id = run["run_id"]
        expected = run.get("expected_profiles") or list(PROFILE_IDS)
        completed: list[str] = []
        for profile_id in expected:
            self.start(run_id, profile_id)
            self.guest_probe(run_id, profile_id)
            self.run_steps(run_id, profile_id)
            self.collect(run_id, profile_id)
            completed.append(profile_id)
        return {"run_id": run_id, "lane": lane, "completed_profiles": completed, "release_passed": False, "next": "gate"}

    def reset(self, run_id: str, profile_id: str | None = None) -> dict[str, Any]:
        self.assert_mutation_context()
        run = self.get_run(run_id)
        targets = [profile_id] if profile_id else list(run.get("profiles", {}))
        removed = []
        for current in targets:
            if current not in run["profiles"]:
                raise LabError(f"unknown profile in run: {current}")
            profile_dir = ensure_owned_child(self.root, self.root / "runs" / run_id / current, "profile directory")
            marker = profile_dir / ".owned-overlay.json"
            overlay = profile_dir / "overlay.qcow2"
            if not marker.is_file():
                raise LabError(f"refusing reset without ownership marker: {marker}")
            metadata = json.loads(marker.read_text(encoding="utf-8"))
            if metadata.get("run_id") != run_id or metadata.get("profile") != current or Path(metadata.get("overlay", "")).resolve() != overlay.resolve():
                raise LabError("overlay ownership marker mismatch")
            vm = run["profiles"][current].get("vm")
            if isinstance(vm, dict) and vm.get("backend") == "android-adapter":
                self._run_android_adapter(run_id, current, "reset")
            if isinstance(vm, dict) and vm.get("backend") != "android-adapter":
                try:
                    owned = self.owned_vm(run_id, current)
                except LabError:
                    # A dead owned process is already reset; a live process
                    # with a mismatched identity is rejected by owned_vm.
                    if Path(f"/proc/{int(vm.get('pid', 0))}").exists():
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
                overlay.unlink()
                removed.append(str(overlay))
            run["profiles"][current] = {"status": "reset", "evidence": None, "vm": None}
        state = self.load_state(); state["runs"][run_id] = run; self.save_state(state)
        return {"run_id": run_id, "reset_profiles": targets, "removed_overlays": removed, "release_passed": False}

    def gate(self, run_id: str, lane: str, artifact_dir: Path | None = None, outer_artifact: Path | None = None) -> dict[str, Any]:
        self.assert_mutation_context()
        run = self.get_run(run_id)
        if lane not in ("candidate", "release"):
            raise LabError("lane must be candidate or release")
        if run.get("lane") != lane:
            raise LabError("gate lane does not match the planned run lane")
        if self.dry_run or run.get("dry_run"):
            return {"run_id": run_id, "lane": lane, "candidate_passed": False, "release_passed": False, "reason": "dry-run cannot pass a release gate"}
        if lane == "release":
            raise LabError("release publication gate is blocked: no verified self-hosted publication evidence; QMP/QGA liveness and consumer fixture HTTP are not publication proof")
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
        if not outer_artifact:
            raise LabError("gate requires the exact planned outer artifact path")
        outer = artifact_record(outer_artifact)
        planned = run.get("outer_artifact") or {}
        if Path(planned.get("path", "")).resolve() != outer_artifact.resolve() or planned.get("sha256") != outer["sha256"] or planned.get("size") != outer["size"]:
            raise LabError("outer artifact changed or path changed after plan; rebuild after testing is forbidden")
        for label in ("manifest", "manifest_public_key"):
            planned = run.get(label)
            if not isinstance(planned, dict):
                continue
            current = artifact_record(Path(planned["path"]))
            if (current["sha256"], current["size"]) != (planned.get("sha256"), planned.get("size")):
                raise LabError(f"{label} changed after guest testing")
        for label in ("profile_records", "runner_records"):
            for item_id, planned in run.get(label, {}).items():
                current = artifact_record(Path(planned["path"]))
                if (current["sha256"], current["size"]) != (planned.get("sha256"), planned.get("size")):
                    raise LabError(f"{label} changed after plan: {item_id}")
        validate_signed_manifest(Path(run["manifest"]["path"]), Path(run["manifest_public_key"]["path"]), version=str(run["candidate_version"]), artifacts=run.get("artifacts", {}))
        if lane == "release":
            observation = run.get("server_observation")
            if not isinstance(observation, dict) or observation.get("role") != "isolated-test-server-router" or observation.get("run_id") != run_id or observation.get("qmp_observed") is not True or observation.get("qga_observed") is not True or observation.get("uuid") != (run.get("profiles", {}).get("server-router", {}).get("vm") or {}).get("uuid") or observation.get("outer_artifact_sha256") != run["outer_artifact"].get("sha256") or observation.get("manifest_sha256") != run["manifest"].get("sha256"):
                raise LabError("release gate server observation is incomplete or not bound to this run")
            self.observe_server(run_id, str(observation.get("ssh_host_key_pin", "")))
        profiles = run.get("profiles", {})
        expected_profiles = run.get("expected_profiles") or list(PROFILE_IDS)
        missing = [profile_id for profile_id in expected_profiles if profiles.get(profile_id, {}).get("status") != "evidence-collected"]
        for profile_id in expected_profiles:
            declared = {step.get("id") for step in load_profiles()[profile_id].get("steps", [])}
            observed = {step.get("id") for step in profiles.get(profile_id, {}).get("steps", []) if isinstance(step, dict) and step.get("passed") is True}
            if not declared.issubset(observed):
                missing.append(f"{profile_id}-steps")
        if profiles.get("windows-x64", {}).get("status") == "evidence-collected" and profiles["windows-x64"].get("evidence", {}).get("interactive_verified") is not True:
            missing.append("windows-x64-interactive-uac")
        if missing:
            return {"run_id": run_id, "lane": lane, "candidate_passed": False, "release_passed": False, "reason": "missing real guest evidence", "missing_profiles": missing}
        result = {"run_id": run_id, "lane": lane, "candidate_passed": True, "release_passed": lane == "release", "artifact_sha256": (run.get("outer_artifact") or {}).get("sha256"), "tested_at": utc_now()}
        if lane == "release":
            marker = ensure_owned_child(self.root, self.root / "exports" / run_id / "publishable.json", "publication marker")
            json_dump(marker, {"schema": 1, "run_id": run_id, "release_passed": True, "artifact_sha256": result["artifact_sha256"], "created_at": utc_now(), "evidence": "qga-real-guest"})
            result["publishable_marker"] = str(marker)
        return result


def validate_receipt(receipt: Mapping[str, Any], *, run_id: str, profile_id: str, artifact: Mapping[str, Any] | None) -> None:
    missing = sorted(RECEIPT_REQUIRED - set(receipt))
    if missing:
        raise LabError(f"guest receipt missing fields: {', '.join(missing)}")
    if receipt.get("schema") != 1 or receipt.get("run_id") != run_id or receipt.get("profile") != profile_id:
        raise LabError("guest receipt identity mismatch")
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", str(receipt.get("baseline_version", ""))) or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", str(receipt.get("candidate_version", ""))):
        raise LabError("guest receipt has invalid baseline/candidate versions")
    expected_transport = "android-adapter" if profile_id == "android-arm64-v8a" else "qga"
    if receipt.get("transport") != expected_transport or receipt.get("origin") == "host" or receipt.get("injected") is True:
        raise LabError("guest receipt is not real QGA evidence")
    marker = receipt.get("guest_marker")
    if not isinstance(marker, str) or marker != f"amnezia-release-lab:{run_id}:{profile_id}":
        raise LabError("guest marker is missing or does not identify this run/profile")
    if not isinstance(receipt.get("steps"), list) or not receipt["steps"] or any(not isinstance(step, dict) or step.get("passed") is not True for step in receipt["steps"]):
        raise LabError("guest receipt has no fully passed steps")
    if artifact and receipt.get("artifact_sha256") != artifact.get("sha256"):
        raise LabError("guest receipt artifact digest differs from planned artifact")
    if not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("artifact_sha256", ""))):
        raise LabError("guest receipt artifact digest is not SHA-256")
    if profile_id == "android-arm64-v8a":
        identity = receipt.get("device_identity")
        if not isinstance(identity, dict) or not identity.get("serial", "").startswith("emulator-") or not identity.get("qemu_uuid"):
            raise LabError("Android receipt lacks the owned emulator serial and QEMU UUID")


def parse_artifacts(values: Sequence[str]) -> dict[str, Path]:
    artifacts: dict[str, Path] = {}
    for value in values:
        name, sep, raw = value.partition("=")
        if not sep or name not in RELEASE_PLATFORM_IDS:
            raise LabError(f"artifact must be platform=path for a supported platform: {value}")
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
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true", dest="as_json")
    sub = parser.add_subparsers(dest="command", required=True)
    preflight = sub.add_parser("preflight")
    preflight.add_argument("--profile", action="append", default=[])
    sub.add_parser("status")
    plan = sub.add_parser("plan")
    plan.add_argument("--lane", choices=("candidate", "release"), default="release")
    plan.add_argument("--artifact", action="append", default=[])
    plan.add_argument("--outer-artifact")
    plan.add_argument("--manifest")
    plan.add_argument("--manifest-public-key")
    plan.add_argument("--baseline-manifest")
    plan.add_argument("--headless-baseline-receipt")
    plan.add_argument("--headless-candidate-receipt")
    plan.add_argument("--baseline-artifact", action="append", default=[])
    plan.add_argument("--baseline-version", required=True)
    plan.add_argument("--candidate-version", required=True)
    create = sub.add_parser("create")
    create.add_argument("--lane", choices=("candidate", "release"), default="release")
    create.add_argument("--artifact", action="append", default=[])
    create.add_argument("--outer-artifact")
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
        if name == "run": command.add_argument("--step", action="append", default=[])
    suite = sub.add_parser("run-suite")
    suite.add_argument("--lane", choices=("candidate", "release"), default="release")
    suite.add_argument("--artifact", action="append", default=[])
    suite.add_argument("--outer-artifact")
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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    controller = LabController(state_root_from(args.state_root), dry_run=args.dry_run)
    try:
        if args.command == "preflight": result = controller.preflight(args.profile or None)
        elif args.command == "status": result = controller.load_state()
        elif args.command in ("plan", "create"):
            result = controller.create(args.lane, parse_artifacts(args.artifact), Path(args.outer_artifact).resolve() if args.outer_artifact else None, getattr(args, "run_id", None), Path(args.manifest).resolve() if args.manifest else None, parse_artifacts(args.baseline_artifact), args.baseline_version, args.candidate_version, Path(args.manifest_public_key).resolve() if args.manifest_public_key else None, Path(args.baseline_manifest).resolve() if args.baseline_manifest else None, Path(args.headless_baseline_receipt).resolve() if args.headless_baseline_receipt else None, Path(args.headless_candidate_receipt).resolve() if args.headless_candidate_receipt else None)
        elif args.command == "start": result = controller.start(args.run_id, args.profile)
        elif args.command == "guest-probe": result = controller.guest_probe(args.run_id, args.profile)
        elif args.command == "run": result = controller.run_steps(args.run_id, args.profile, args.step)
        elif args.command == "collect": result = controller.collect(args.run_id, args.profile)
        elif args.command == "run-suite": result = controller.run_suite(args.lane, parse_artifacts(args.artifact), Path(args.outer_artifact).resolve() if args.outer_artifact else None, args.run_id, Path(args.manifest).resolve() if args.manifest else None, parse_artifacts(args.baseline_artifact), args.baseline_version, args.candidate_version, Path(args.manifest_public_key).resolve() if args.manifest_public_key else None, Path(args.baseline_manifest).resolve() if args.baseline_manifest else None, Path(args.headless_baseline_receipt).resolve() if args.headless_baseline_receipt else None, Path(args.headless_candidate_receipt).resolve() if args.headless_candidate_receipt else None)
        elif args.command == "reset": result = controller.reset(args.run_id, args.profile)
        elif args.command == "gate": result = controller.gate(args.run_id, args.lane, Path(args.artifact_dir).resolve() if args.artifact_dir else None, Path(args.outer_artifact).resolve() if args.outer_artifact else None)
        elif args.command == "server-observe": result = controller.observe_server(args.run_id, args.ssh_host_key_pin)
        elif args.command == "fixture-start": result = controller.start_consumer_fixture(args.run_id, Path(args.manifest).resolve(), Path(args.artifact).resolve())
        elif args.command == "fixture-stop": result = controller.stop_consumer_fixture(args.run_id)
        else: raise LabError(f"unsupported command: {args.command}")
        emit(result, args.as_json)
        if args.command == "preflight" and not result.get("ready", False): return 2
        if args.command == "gate" and not (result.get("release_passed") or result.get("candidate_passed")): return 3
        return 0
    except (LabError, OSError, subprocess.SubprocessError) as exc:
        emit({"ok": False, "error": str(exc), "release_passed": False}, args.as_json)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
