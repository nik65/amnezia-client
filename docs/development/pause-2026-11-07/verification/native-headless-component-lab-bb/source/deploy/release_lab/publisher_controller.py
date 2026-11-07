"""Owned self-hosted publication lifecycle.

The controller deliberately has one public input (an existing lab run id). All
identities and artifact paths come from the immutable run plan. Runtime work is
delegated to the release-lab adapters; this module only assembles their
bounded lifecycle and records controller-created evidence.
"""
from __future__ import annotations

import hashlib
import base64
import contextlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import urllib.parse
import urllib.request
import urllib.error
from pathlib import PurePosixPath, PureWindowsPath
from pathlib import Path
from typing import Any, Mapping, Protocol

try:
    from .lab import (
        LabController,
        LabError,
        QgaClient,
        immutable_bytes_dump,
        immutable_json_dump,
        sha256_file,
        validate_publication_evidence,
        windows_path_for_wsl,
    )
    from .publisher_filemap import PublisherFileMapError, canonical_publisher_file_map
except ImportError:
    if "__main__" in sys.modules and hasattr(sys.modules["__main__"], "LabController"):
        from __main__ import LabController, LabError, QgaClient, immutable_bytes_dump, immutable_json_dump, sha256_file, validate_publication_evidence, windows_path_for_wsl
    else:
        from lab import LabController, LabError, QgaClient, immutable_bytes_dump, immutable_json_dump, sha256_file, validate_publication_evidence, windows_path_for_wsl
    from publisher_filemap import PublisherFileMapError, canonical_publisher_file_map


class PublisherOps(Protocol):
    def start_server(self, run_id: str) -> Mapping[str, Any]: ...
    def start_child(self, run_id: str, case_id: str) -> Mapping[str, Any]: ...
    def stage_outer(self, run_id: str, case_id: str, artifact: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def run_outer_reinstall(self, run_id: str, case_id: str, artifact: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def seed_lab_profile(self, run_id: str, case_id: str, server: Mapping[str, Any], nonce: str) -> Mapping[str, Any]: ...
    def start_relays(self, run_id: str, case_id: str, child: Mapping[str, Any], server: Mapping[str, Any], nonce: str) -> Mapping[str, Any]: ...
    def publish_once(self, run_id: str, case_id: str) -> Mapping[str, Any]: ...
    def collect_readback(self, run_id: str, case_id: str, server: Mapping[str, Any], nonce: str) -> Mapping[str, Any]: ...
    def cleanup(self, run_id: str, case_id: str) -> Mapping[str, Any]: ...

    def recover_attempt(self, run_id: str, attempt: Mapping[str, Any]) -> Mapping[str, Any]: ...


# The guest capture is bounded to 256 KiB, but JSON escaping is not: each
# control character expands to a six-byte escape in the encoded document,
# so the old fixed 1 MiB refusal silently discarded realistic captures.
# 4 MiB admits the fully escaped bounded server capture plus the client
# envelope; anything larger is stored as a bounded head/tail record.
_PRIVATE_SNAPSHOT_MAX_BYTES = 4 * 1024 * 1024
_PRIVATE_SNAPSHOT_STRING_BYTES = 262144


def _snapshot_json(binding: Mapping[str, Any]) -> bytes:
    return (json.dumps(binding, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _snapshot_fragment(data: bytes, half: int, label: str) -> dict[str, Any]:
    return {"_snapshot_truncated": {
        "label": label, "encoding": "base64",
        "original_bytes": len(data), "original_sha256": hashlib.sha256(data).hexdigest(),
        "head": base64.b64encode(data[:half]).decode("ascii"),
        "tail": base64.b64encode(data[-half:]).decode("ascii"),
    }}


def _snapshot_bounded_value(value: Any, limit: int) -> Any:
    """Head/tail truncate long strings while keeping the JSON shape readable."""
    if isinstance(value, str):
        data = value.encode("utf-8", "surrogatepass")
        if len(data) <= limit:
            return value
        return _snapshot_fragment(data, max(limit // 2, 1024), "string")
    if isinstance(value, Mapping):
        return {str(key): _snapshot_bounded_value(item, limit) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_snapshot_bounded_value(item, limit) for item in value]
    return value


def _private_publication_snapshot(root: Path, run_id: str, case_id: str, nonce: str, label: str, value: Mapping[str, Any]) -> Mapping[str, Any]:
    """Best-effort immutable private diagnostics, never publication authority.

    The exact serialized bytes are persisted when they fit the bounded
    ceiling; otherwise long strings keep a base64 head/tail plus the original
    size and digest so a pathological JSON expansion cannot lose the record.
    """
    try:
        if os.name != "posix" or not hasattr(os, "geteuid"):
            return {"status": "unavailable-platform"}
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", run_id)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", case_id)
                or not re.fullmatch(r"[0-9a-f]{48}", nonce) or label not in {"client", "server"}):
            return {"status": "unavailable-identity"}
        root = Path(root).absolute()
        if any(stat.S_ISLNK(path.lstat().st_mode) for path in (root, *root.parents)):
            return {"status": "unavailable-path"}
        uid = os.geteuid()
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
            return {"status": "unavailable-root"}
        directory = root
        for component in ("exports", run_id, "publication", nonce, "private-pre-http"):
            directory = directory / component
            try:
                directory.mkdir(mode=0o700)
            except FileExistsError:
                pass
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
                return {"status": "unavailable-path"}
        if directory.stat().st_mode & 0o077:
            return {"status": "unavailable-permissions"}
        binding = {"schema": 1, "run_id": run_id, "case_id": case_id, "attempt_nonce": nonce,
                   "diagnostic_only": True, "label": label, "raw": value}
        raw = _snapshot_json(binding)
        record: dict[str, Any] = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
        if len(raw) > _PRIVATE_SNAPSHOT_MAX_BYTES:
            full_sha256, full_size = record["sha256"], record["size"]
            limit = _PRIVATE_SNAPSHOT_STRING_BYTES
            while limit >= 1024:
                candidate = _snapshot_json({**binding, "raw": _snapshot_bounded_value(value, limit)})
                if len(candidate) <= _PRIVATE_SNAPSHOT_MAX_BYTES:
                    raw = candidate
                    break
                limit //= 2
            else:
                half = _PRIVATE_SNAPSHOT_MAX_BYTES // 8
                candidate = _snapshot_json({**binding, "raw": _snapshot_fragment(raw, half, "document")})
                raw = candidate if len(candidate) <= _PRIVATE_SNAPSHOT_MAX_BYTES else b""
            if not raw:
                return {"status": "oversize-not-persisted", "sha256": full_sha256, "size": full_size}
            record = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
                      "truncated": True, "full_sha256": full_sha256, "full_size": full_size}
        path = directory / (label + "-" + secrets.token_hex(16) + ".json")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if path.read_bytes() != raw or stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise OSError("snapshot readback differs")
        return {"status": "preserved", "path": str(path), **record}
    except Exception:
        return {"status": "unavailable"}


_PUBLISHER_SERVER_DIAGNOSTIC_COMMAND = "set +e; { printf '%s\\n' '--- ssh stderr'; cat /tmp/amnezia-release-lab-publisher-ssh.stderr 2>&1; printf '%s\\n' '--- attempt marker'; cat /tmp/amnezia-release-lab-publisher-attempt.json 2>&1; printf '%s\\n' '--- paths'; find /opt/amnezia -maxdepth 3 -type f -printf '%p|%u:%g|%m|%s\\n' 2>&1; printf '%s\\n' '--- containers'; docker ps -a --no-trunc 2>&1; printf '%s\\n' '--- networks'; docker network ls --no-trunc 2>&1; printf '%s\\n' '--- ports'; ss -ltn 2>&1; printf '%s\\n' '--- publication history'; for state in /opt/amnezia/client-updates/.publish-history.*; do test -f \"$state\" || continue; printf 'FILE=%s\\n' \"$state\"; cat \"$state\"; done; } | head -c 262144; exit 0"


class PublisherError(LabError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _persist_attempt(controller: LabController, run_id: str, attempt: Mapping[str, Any]) -> dict[str, Any]:
    """Persist the publication intent after every ownership boundary.

    The lab state is the durable ledger.  It is deliberately kept alongside
    the run instead of in a process-local object: a controller crash between
    an adapter mutation and its response must leave enough identity for the
    next invocation to run the adapter's guarded recovery path.
    """
    state = controller.load_state()
    runs = state.setdefault("runs", {})
    run = runs.get(run_id)
    if not isinstance(run, dict):
        raise PublisherError(f"publication attempt run disappeared: {run_id}")
    value = dict(attempt)
    value["schema"] = 1
    value["controller_created"] = True
    value["run_id"] = run_id
    run["publication_attempt"] = value
    runs[run_id] = run
    controller.save_state(state)
    return value


def _merge_attempt(controller: LabController, run_id: str, **updates: Any) -> dict[str, Any]:
    run = controller.get_run(run_id)
    current = run.get("publication_attempt")
    if not isinstance(current, Mapping):
        raise PublisherError("publication attempt ledger is missing")
    attempt = dict(current)
    for key, value in updates.items():
        if isinstance(value, Mapping) and isinstance(attempt.get(key), Mapping):
            merged = dict(attempt[key])
            merged.update(value)
            attempt[key] = merged
        else:
            attempt[key] = value
    return _persist_attempt(controller, run_id, attempt)


class ConcretePublisherOps:
    """Adapter-backed operations; all IDs and paths are supplied by the run."""

    RELAY_HELPER_SHA256 = "6ecc6aedcddaf005b4ff3116d0758d710f69b5cc3473318f51a67c722fb73824"

    def __init__(self, controller: LabController):
        self.controller = controller
        self._key = None
        self._client_raw: dict[str, Any] = {}
        self._client_raw_nonce = ""
        self._publish_result_snapshot: Mapping[str, Any] | None = None
        self._publish_result_snapshot_nonce = ""
        self._pre_http_diagnostics: Mapping[str, Any] | None = None
        self._relays_started = False
        self._server_started = False
        self._child_started = False
        self._attempt_nonce = ""
        self._history_before: set[str] = set()
        self._child_record: dict[str, Any] = {}

    def _attempt_update(self, run_id: str, **updates: Any) -> dict[str, Any]:
        return _merge_attempt(self.controller, run_id, **updates)

    def recover_attempt(self, run_id: str, attempt: Mapping[str, Any]) -> Mapping[str, Any]:
        """Rehydrate only resources named by the durable owned attempt.

        Hyper-V reset and relay-stop perform their own run/case/VM/lease
        ownership checks.  Rehydrating these flags lets cleanup invoke those
        guards after a controller process died; no broad process or resource
        discovery is attempted.
        """
        if attempt.get("schema") != 1 or attempt.get("controller_created") is not True or attempt.get("run_id") != run_id or attempt.get("case_id") != "publisher-clean":
            raise PublisherError("publication attempt ledger identity is invalid")
        nonce = str(attempt.get("attempt_nonce", ""))
        if not re.fullmatch(r"[0-9a-f]{48}", nonce):
            raise PublisherError("publication attempt nonce is invalid")
        resources = attempt.get("resources")
        if not isinstance(resources, Mapping):
            raise PublisherError("publication attempt resource ledger is invalid")
        self._attempt_nonce = nonce
        child = resources.get("child")
        if isinstance(child, Mapping):
            self._child_record = dict(child.get("record") or child)
        self._child_started = bool(isinstance(child, Mapping) and child.get("intent"))
        self._server_started = bool(isinstance(resources.get("server"), Mapping) and resources["server"].get("intent"))
        self._relays_started = bool(isinstance(resources.get("relays"), Mapping) and resources["relays"].get("intent"))
        key = resources.get("key")
        if isinstance(key, Mapping) and key.get("intent"):
            private_value = str(key.get("private_path", ""))
            public_value = str(key.get("public_path", ""))
            expected_dir = (self.controller.root / "runs" / run_id / "publisher").resolve()
            private = Path(private_value).resolve() if private_value else Path("__missing__")
            public_path = Path(public_value).resolve() if public_value else Path("__missing__")
            if private.parent != expected_dir or private.name != "id_ed25519" or public_path.parent != expected_dir or public_path.name != "id_ed25519.pub":
                raise PublisherError("publication key ledger path is outside the owned run scratch")
            if private.is_symlink() or public_path.is_symlink():
                raise PublisherError("publication key ledger points to a symlink")
            self._key = dict(key)
            self._key.update(private_path=private, public_path=public_path)
            if "public" not in self._key and public_path.is_file():
                self._key["public"] = public_path.read_text(encoding="utf-8")
            if "public" not in self._key and private.is_file():
                derived = subprocess.run(("ssh-keygen", "-y", "-f", str(private)), check=False, capture_output=True, text=True, timeout=30)
                if derived.returncode == 0 and derived.stdout.strip():
                    self._key["public"] = derived.stdout.strip() + "\n"
                    self._key["public_sha256"] = hashlib.sha256(self._key["public"].encode("utf-8")).hexdigest()
        return self.cleanup(run_id, str(attempt.get("case_id")))

    @staticmethod
    def _require_envelope(value: Mapping[str, Any], action: str, *, vm_id: str | None = None) -> Mapping[str, Any]:
        if value.get("action") != action or value.get("transport") != "hyperv-powershell-direct" or value.get("origin") != "guest" or value.get("injected") is not False:
            raise PublisherError(f"Hyper-V adapter {action} returned an invalid guest envelope")
        if vm_id is not None and value.get("vm_id") != vm_id:
            raise PublisherError(f"Hyper-V adapter {action} returned a VM identity mismatch")
        return value

    def start_server(self, run_id: str) -> Mapping[str, Any]:
        previous = os.environ.get("AMNEZIA_LAB_RELAY_FIXED_ENDPOINTS")
        os.environ["AMNEZIA_LAB_RELAY_FIXED_ENDPOINTS"] = "1"
        try:
            self._server_started = True
            vm = self.controller.start(run_id, "server-router")
            probe = self.controller.guest_probe(run_id, "server-router")
            if probe.get("transport") != "qga" or probe.get("profile") != "server-router" or probe.get("guest_sync") is not True:
                raise PublisherError("server QGA probe returned an invalid envelope")
            pin = os.environ.get("AMNEZIA_LAB_SSH_HOST_KEY_PIN", "")
            if not pin:
                raise PublisherError("AMNEZIA_LAB_SSH_HOST_KEY_PIN is required for publisher server observation")
            observation = self.controller.observe_server(run_id, pin)
            observation = dict(observation)
            observation.update(qmp_socket=vm["qmp_socket"], qga_socket=vm["qga_socket"])
            run = self.controller.get_run(run_id)
            run["server_observation"] = observation
            state = self.controller.load_state(); state["runs"][run_id] = run; self.controller.save_state(state)
            qga = QgaClient(Path(str(vm["qga_socket"])), timeout=10)
            if not qga.sync():
                raise PublisherError("server QGA is not responsive while capturing publication history baseline")
            baseline = qga.guest_exec_wait("/usr/bin/bash", ["-lc", "for state in /opt/amnezia/client-updates/.publish-history.*; do test -f \"$state\" || continue; basename \"$state\"; done"], timeout=30)
            self._history_before = {line.strip() for line in str(baseline.get("stdout", "")).splitlines() if re.fullmatch(r"\.publish-history\.[0-9a-f]{48}", line.strip())}
        finally:
            if previous is None: os.environ.pop("AMNEZIA_LAB_RELAY_FIXED_ENDPOINTS", None)
            else: os.environ["AMNEZIA_LAB_RELAY_FIXED_ENDPOINTS"] = previous
        return {"uuid": vm["uuid"], "qmp_socket": vm["qmp_socket"], "qga_socket": vm["qga_socket"], "qmp_observed": True, "qga_observed": True, "observation": observation}

    @staticmethod
    def _require_host_plan(value: Mapping[str, Any]) -> Mapping[str, Any]:
        if (not isinstance(value, Mapping) or type(value.get("schema")) is not int or value.get("schema") != 1
                or value.get("backend") != "hyperv" or value.get("profile") != "windows-x64"
                or value.get("transport") != "hyperv-powershell-direct" or value.get("ready") is not True
                or value.get("parent_state") != "Off" or value.get("host_network_mutation") is not False
                or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("parent_sha256", "")))
                or not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", str(value.get("parent_vm_id", "")))):
            raise PublisherError("sealed Hyper-V host plan is invalid")
        parent = PureWindowsPath(str(value.get("parent_vhdx", "")))
        if (parent.parent != PureWindowsPath(r"C:\ProgramData\AmneziaReleaseLab\hyperv\windows-x64")
                or parent.suffix.lower() != ".vhdx"
                or PureWindowsPath(str(value.get("child_root", ""))) != PureWindowsPath(r"C:\ProgramData\AmneziaReleaseLab\hyperv\runs\RUN_ID\windows-x64\cases\CASE_ID")
                or not isinstance(value.get("cases"), list) or "publisher-clean" not in value["cases"]):
            raise PublisherError("sealed Hyper-V host plan paths/cases differ")
        return value

    @staticmethod
    def _require_owned_host_envelope(value: Mapping[str, Any], action: str, *, run_id: str,
                                    case_id: str, parent: Mapping[str, Any], expected_child: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        if (not isinstance(value, Mapping) or action not in {"create-child", "start"}
                or value.get("action") != action or value.get("origin") not in (None, "controller")
                or ("injected" in value and value["injected"] is not False)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", run_id)
                or case_id != "publisher-clean"):
            raise PublisherError("owned Hyper-V host command envelope is invalid")
        child, configuration = value.get("child"), value.get("configuration")
        if not isinstance(child, Mapping) or not isinstance(configuration, Mapping):
            raise PublisherError("owned Hyper-V host child/configuration missing")
        expected_root = PureWindowsPath(r"C:\ProgramData\AmneziaReleaseLab\hyperv\runs") / run_id / "windows-x64" / "cases" / case_id
        expected_disk = expected_root / "disk" / "child.vhdx"
        vm_id = child.get("vm_id")
        name_hash = hashlib.sha256((run_id + "|" + case_id).encode()).hexdigest()[:12]
        expected_name = ("AmneziaLab-" + run_id[:32] + "-" + case_id + "-" + name_hash)[:80]
        state = "created" if action == "create-child" else "running"
        if (type(child.get("schema")) is not int or child["schema"] != 1
                or child.get("backend") != "hyperv" or child.get("profile") != "windows-x64"
                or child.get("run_id") != run_id or child.get("case_id") != case_id
                or not isinstance(vm_id, str) or not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", vm_id)
                or child.get("vm_name") != expected_name or child.get("state") != state
                or child.get("transport") != "hyperv-powershell-direct"
                or PureWindowsPath(str(child.get("run_root", ""))) != expected_root
                or PureWindowsPath(str(child.get("child_vhdx", ""))) != expected_disk
                or PureWindowsPath(str(child.get("parent_vhdx", ""))) != PureWindowsPath(parent["parent_vhdx"])
                or child.get("parent_vm_id") != parent["parent_vm_id"]
                or any(child.get(k) != parent["parent_sha256"] for k in ("parent_sha256", "parent_sha256_before", "parent_sha256_after"))):
            raise PublisherError("owned Hyper-V child marker/run/parent binding differs")
        fixed = configuration.get("fixed_memory_readback")
        numeric = {"generation": 2, "processors": 4, "memory_bytes": 8589934592,
                   "network_adapter_count": 0, "dvd_count": 0}
        if (configuration.get("vm_id") != vm_id or configuration.get("state") != ("Off" if action == "create-child" else "Running")
                or any(type(configuration.get(k)) is not int or configuration[k] != expected for k, expected in numeric.items())
                or any(configuration.get(k) is not True for k in ("secure_boot", "vtp_enabled", "key_protector_present"))
                or configuration.get("secure_boot_template") != "MicrosoftWindows"
                or configuration.get("vhd_type") != "Differencing"
                or PureWindowsPath(str(configuration.get("child_vhdx", ""))) != expected_disk
                or PureWindowsPath(str(configuration.get("parent_vhdx", ""))) != PureWindowsPath(parent["parent_vhdx"])
                or not isinstance(fixed, Mapping) or fixed.get("dynamic_memory_enabled") is not False
                or type(fixed.get("startup_bytes")) is not int or fixed["startup_bytes"] != 8589934592):
            raise PublisherError("owned Hyper-V host configuration differs")
        if action == "create-child":
            readback = value.get("parent_readback")
            expected = {"before_sha256": parent["parent_sha256"], "after_sha256": parent["parent_sha256"],
                        "before_vm_id": parent["parent_vm_id"], "after_vm_id": parent["parent_vm_id"]}
            if (not isinstance(readback, Mapping) or any(readback.get(k) != expected_value for k, expected_value in expected.items())
                    or any(PureWindowsPath(str(readback.get(k, ""))) != PureWindowsPath(parent["parent_vhdx"]) for k in ("before_vhdx", "after_vhdx"))):
                raise PublisherError("sealed parent changed across owned child creation")
        else:
            worker = value.get("worker")
            if (not isinstance(expected_child, Mapping) or vm_id != expected_child.get("vm_id")
                    or value.get("parent_sha256") != parent["parent_sha256"]
                    or not isinstance(worker, Mapping) or type(worker.get("process_pid")) is not int or worker["process_pid"] <= 0
                    or worker.get("process_uuid") != vm_id or worker.get("source") != "Msvm_ComputerSystem.ProcessID"
                    or not isinstance(worker.get("process_start_time"), str) or not worker["process_start_time"]
                    or any(child.get(k) != worker.get(k) for k in ("process_pid", "process_uuid", "process_start_time"))):
                raise PublisherError("started Hyper-V child worker identity differs")
        return value

    def start_child(self, run_id: str, case_id: str) -> Mapping[str, Any]:
        self._child_started = True
        parent = self._require_host_plan(self.controller.hyperv_call("plan", run_id=run_id))
        made = self.controller.hyperv_call("create-child", run_id=run_id, CaseId=case_id)
        self._require_owned_host_envelope(made, "create-child", run_id=run_id, case_id=case_id, parent=parent)
        child = dict(made.get("child") or {})
        self.controller._record_hyperv_case(run_id, "windows-x64", case_id, "created", vm_id=child.get("vm_id"), parent_sha256=child.get("parent_sha256"), run_root=child.get("run_root"), child_vhdx=child.get("child_vhdx"))
        started = self.controller.hyperv_call("start", run_id=run_id, CaseId=case_id, credential=True)
        self._require_owned_host_envelope(started, "start", run_id=run_id, case_id=case_id, parent=parent, expected_child=child)
        child.update(started.get("child") or {})
        probe = self.controller.hyperv_call("probe", run_id=run_id, CaseId=case_id, credential=True)
        self._require_envelope(probe, "probe", vm_id=str(child.get("vm_id")))
        if probe.get("parent_sha256") != parent["parent_sha256"]:
            raise PublisherError("guest probe sealed parent differs from owned host child")
        record = {"vm_id": child.get("vm_id"), "parent_sha256": child.get("parent_sha256"), "process_pid": child.get("process_pid", child.get("pid")), "process_uuid": child.get("process_uuid", child.get("uuid")), "marker": child.get("marker", f"amnezia-release-lab:{run_id}:windows-x64"), "case_id": case_id}
        self._child_record = dict(record)
        self.controller._record_hyperv_case(run_id, "windows-x64", case_id, "running", vm_id=record["vm_id"], parent_sha256=record["parent_sha256"], run_root=child.get("run_root"), child_vhdx=child.get("child_vhdx"))
        run = self.controller.get_run(run_id)
        run["profiles"]["windows-x64"].update(status="started", vm={**record, "backend": "hyperv", "transport": "hyperv-powershell-direct"})
        state = self.controller.load_state(); state["runs"][run_id] = run; self.controller.save_state(state)
        return record

    def stage_outer(self, run_id: str, case_id: str, artifact: Mapping[str, Any]) -> Mapping[str, Any]:
        path = Path(str(artifact["path"])).resolve()
        envelope = self.controller.hyperv_call("stage", run_id=run_id, CaseId=case_id, credential=True, ArtifactPath=windows_path_for_wsl(path), ArtifactSha256=str(artifact["sha256"]), ArtifactSize=int(artifact["size"]), Stage="candidate-outer")
        self._require_envelope(envelope, "stage", vm_id=str(self._child_record.get("vm_id")))
        guest = envelope.get("guest")
        if not isinstance(guest, Mapping) or guest.get("sha256") != artifact.get("sha256") or guest.get("size") != artifact.get("size"):
            raise PublisherError("Hyper-V stage envelope lacks exact guest artifact readback")
        return guest

    def run_outer_reinstall(self, run_id: str, case_id: str, artifact: Mapping[str, Any]) -> Mapping[str, Any]:
        runner = Path(__file__).parent / "guest_runners" / "windows-release-lab.ps1"
        try:
            result = self.controller.hyperv_call("run", run_id=run_id, CaseId=case_id, credential=True, GuestAction="reinstall", ExpectedSha256=str(artifact["sha256"]), ExpectedVersion=str(self.controller.get_run(run_id)["candidate_version"]), ExpectedArtifactRole="candidate", BaselineVersion=str(self.controller.get_run(run_id)["baseline_version"]), CandidateVersion=str(self.controller.get_run(run_id)["candidate_version"]), RunnerPath=windows_path_for_wsl(runner), RunnerSha256=sha256_file(runner)[0])
        except Exception as exc:
            return {"passed": False, "transport": "hyperv-powershell-direct", "error": str(exc)}
        envelope = result.get("result")
        if not isinstance(envelope, Mapping):
            return {"passed": False, "transport": "hyperv-powershell-direct", "error": "Hyper-V run did not return a guest result envelope", "guest_result": result}
        assertion = ((envelope.get("readback") or {}).get("receipt"))
        passed = False
        receipt_value: Mapping[str, Any] | None = None
        if assertion:
            try:
                receipt_value = json.loads(assertion)
                nested = receipt_value.get("assertion") or {}
                steps = receipt_value.get("steps") or []
                passed = nested.get("passed") is True and bool(steps) and all(isinstance(step, Mapping) and step.get("passed") is True for step in steps)
            except (TypeError, json.JSONDecodeError):
                passed = False
        collect = None
        try:
            collect = self.controller.hyperv_call("collect", run_id=run_id, CaseId=case_id, credential=True)
        except Exception as exc:
            return {"passed": False, "transport": "hyperv-powershell-direct", "error": f"guest collect after reinstall failed: {exc}", "guest_result": result}
        run = self.controller.get_run(run_id)
        expected_sha = str(artifact.get("sha256", "")).lower()
        candidate = str(run.get("candidate_version", ""))
        baseline = str(run.get("baseline_version", ""))
        marker = f"amnezia-release-lab:{run_id}:windows-x64"
        nested = (receipt_value or {}).get("assertion") if isinstance(receipt_value, Mapping) else None
        marker_readback = str((receipt_value or {}).get("guest_marker_readback", "")) if isinstance(receipt_value, Mapping) else ""
        marker_lines = {line.strip() for line in marker_readback.splitlines()}
        top_level_ok = (
            isinstance(receipt_value, Mapping)
            and receipt_value.get("schema") == 1
            and receipt_value.get("run_id") == run_id
            and receipt_value.get("profile") == "windows-x64"
            and receipt_value.get("case_id") == case_id
            and receipt_value.get("action") == "reinstall"
            and receipt_value.get("artifact_sha256") == expected_sha
            and receipt_value.get("artifact_size") == artifact.get("size")
            # Hyper-V stages every source into the case-owned `current.exe`;
            # the host source filename is intentionally not reused in guest.
            and receipt_value.get("artifact") == "current.exe"
            and receipt_value.get("artifact_role") == "candidate"
            and receipt_value.get("baseline_version") == baseline
            and receipt_value.get("candidate_version") == candidate
            and receipt_value.get("guest_marker") == marker
            and marker in marker_lines
            and f"case_id={case_id}" in marker_lines
            and receipt_value.get("transport") == "hyperv-powershell-direct"
            and receipt_value.get("origin") == "guest"
            and receipt_value.get("injected") is False
        )
        source = receipt_value.get("artifact_source") if isinstance(receipt_value, Mapping) else None
        source_ok = isinstance(source, Mapping) and source.get("transport") == "hyperv-powershell-direct" and source.get("hash_verified") is True
        nested_ok = (
            isinstance(nested, Mapping)
            and nested.get("passed") is True
            and nested.get("run_id") == run_id
            and nested.get("profile") == "windows-x64"
            and nested.get("action") == "reinstall"
            and nested.get("artifact_sha256") == expected_sha
            and nested.get("expected_sha256") == expected_sha
            and nested.get("expected_version") == candidate
            and nested.get("installed_version") == candidate
        )
        envelope_ok = envelope.get("transport") == "hyperv-powershell-direct" and envelope.get("origin") == "guest" and envelope.get("injected") is False and envelope.get("vm_id") == self._child_record.get("vm_id")
        passed = bool(passed and top_level_ok and source_ok and nested_ok and envelope_ok)
        return {"passed": passed, "transport": envelope.get("transport", "hyperv-powershell-direct"), "error": None if passed else "guest receipt assertion/steps/hash/version/role/binding did not pass", "guest_result": result, "guest_collect": collect}

    def _relay_helper_paths(self) -> tuple[Path, Path, Path]:
        root = Path(__file__).parent / "windows_host"
        helper = None
        for candidate in (Path(__file__).parents[2] / "Testing" / "focused-hyperv-relay-release", Path(__file__).parents[2] / "Testing" / "focused-hyperv-relay"):
            if (candidate / "amnezia_hyperv_socket_relay.exe").is_file() and candidate.name == "focused-hyperv-relay-release":
                helper = candidate
                break
        if helper is None or not (helper / "amnezia_hyperv_socket_relay.exe").is_file():
            raise PublisherError("focused AF_HYPERV relay helper is missing")
        relay = helper / "amnezia_hyperv_socket_relay.exe"
        if sha256_file(relay)[0] != self.RELAY_HELPER_SHA256:
            raise PublisherError("focused AF_HYPERV relay helper hash is not the frozen release helper")
        supervisor = helper / "amnezia_hyperv_socket_relay_supervisor.exe"
        task = root / "hyperv_relay_guest_task.ps1"
        if not supervisor.is_file() or not task.is_file():
            raise PublisherError("focused AF_HYPERV relay supervisor or guest task is missing")
        return relay, supervisor, task

    def _with_publisher_key(self, key: str, action: str, **kwargs: Any) -> Mapping[str, Any]:
        variable = "AMNEZIA_LAB_PUBLISHER_KEY_B64"
        previous = os.environ.get(variable)
        previous_wslenv = os.environ.get("WSLENV")
        # WSL does not forward Linux environment variables to Win32 children
        # unless WSLENV explicitly opts them in. The key is data, never a path.
        entries = [entry for entry in (previous_wslenv or "").split(":")
                   if entry and entry.split("/", 1)[0].upper() != variable]
        os.environ[variable] = base64.b64encode(key.encode("utf-8")).decode("ascii")
        os.environ["WSLENV"] = ":".join([*entries, variable + "/w"])
        try:
            return self.controller.hyperv_call(action, run_id=kwargs.pop("run_id"), credential=True, **kwargs)
        finally:
            if previous is None:
                os.environ.pop(variable, None)
            else:
                os.environ[variable] = previous
            if previous_wslenv is None:
                os.environ.pop("WSLENV", None)
            else:
                os.environ["WSLENV"] = previous_wslenv

    def seed_lab_profile(self, run_id: str, case_id: str, server: Mapping[str, Any], nonce: str) -> Mapping[str, Any]:
        self._attempt_nonce = nonce
        publisher_dir = self.controller.root / "runs" / run_id / "publisher"
        publisher_dir.mkdir(parents=True, exist_ok=True)
        private = publisher_dir / "id_ed25519"
        if private.exists():
            raise PublisherError("publisher key scratch already exists; refusing reuse")
        self._key = {"private_path": private, "public_path": private.with_suffix(".pub")}
        self._attempt_update(run_id, resources={"key": {"intent": True, "private_path": str(private), "public_path": str(private.with_suffix(".pub")), "attempt_nonce": nonce}})
        generated = subprocess.run(("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private)), check=False, capture_output=True, text=True, timeout=30)
        if generated.returncode != 0 or not private.is_file() or not private.with_suffix(".pub").is_file():
            raise PublisherError("unable to generate a fresh ephemeral publisher key")
        self._key.update({"public": private.with_suffix(".pub").read_text(encoding="utf-8"), "public_sha256": hashlib.sha256(private.with_suffix(".pub").read_bytes()).hexdigest()})
        self._attempt_update(run_id, resources={"key": {"public": self._key["public"], "public_sha256": self._key["public_sha256"]}})
        qga = QgaClient(Path(str(server["qga_socket"])), timeout=10)
        if not qga.sync():
            raise PublisherError("server QGA is not responsive while seeding publisher key")
        public_guest = "/tmp/amnezia-release-lab-publisher.pub"
        qga.write_file(public_guest, self._key["public"].encode("utf-8"))
        qga.guest_exec_wait("/usr/bin/bash", ["-lc", "set -eu; install -d -m 0700 -o lab -g lab /home/lab/.ssh; touch /home/lab/.ssh/authorized_keys; chown lab:lab /home/lab/.ssh/authorized_keys; chmod 0600 /home/lab/.ssh/authorized_keys; grep -qxF \"$(cat /tmp/amnezia-release-lab-publisher.pub)\" /home/lab/.ssh/authorized_keys || cat /tmp/amnezia-release-lab-publisher.pub >> /home/lab/.ssh/authorized_keys; rm -f /tmp/amnezia-release-lab-publisher.pub"], timeout=30)
        qga.write_file("/tmp/amnezia-release-lab-publisher-attempt.json", json.dumps({"schema": 1, "run_id": run_id, "case_id": case_id, "attempt_nonce": nonce, "manifest_sha256": (self.controller.get_run(run_id).get("manifest") or {}).get("sha256")}, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        seed_helper = Path(__file__).parents[2] / "Testing" / "publisher_seed_qsettings_build2" / "Release" / "amnezia_publisher_seed.exe"
        seed_source = Path(__file__).parents[2] / "Testing" / "publisher_seed_qsettings" / "main.cpp"
        seed_manifest = Path(__file__).parents[2] / "Testing" / "publisher_seed_qsettings" / "build-manifest.json"
        if not seed_source.is_file() or not seed_manifest.is_file():
            raise PublisherError("audited publisher seed source/manifest is missing")
        if not seed_helper.is_file():
            raise PublisherError("compiled publisher seed helper is missing")
        try:
            frozen = json.loads(seed_manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PublisherError("audited publisher seed manifest is invalid") from exc
        helper_sha = sha256_file(seed_helper)[0]
        if frozen.get("source") != "Testing/publisher_seed_qsettings/main.cpp" or frozen.get("source_sha256") != sha256_file(seed_source)[0] or frozen.get("frozen_artifact_sha256") != helper_sha:
            raise PublisherError("compiled publisher seed helper does not match the audited frozen build manifest")
        seed = self._with_publisher_key(Path(self._key["private_path"]).read_text(encoding="utf-8"), "seed-profile", run_id=run_id, CaseId=case_id, AttemptNonce=nonce, SeedHelperPath=windows_path_for_wsl(seed_helper), SeedHelperSha256=helper_sha, SeedHost="127.0.0.1", SeedUser="lab", SeedPort=22222, SeedFingerprint=os.environ.get("AMNEZIA_LAB_SSH_HOST_KEY_PIN", ""))
        self._require_envelope(seed, "seed-profile", vm_id=str(self._child_record.get("vm_id")))
        if seed.get("passed") is not True:
            raise PublisherError("publisher profile seed failed in the owned Windows guest")
        return {"passed": True, "transport": "hyperv-powershell-direct", "public_key_sha256": self._key["public_sha256"], "seed": seed}

    def start_relays(self, run_id: str, case_id: str, child: Mapping[str, Any], server: Mapping[str, Any], nonce: str) -> Mapping[str, Any]:
        del server
        relay, supervisor, task = self._relay_helper_paths()
        self._relays_started = True
        result = self.controller.hyperv_call("relays-start", run_id=run_id, CaseId=case_id, credential=True, AttemptNonce=nonce, ChildVmId=str(child["vm_id"]), RelayHelperPath=windows_path_for_wsl(relay), RelaySupervisorPath=windows_path_for_wsl(supervisor), RelayGuestTaskPath=windows_path_for_wsl(task), RelayHelperSha256=self.RELAY_HELPER_SHA256)
        self._require_envelope(result, "relays-start", vm_id=str(child["vm_id"]))
        if result.get("passed") is not True:
            raise PublisherError("owned AF_HYPERV relays failed to start")
        return result

    def publish_once(self, run_id: str, case_id: str) -> Mapping[str, Any]:
        result = self.controller.hyperv_call("publish", run_id=run_id, CaseId=case_id, credential=True, AttemptNonce=self._attempt_nonce)
        # Persist the real adapter result before the ownership envelope (or a
        # later lifecycle failure) can trigger finally-cleanup.
        self._client_raw = dict(result)
        self._client_raw_nonce = self._attempt_nonce
        try:
            self._publish_result_snapshot = _private_publication_snapshot(self.controller.root, run_id, case_id, self._attempt_nonce, "client", self._client_raw)
        except Exception:
            self._publish_result_snapshot = {"status": "unavailable"}
        self._publish_result_snapshot_nonce = self._attempt_nonce
        self._require_envelope(result, "publish", vm_id=str(self._child_record.get("vm_id")))
        return result

    def _capture_pre_http_diagnostics(self, run_id: str, case_id: str, server: Mapping[str, Any], nonce: str) -> Mapping[str, Any]:
        client = getattr(self, "_publish_result_snapshot", None)
        if (getattr(self, "_publish_result_snapshot_nonce", None) != nonce
                or not isinstance(client, Mapping) or client.get("status") != "preserved"):
            value: Mapping[str, Any] = {}
            if getattr(self, "_client_raw_nonce", None) == nonce:
                raw_value = getattr(self, "_client_raw", None)
                if isinstance(raw_value, Mapping):
                    value = dict(raw_value)
            client = _private_publication_snapshot(self.controller.root, run_id, case_id, nonce, "client", value)
            self._publish_result_snapshot = client
            self._publish_result_snapshot_nonce = nonce
        try:
            qga = QgaClient(Path(str(server["qga_socket"])), timeout=10)
            if not qga.sync():
                raise PublisherError("diagnostic QGA unavailable")
            raw = qga.guest_exec_wait("/usr/bin/bash", ["-lc", _PUBLISHER_SERVER_DIAGNOSTIC_COMMAND], timeout=30)
        except Exception as exc:
            # No exception text/locals: raw output can contain private data.
            raw = {"diagnostic_capture_failed": True, "error_type": type(exc).__name__}
        saved = _private_publication_snapshot(self.controller.root, run_id, case_id, nonce, "server", raw)
        diagnostics = {"attempt_nonce": nonce, "diagnostic_only": True, "client": client, "server": saved}
        self._pre_http_diagnostics = diagnostics
        return diagnostics

    def collect_readback(self, run_id: str, case_id: str, server: Mapping[str, Any], nonce: str) -> Mapping[str, Any]:
        if nonce != self._attempt_nonce or not re.fullmatch(r"[0-9a-f]{48}", nonce):
            raise PublisherError("publication readback nonce is not bound to the seeded attempt")
        run = self.controller.get_run(run_id)
        # Preserve the actual client result and bounded owned-server evidence
        # before any HTTP failure can lead finally-cleanup to reset the guest.
        # The original later QGA/HTTP/phase verification remains mandatory.
        try:
            self._pre_http_diagnostics = self._capture_pre_http_diagnostics(run_id, case_id, server, nonce)
        except Exception:
            self._pre_http_diagnostics = {"attempt_nonce": nonce, "diagnostic_only": True, "status": "unavailable"}
        try:
            _merge_attempt(self.controller, run_id, pre_http_diagnostics=self._pre_http_diagnostics)
        except Exception:
            pass  # A diagnostic pointer must never mask the real HTTP failure.
        base = "http://127.0.0.1:17865/"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
        def fetch(path: str, expected_size: int) -> bytes:
            parsed = urllib.parse.urlparse(path)
            pure = PurePosixPath(parsed.path)
            if (parsed.scheme or parsed.netloc or parsed.query or parsed.fragment
                    or parsed.path != str(pure) or ".." in pure.parts
                    or (not parsed.path.startswith("files/artifacts/") and path != "manifest.json")):
                raise PublisherError("published HTTP path is outside the owned update endpoint")
            if not isinstance(expected_size, int) or expected_size < 0:
                raise PublisherError("published file has no valid planned size")
            try:
                with opener.open(urllib.request.Request(urllib.parse.urljoin(base, path)), timeout=10) as response:
                    if response.geturl() != urllib.parse.urljoin(base, path):
                        raise PublisherError("published HTTP endpoint redirected outside the exact planned URL")
                    chunks: list[bytes] = []
                    remaining = expected_size
                    while remaining:
                        chunk = response.read(min(65536, remaining))
                        if not chunk:
                            raise PublisherError("published HTTP body ended before the planned size")
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    if response.read(1):
                        raise PublisherError("published HTTP body exceeds the planned size")
                    return b"".join(chunks)
            except urllib.error.HTTPError as exc:
                raise PublisherError(f"published HTTP request failed without accepted redirects: {exc.code}") from exc
        manifest_plan = run.get("manifest") or {}
        manifest_bytes = fetch("manifest.json", manifest_plan.get("size"))
        manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
        if manifest_sha != manifest_plan.get("sha256") or len(manifest_bytes) != manifest_plan.get("size"):
            raise PublisherError("published manifest bytes differ from the planned signed manifest")
        try:
            envelope = json.loads(manifest_bytes.decode("utf-8"))
            payload = json.loads(base64.urlsafe_b64decode(str(envelope["payload"]) + "=" * (-len(str(envelope["payload"])) % 4)).decode("utf-8"))
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PublisherError("published manifest payload is not readable") from exc
        observed: dict[str, Any] = {}
        try:
            expected_file_map = canonical_publisher_file_map(run, payload)
        except PublisherFileMapError as exc:
            raise PublisherError(f"signed publication file map is invalid: {exc}") from exc
        seen_paths: set[str] = set()
        for label, planned in expected_file_map.items():
            relative = str(planned["path"])
            if relative.startswith("/") or not relative.startswith("files/artifacts/"):
                raise PublisherError(f"published artifact URL is not a local owned path: {label}")
            if relative in seen_paths:
                raise PublisherError(f"published manifest repeats an artifact path: {relative}")
            seen_paths.add(relative)
            expected_size = planned["size"]
            data = fetch(relative, expected_size)
            digest = hashlib.sha256(data).hexdigest()
            if digest != planned["sha256"] or len(data) != planned["size"]:
                raise PublisherError(f"published artifact bytes differ from plan: {label}")
            observed[label] = {"sha256": digest, "size": len(data), "path": relative}
        qga = QgaClient(Path(str(server["qga_socket"])), timeout=10)
        if not qga.sync():
            raise PublisherError("server QGA is not responsive during publication readback")
        command = _PUBLISHER_SERVER_DIAGNOSTIC_COMMAND
        server_raw = qga.guest_exec_wait("/usr/bin/bash", ["-lc", command], timeout=30)
        marker_match = re.search(r"--- attempt marker\s*\n(\{[^\n]+\})", str(server_raw.get("stdout", "")))
        try:
            attempt_marker = json.loads(marker_match.group(1)) if marker_match else None
        except json.JSONDecodeError:
            attempt_marker = None
        if attempt_marker != {"schema": 1, "run_id": run_id, "case_id": case_id, "attempt_nonce": nonce, "manifest_sha256": manifest_sha}:
            raise PublisherError("server QGA readback attempt marker is not bound to this run/case/nonce/manifest")
        history_records: list[dict[str, str]] = []
        history_file = ""
        for line in str(server_raw.get("stdout", "")).splitlines():
            file_match = re.fullmatch(r"FILE=(/opt/amnezia/client-updates/)?(\.publish-history\.[0-9a-f]{48})", line)
            if file_match:
                history_file = file_match.group(2)
                continue
            fields = line.split("\t")
            if len(fields) == 7 and fields[0] == "amnezia-bundled-publish-state-v1":
                history_records.append({"magic": fields[0], "publication_run_id": fields[1], "expected": fields[2], "candidate": fields[3], "metadata_sha256": fields[4], "file_count": fields[5], "phase": fields[6], "record": line, "history_file": history_file})
        metadata_sha, expected_file_count = self._planned_publish_metadata(run, payload)
        baseline_manifest = (run.get("baseline_manifest") or {}).get("sha256")
        matching = [record for record in history_records if record["history_file"] not in self._history_before and record["history_file"] == ".publish-history." + record["publication_run_id"] and record["candidate"] == manifest_sha and record["metadata_sha256"] == metadata_sha and record["file_count"] == str(expected_file_count) and record["expected"] in {"absent", baseline_manifest} and re.fullmatch(r"[0-9a-f]{48}", record["publication_run_id"] or "")]
        publication_run_ids = {record["publication_run_id"] for record in matching}
        if len(publication_run_ids) != 1:
            raise PublisherError("server QGA readback did not identify exactly one new publication history for this attempt")
        phase_records: dict[str, Any] = {}
        for publication_run_id in publication_run_ids:
            current = [record for record in matching if record["publication_run_id"] == publication_run_id]
            phases = [record["phase"] for record in current]
            required = ["prepared", "committing", "committed", "finalizing", "finalized"]
            positions = [phases.index(phase) for phase in required if phase in phases]
            if len(positions) == len(required) and positions == sorted(positions):
                phase_by_name = {record["phase"]: record for record in current}
                phase_records = {
                    "prepare": {"passed": True, "run_id": run_id, "origin": "guest", "transport": "qga", "publication_run_id": publication_run_id, "phase": "prepared", "durable_record": phase_by_name["prepared"]},
                    "commit": {"passed": True, "run_id": run_id, "origin": "guest", "transport": "qga", "publication_run_id": publication_run_id, "phase": "committed", "durable_record": phase_by_name["committed"]},
                    "finalize": {"passed": True, "run_id": run_id, "origin": "guest", "transport": "qga", "publication_run_id": publication_run_id, "phase": "finalized", "durable_record": phase_by_name["finalized"]},
                }
                break
        if set(phase_records) != {"prepare", "commit", "finalize"}:
            raise PublisherError("server QGA readback lacks an ordered durable prepare/commit/finalize publication history")
        archive_root = self.controller.root / "exports" / run_id / "publication" / nonce / "raw"
        archive_root.mkdir(parents=True, exist_ok=True)
        client_binding = {"transport": "hyperv-powershell-direct", "origin": "guest", "run_id": run_id, "case_id": case_id, "attempt_nonce": nonce, "vm_id": self._child_record.get("vm_id"), "raw": self._client_raw}
        server_binding = {"transport": "qga", "origin": "guest", "run_id": run_id, "case_id": case_id, "attempt_nonce": nonce, "server_uuid": server.get("uuid"), "qga_socket": server.get("qga_socket"), "manifest_sha256": manifest_sha, "metadata_sha256": metadata_sha, "attempt_marker": attempt_marker, "raw": server_raw}
        raw_values = {"client": client_binding, "server": server_binding}
        raw_sources: dict[str, Any] = {}
        for label, value in raw_values.items():
            data = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
            destination = archive_root / f"{label}.json"
            immutable_bytes_dump(destination, data)
            digest, size = sha256_file(destination)
            raw_sources[label] = {"origin": "guest", "archive_path": str(destination), "sha256": digest, "size": size}
        return {"passed": True, "transport": "qga", "attempt_nonce": nonce, "http_readback": {"manifest_sha256": manifest_sha, "manifest_bytes": len(manifest_bytes), "artifacts": observed}, "phase_receipts": phase_records, "raw_sources": raw_sources, "server_raw": server_raw, "case_id": case_id}

    @staticmethod
    def _planned_publish_metadata(run: Mapping[str, Any], payload: Mapping[str, Any]) -> tuple[str, int]:
        # Exact mirror of the shipped C++ producer (selfHostedUpdateBootstrapper.cpp
        # loadPayload -> publishNow).  The signed payload's URL is validated and
        # decoded to the same local relative path that the client uploads and
        # enumerates in publish.meta; the raw signed URL is not wire metadata.
        if not isinstance(run, Mapping) or not isinstance(payload, Mapping):
            raise PublisherError("publication metadata inputs are not mappings")

        def canonical_sha(value: Any) -> bool:
            return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None

        def canonical_decimal(value: Any) -> bool:
            if not isinstance(value, str):
                return False
            return re.fullmatch(r"0|[1-9][0-9]*", value) is not None

        def canonical_version(value: Any) -> bool:
            if not isinstance(value, str):
                return False
            parts = value.split(".")
            return (len(parts) == 4
                    and all(len(part) <= 10 and canonical_decimal(part) and int(part) <= 2147483647
                            for part in parts))

        def strict_url_path(value: Any) -> str:
            # QUrl(..., QUrl::StrictMode).path(QUrl::FullyDecoded): reject the
            # characters/URL forms StrictMode rejects, then decode UTF-8 escapes.
            if not isinstance(value, str) or not value:
                raise PublisherError("publication metadata URL is missing")
            if value.startswith("/") or value.startswith("\\") or value.startswith("//"):
                raise PublisherError("publication metadata URL is absolute or has an authority")
            if re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", value):
                raise PublisherError("publication metadata URL has a scheme")
            if "?" in value or "#" in value:
                raise PublisherError("publication metadata URL has a query or fragment")
            if any(ch in value for ch in '"<>^`{|}\\'):
                raise PublisherError("publication metadata URL has a StrictMode-invalid character")
            if any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in value):
                raise PublisherError("publication metadata URL has whitespace or a control character")
            if re.search(r"%(?![0-9A-Fa-f]{2})", value):
                raise PublisherError("publication metadata URL has an invalid percent escape")
            return urllib.parse.unquote(value, encoding="utf-8", errors="replace")

        def valid_filename(value: str) -> bool:
            if value in {"", ".", ".."} or ":" in value or "\\" in value or "/" in value:
                return False
            return not any(ord(ch) <= 0x1F or 0x7F <= ord(ch) <= 0x9F for ch in value)

        def digest_and_size(metadata: Mapping[str, Any], label: str) -> tuple[str, int]:
            digest = metadata.get("sha256")
            if not canonical_sha(digest):
                raise PublisherError(f"publication metadata has an invalid sha256 for {label}")
            size = metadata.get("size")
            if type(size) is not int or size <= 0 or size > 9223372036854775807:
                raise PublisherError(f"publication metadata has an invalid size for {label}")
            return digest, size

        def artifact_record(metadata: Mapping[str, Any], label: str) -> tuple[str, str, int]:
            digest, size = digest_and_size(metadata, label)
            segments = strict_url_path(metadata.get("url")).split("/")
            if (len(segments) != 4 or segments[0] != "files" or segments[1] != "artifacts"
                    or segments[2] != digest):
                raise PublisherError(f"publication metadata has an invalid artifact path for {label}")
            if not valid_filename(segments[3]):
                raise PublisherError(f"publication metadata has an invalid artifact name for {label}")
            relative = f"files/artifacts/{digest}/{segments[3]}"
            if len(relative.encode("utf-8")) > 1024:
                raise PublisherError(f"publication metadata path is too long for {label}")
            return relative, digest, size

        def rollback_record(metadata: Mapping[str, Any], generation: str,
                            rollback_version: str, label: str) -> tuple[str, str, int]:
            digest, size = digest_and_size(metadata, label)
            segments = strict_url_path(metadata.get("url")).split("/")
            if (len(segments) != 5 or segments[0] != "files" or segments[1] != "rollback"
                    or segments[2] != generation or not canonical_decimal(segments[2])
                    or segments[3] != rollback_version or not canonical_version(segments[3])):
                raise PublisherError(f"publication metadata has an invalid rollback path for {label}")
            if not valid_filename(segments[4]):
                raise PublisherError(f"publication metadata has an invalid rollback name for {label}")
            relative = f"files/rollback/{segments[2]}/{segments[3]}/{segments[4]}"
            if len(relative.encode("utf-8")) > 1024:
                raise PublisherError(f"publication metadata path is too long for {label}")
            return relative, digest, size

        def sorted_keys(mapping: Mapping[str, Any]) -> list[str]:
            if any(not isinstance(key, str) for key in mapping):
                raise PublisherError("publication metadata contains a non-string platform key")
            # QJsonObject iterates keys in UTF-16 code-unit order, independent of
            # the JSON source order.
            return sorted(mapping, key=lambda key: key.encode("utf-16-be", "surrogatepass"))

        manifest = run.get("manifest")
        if not isinstance(manifest, Mapping) or not canonical_sha(manifest.get("sha256")):
            raise PublisherError("publication metadata has no canonical manifest sha256")
        manifest_sha = manifest["sha256"]

        schema = payload.get("schema")
        if type(schema) is not int or schema not in {1, 2}:
            raise PublisherError("publication metadata has an unsupported payload schema")
        version = payload.get("version")
        if not canonical_version(version):
            raise PublisherError("publication metadata has a non-canonical payload version")
        if "candidate_version" in run and run.get("candidate_version") != version:
            raise PublisherError("publication metadata candidate version differs from the signed payload")

        policy = payload.get("releasePolicy")
        if schema == 1:
            generation = "0"
        else:
            if not isinstance(policy, Mapping) or policy.get("schema") != 2:
                raise PublisherError("publication metadata schema-2 policy is invalid")
            raw_generation = policy.get("generation")
            if type(raw_generation) is not int or not (1 <= raw_generation <= 9007199254740991):
                raise PublisherError("publication metadata schema-2 generation is invalid")
            generation = str(raw_generation)

        platforms = payload.get("platforms")
        if not isinstance(platforms, Mapping) or not platforms:
            raise PublisherError("publication metadata has no signed platforms")
        records: list[tuple[str, str, str, int]] = []
        seen_paths: set[str] = set()
        for platform in sorted_keys(platforms):
            metadata = platforms[platform]
            if not isinstance(metadata, Mapping) or not metadata:
                raise PublisherError(f"publication metadata platform entry is invalid: {platform}")
            if "headless" in platform.lower() and platform != "linux-headless-x64":
                raise PublisherError(f"publication metadata platform entry is non-canonical: {platform}")
            if platform == "linux-headless-x64":
                if "openExternal" in metadata and type(metadata["openExternal"]) is not bool:
                    raise PublisherError("publication metadata headless openExternal is invalid")
                if metadata.get("openExternal") is True:
                    raise PublisherError("publication metadata headless platform cannot be external")
            if metadata.get("openExternal") is True:
                continue
            relative, digest, size = artifact_record(metadata, platform)
            if relative in seen_paths:
                raise PublisherError(f"publication metadata repeats an artifact path: {relative}")
            seen_paths.add(relative)
            records.append(("A", relative, digest, size))

        provisioning_present = "headlessProvisioning" in payload
        provisioning = payload.get("headlessProvisioning")
        if provisioning_present:
            if not isinstance(provisioning, Mapping) or not provisioning:
                raise PublisherError("publication metadata provisioning entry is invalid")
        if ("linux-headless-x64" in platforms) != provisioning_present:
            raise PublisherError("publication metadata does not bind the headless platform to provisioning")
        if provisioning_present:
            relative, digest, size = artifact_record(provisioning, "headlessProvisioning")
            if relative in seen_paths:
                raise PublisherError(f"publication metadata repeats an artifact path: {relative}")
            seen_paths.add(relative)
            records.append(("A", relative, digest, size))

        if isinstance(policy, Mapping) and "rollback" in policy:
            if schema != 2:
                raise PublisherError("publication metadata schema-1 payload has a rollback policy")
            rollback = policy.get("rollback")
            if not isinstance(rollback, Mapping) or not rollback:
                raise PublisherError("publication metadata rollback policy is invalid")
            rollback_version = rollback.get("version")
            if not canonical_version(rollback_version) or rollback_version != policy.get("previousVersion"):
                raise PublisherError("publication metadata rollback version is invalid")
            rollback_platforms = rollback.get("platforms")
            if not isinstance(rollback_platforms, Mapping) or not rollback_platforms:
                raise PublisherError("publication metadata rollback platforms are invalid")
            for platform in sorted_keys(rollback_platforms):
                metadata = rollback_platforms[platform]
                if not isinstance(metadata, Mapping) or not metadata:
                    raise PublisherError(f"publication metadata rollback entry is invalid: {platform}")
                if "headless" in platform.lower() and platform != "linux-headless-x64":
                    raise PublisherError(f"publication metadata rollback entry is non-canonical: {platform}")
                if "openExternal" in metadata and type(metadata["openExternal"]) is not bool:
                    raise PublisherError("publication metadata rollback openExternal is invalid")
                if metadata.get("openExternal") is True:
                    raise PublisherError("publication metadata rollback artifact cannot be external")
                relative, digest, size = rollback_record(
                    metadata, generation, rollback_version, "rollback:" + platform)
                if relative in seen_paths:
                    raise PublisherError(f"publication metadata repeats an artifact path: {relative}")
                seen_paths.add(relative)
                records.append(("R", relative, digest, size))

        if not records or len(records) > 64:
            raise PublisherError("publication metadata has an unsupported file count")
        lines = ["amnezia-bundled-publish-v1", manifest_sha, version, str(schema), generation,
                 str(len(records))]
        metadata_lines = ["\t".join(lines)]
        metadata_lines.extend("\t".join((kind, relative, digest, str(size)))
                              for kind, relative, digest, size in records)
        metadata = ("\n".join(metadata_lines) + "\n").encode("utf-8")
        if len(metadata) > 64 * 1024:
            raise PublisherError("publication metadata exceeds the supported size")
        return hashlib.sha256(metadata).hexdigest(), len(records)

    def cleanup(self, run_id: str, case_id: str) -> Mapping[str, Any]:
        result = {"child_reset": False, "server_reset": False, "relays_stopped": False, "relay_registry_unregistered": False, "ephemeral_key_removed": False, "host_network_mutation": False}
        errors: list[str] = []
        if self._relays_started:
            try:
                relay, supervisor, task = self._relay_helper_paths()
                stopped = self.controller.hyperv_call("relays-stop", run_id=run_id, CaseId=case_id, credential=True, AttemptNonce=self._attempt_nonce, RelaySupervisorPath=windows_path_for_wsl(supervisor), RelayGuestTaskPath=windows_path_for_wsl(task), RelayHelperPath=windows_path_for_wsl(relay), RelayHelperSha256=self.RELAY_HELPER_SHA256, RelayGuestTaskSha256=sha256_file(task)[0])
                result["relays_stopped"] = stopped.get("relays_stopped") is True
                result["relay_registry_unregistered"] = stopped.get("relay_registry_unregistered") is True
                if not result["relays_stopped"] or not result["relay_registry_unregistered"]:
                    errors.append("relay cleanup did not confirm all guest/host resources stopped")
            except Exception as exc:
                errors.append(f"relays: {exc}")
        else:
            result["relays_stopped"] = True
            result["relay_registry_unregistered"] = True
        if self._key is None or "public" not in self._key:
            result["ephemeral_key_removed"] = True
        if self._key is not None and "public" in self._key:
            try:
                qga = QgaClient(Path(str((self.controller.get_run(run_id).get("server_observation") or {}).get("qga_socket") or (self.controller.get_run(run_id).get("profiles", {}).get("server-router", {}).get("vm") or {}).get("qga_socket"))), timeout=10)
                if not qga.sync():
                    raise PublisherError("server QGA unavailable while removing ephemeral key")
                qga.write_file("/tmp/amnezia-release-lab-publisher.pub", self._key["public"].encode("utf-8"))
                qga.guest_exec_wait("/usr/bin/bash", ["-lc", "set -eu; touch /home/lab/.ssh/authorized_keys; grep -vxF \"$(cat /tmp/amnezia-release-lab-publisher.pub)\" /home/lab/.ssh/authorized_keys > /tmp/amnezia-release-lab-authorized_keys || true; install -o lab -g lab -m 0600 /tmp/amnezia-release-lab-authorized_keys /home/lab/.ssh/authorized_keys; rm -f /tmp/amnezia-release-lab-publisher.pub /tmp/amnezia-release-lab-authorized_keys"], timeout=30)
            except Exception as exc:
                errors.append(f"ephemeral guest key: {exc}")
        if self._child_started:
            try:
                reset = self.controller.hyperv_call("reset", run_id=run_id, CaseId=case_id, credential=False)
                if reset.get("removed_child") is not True or reset.get("parent_sha256_before") != reset.get("parent_sha256_after"):
                    raise PublisherError("exact Hyper-V publisher case reset did not confirm removal and unchanged parent")
                self.controller._record_hyperv_case(run_id, "windows-x64", case_id, "reset", reset_result=reset)
                run = self.controller.get_run(run_id)
                run["profiles"]["windows-x64"].update(status="reset", vm=None)
                state = self.controller.load_state(); state["runs"][run_id] = run; self.controller.save_state(state)
                result["child_reset"] = True
            except Exception as exc:
                errors.append(f"child reset: {exc}")
        else:
            result["child_reset"] = True
        if self._server_started:
            try:
                self.controller.reset(run_id, "server-router"); result["server_reset"] = True
            except Exception as exc:
                errors.append(f"server reset: {exc}")
        else:
            result["server_reset"] = True
        if self._key is not None:
            try:
                private = Path(self._key["private_path"])
                for path in (private, Path(str(private) + ".pub")):
                    if path.exists(): path.unlink()
                result["ephemeral_key_removed"] = not private.exists() and not Path(str(private) + ".pub").exists()
                if not result["ephemeral_key_removed"]: errors.append("ephemeral key scratch remained")
            except Exception as exc:
                errors.append(f"ephemeral key scratch: {exc}")
        if errors:
            detail = "publication cleanup failed: " + "; ".join(errors)
            try:
                state = self.controller.load_state(); state["runs"][run_id].setdefault("publication_cleanup_errors", []).extend(errors); self.controller.save_state(state)
            except Exception as state_exc:
                detail += f"; cleanup error persistence failed: {state_exc}"
            raise PublisherError(detail)
        return result


class ControllerPublisher:
    def __init__(self, controller: LabController, ops: PublisherOps):
        self.controller = controller
        self.ops = ops

    def run(self, run_id: str) -> dict[str, Any]:
        session = getattr(self.controller, "mutation_session", None)
        lock_context = session(f"publish-validation:{run_id}") if session is not None else contextlib.nullcontext()
        with lock_context:
            return self._run_locked(run_id)

    def _run_locked(self, run_id: str) -> dict[str, Any]:
        run = self.controller.get_run(run_id)
        if run.get("lane") not in {"release", "publisher-diagnostic"}:
            raise PublisherError("publication controller requires a release or publisher-diagnostic run")
        artifact = run.get("outer_artifact")
        manifest = run.get("manifest")
        if not isinstance(artifact, Mapping) or not isinstance(manifest, Mapping):
            raise PublisherError("publication run lacks planned outer artifact or manifest")
        case_id = "publisher-clean"
        previous_attempt = run.get("publication_attempt")
        if isinstance(previous_attempt, Mapping) and previous_attempt.get("state") not in {"completed-cleaned", "failed-cleaned"}:
            recover = getattr(self.ops, "recover_attempt", None)
            if recover is None:
                raise PublisherError("an unfinished publication attempt exists but its recovery adapter is unavailable")
            try:
                recovery = recover(run_id, previous_attempt)
            except Exception as exc:
                _merge_attempt(self.controller, run_id, state="recovery-failed", recovery_error=str(exc))
                raise PublisherError(f"owned publication attempt recovery failed: {exc}") from exc
            _merge_attempt(self.controller, run_id, state="recovered-cleaned", recovery=recovery)
        nonce = secrets.token_hex(24)
        attempt: dict[str, Any] = {
            "schema": 1,
            "controller_created": True,
            "run_id": run_id,
            "case_id": case_id,
            "attempt_nonce": nonce,
            "state": "active",
            "phase": "start-server",
            "resources": {
                "server": {"intent": False},
                "child": {"intent": False},
                "relays": {"intent": False, "attempt_nonce": nonce},
                "key": {"intent": False, "attempt_nonce": nonce},
            },
        }
        _persist_attempt(self.controller, run_id, attempt)
        # Diagnostic pointers belong to exactly one nonce; never carry a
        # previous attempt's preserved evidence into this attempt.
        self.ops._pre_http_diagnostics = None
        server: Mapping[str, Any] | None = None
        child: Mapping[str, Any] | None = None
        ack: dict[str, Any] = {}
        raw: dict[str, Any] = {}
        cleanup: Mapping[str, Any] = {}
        pending: tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]] | None = None
        result: dict[str, Any] | None = None
        primary: BaseException | None = None
        cleanup_error: Exception | None = None
        phase = "start-server"
        try:
            phase = "start-server"
            attempt["phase"] = phase
            attempt["resources"]["server"]["intent"] = True
            _persist_attempt(self.controller, run_id, attempt)
            server = self.ops.start_server(run_id)
            attempt["resources"]["server"].update(record=dict(server))
            _persist_attempt(self.controller, run_id, attempt)
            phase = "start-child"
            attempt["phase"] = phase
            attempt["resources"]["child"]["intent"] = True
            _persist_attempt(self.controller, run_id, attempt)
            child = self.ops.start_child(run_id, case_id)
            attempt["resources"]["child"].update(record=dict(child))
            _persist_attempt(self.controller, run_id, attempt)
            phase = "stage-outer"
            attempt["phase"] = phase
            _persist_attempt(self.controller, run_id, attempt)
            staged = self.ops.stage_outer(run_id, case_id, artifact)
            if staged.get("sha256") not in (None, artifact.get("sha256")):
                raise PublisherError("staged outer artifact differs from planned bytes")
            phase = "reinstall"
            attempt["phase"] = phase
            _persist_attempt(self.controller, run_id, attempt)
            reinstall = self.ops.run_outer_reinstall(run_id, case_id, artifact)
            if reinstall.get("passed") is not True:
                raise PublisherError(f"owned Windows guest reinstall did not pass: {reinstall.get('error', 'guest assertion failed')}")
            phase = "start-relays"
            attempt["phase"] = phase
            attempt["resources"]["relays"]["intent"] = True
            _persist_attempt(self.controller, run_id, attempt)
            relays = self.ops.start_relays(run_id, case_id, child, server, nonce)
            attempt["resources"]["relays"].update(record=dict(relays))
            _persist_attempt(self.controller, run_id, attempt)
            phase = "seed-profile"
            attempt["phase"] = phase
            attempt["resources"]["key"]["intent"] = True
            _persist_attempt(self.controller, run_id, attempt)
            self.ops.seed_lab_profile(run_id, case_id, server, nonce)
            phase = "publish"
            attempt["phase"] = phase
            _persist_attempt(self.controller, run_id, attempt)
            published = self.ops.publish_once(run_id, case_id)
            if published.get("passed") is not True:
                raise PublisherError("guest publisher CLI did not complete successfully")
            phase = "readback"
            attempt["phase"] = phase
            _persist_attempt(self.controller, run_id, attempt)
            readback = self.ops.collect_readback(run_id, case_id, server, nonce)
            diagnostics = getattr(self.ops, "_pre_http_diagnostics", None)
            if isinstance(diagnostics, Mapping) and diagnostics.get("attempt_nonce") == nonce:
                attempt["pre_http_diagnostics"] = dict(diagnostics)
            if readback.get("attempt_nonce") != nonce:
                raise PublisherError("publication readback nonce does not match the durable attempt ledger")
            phase_receipts = readback.get("phase_receipts")
            if not isinstance(phase_receipts, Mapping) or any(
                not isinstance(phase_receipts.get(phase), Mapping)
                or phase_receipts[phase].get("passed") is not True
                for phase in ("prepare", "commit", "finalize")
            ):
                raise PublisherError("server durable publication phase records are incomplete")
            ack = {phase: dict(phase_receipts[phase]) for phase in ("prepare", "commit", "finalize")}
            raw = dict(readback.get("raw_sources") or {})
            pending = (child, server, ack, readback, raw)
        except BaseException as exc:
            primary = exc
            diagnostics = getattr(self.ops, "_pre_http_diagnostics", None)
            if phase in {"publish", "readback"} and server is not None and not (
                    isinstance(diagnostics, Mapping) and diagnostics.get("attempt_nonce") == nonce):
                diagnostic_capture = getattr(self.ops, "_capture_pre_http_diagnostics", None)
                if callable(diagnostic_capture):
                    try:
                        diagnostics = diagnostic_capture(run_id, case_id, server, nonce)
                    except Exception:
                        diagnostics = {"attempt_nonce": nonce, "diagnostic_only": True, "status": "unavailable"}
            if isinstance(diagnostics, Mapping) and diagnostics.get("attempt_nonce") == nonce:
                attempt["pre_http_diagnostics"] = dict(diagnostics)
            capture = getattr(self.controller, "capture_hyperv_failure", None)
            if isinstance(exc, Exception) and child is not None and capture is not None:
                try:
                    capture(run_id, "windows-x64", case_id, phase, artifact, exc)
                except Exception as capture_exc:
                    if hasattr(primary, "add_note"):
                        primary.add_note(f"failure capture failed: {capture_exc}")
            raise
        finally:
            try:
                attempt["cleanup_phase"] = "started"
                _persist_attempt(self.controller, run_id, attempt)
            except Exception as attempt_phase_error:
                if primary is not None and hasattr(primary, "add_note"):
                    primary.add_note(f"cleanup phase ledger persistence failed: {attempt_phase_error}")
            try:
                cleanup = self.ops.cleanup(run_id, case_id)
            except Exception as cleanup_exc:
                cleanup_error = cleanup_exc
                persistence_error = None
                try:
                    state = self.controller.load_state(); state["runs"][run_id].setdefault("publication_cleanup_errors", []).append(str(cleanup_exc)); self.controller.save_state(state)
                except Exception as state_exc:
                    persistence_error = state_exc
                if persistence_error is not None and hasattr(primary, "add_note"):
                    primary.add_note(f"cleanup error persistence failed: {persistence_error}")
                if primary is not None and hasattr(primary, "add_note"):
                    primary.add_note(f"cleanup failure: {cleanup_exc}")
            try:
                required_cleanup = ("child_reset", "server_reset", "relays_stopped", "relay_registry_unregistered", "ephemeral_key_removed")
                cleanup_ok = isinstance(cleanup, Mapping) and all(cleanup.get(key) is True for key in required_cleanup)
                attempt["state"] = "cleanup-failed" if cleanup_error is not None or not cleanup_ok else ("failed-cleaned" if primary is not None else "completed-cleaned")
                attempt["cleanup"] = dict(cleanup) if isinstance(cleanup, Mapping) else {}
                if cleanup_error is not None:
                    attempt["cleanup_error"] = str(cleanup_error)
                _persist_attempt(self.controller, run_id, attempt)
            except Exception as attempt_persistence_error:
                if primary is not None and hasattr(primary, "add_note"):
                    primary.add_note(f"publication attempt ledger persistence failed: {attempt_persistence_error}")
                elif cleanup_error is not None:
                    cleanup_error = PublisherError(f"publication attempt ledger persistence failed: {attempt_persistence_error}")
            if primary is None and cleanup_error is None and not (isinstance(cleanup, Mapping) and all(cleanup.get(key) is True for key in ("child_reset", "server_reset", "relays_stopped", "relay_registry_unregistered", "ephemeral_key_removed"))):
                raise PublisherError("publication cleanup returned incomplete ownership proof")
            if cleanup_error is not None and primary is None:
                raise PublisherError(f"publication cleanup failed: {cleanup_error}") from cleanup_error
            if primary is not None:
                try:
                    failed_run = self.controller.get_run(run_id)
                    failed_run["publication_failure"] = {"controller_created": True, "run_id": run_id, "case_id": case_id, "error": str(primary), "cleanup": dict(cleanup)}
                    state = self.controller.load_state(); state["runs"][run_id] = failed_run; self.controller.save_state(state)
                except Exception as failure_persistence_error:
                    if hasattr(primary, "add_note"):
                        primary.add_note(f"publication failure persistence failed: {failure_persistence_error}")
            if primary is None and pending is not None:
                p_child, p_server, p_ack, p_readback, p_raw = pending
                final_run = self.controller.get_run(run_id)
                evidence = self._evidence(final_run, run_id, case_id, artifact, manifest, p_child, p_server, p_ack, p_readback, p_raw, cleanup)
                validate_publication_evidence(evidence, final_run, self.controller.root)
                final_run["publication_evidence"] = evidence
                state = self.controller.load_state(); state["runs"][run_id] = final_run; self.controller.save_state(state)
                result = evidence
        if result is None:
            raise PublisherError("publication flow ended without evidence")
        return result

    def _evidence(self, run: Mapping[str, Any], run_id: str, case_id: str, artifact: Mapping[str, Any], manifest: Mapping[str, Any], child: Mapping[str, Any], server: Mapping[str, Any], ack: Mapping[str, Any], readback: Mapping[str, Any], raw: Mapping[str, Any], cleanup: Mapping[str, Any]) -> dict[str, Any]:
        nonce = str(readback.get("attempt_nonce", ""))
        if not re.fullmatch(r"[0-9a-f]{48}", nonce):
            raise PublisherError("publication evidence archive requires the exact attempt nonce")
        archive_dir = self.controller.root / "exports" / run_id / "publication" / nonce
        archive_dir.mkdir(parents=True, exist_ok=True)
        evidence = {"schema": 1, "controller_created": True, "live": True, "publisher_diagnostic": run.get("lane") == "publisher-diagnostic", "release_passed": False, "run_id": run_id, "case_id": case_id, "attempt_nonce": readback.get("attempt_nonce"), "outer_artifact_sha256": artifact["sha256"], "manifest_sha256": manifest["sha256"], "windows_child": dict(child), "server": dict(server), "client_acknowledgements": dict(ack), "http_readback": dict(readback.get("http_readback") or {}), "raw_sources": dict(raw), "cleanup": dict(cleanup), "archive": {"origin": "controller", "immutable": True}}
        core_sha = hashlib.sha256(json.dumps({key: value for key, value in evidence.items() if key != "archive"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        archive_path = archive_dir / "evidence.json"
        immutable_json_dump(archive_path, {"run_id": run_id, "controller_created": True, "evidence_sha256": core_sha})
        archive_sha, _ = sha256_file(archive_path)
        evidence["archive"].update(path=str(archive_path), sha256=archive_sha)
        return evidence
