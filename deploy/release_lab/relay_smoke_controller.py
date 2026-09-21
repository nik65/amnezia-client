"""Fail-closed controller glue for the Windows AF_HYPERV relay smoke.

This module only builds and validates an owned smoke plan.  Runtime execution
is deliberately delegated to the Windows host adapter and guest-owned task;
the release controller must never infer a guest result from host probes.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping


SSH_SERVICE_GUID = "{5f2f2a1e-9c3a-4fa9-8f4d-31e9960d7c31}"
HTTP_SERVICE_GUID = "{6f3bdc8b-7b21-4df1-a3f5-6e4aaecf8f42}"
SSH_RELAY_PORT = 22222
HTTP_RELAY_PORT = 17865
LINUX_SSH_PORT = 22
HTTP_PATH = "/__lab__/request-log"
STOP_EVENT_PREFIX = "Local\\AmneziaReleaseLabRelayStop_"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")


class RelaySmokeError(RuntimeError):
    pass


def _read(path: Path, label: str) -> Mapping[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RelaySmokeError(f"{label} is missing or not a regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RelaySmokeError(f"{label} is invalid: {exc}") from exc
    if not isinstance(value, Mapping):
        raise RelaySmokeError(f"{label} is not an object")
    return value


def _owned_path(path: Path, run_root: Path, label: str) -> Path:
    resolved = path.resolve()
    root = run_root.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise RelaySmokeError(f"{label} escaped owned run root") from exc
    return resolved


def build_plan(*, run_id: str, case_id: str, vm_id: str, child_record: Path, server_record: Path, supervisor: Path, relay: Path, run_root: Path) -> dict[str, Any]:
    if not _ID.fullmatch(run_id) or not _ID.fullmatch(case_id):
        raise RelaySmokeError("run_id/case_id are not bounded owned identifiers")
    vm_id = vm_id.lower()
    if not re.fullmatch(r"\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}", vm_id) or vm_id == "{00000000-0000-0000-0000-000000000000}" or vm_id == "{ffffffff-ffff-ffff-ffff-ffffffffffff}":
        raise RelaySmokeError("vm_id is not an exact non-wildcard GUID")
    child_path = _owned_path(child_record, run_root, "child record")
    server_path = _owned_path(server_record, run_root, "server record")
    child = _read(child_path, "child record")
    server = _read(server_path, "server record")
    for label, record in (("child", child), ("server", server)):
        if str(record.get("run_id")) != run_id:
            raise RelaySmokeError(f"{label} run identity mismatch")
    for key in ("case_id", "vm_id", "parent_sha256", "qmp_socket", "qga_socket", "process_pid", "process_uuid", "marker"):
        if key not in child:
            raise RelaySmokeError(f"child record lacks {key}")
    if str(child["case_id"]) != case_id or str(child["vm_id"]).lower() != vm_id or not re.fullmatch(r"[0-9a-fA-F]{64}", str(child["parent_sha256"])):
        raise RelaySmokeError("child record identity/hash mismatch")
    if str(child["marker"]) != f"amnezia-release-lab:{run_id}:windows-x64" or int(child["process_pid"]) <= 0 or not re.fullmatch(r"[0-9a-fA-F-]{36}", str(child["process_uuid"])):
        raise RelaySmokeError("child marker/process binding is incomplete")
    if str(server.get("profile")) != "server-router" or str(server.get("host_bind")) != "127.0.0.1" or int(server.get("ssh_guest_port", -1)) != LINUX_SSH_PORT or int(server.get("http_guest_port", -1)) != HTTP_RELAY_PORT:
        raise RelaySmokeError("server-router fixed endpoint/readback mismatch")
    return {
        "schema": 1,
        "action": "relay-smoke-plan",
        "run_id": run_id,
        "case_id": case_id,
        "vm_id": vm_id,
        "parent_sha256": str(child["parent_sha256"]).lower(),
        "child": {"qmp_socket": str(child["qmp_socket"]), "qga_socket": str(child["qga_socket"]), "process_pid": int(child["process_pid"]), "process_uuid": str(child["process_uuid"]), "marker": str(child["marker"])},
        "server": {"qmp_socket": str(server["qmp_socket"]), "qga_socket": str(server["qga_socket"]), "host_bind": "127.0.0.1", "ssh_guest_port": LINUX_SSH_PORT, "http_guest_port": HTTP_RELAY_PORT},
        "relay": {"supervisor": str(supervisor), "helper": str(relay), "stop_event": f"{STOP_EVENT_PREFIX}{run_id}_{case_id}", "ssh": {"service_guid": SSH_SERVICE_GUID, "host_port": SSH_RELAY_PORT, "guest_port": SSH_RELAY_PORT}, "http": {"service_guid": HTTP_SERVICE_GUID, "host_port": HTTP_RELAY_PORT, "guest_port": HTTP_RELAY_PORT, "path": HTTP_PATH}},
        "host_network_mutation": False,
        "live": False,
    }
