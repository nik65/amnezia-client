"""Frozen fixture inputs and diagnostic-only guest receipt validation."""
import hashlib
import json
import re
import secrets
from pathlib import Path

FILES = {"helper": "fixture.exe", "observer": "product_observer.ps1",
         "profile": "profile-template.json", "expected_routes": "expected-routes.json",
         "routes": "routes.json", "config": "config.json", "observer_plan": "observer-plan.json"}


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate fixture JSON key")
            result[key] = value
        return result
    def invalid_constant(_):
        raise ValueError("non-finite fixture JSON number")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)


def checked_manifest(path, expected_sha256, artifact_sha256):
    path = Path(path)
    raw = path.read_bytes()
    if path.is_symlink() or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("fixture manifest bytes changed")
    value = strict_json(raw)
    if (set(value) != {"schema", "candidate_artifact_sha256", "installed_exe_sha256", "files"}
            or type(value["schema"]) is not int or value["schema"] != 1 or value["candidate_artifact_sha256"] != artifact_sha256
            or not re.fullmatch(r"[0-9a-f]{64}", value["installed_exe_sha256"])
            or set(value["files"]) != set(FILES)):
        raise ValueError("fixture closure or candidate identity mismatch")
    for record in value["files"].values():
        source = Path(record["path"])
        if set(record) != {"path", "sha256", "size"} or not source.is_absolute() or source.is_symlink() or not source.is_file():
            raise ValueError("fixture source path invalid")
        data = source.read_bytes()
        if type(record["size"]) is not int or len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise ValueError("fixture source bytes changed")
    return value


def bind_manifest(value, output, *, run_id, case_id, vm_id, path_mapper=str):
    """Bind frozen private templates after normal create-child; never create a VM."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", run_id) or case_id != "outer-clean" or not re.fullmatch(r"[0-9a-fA-F-]{36}", vm_id):
        raise ValueError("invalid fixture child identity")
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    config = strict_json(Path(value["files"]["config"]["path"]).read_bytes())
    plan = strict_json(Path(value["files"]["observer_plan"]["path"]).read_bytes())
    nonce, token = secrets.token_hex(24), secrets.token_hex(24)
    identity = dict(run_id=run_id, case_id=case_id, vm_id=vm_id, nonce=nonce)
    root = rf"C:\ProgramData\AmneziaLab\runs\{run_id}\windows-x64\{case_id}\netstack-fixture"
    config.update(identity, marker=root.rsplit("\\", 1)[0] + r"\run-marker.txt", routes=root + r"\routes.json", routes_sha256=value["files"]["routes"]["sha256"])
    plan.update(identity, task_token=token, installed_exe_sha256=value["installed_exe_sha256"])
    plan["files"] = {FILES[k]: value["files"][k]["sha256"] for k in ("profile", "expected_routes", "routes")}
    bound = dict(value, files={k: dict(v) for k, v in value["files"].items()})
    for key, document in (("config", config), ("observer_plan", plan)):
        path = output / FILES[key]
        raw = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        with path.open("xb") as stream:
            stream.write(raw)
        bound["files"][key] = dict(path=str(path), size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    for record in bound["files"].values():
        record["path"] = path_mapper(Path(record["path"]))
    raw = json.dumps(bound, sort_keys=True, separators=(",", ":")).encode()
    path = output / "manifest.json"
    with path.open("xb") as stream:
        stream.write(raw)
    return path, hashlib.sha256(raw).hexdigest(), nonce, token


def validate_observed(value, *, run_id, case_id, vm_id, nonce, task_token, parent_sha256, artifact_sha256,
                      manifest_sha256, helper_sha256, routes_sha256, expected_route_shape="synthetic-windows-dataplane-v1", expected_route_count=1266):
    expected = {"action": "netstack-fixture", "run_id": run_id, "case_id": case_id,
                "vm_id": vm_id, "nonce": nonce, "task_token": task_token,
                "parent_sha256": parent_sha256, "candidate_artifact_sha256": artifact_sha256,
                "manifest_sha256": manifest_sha256,
                "transport": "hyperv-powershell-direct", "origin": "guest", "injected": False,
                "production_journal": False, "migration_pass": False, "runtime_pass": False}
    if any(type(value.get(k)) is not type(v) or value.get(k) != v for k, v in expected.items()):
        raise ValueError("fixture guest provenance mismatch")
    cleanup = value.get("cleanup")
    cleanup_keys = {"helper_process_absent", "helper_udp_ports_absent",
                    "observer_task_removed", "observer_process_absent"}
    if not isinstance(cleanup, dict) or set(cleanup) != cleanup_keys or any(cleanup[k] is not True for k in cleanup_keys):
        raise ValueError("fixture cleanup incomplete")
    lease, terminal = value.get("lease") or {}, value.get("terminal") or {}
    for record in (lease, terminal):
        identity = dict(run_id=run_id, case_id=case_id, vm_id=vm_id, nonce=nonce,
                        exe_sha256=helper_sha256, routes_sha256=routes_sha256,
                        production_journal=False, runtime_pass=False)
        if any(type(record.get(k)) is not type(v) or record.get(k) != v for k, v in identity.items()):
            raise ValueError("fixture lease identity mismatch")
        if any(type(record.get(k)) is not int or record[k] <= 0 for k in ("pid", "process_start_unix_ns", "source_udp_port", "target_udp_port")):
            raise ValueError("fixture process/port identity absent")
        if not all(record[k] <= 65535 for k in ("source_udp_port", "target_udp_port")) or record["source_udp_port"] == record["target_udp_port"]:
            raise ValueError("fixture port identity invalid")
    if lease.get("ready") is not True or terminal.get("terminal_state") != "closed_by_owned_process" or any(lease[k] != terminal[k] for k in ("pid", "process_start_unix_ns", "source_udp_port", "target_udp_port")):
        raise ValueError("fixture terminal process differs")
    observation = value.get("observation") or {}
    if (observation.get("run_id") != run_id or observation.get("case_id") != case_id
            or observation.get("vm_id") != vm_id or observation.get("nonce") != nonce
            or observation.get("task_token") != task_token or observation.get("capability_observed") is not True
            or observation.get("production_journal") is not False or observation.get("runtime_pass") is not False
            or observation.get("migration_pass") is not False or observation.get("feed_sha256") != routes_sha256):
        raise ValueError("fixture observer identity mismatch")
    if (observation.get("known_nonce_proved") is not True or observation.get("gui_visible") is not True
            or observation.get("route_shape") != expected_route_shape
            or type(observation.get("fixture_prefix_count")) is not int or observation["fixture_prefix_count"] != expected_route_count
            or expected_route_shape != "synthetic-windows-dataplane-v1"):
        raise ValueError("fixture dataplane evidence absent")
    for key in ("native_before", "native_after"):
        native = observation.get(key) or {}
        for field in ("last_handshake_time_sec", "rx_bytes", "tx_bytes"):
            raw = native.get(field)
            if not isinstance(raw, str) or not raw.isascii() or not raw.isdecimal() or int(raw) <= 0:
                raise ValueError("fixture encrypted traffic evidence absent")
    if any(int(observation["native_after"][field]) < int(observation["native_before"][field]) for field in ("rx_bytes", "tx_bytes")):
        raise ValueError("fixture encrypted counters reset")
    before, after = observation.get("before") or {}, observation.get("after") or {}
    if not before or before != after or not isinstance(before.get("routes"), list):
        raise ValueError("fixture route/process stability evidence absent")
    for name in ("gui", "service", "tunnel"):
        process = before.get(name) or {}
        if any(type(process.get(k)) is not int or process[k] <= 0 for k in ("pid", "start_ticks")) or not isinstance(process.get("exe"), str) or not process["exe"]:
            raise ValueError("fixture product process identity absent")
    return value
