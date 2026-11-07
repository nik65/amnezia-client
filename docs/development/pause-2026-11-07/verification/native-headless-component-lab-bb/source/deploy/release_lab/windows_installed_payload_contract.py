"""Read-only installed Windows payload evidence, separate from installer receipts."""
import hashlib
import json
import re
from pathlib import Path

PATHS = {"app": r"C:\Program Files\AmneziaVPN\AmneziaVPN.exe",
         "service": r"C:\Program Files\AmneziaVPN\AmneziaVPN-service.exe"}


def strict_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate payload plan key")
            out[key] = value
        return out
    def invalid(_):
        raise ValueError("non-finite payload JSON")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def checked_plan(path, sha256, artifacts):
    path = Path(path)
    raw = path.read_bytes()
    if path.is_symlink() or hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError("installed payload plan changed")
    value = strict_json(raw)
    if set(value) != {"schema", "version", "artifacts"} or type(value["schema"]) is not int or value["schema"] != 1 or value["version"] != "5.0.3.11":
        raise ValueError("installed payload plan schema/version invalid")
    if set(value["artifacts"]) != {a["sha256"] for a in artifacts}:
        raise ValueError("installed payload plan does not bind exact baseline/candidate artifacts")
    for artifact in artifacts:
        record = value["artifacts"][artifact["sha256"]]
        if set(record) != {"artifact_size", "files"} or type(record["artifact_size"]) is not int or record["artifact_size"] != artifact["size"] or set(record["files"]) != set(PATHS):
            raise ValueError("installed payload plan artifact/file set invalid")
        for file in record["files"].values():
            if set(file) != {"sha256", "size"} or not isinstance(file["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", file["sha256"]) or type(file["size"]) is not int or file["size"] <= 0:
                raise ValueError("installed payload plan file identity invalid")
    return value


def validate(value, *, run_id, case_id, vm_id, parent_sha256, artifact, role, version, nonce, files):
    expected = dict(action="installed-payload", run_id=run_id, case_id=case_id, vm_id=vm_id,
        parent_sha256=parent_sha256, artifact_sha256=artifact["sha256"], artifact_size=artifact["size"],
        artifact_role=role, version=version, nonce=nonce, transport="hyperv-powershell-direct", origin="guest",
        injected=False, read_only=True)
    if any(type(value.get(k)) is not type(v) or value.get(k) != v for k,v in expected.items()):
        raise ValueError("installed payload guest binding differs")
    observed = value.get("files")
    if not isinstance(observed, dict) or set(observed) != set(PATHS):
        raise ValueError("installed payload file set differs")
    for name, path in PATHS.items():
        file = observed[name]
        if (file.get("path") != path or file.get("sha256") != files[name]["sha256"]
                or type(file.get("size")) is not int or file["size"] != files[name]["size"]
                or file.get("file_version") != version or file.get("product_version") != version):
            raise ValueError("installed payload bytes/version differ")
    service = value.get("service") or {}
    if (service.get("name") != "AmneziaVPN-service" or service.get("state") != "Running"
            or service.get("image_path") != PATHS["service"]
            or any(type(service.get(k)) is not int or service[k] <= 0 for k in ("pid", "start_ticks"))):
        raise ValueError("installed service process identity absent")
    return value
