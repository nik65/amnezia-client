"""Linux packaged-GUI AWG scenario controller; all guest effects use lab ownership.

The product installer and installed product remain unchanged. Fixture helpers
have a separate immutable closure and are never release/publication evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import subprocess
import tempfile

from .lab import (LabError, QgaClient, QmpClient, artifact_record, golden_readiness,
                  load_profiles, require_qmp_return, validate_signed_manifest)
from .awg_migration_native import validate_bundle as validate_native_bundle

PROFILE = "linux-x64-gui"
SCHEMA = "amnezia.release-lab.awg-gui.v1"
BUNDLE_SCHEMA = "amnezia.release-lab.awg-gui-bundle.v1"
ASSETS = frozenset(("amneziawg-go", "awg", "awg-quick", "legacy-amneziawg-go", "legacy-awg", "legacy-musl"))
HELPERS = {"native_guest.py": "awg_migration_native_guest.py",
           "guest.py": "awg_migration_gui_guest.py",
           "observer.py": "awg_migration_gui_observer.py",
           "gui_window.py": "guest_helpers/linux_gui_window_evidence.py"}
REQUIRED_PRODUCT = frozenset(("/opt/AmneziaVPN/bin/AmneziaVPN", "/opt/AmneziaVPN/bin/AmneziaVPN-service",
                              "/opt/AmneziaVPN/bin/amneziawg-go"))
SHA = re.compile(r"[0-9a-f]{64}\Z")
RUN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def regular(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise LabError("GUI scenario input must be a regular file: " + path.name)
    # Reject symlink ancestors as well: resolve() alone would hide them.
    if any(parent.is_symlink() for parent in path.parents):
        raise LabError("GUI scenario input has a symlink ancestor")
    return path.read_bytes()


def exclusive_json(path: Path, value: dict) -> None:
    if path.is_symlink() or path.exists() or not path.parent.is_dir() or any(p.is_symlink() for p in path.parents):
        raise LabError("GUI scenario evidence destination is not fresh")
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def compose_bundle(seed: Path, destination: Path, service_source: Path) -> dict:
    """Copy pinned fixture assets only; never copy headless product executables."""
    seed = Path(seed)
    native = validate_native_bundle(seed)
    if native.get("schema") != 2:
        raise LabError("GUI fixture requires pinned official legacy assets")
    destination = Path(destination)
    if destination.exists() or destination.is_symlink() or any(p.is_symlink() for p in destination.parents):
        raise LabError("GUI fixture bundle destination must be new")
    sources = {name: seed / name for name in ASSETS}
    sources.update({name: Path(__file__).parent / relative for name, relative in HELPERS.items()})
    sources["service.py"] = Path(service_source)
    data = {name: regular(path) for name, path in sources.items()}
    destination.mkdir(mode=0o700)
    for name, content in data.items():
        with (destination / name).open("xb") as stream:
            stream.write(content)
    contract = {"schema": BUNDLE_SCHEMA, "files": {name: digest(content) for name, content in data.items()},
                "seedBundleSha256": digest(regular(seed / "bundle.json")),
                "sourceCommit": native["sourceCommit"],
                "goReceipt": native["goReceipt"], "toolsReceipt": native["toolsReceipt"],
                "legacyReceipt": native["legacyReceipt"]}
    exclusive_json(destination / "bundle.json", contract)
    validate_bundle(destination)
    return contract


def validate_bundle(directory: Path) -> dict:
    directory = Path(directory)
    try:
        contract = json.loads(regular(directory / "bundle.json"))
    except (ValueError, UnicodeError) as error:
        raise LabError("GUI fixture bundle is not JSON") from error
    fields = {"schema", "files", "seedBundleSha256", "sourceCommit", "goReceipt", "toolsReceipt", "legacyReceipt"}
    if (not isinstance(contract, dict) or set(contract) != fields or contract["schema"] != BUNDLE_SCHEMA
        or not all(isinstance(contract[key], dict) for key in ("files", "goReceipt", "toolsReceipt", "legacyReceipt"))
        or set(contract["files"]) != ASSETS | set(HELPERS) | {"service.py"}):
        raise LabError("GUI fixture bundle schema or roles")
    if (not isinstance(contract["sourceCommit"], str) or not re.fullmatch(r"[0-9a-f]{40}", contract["sourceCommit"])
        or not isinstance(contract["seedBundleSha256"], str) or not SHA.fullmatch(contract["seedBundleSha256"])):
        raise LabError("GUI fixture seed binding")
    for name, expected in contract["files"].items():
        if not isinstance(expected, str) or not SHA.fullmatch(expected) or digest(regular(directory / name)) != expected:
            raise LabError("GUI fixture changed bytes: " + name)
    # Reuse the strict existing provenance verifier in memory without copying
    # or accepting its headless product files as GUI product inputs.
    from .awg_migration_native import LEGACY_RECEIPT
    if (contract["legacyReceipt"] != LEGACY_RECEIPT
        or contract["files"]["legacy-amneziawg-go"] != LEGACY_RECEIPT["engineSha256"]
        or contract["files"]["legacy-awg"] != LEGACY_RECEIPT["toolsSha256"]
        or contract["files"]["legacy-musl"] != LEGACY_RECEIPT["loaderSha256"]
        or contract["goReceipt"].get("sourceArchiveSha256") != "a95853baa25d438a3e92ea5207bd315e3a45143b5209488ebf7f0b44e2e2bcc3"
        or contract["goReceipt"].get("sha256") != contract["files"]["amneziawg-go"]
        or contract["goReceipt"].get("socketDirectory") != "/run/amnezia/awg3/amneziawg"
        or contract["toolsReceipt"].get("revision") != "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"
        or contract["toolsReceipt"].get("RUNSTATEDIR") != "/run/amnezia/awg3"
        or contract["toolsReceipt"].get("archiveSha256") != "19b52a13b014b9ca3cf74226436ce657ac42ba4c83d1eeca9ee48a339aa1abe6"):
        raise LabError("GUI fixture native asset provenance")
    return contract


def parse_archive_listing(text: str) -> list[dict]:
    """Accept relative files and explicit symlink metadata before stdout reads."""
    if "----------\n" not in text.replace("\r\n", "\n"):
        raise LabError("GUI payload archive listing incomplete")
    body = text.replace("\r\n", "\n").split("----------\n", 1)[1]
    result = []
    seen = set()
    for block in re.split(r"\n\s*\n", body.strip()):
        row = dict(line.split(" = ", 1) for line in block.splitlines() if " = " in line)
        name = row.get("Path", "")
        parts = PurePosixPath(name).parts
        if (not name or "\\" in name or name.startswith("/") or ":" in name
            or any(p in (".", "..", "") for p in name.split("/")) or not parts
            or "\x00" in name or name in seen or "Hard Link" in row
            or row.get("Encrypted") == "+"):
            raise LabError("GUI payload archive contains unsafe member")
        seen.add(name)
        if row.get("Folder") == "+" or "D" in row.get("Attributes", ""):
            continue
        try:
            size = int(row["Size"])
        except (KeyError, ValueError) as error:
            raise LabError("GUI payload archive member size") from error
        permissions = row.get("Attributes", "").split()[-1:]
        link = "Symbolic Link" in row or bool(permissions and permissions[0].startswith("l"))
        if permissions and re.fullmatch(r"[bcpDs].{9}", permissions[0]):
            raise LabError("GUI payload archive contains special device")
        if not 0 <= size <= (4096 if link else 1024 * 1024 * 1024):
            raise LabError("GUI payload archive member is too large")
        item = {"name": name, "size": size}
        if link:
            item["type"] = "symlink"
        result.append(item)
    return result


def resolve_product_link(name: str, target: str) -> str:
    if (not isinstance(target, str) or not target or target.startswith("/")
        or any(c in target for c in ("\\", ":", "\x00", "\r", "\n"))):
        raise LabError("GUI payload symlink target is unsafe")
    prefix = ("/", "opt", "AmneziaVPN")
    parts = list(PurePosixPath(name).parent.parts)
    if tuple(parts[:3]) != prefix:
        raise LabError("GUI payload link outside product root")
    for part in target.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if len(parts) <= 3:
                raise LabError("GUI payload symlink escapes product root")
            parts.pop()
        else:
            parts.append(part)
    return str(PurePosixPath(*parts))


def validate_product_closure(records: dict) -> None:
    if not REQUIRED_PRODUCT <= set(records) or any(records[name].get("type") == "symlink" for name in REQUIRED_PRODUCT):
        raise LabError("GUI offline installer lacks regular GUI, desktop daemon or native engine")
    for name, record in records.items():
        if record.get("type") != "symlink":
            continue
        current = name
        seen = set()
        while records[current].get("type") == "symlink":
            if current in seen:
                raise LabError("GUI payload symlink cycle")
            seen.add(current)
            current = resolve_product_link(current, records[current]["target"])
            if current not in records:
                raise LabError("GUI payload symlink target is absent from product closure")
        # No archive member may use a symlink as an ancestor; stdout extraction
        # never follows links, and installed path checks retain the same rule.
        if any(other.startswith(name + "/") for other in records):
            raise LabError("GUI payload has a symlink directory ancestor")


def inspect_payload(artifact: dict, devtool: Path, devtool_sha256: str,
                    seven_zip: Path, seven_zip_sha256: str) -> dict:
    """Derive expected installed bytes from the signed offline installer itself.

    devtool dumps data; the installer is never launched by this function. 7z
    writes selected members to stdout only, so archive paths cannot create files.
    """
    for tool, expected in ((devtool, devtool_sha256), (seven_zip, seven_zip_sha256)):
        if not isinstance(expected, str) or not SHA.fullmatch(expected) or digest(regular(Path(tool))) != expected:
            raise LabError("GUI offline payload inspector hash differs")
    artifact_path = Path(artifact["path"])
    if artifact_path.is_symlink() or not artifact_path.is_file() or any(p.is_symlink() for p in artifact_path.parents):
        raise LabError("GUI signed installer must be a regular immutable input")
    if artifact_record(artifact_path) != artifact:
        raise LabError("GUI signed installer bytes changed before inspection")
    def execute(args: list[str]) -> bytes:
        process = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, check=False)
        if process.returncode != 0:
            raise LabError("GUI offline payload inspection failed: " + Path(args[0]).name)
        return process.stdout
    records = {}
    with tempfile.TemporaryDirectory(prefix="amnezia-gui-payload-") as temp:
        dump = Path(temp) / "dump"
        dump.mkdir()
        execute([str(devtool), "dump", str(artifact_path), str(dump)])
        archives = sorted(dump.glob("metadata/AmneziaVPN/**/*.7z"))
        if not archives:
            raise LabError("GUI offline installer has no AmneziaVPN component archives")
        for archive in archives:
            regular(archive)
            listing = execute([str(seven_zip), "l", "-slt", "--", str(archive)]).decode("utf-8", errors="strict")
            for member in parse_archive_listing(listing):
                # IFW component archives are relative to @TargetDir@.
                name = member["name"]
                if not name.startswith(("bin/", "lib/", "plugins/", "qml/")):
                    continue
                installed = "/opt/AmneziaVPN/" + name
                if installed in records:
                    raise LabError("GUI offline installer has duplicate product members")
                content = execute([str(seven_zip), "x", "-so", "-spd", "--", str(archive), name])
                if len(content) != member["size"]:
                    raise LabError("GUI offline payload extraction size differs")
                if member.get("type") == "symlink":
                    try:
                        target = content.decode("utf-8", errors="strict")
                    except UnicodeError as error:
                        raise LabError("GUI payload symlink target is not UTF-8") from error
                    resolve_product_link(installed, target)
                    records[installed] = {"type": "symlink", "target": target}
                else:
                    records[installed] = {"sha256": digest(content), "size": len(content)}
    validate_product_closure(records)
    if artifact_record(artifact_path) != artifact:
        raise LabError("GUI signed installer changed during payload inspection")
    return {"artifactSha256": artifact["sha256"], "artifactSize": artifact["size"],
            "files": records, "method": "qt-ifw-devtool-dump-7z-stdout",
            "inspectors": {"devtool": devtool_sha256, "sevenZip": seven_zip_sha256}}


def installed_candidate(planned: dict, vm: dict) -> None:
    if (not isinstance(planned, dict) or not isinstance(vm, dict)
        or not isinstance(planned.get("artifacts"), dict) or not isinstance(planned.get("profiles"), dict)
        or not isinstance(planned["profiles"].get(PROFILE), dict)):
        raise LabError("GUI planned run metadata is malformed")
    if planned.get("dry_run") or planned.get("test_mode") or planned.get("automatic_migration_wan") is not None:
        raise LabError("GUI migration requires a real sealed guest run")
    artifact = planned.get("artifacts", {}).get("linux-x64")
    if not isinstance(artifact, dict) or not {"sha256", "size", "path"} <= set(artifact):
        raise LabError("GUI candidate artifact missing")
    rows = planned.get("profiles", {}).get(PROFILE, {}).get("steps", [])
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise LabError("GUI install step records are malformed")
    candidates = [row for row in rows if row.get("action") == "update" and row.get("passed") is True]
    if len(candidates) != 1:
        raise LabError("GUI candidate needs one completed official guest update step")
    row = candidates[0]
    assertion = row.get("assertion", {})
    source = row.get("artifact_source", {})
    if not isinstance(assertion, dict) or not isinstance(source, dict):
        raise LabError("GUI install assertion/source is malformed")
    if (row.get("artifact_sha256") != artifact["sha256"] or row.get("artifact_size") != artifact["size"]
        or row.get("artifact_role") != "candidate" or source.get("transport") != "qga"
        or source.get("kind") != "qga-upload" or source.get("hash_verified") is not True
        or assertion.get("passed") is not True or assertion.get("official_entrypoint") is not True
        or assertion.get("installed_version") != planned["candidate_version"]
        or assertion.get("artifact_sha256_after") != artifact["sha256"]):
        raise LabError("GUI installed candidate step is not bound to planned product")
    binding = row.get("guest_binding", {})
    if (not isinstance(binding, dict) or not isinstance(row.get("qga_response"), dict)
        or row["qga_response"].get("exitcode") != 0):
        raise LabError("GUI candidate installer did not exit successfully")
    for name in ("pid", "uuid", "proc_start_time", "qga_socket"):
        if binding.get(name) != vm.get(name):
            raise LabError("GUI candidate install belongs to another guest")


def run(controller, run_id: str, bundle: Path, output: Path, *, devtool: Path,
        devtool_sha256: str, seven_zip: Path, seven_zip_sha256: str) -> dict:
    if controller.dry_run or controller.test_mode or not RUN.fullmatch(run_id):
        raise LabError("GUI migration requires a real owned run")
    contract = validate_bundle(bundle)
    output = Path(output)
    if output.exists() or output.is_symlink() or not output.parent.is_dir() or any(p.is_symlink() for p in output.parents):
        raise LabError("GUI migration output must be a fresh destination")
    with controller.mutation_session("awg-migration-gui"):
        vm = controller.owned_vm(run_id, PROFILE)
        planned = controller.get_run(run_id)
        installed_candidate(planned, vm)
        for role in ("manifest", "manifest_public_key"):
            if artifact_record(Path(planned[role]["path"])) != planned[role]:
                raise LabError("GUI planned signed input changed")
        validate_signed_manifest(Path(planned["manifest"]["path"]), Path(planned["manifest_public_key"]["path"]),
                                 version=planned["candidate_version"], artifacts=planned["artifacts"])
        artifact = planned["artifacts"]["linux-x64"]
        payload = inspect_payload(artifact, devtool, devtool_sha256, seven_zip, seven_zip_sha256)
        profile = load_profiles()[PROFILE]
        if profile.get("nic") != "none" or profile.get("post_seal_wan") != "disabled":
            raise LabError("GUI migration fixture requires a NIC-free sealed profile")
        ready, reason = golden_readiness(controller.root, profile)
        if not ready:
            raise LabError(reason)
        golden = json.loads((controller.root / profile["golden_readiness"]).read_text())["base_sha256"]
        qmp = QmpClient(Path(vm["qmp_socket"]))
        harness_sources = {name: Path(__file__).parent / name for name in ("awg_migration_gui.py", "awg_migration_native.py", "lab.py")}
        harness_hashes = {name: digest(regular(path)) for name, path in harness_sources.items()}
        def fence():
            if any(digest(regular(path)) != harness_hashes[name] for name, path in harness_sources.items()):
                raise LabError("GUI scenario controller closure changed during execution")
            current = controller.owned_vm(run_id, PROFILE)
            if any(current.get(key) != vm.get(key) for key in ("pid", "uuid", "proc_start_time", "qmp_socket", "qga_socket")):
                raise LabError("GUI fixture guest identity changed")
            status = require_qmp_return(qmp.request("query-status"), "query-status")
            uuid = require_qmp_return(qmp.request("query-uuid"), "query-uuid")["return"]["UUID"]
            if uuid.lower() != vm["uuid"].lower() or status["return"].get("status") != "running":
                raise LabError("GUI fixture QMP UUID/status mismatch")
            return current
        fence()
        qga = QgaClient(Path(vm["qga_socket"]))
        marker = f"amnezia-release-lab:{run_id}:{PROFILE}"
        # The installer runner must already have supplied this root-owned marker.
        if qga.read_file("/tmp/amnezia-release-lab-marker").decode().strip() != marker:
            raise LabError("GUI fixture guest marker mismatch")
        root = f"/var/lib/amnezia-release-lab/gui-migration-{run_id}"
        if planned.get("awg_gui_scenario") is not None:
            raise LabError("GUI migration attempt already exists; use a fresh owned run")
        plan = {"schema": SCHEMA, "runId": run_id, "profile": PROFILE, "marker": marker,
                "uuid": vm["uuid"], "root": root, "goldenSha256": golden,
                "attemptNonce": secrets.token_hex(16), "candidateVersion": planned["candidate_version"],
                "guiBinary": "/opt/AmneziaVPN/bin/AmneziaVPN", "guiUser": "lab",
                "artifact": {key: artifact[key] for key in ("sha256", "size")},
                "files": contract["files"], "expectedProductFiles": payload["files"]}
        planned["awg_gui_scenario"] = {"status": "processing", "passed": False, "release_passed": False,
            "attempt_nonce": plan["attemptNonce"], "root": root, "controller_files": harness_hashes,
            "bundle_sha256": digest(regular(Path(bundle) / "bundle.json")),
            "artifact_sha256": artifact["sha256"], "guest_uuid": vm["uuid"]}
        state = controller.load_state()
        state["runs"][run_id] = planned
        controller.save_state(state)
        # Execute only a constant resource/ownership guard before staging helpers.
        setup = """import json,os,pathlib,shutil,sys
assert os.geteuid()==0
assert pathlib.Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==sys.argv[1].lower()
m=pathlib.Path('/tmp/amnezia-release-lab-marker')
assert not m.is_symlink() and m.stat().st_uid==0 and m.read_text().strip()==sys.argv[2]
mem={k:int(v.split()[0]) for k,v in (line.split(':',1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())}
assert mem['MemTotal']>=2*1024*1024 and mem['MemAvailable']>=512*1024
assert shutil.disk_usage('/var/lib').free>=1024*1024*1024
parent=pathlib.Path('/var/lib/amnezia-release-lab')
if not os.path.lexists(parent): parent.mkdir(mode=0o700)
assert parent.is_dir() and not parent.is_symlink() and parent.resolve()==parent and parent.stat().st_uid==0 and not parent.stat().st_mode&0o022
root=pathlib.Path(sys.argv[3]);assert root.parent==parent
os.mkdir(root,0o700)
print(json.dumps({'passed':True,'freeBytes':shutil.disk_usage(root).free,'availableKiB':mem['MemAvailable']}))
"""
        fence()
        response = qga.guest_exec_wait("/usr/bin/python3", ["-c", setup, vm["uuid"], marker, root], timeout=30)
        if response.get("exitcode") != 0:
            raise LabError("GUI fixture resources or root ownership guard failed")
        for name, expected in sorted(contract["files"].items()):
            fence()
            content = regular(Path(bundle) / name)
            if digest(content) != expected:
                raise LabError("GUI fixture helper changed before staging")
            qga.write_file(root + "/" + name, content)
            fence()
            if digest(qga.read_file(root + "/" + name)) != expected:
                raise LabError("GUI fixture staged readback differs: " + name)
        fence()
        encoded_plan = (json.dumps(plan, sort_keys=True) + "\n").encode()
        qga.write_file(root + "/plan.json", encoded_plan)
        fence()
        if qga.read_file(root + "/plan.json") != encoded_plan:
            raise LabError("GUI fixture staged plan differs")
        fence()
        response = qga.guest_exec_wait("/usr/bin/python3", [root + "/guest.py", root + "/plan.json"], timeout=2100)
        fence()
        try:
            receipt_bytes = qga.read_file(root + "/receipt.json")
            if len(receipt_bytes) > 2 * 1024 * 1024:
                raise LabError("GUI fixture receipt exceeds its exact bound")
            receipt = json.loads(receipt_bytes)
        except (KeyError, ValueError, OSError) as error:
            raise LabError("GUI fixture returned no receipt; preserve owned guest for diagnosis") from error
        receipt["controllerBinding"] = {key: vm[key] for key in ("pid", "uuid", "proc_start_time", "qmp_socket", "qga_socket")}
        receipt["payloadBinding"] = payload
        receipt["bundleSha256"] = digest(regular(Path(bundle) / "bundle.json"))
        receipt["harnessFiles"] = harness_hashes
        receipt["releasePassed"] = False
        exclusive_json(output, receipt)
        validate_receipt(receipt, plan)
        fence()
        if response.get("exitcode") != 0:
            raise LabError("GUI fixture process failed; evidence archived")
        state = controller.load_state()
        state["runs"][run_id]["awg_gui_scenario"].update(status="completed", passed=True,
            receipt=artifact_record(output), cleanup_confirmed=True)
        controller.save_state(state)
        return receipt


def validate_receipt(receipt: dict, plan: dict) -> None:
    if (not isinstance(receipt, dict) or receipt.get("schema") != SCHEMA or receipt.get("origin") != "guest" or receipt.get("transport") != "qga"
        or receipt.get("injected") is not False or receipt.get("passed") is not True
        or any(receipt.get(key) != plan[key] for key in ("runId", "profile", "marker", "uuid", "attemptNonce"))):
        raise LabError("GUI fixture receipt identity or outcome mismatch")
    # The exact semantic mandatory set is shared with the passive observer.
    from .awg_migration_gui_observer import MANDATORY_CHECKS
    checks = receipt.get("checks")
    if not isinstance(checks, dict) or set(checks) != set(MANDATORY_CHECKS) or any(value is not True for value in checks.values()):
        raise LabError("GUI fixture mandatory observations incomplete")
    if receipt.get("productFilesAfter") != plan["expectedProductFiles"] or receipt.get("cleanupConfirmed") is not True:
        raise LabError("GUI fixture product bytes changed or owned cleanup incomplete")
