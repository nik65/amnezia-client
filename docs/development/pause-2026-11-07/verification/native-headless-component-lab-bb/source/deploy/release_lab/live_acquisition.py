"""Controller-owned live evidence acquisition; acquisition never means PASS.

The release keyholder/controller host is the trust boundary. This module has
no JSON import, signing, approval, or caller-selected guest command entrypoint.
Only a live LabController ownership check can select the QGA transport.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import secrets
import time

PROFILES = {"linux-x64-gui": "linux-x64", "linux-headless-x64": "linux-headless-x64"}
# Receipt base64 is itself carried in QGA out-data base64. Keep the entire
# double-encoded reply below QmpClient's 1 MiB wire limit, including metadata.
MAX_RECEIPT_BYTES = 512 * 1024
MAX_RESPONSE_BYTES = 704 * 1024


class AcquisitionError(RuntimeError):
    pass


# All paths derive from controller-validated run/profile identifiers. The file
# is opened without following symlinks, read once, and fstat is fenced around
# the read. The nonce is created by the controller immediately before QGA exec.
LINUX_CAPTURE = r'''import base64,hashlib,json,os,stat,sys
run,profile,nonce=sys.argv[1:]
path='/run/amnezia-release-lab/'+run+'/'+profile+'/receipt.json'
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 a=os.fstat(fd)
 if not stat.S_ISREG(a.st_mode) or a.st_size<=0 or a.st_size>524288:raise SystemExit('receipt bounds')
 chunks=[];remaining=a.st_size
 while remaining:
  b=os.read(fd,min(65536,remaining))
  if not b:raise SystemExit('receipt truncated')
  chunks.append(b);remaining-=len(b)
 b=b''.join(chunks);z=os.fstat(fd)
 if (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns):raise SystemExit('receipt changed')
 print(json.dumps({'nonce':nonce,'run_id':run,'profile':profile,'path':path,'sha256':hashlib.sha256(b).hexdigest(),'size':len(b),'bytes_b64':base64.b64encode(b).decode()},separators=(',',':')))
finally:os.close(fd)
'''


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AcquisitionError("duplicate response key")
        result[key] = value
    return result


def _capture_response(raw, nonce, run_id, profile):
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise AcquisitionError("capture response bounds")
    try:
        value = json.loads(raw, object_pairs_hook=_strict_object)
        if not isinstance(value, dict) or set(value) != {"nonce", "run_id", "profile", "path", "sha256", "size", "bytes_b64"}:
            raise AcquisitionError("capture response shape")
        if (value["nonce"], value["run_id"], value["profile"], value["path"]) != (
            nonce, run_id, profile, f"/run/amnezia-release-lab/{run_id}/{profile}/receipt.json"
        ):
            raise AcquisitionError("capture challenge or identity mismatch")
        if type(value["size"]) is not int or not 0 < value["size"] <= MAX_RECEIPT_BYTES:
            raise AcquisitionError("capture receipt bounds")
        data = base64.b64decode(value["bytes_b64"], validate=True)
        if len(data) != value["size"] or hashlib.sha256(data).hexdigest() != value["sha256"]:
            raise AcquisitionError("capture bytes differ")
        return value, data
    except (ValueError, TypeError, KeyError) as error:
        raise AcquisitionError("invalid capture response") from error


def _verify_record(record):
    if not isinstance(record, dict) or type(record.get("size")) is not int or record["size"] <= 0:
        raise AcquisitionError("planned file record missing")
    path = Path(record.get("path", ""))
    if path.is_symlink() or not path.is_file():
        raise AcquisitionError("planned file is not regular")
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    if path.stat().st_size != record["size"] or digest != record.get("sha256"):
        raise AcquisitionError("planned file bytes changed")


def acquire_linux_receipt(controller, run_id: str, profile: str):
    """Capture original guest bytes now; never consume an imported PASS file.

    Caller must be the trusted controller, inside its existing mutation session.
    No acquisition is attempted for dry-run/test mode, Android, or Windows. The
    returned raw bytes still need full semantic validation AND owned cleanup;
    the wrapper challenge proves a fresh channel read, not that the receipt
    was freshly generated or that its claimed test actually ran. Full semantic
    validation must bind its original attempt, timestamps, exact artifacts and
    cleanup independently. This API has no acceptance/signing operation.
    """
    from .lab import LabController, QgaClient

    if type(controller) is not LabController or controller.dry_run or controller.test_mode:
        raise AcquisitionError("live production controller required")
    controller.assert_mutation_context()
    if controller._mutation_lock_depth <= 0 or controller._mutation_lock_fd is None:
        raise AcquisitionError("active controller mutation lock required")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", run_id) or profile not in PROFILES:
        raise AcquisitionError("unsupported acquisition run/profile")
    run = copy.deepcopy(controller.get_run(run_id))
    if run.get("dry_run") or run.get("test_mode") or run.get("automatic_migration_wan") is not None:
        raise AcquisitionError("diagnostic/test run cannot acquire release evidence")
    records = [run.get("manifest"), run.get("outer_artifact")]
    for field in ("artifacts", "baseline_artifacts", "runner_records", "semantic_helper_records"):
        mapping = run.get(field)
        if not isinstance(mapping, dict) or not mapping:
            raise AcquisitionError("planned closure missing")
        records.extend(mapping.values())
    if PROFILES[profile] not in run["artifacts"]:
        raise AcquisitionError("candidate profile missing")
    for record in records:
        _verify_record(record)
    before = copy.deepcopy(controller.owned_vm(run_id, profile))
    nonce = secrets.token_hex(32)
    started = time.monotonic()
    response = QgaClient(Path(before["qga_socket"])).guest_exec_wait(
        "/usr/bin/python3", ["-c", LINUX_CAPTURE, run_id, profile, nonce], timeout=30
    )
    if not isinstance(response, dict) or type(response.get("exitcode")) is not int or response["exitcode"] != 0:
        raise AcquisitionError("live guest capture failed")
    captured, data = _capture_response(response.get("stdout"), nonce, run_id, profile)
    if time.monotonic() - started > 35:
        raise AcquisitionError("capture freshness deadline exceeded")
    if controller.owned_vm(run_id, profile) != before or controller.get_run(run_id) != run:
        raise AcquisitionError("controller/guest binding changed during acquisition")
    for record in records:
        _verify_record(record)
    return {
        "schema": 1, "state": "acquired-not-accepted", "run_id": run_id,
        "profile": profile, "transport": "qga", "binding": before,
        "challenge": nonce, "capture": captured, "raw_receipt": data,
        "requires": ["semantic-validation", "owned-cleanup", "complete-platform-matrix"],
    }
