"""Read-only physical Android acquisition. Captured evidence is never a PASS.

The existing trusted controller/keyholder must invoke this module directly,
validate the complete acceptance matrix and preserve the original capture. This
module accepts no receipt imports, device commands, signing keys or PASS flags.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import threading
import time

PACKAGE = "org.amnezia.vpn"
PINNED_ADB = Path("C:/Users/ivano/Android/Sdk/platform-tools/adb.exe")
MAX_OUTPUT = 16 * 1024 * 1024
MAX_CAPTURE_OUTPUT = 32 * 1024 * 1024
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}")
SHA = re.compile(r"[0-9a-f]{64}")


class AndroidAcquisitionError(RuntimeError):
    pass


def _bounded_process(command, *, timeout, max_output, input_bytes=None):
    """Bound combined stdout/stderr while reading, not after communicate().

    On overflow/deadline signal only the Popen-owned ADB client, never the ADB
    server or another process. Two reader threads retain at most the shared
    limit plus two 64-KiB chunks; the caller receives exact captured bytes.
    """
    if (timeout <= 0 or type(max_output) is not int or max_output <= 0
            or input_bytes is not None and (not isinstance(input_bytes, bytes) or len(input_bytes) > 1024*1024)):
        raise AndroidAcquisitionError("invalid transport bounds")
    process = subprocess.Popen(command, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=False, bufsize=0,
                               creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    buffers = [bytearray(), bytearray()]
    lock = threading.Lock()
    overflow = threading.Event()
    failures = []
    total = 0

    def drain(index, pipe):
        nonlocal total
        try:
            while True:
                chunk = pipe.read(65536)
                if not chunk:
                    return
                with lock:
                    if total + len(chunk) > max_output:
                        overflow.set()
                        return
                    buffers[index].extend(chunk)
                    total += len(chunk)
        except (OSError, ValueError) as error:
            failures.append(type(error).__name__)

    readers = [threading.Thread(target=drain, args=(i, pipe), daemon=True)
               for i, pipe in enumerate((process.stdout, process.stderr))]
    def feed():
        try:
            source = memoryview(input_bytes)
            while source:
                written = process.stdin.write(source[:65536])
                if not written:
                    raise OSError("short transport input write")
                source = source[written:]
        except (OSError, ValueError) as error:
            failures.append(type(error).__name__)
        finally:
            process.stdin.close()
    writer = threading.Thread(target=feed, daemon=True) if input_bytes is not None else None
    for reader in readers:
        reader.start()
    if writer:
        writer.start()
    deadline = time.monotonic() + timeout
    error = None
    try:
        while process.poll() is None or any(reader.is_alive() for reader in readers) or writer and writer.is_alive():
            if overflow.is_set():
                error = "transport output limit exceeded"
                break
            if time.monotonic() >= deadline:
                error = "transport acquisition deadline exceeded"
                break
            time.sleep(0.01)
        if overflow.is_set():
            error = "transport output limit exceeded"
        if error:
            raise AndroidAcquisitionError(error)
        if failures:
            raise AndroidAcquisitionError("transport output read failed")
        return subprocess.CompletedProcess(command, process.returncode, bytes(buffers[0]), bytes(buffers[1]))
    finally:
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired as exc:
            raise AndroidAcquisitionError("owned ADB client did not exit after bounded stop") from exc
        for reader in readers:
            reader.join(timeout=1)
        if writer:
            writer.join(timeout=1)
        # FileIO pipes (bufsize=0) have no BufferedReader lock held by a reader.
        # Closing our handles cannot signal the separate ADB server.
        for pipe in (process.stdout, process.stderr):
            pipe.close()
        if process.stdin and not process.stdin.closed:
            process.stdin.close()


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _regular(path):
    path = Path(path)
    if not path.is_absolute():
        raise AndroidAcquisitionError("absolute managed path required")
    for part in (path, *path.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise AndroidAcquisitionError("managed path follows a link/reparse point")
    if not path.is_file():
        raise AndroidAcquisitionError("managed file missing")
    return path


def file_record(path):
    path = _regular(path)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    # CPython 3.13 Windows fstat/stat disagree on deprecated st_ctime (last
    # write versus creation). Device/file ID, length and mtime agree; the
    # complete content hash is independently fenced again after acquisition.
    fence = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns,
                       s.st_ctime_ns if os.name != "nt" else 0)
    if fence(before) != fence(after) or fence(after) != fence(path.stat()):
        raise AndroidAcquisitionError("managed file changed while hashing")
    return {"path": str(path), "sha256": digest, "size": after.st_size}


def _verify_record(record):
    if (not isinstance(record, dict) or set(record) != {"path", "sha256", "size"}
            or not isinstance(record["path"], str) or not isinstance(record["sha256"], str)
            or not SHA.fullmatch(record["sha256"]) or type(record["size"]) is not int
            or record["size"] <= 0 or file_record(record["path"]) != record):
        raise AndroidAcquisitionError("planned artifact bytes changed or invalid record")


def _package_identity(text):
    def field(pattern):
        matches = re.findall(pattern, text, re.MULTILINE)
        if len(matches) != 1:
            raise AndroidAcquisitionError("ambiguous installed package identity")
        return matches[0]
    return {"version": field(r"^\s*versionName=(\d+\.\d+\.\d+\.\d+)\s*$"),
            "version_code": int(field(r"^\s*versionCode=(\d+)\b.*$")),
            "app_id": int(field(r"^\s*(?:userId|appId)=(\d+)\s*$"))}


def _package_path(text):
    match = re.fullmatch(r"package:(/data/app/[A-Za-z0-9_./+~=-]+/base\.apk)\s*", text)
    if not match or ".." in match[1].split("/"):
        raise AndroidAcquisitionError("installed APK path is not one regular base package")
    return match[1]


def _processes(text, uid):
    result = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) != 3 or not parts[2].startswith(PACKAGE):
            continue
        if not (parts[2] == PACKAGE or parts[2] in {
                PACKAGE + ":amneziaAwgService", PACKAGE + ":amneziaOpenVpnService",
                PACKAGE + ":amneziaXrayService", PACKAGE + ":amneziaTileService"}):
            raise AndroidAcquisitionError("unexpected process sharing package prefix")
        if not parts[0].isdigit() or not parts[1].isdigit() or int(parts[0]) != uid or int(parts[1]) <= 1:
            raise AndroidAcquisitionError("package process UID/PID mismatch")
        result.append({"uid": uid, "pid": int(parts[1]), "name": parts[2]})
    if len({p["pid"] for p in result}) != len(result) or not any(p["name"] == PACKAGE for p in result):
        raise AndroidAcquisitionError("main package process missing or duplicate PID")
    return sorted(result, key=lambda p: p["pid"])


def _start_ticks(text, pid):
    if not text.startswith(str(pid) + " (") or ") " not in text:
        raise AndroidAcquisitionError("process stat identity mismatch")
    fields = text[text.rfind(") ") + 2:].split()
    if len(fields) < 20 or not fields[19].isdigit():
        raise AndroidAcquisitionError("process start identity missing")
    return int(fields[19])


def _vpn_observations(text, uid):
    observations = []
    for line in text.splitlines():
        transports = re.search(r"Transports: ([A-Z_|]+)", line)
        if ("NetworkAgentInfo{" not in line or not transports
                or "VPN" not in transports[1].split("|")):
            continue
        network = re.search(r"network\{(\d+)\}", line)
        owner = re.search(r"OwnerUid: (\d+)", line)
        interface = re.search(r"InterfaceName: (\w+)", line)
        if owner and int(owner[1]) == uid and network and interface:
            observations.append({"network": int(network[1]), "owner_uid": uid,
                                 "interface": interface[1], "validated": "&VALIDATED" in line,
                                 "connected": "ni{VPN CONNECTED" in line})
    return observations


def acquire_android_device(*, run_id, serial, candidate, manifest, version, version_code):
    """Acquire fresh original bytes from the selected real device, without writes.

    Call inside the trusted controller's exclusive capture session. The caller
    supplies already planned artifact records, not a claimed device receipt.
    Returned raw_capture bytes bind every original subprocess output, including
    PID-specific log buffers. Semantic acceptance remains a separate operation.
    """
    if (not isinstance(run_id, str) or not ID.fullmatch(run_id)
            or not isinstance(serial, str) or not ID.fullmatch(serial)
            or serial.lower().startswith("emulator-")
            or not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", version)
            or type(version_code) is not int or version_code <= 0):
        raise AndroidAcquisitionError("invalid physical device/run/version identity")
    _verify_record(candidate)
    _verify_record(manifest)
    adb_record = file_record(PINNED_ADB)
    producer = file_record(Path(__file__).absolute())
    records = []
    total_output = 0
    started = _utc()
    deadline = time.monotonic() + 120
    nonce = secrets.token_hex(32)

    def run(label, args):
        nonlocal total_output
        if time.monotonic() >= deadline:
            raise AndroidAcquisitionError("capture freshness deadline exceeded")
        command = [str(PINNED_ADB), "-s", serial, *args]
        before = _utc()
        result = _bounded_process(command, timeout=min(25, max(1, deadline-time.monotonic())),
                                  max_output=min(MAX_OUTPUT, MAX_CAPTURE_OUTPUT-total_output))
        if (type(result.returncode) is not int or not isinstance(result.stdout, bytes)
                or not isinstance(result.stderr, bytes)
                or len(result.stdout) + len(result.stderr) > MAX_OUTPUT):
            raise AndroidAcquisitionError("transport response bounds")
        total_output += len(result.stdout) + len(result.stderr)
        if total_output > MAX_CAPTURE_OUTPUT:
            raise AndroidAcquisitionError("aggregate capture response bounds")
        records.append({"label": label, "argv": args, "started_at": before, "finished_at": _utc(),
                        "exit_code": result.returncode,
                        "stdout_b64": base64.b64encode(result.stdout).decode(),
                        "stderr_b64": base64.b64encode(result.stderr).decode()})
        if result.returncode != 0:
            raise AndroidAcquisitionError(f"read-only acquisition command failed: {label}")
        return result.stdout.decode("utf-8", errors="strict").replace("\r\n", "\n").strip()

    def challenge(label):
        # Only controller-generated hex enters this fixed, read-only shell program.
        raw = run(label, ["shell", f"printf '{nonce}\\n'; cat /proc/sys/kernel/random/boot_id; id -u; date +%s"])
        lines = raw.splitlines()
        if (len(lines) != 4 or lines[0] != nonce
                or not re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", lines[1])
                or lines[2] != "2000" or not lines[3].isdigit()):
            raise AndroidAcquisitionError("live challenge, boot identity or shell UID mismatch")
        return {"boot_id": lines[1], "shell_uid": 2000, "device_epoch": int(lines[3])}

    if run("device-state", ["get-state"]) != "device" or run("serial", ["get-serialno"]) != serial:
        raise AndroidAcquisitionError("selected physical transport not ready")
    first = challenge("challenge-before")
    properties = {key: run("property:"+key, ["shell", "getprop", key]) for key in (
        "ro.kernel.qemu", "ro.boot.qemu", "ro.hardware", "ro.product.manufacturer",
        "ro.product.model", "ro.build.fingerprint", "ro.build.version.release", "ro.build.version.sdk")}
    if (properties["ro.kernel.qemu"] not in ("", "0") or properties["ro.boot.qemu"] not in ("", "0")
            or properties["ro.hardware"].lower() in {"ranchu", "goldfish", "cutf_cvm", "cuttlefish"}
            or any(not properties[k] for k in ("ro.hardware", "ro.product.manufacturer", "ro.product.model", "ro.build.fingerprint"))
            or not properties["ro.build.version.sdk"].isdigit() or int(properties["ro.build.version.sdk"]) < 28):
        raise AndroidAcquisitionError("physical Android identity required; emulator evidence forbidden")

    def installed(label):
        identity = _package_identity(run(label+":package", ["shell", "dumpsys", "package", PACKAGE]))
        uid_text = run(label+":uid", ["shell", "pm", "list", "packages", "-U", "--user", "current", PACKAGE])
        uid_match = re.fullmatch(r"package:org\.amnezia\.vpn uid:(\d+)", uid_text)
        if not uid_match or int(uid_match[1]) % 100000 != identity["app_id"] % 100000:
            raise AndroidAcquisitionError("package app ID/active-user UID mismatch")
        identity["uid"] = int(uid_match[1])
        path = _package_path(run(label+":path", ["shell", "pm", "path", PACKAGE]))
        digest = run(label+":apk-sha256", ["shell", "sha256sum", path]).split()
        size = run(label+":apk-size", ["shell", "stat", "-c", "%s", path])
        if (len(digest) != 2 or digest[1] != path or digest[0] != candidate["sha256"]
                or not size.isdigit() or int(size) != candidate["size"]
                or identity["version"] != version or identity["version_code"] != version_code):
            raise AndroidAcquisitionError("installed candidate bytes/version mismatch")
        return {**identity, "path": path, "sha256": digest[0], "size": int(size)}

    before = installed("before")

    def bound_processes(label):
        processes = _processes(run(label+":processes", ["shell", "ps", "-A", "-o", "UID,PID,NAME"]), before["uid"])
        for process in processes:
            process["start_ticks"] = _start_ticks(run(label+":stat:"+str(process["pid"]),
                                                    ["shell", "cat", f"/proc/{process['pid']}/stat"]), process["pid"])
        return processes

    processes = bound_processes("before")
    vpn_before = _vpn_observations(run("vpn-before", ["shell", "dumpsys", "connectivity"]), before["uid"])
    for process in processes:
        run("logcat:"+str(process["pid"]), ["logcat", "-d", "-v", "epoch", "--pid="+str(process["pid"]), "-t", "4000"])
    run("uid-logcat", ["logcat", "-d", "-v", "epoch", "--uid="+str(before["uid"]), "-t", "6000"])
    vpn_after = _vpn_observations(run("vpn-after", ["shell", "dumpsys", "connectivity"]), before["uid"])
    after = installed("after")
    processes_after = bound_processes("after")
    last = challenge("challenge-after")
    if (first["boot_id"] != last["boot_id"] or after != before or processes_after != processes
            or vpn_after != vpn_before or last["device_epoch"] < first["device_epoch"]
            or last["device_epoch"] - first["device_epoch"] > 120 or time.monotonic() > deadline):
        raise AndroidAcquisitionError("device/package/process/VPN binding changed during capture")
    _verify_record(candidate)
    _verify_record(manifest)
    if file_record(PINNED_ADB) != adb_record:
        raise AndroidAcquisitionError("ADB executable changed during capture")
    if file_record(Path(__file__).absolute()) != producer:
        raise AndroidAcquisitionError("capture producer changed during acquisition")
    raw = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return {"schema": 1, "state": "acquired-not-accepted", "run_id": run_id,
            "profile": "android-real-device", "transport": "adb-selected-physical-device",
            "started_at": started, "finished_at": _utc(), "challenge": nonce,
            "binding": {"serial": serial, **first, "properties": properties, "processes": processes},
            "candidate": candidate, "manifest": manifest, "adb": adb_record, "producer": producer,
            "installed_before": before, "installed_after": after,
            "vpn_observations": vpn_before, "raw_capture": raw,
            "capture": {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
                        "bytes_b64": base64.b64encode(raw).decode()},
            "requires": ["semantic-validation", "owned-cleanup-or-readonly-closeout", "complete-platform-matrix"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--version-code", required=True, type=int)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("capture output must be a new directory")
    result = acquire_android_device(run_id=args.run_id, serial=args.serial,
                                    candidate=file_record(args.candidate.absolute()),
                                    manifest=file_record(args.manifest.absolute()),
                                    version=args.version, version_code=args.version_code)
    args.out.mkdir(parents=True)
    raw = result.pop("raw_capture")
    (args.out/"raw-capture.json").write_bytes(raw)
    (args.out/"acquisition.json").write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps({"state": result["state"], "capture_sha256": result["capture"]["sha256"],
                      "installed_version": result["installed_after"]["version"],
                      "processes": len(result["binding"]["processes"]), "out": str(args.out)}))


if __name__ == "__main__":
    main()
