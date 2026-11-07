#!/usr/bin/python3
"""Guest-only headless provisioning-verifier DATA probe.

Controller invocation:
  /usr/bin/python3 -I -B <root>/probe.py --plan <root>/plan.json

It runs the separately admitted verifier only in the owned guest root:
default verify -> --stage-inputs -> --validate-package, captures all streams,
proves root-owned private staging, removes exactly the known root children, and
prints one bounded canonical receipt. It never runs the packaged daemon/CLI,
installer, service, host probe, network, namespace, or root wrapper.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time

PROFILE = "linux-headless-x64"
MARKER_PATH = "/tmp/amnezia-release-lab-marker"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_RE = re.compile(r"^native-[0-9a-f]{32}$")
KIND = "headless-verifier"
WORK_LIMIT = 15.0
CLEANUP_RESERVE = 3.0
CAPTURE_LIMIT = 1 << 20
RECEIPT_LIMIT = 65536
NOT_RUN = ["headlessInstaller", "rootOSMutation", "hostProbes", "recovery", "applicationAcceptance"]
CASES = ("default_verify", "stage_inputs", "validate_package", "package_identity", "owned_root_cleanup")


class Refusal(ValueError):
    pass


def sign(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def read(path, bound):
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or not 0 < before.st_size <= bound:
        raise Refusal("input metadata refused")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if sign(os.fstat(fd)) != sign(before):
            raise Refusal("input open race")
        data = os.read(fd, bound + 1)
        if len(data) != before.st_size or sign(os.fstat(fd)) != sign(before):
            raise Refusal("input read race")
        return data
    finally:
        os.close(fd)


def stream_record(data):
    if len(data) > CAPTURE_LIMIT:
        raise Refusal("capture exceeds bound")
    return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "eof": True,
            "truncated": False, "head_b64": base64.b64encode(data[:2048]).decode(),
            "tail_b64": base64.b64encode(data[-2048:]).decode()}


def run(label, argv, env, cwd, deadline, streams):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise Refusal("work deadline expired")
    started = time.monotonic()
    proc = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, cwd=cwd, env=env, timeout=remaining)
    streams[f"{proc.pid}:stdout"] = stream_record(proc.stdout)
    streams[f"{proc.pid}:stderr"] = stream_record(proc.stderr)
    if proc.returncode != 0:
        raise Refusal(label + " native exit " + str(proc.returncode))
    return proc, started


def cleanup(root, identity):
    names = {"amnezia-verify-provisioning-native", "manifest.json", "owned-TEST-public.pem",
             "AmneziaHeadless_1.0.0.42_linux_x64_provisioning.tar.gz", "probe.py", "plan.json",
             "verified-receipt.json", "staged-receipt.json", "metadata.json", "private"}
    current = os.lstat(root)
    if (current.st_dev, current.st_ino) != identity or current.st_uid != 0 or stat.S_IMODE(current.st_mode) != 0o700:
        raise Refusal("owned root identity changed")
    entries = set(os.listdir(root))
    if not entries <= names:
        raise Refusal("unexpected guest root entry")
    for name in sorted(entries, reverse=True):
        path = os.path.join(root, name)
        info = os.lstat(path)
        if info.st_uid != 0:
            raise Refusal("guest root child owner refused")
        if name == "private":
            if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
                raise Refusal("private staging root refused")
            shutil.rmtree(path)
        elif stat.S_ISREG(info.st_mode):
            os.unlink(path)
        else:
            raise Refusal("guest root child type refused")
    os.rmdir(root)
    if os.path.lexists(root):
        raise Refusal("owned root still exists")


def main(argv=None):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--plan", required=True)
    args = parser.parse_args(argv)
    receipt = {"schema": 1, "kind": KIND, "run_id": None, "profile": PROFILE, "nonce": None,
               "artifacts": [], "expected": {}, "mode_exits": {"default_verify": -1, "stage_inputs": -1, "validate_package": -1},
               "root_identity": {"before": None, "after": None},
               "package": {"files": [], "structural_validated": False, "host_probes_executed": True,
                           "release_accepted": True, "native_verifier_sha256": ""},
               "work_passed": False, "cleanup_passed": False, "capture_complete": False,
               "cases": [{"name": name, "status": "FAIL"} for name in CASES],
               "streams": {}, "errors": {"primary": None, "cleanup": None}, "not_run": NOT_RUN}
    cases = {row["name"]: row for row in receipt["cases"]}
    root = ""
    deadline = time.monotonic() + WORK_LIMIT
    try:
        if os.geteuid() != 0:
            raise Refusal("guest uid0 required")
        plan_raw = read(args.plan, 65536)
        plan = json.loads(plan_raw)
        root = plan["root"]
        if (plan.get("kind") != KIND or plan.get("profile") != PROFILE or not RUN_RE.fullmatch(str(plan.get("run_id", "")))
                or not NONCE_RE.fullmatch(str(plan.get("nonce", ""))) or root != "/var/tmp/amnezia-native-" + plan["nonce"]
                or plan_raw != (json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n").encode()):
            raise Refusal("guest plan identity or canonical bytes refused")
        info = os.lstat(root)
        identity = (info.st_dev, info.st_ino)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise Refusal("guest owned root refused")
        receipt["root_identity"]["before"] = [identity[0], identity[1]]
        marker = read(MARKER_PATH, 256)
        if marker != ("amnezia-release-lab:" + plan["run_id"] + ":" + PROFILE).encode():
            raise Refusal("guest marker refused")
        receipt.update(run_id=plan["run_id"], nonce=plan["nonce"], artifacts=plan["artifacts"],
                       expected=plan["expected"])
        files = plan["files"] if "files" in plan else plan.get("inputs", {})
        component = plan["inputs"]["component"]
        manifest = plan["inputs"]["manifest"]
        public_key = plan["inputs"]["public_key"]
        archive = plan["inputs"]["archive"]
        private = plan["inputs"]["private_root"]
        source = plan["inputs"]["staged_receipt"]
        verified = plan["inputs"]["verified_receipt"]
        metadata = plan["inputs"]["metadata_receipt"]
        component_record = [row for row in plan["artifacts"] if row["role"] == "provisioning-verifier"]
        if len(component_record) != 1:
            raise Refusal("component role refused")
        component_sha = component_record[0]["sha256"]
        if hashlib.sha256(read(component, 64 << 20)).hexdigest() != component_sha:
            raise Refusal("component bytes refused")
        os.chmod(component, 0o700)
        if stat.S_IMODE(os.lstat(component).st_mode) != 0o700:
            raise Refusal("component exec mode refused")
        env = {"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C", "LC_ALL": "C", "TMPDIR": private + "-tmp"}
        pins = ["--expected-public-key-sha256", plan["expected"]["public_key_sha256"],
                "--expected-package-manifest-sha256", plan["package_manifest_sha256"],
                "--expected-checksums-sha256", plan["checksums_sha256"],
                "--expected-signed-manifest-sha256", plan["manifest_sha256"]]
        _, started = run("default_verify", [component, "--manifest", manifest, "--public-key", public_key,
                                           "--expected-public-key-sha256", plan["expected"]["public_key_sha256"],
                                           "--provisioning", archive, "--receipt-out", verified],
                         env, root, deadline, receipt["streams"])
        receipt["mode_exits"]["default_verify"] = 0
        cases["default_verify"]["status"] = "PASS"
        verified_doc = json.loads(read(verified, 65536))
        if (verified_doc.get("schema") != 1 or verified_doc.get("tool") != "amnezia-verify-provisioning-v1"
                or verified_doc.get("verified") is not True
                or verified_doc.get("manifestSha256") != plan["manifest_sha256"]
                or verified_doc.get("publicKeySha256") != plan["expected"]["public_key_sha256"]
                or verified_doc.get("archiveSha256") != plan["archive_sha256"]
                or verified_doc.get("version") != plan["version"] or verified_doc.get("packageVersion") != plan["version"]
                or verified_doc.get("packageManifestSha256") != plan["package_manifest_sha256"]
                or verified_doc.get("checksumsSha256") != plan["checksums_sha256"]
                or not isinstance(verified_doc.get("packageFiles"), list)):
            raise Refusal("default verify receipt binding refused")
        os.mkdir(private, 0o700)
        info = os.lstat(private)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise Refusal("private root refused")
        os.mkdir(private + "-tmp", 0o700)
        _, _ = run("stage_inputs", [component, "--stage-inputs", "--source-root", root, "--private-root", private,
                                    "--public-key", public_key, "--verified-receipt", verified, *pins,
                                    "--receipt-out", source], env, root, deadline, receipt["streams"])
        receipt["mode_exits"]["stage_inputs"] = 0
        cases["stage_inputs"]["status"] = "PASS"
        staged_doc = json.loads(read(source, 65536))
        if staged_doc.get("staged") is not True or staged_doc.get("packageFiles") != verified_doc["packageFiles"]:
            raise Refusal("staged receipt binding refused")
        package_root = os.path.join(private, "package")
        if set(os.listdir(package_root)) != set(verified_doc["packageFiles"]):
            raise Refusal("staged package member set refused")
        _, _ = run("validate_package", [component, "--validate-package", "--package-root", package_root,
                                         "--public-key", os.path.join(private, "update-public-key.pem"),
                                         "--receipt", os.path.join(private, "verified-receipt.json"),
                                         "--ubuntu-id", "ubuntu", "--ubuntu-version-id", "24.04",
                                         "--ubuntu-codename", "noble", *pins, "--receipt-out", metadata],
                   env, root, deadline, receipt["streams"])
        receipt["mode_exits"]["validate_package"] = 0
        cases["validate_package"]["status"] = "PASS"
        doc = json.loads(read(metadata, 65536))
        native_record = [row for row in plan["artifacts"] if row["role"] == "provisioning-verifier"]
        package_native = os.path.join(package_root, "amnezia-verify-provisioning-native")
        if (doc.get("structuralValidated") is not True or doc.get("hostProbesExecuted") is not False
                or doc.get("releaseAccepted") is not False or doc.get("packageFiles") != verified_doc["packageFiles"]):
            raise Refusal("validate package metadata scope refused")
        receipt["package"] = {"files": verified_doc["packageFiles"], "structural_validated": True,
                              "host_probes_executed": False, "release_accepted": False,
                              "native_verifier_sha256": hashlib.sha256(read(package_native, 64 << 20)).hexdigest()}
        cases["package_identity"]["status"] = "PASS"
        receipt["work_passed"] = True
        receipt["capture_complete"] = True
    except Refusal as exc:
        receipt["errors"]["primary"] = str(exc)[:512]
    except BaseException as exc:
        receipt["errors"]["primary"] = (type(exc).__name__ + ": " + str(exc))[:512]
    finally:
        if root:
            try:
                cleanup(root, tuple(receipt["root_identity"]["before"]))
                receipt["cleanup_passed"] = True
                cases["owned_root_cleanup"]["status"] = "PASS"
            except BaseException as exc:
                receipt["errors"]["cleanup"] = (type(exc).__name__ + ": " + str(exc))[:512]
    text = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    if len(text.encode()) > RECEIPT_LIMIT:
        sys.stderr.write("receipt too large\n")
        return 1
    sys.stdout.write(text + "\n")
    sys.stdout.flush()
    return 0 if (receipt["work_passed"] and receipt["cleanup_passed"] and receipt["capture_complete"]) else 1


if __name__ == "__main__":
    sys.exit(main())
