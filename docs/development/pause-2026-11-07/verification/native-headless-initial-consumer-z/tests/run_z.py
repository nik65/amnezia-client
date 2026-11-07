#!/usr/bin/env python3
"""Z: drive the ACTUAL initial-native consumer chain end to end.

Source-only extraction: the production installer is never executed or sourced
as a whole.  Exact blocks are copied out of the product text and executed in a
fresh bash child:
  - declared-role functions y_stage_inputs .. y_consume_metadata
  - the literal post-stage path reassignment lines
  - base lane: the literal legacy Python stage block

The subject verifier is a Z-owned inert main compiled from the CURRENT
canonical candidate sources (HEAD 4834452) with the test boundary; only lstat
uid/gid of the exact dev/ino-pinned owned private directory is modeled 0.
Real process uid stays 1000 and every real copy/hash/checksum/receipt check
runs.  dpkg execs are mapped to a Z-owned pure argv worker.  No packaged
product/static CMake artifact/installer/host binary is executed.
"""
import argparse, hashlib, json, os, pathlib, re, shutil, subprocess, sys, time

Q = pathlib.Path("/mnt/c/Users/ivano/PycharmProjects/amnezia-client/dist/diagnostics/upstream-5106-continuation-a/final-build-readiness-q")
ROOT = pathlib.Path("/home/ivano/codex-amnezia-upstream-20261104")
PARENT = pathlib.Path("/home/ivano/amnezia-product-50318-q/native-headless-integration-parent/integrated-stage-a")
Z = pathlib.Path("/home/ivano/amnezia-product-50318-q/native-headless-initial-consumer-z")
BINARY = Z / "build/inert-native-main"
WORKER = Z / "build/owned-pure-worker"
BASE = Q / "native-headless-delivery-parent/selected-a/install_headless.sh"
SUBJECT = Z / "src/install_headless.sh"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def funcs(text, names):
    out = []
    lines = text.splitlines()
    for name in names:
        for i, line in enumerate(lines):
            if line.startswith(name + "() {"):
                j = i + 1
                while j < len(lines) and lines[j] != "}":
                    j += 1
                out.append("\n".join(lines[i:j + 1]))
                break
        else:
            raise SystemExit(f"missing function block: {name}")
    return "\n".join(out)

def reassignment(text):
    picked = [l for l in text.splitlines() if re.fullmatch(
        r'(PACKAGE_ROOT|PUBLIC_KEY|VERIFIED_RECEIPT)="\$PRIVATE_INPUTS_ROOT/[^"]+"', l)]
    if len(picked) != 3:
        raise SystemExit("missing literal post-stage path reassignment")
    return "\n".join(picked)

def base_stage_block(text):
    lines = text.splitlines()
    start = next(i for i, l in enumerate(lines)
                 if l.startswith('if ! python3 - "$SOURCE_PACKAGE_ROOT" "$PRIVATE_INPUTS_ROOT"'))
    end = start
    while lines[end] != "PY":
        end += 1
    end += 4  # PY, then, echo, exit 3, fi
    if lines[end] != "fi":
        raise SystemExit("base stage block does not end at fi")
    return "\n".join(lines[start:end + 1])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fail-work", action="store_true")
    a = ap.parse_args()
    attempt = Z / (("failedwork-" if a.fail_work else "green-") + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    attempt.mkdir(mode=0o700)
    inputs = {}
    for p in (BINARY, WORKER, SUBJECT, BASE):
        inputs[str(p)] = sha(p)
    receipt = json.loads((PARENT / "full-stage-role9.stage.json").read_text())
    package_source = PARENT / "full-stage-role9-private/package"
    key = pathlib.Path("/home/ivano/amnezia-product-50318-q/native-headless-authority-parent/integrated-g/owned-TEST-public.pem")
    verified_receipt = PARENT / "full-stage-role9-private/verified-receipt.json"
    runtime = json.loads((package_source / "runtime-dependencies.json").read_text())
    for p in (package_source / "runtime-dependencies.json", key, verified_receipt):
        inputs[str(p)] = sha(p)
    # owned PATH placeholders for every declared command/alternative
    pathdir = attempt / "owned-path"; pathdir.mkdir(mode=0o700)
    declared = list(runtime["commands"]["required"])
    for mode in runtime["commands"]["backendModes"]:
        declared += mode["alternatives"]
    for name in sorted(set(declared)):
        placeholder = pathdir / name
        placeholder.write_bytes(b"")
        placeholder.chmod(0o755)
    result = {"schema": 1, "kind": "native-headless-initial-consumer-z", "attempt": str(attempt),
              "inputs": inputs, "commands": [], "componentPass": False, "releasePass": False,
              "published": False, "outerExit": None}
    env = dict(PATH=str(pathdir), HOME=str(attempt), TMPDIR=str(attempt), LANG="C", LC_ALL="C",
               AMNEZIA_TEST_WORKER=str(WORKER),
               AMNEZIA_TEST_BOUNDARY_LOG=str(attempt / "boundary.log"))
    def run(label, argv, expected, extra=None):
        with (attempt / (label + ".stdout")).open("xb") as out, (attempt / (label + ".stderr")).open("xb") as err:
            p = subprocess.run(argv, env=dict(env, **(extra or {})), stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=120)
        result["commands"].append({"label": label, "nativeExit": p.returncode, "expectedExit": expected})
        return p.returncode
    # ---- RED: actual base caller, legacy stage alone, no native mode ----
    base_text = BASE.read_text()
    block = base_stage_block(base_text)
    red_dir = attempt / "red-base-private"; red_dir.mkdir(mode=0o700)
    red = attempt / "red-base.sh"
    red.write_text("set -euo pipefail\nSOURCE_PACKAGE_ROOT=%s\nPRIVATE_INPUTS_ROOT=%s\nPUBLIC_KEY=%s\nVERIFIED_RECEIPT=%s\n%s\n" % (
        package_source, red_dir, key, verified_receipt, block))
    rc = run("red-base-actual-legacy-stage", ["/bin/bash", str(red)], 3, dict(env, PATH="/usr/bin:/bin"))
    red_native_modes = (attempt / "red-native-modes.log").exists()
    result["red"] = {"actualCallerExit": rc, "nativeModesInvoked": red_native_modes,
                     "verdict": "RED: actual base caller emits no native stage/validate/probe mode"}
    # ---- GREEN: actual Z consumer chain against actual inert native main ----
    text = SUBJECT.read_text()
    names = ("y_stage_inputs", "y_consume_stage_inputs", "y_validate_package",
             "y_probe_host", "y_consume_metadata")
    private = attempt / "green-private"; private.mkdir(mode=0o700); private.chmod(0o700)
    meta = private.lstat()
    green_env = dict(env)
    green_env.update(W_PRIVATE_MODEL_ROOT=str(private), W_PRIVATE_MODEL_DEV=str(meta.st_dev),
                     W_PRIVATE_MODEL_INO=str(meta.st_ino))
    pins = dict(receipt)
    if a.fail_work:
        pins["expectedChecksumsSha256"] = ("0" if pins["expectedChecksumsSha256"][0] != "0" else "1") + pins["expectedChecksumsSha256"][1:]
    subject = attempt / "green-subject.sh"
    body = (
        "set -euo pipefail\n"
        "BOOTSTRAP_VERIFIER=%s\nSOURCE_PACKAGE_ROOT=%s\nPRIVATE_INPUTS_ROOT=%s\n"
        "PUBLIC_KEY=%s\nVERIFIED_RECEIPT=%s\nEXPECTED_KEY_SHA256=%s\n"
        "EXPECTED_MANIFEST_SHA256=%s\nEXPECTED_CHECKSUMS_SHA256=%s\nEXPECTED_SIGNED_MANIFEST_SHA256=%s\n"
        "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n"
        "%s\n"
        "y_consume_stage_inputs\n%s\n"
        "y_consume_metadata\n"
        "python3 -c 'import sys;print(open(sys.argv[1],\"rb\").read(4).decode(\"latin1\"))' \"$PACKAGE_ROOT/amneziad\"\n" % (
            BINARY, package_source, private, key, verified_receipt,
            pins["expectedKeySha256"], pins["expectedPackageManifestSha256"],
            pins["expectedChecksumsSha256"], pins["expectedSignedManifestSha256"],
            funcs(text, names), reassignment(text)))
    body = body.replace("python3 -c", "/usr/bin/python3 -c")
    subject.write_text(body)
    env_exec = dict(green_env)
    p = subprocess.run(["/bin/bash", str(subject)], env=env_exec, stdin=subprocess.DEVNULL,
                       stdout=(attempt / "green-chain.stdout").open("xb"),
                       stderr=(attempt / "green-chain.stderr").open("xb"), timeout=180)
    result["commands"].append({"label": "green-actual-consumer-chain", "nativeExit": p.returncode, "expectedExit": 0})
    result["green"] = {"actualChainExit": p.returncode,
                       "trueBoundaryExit": 13,
                       "boundary": "chain stops before ldd/`amneziad --version`; product bytes never executed"}
    ok = p.returncode == 0 and not red_native_modes and rc == 3
    result["componentPass"] = ok and not a.fail_work
    (attempt / "RESULT.json").write_text(json.dumps(result, indent=1) + "\n")
    if a.fail_work:
        result["outerExit"] = 23
        (attempt / "RESULT.json").write_text(json.dumps(result, indent=1) + "\n")
        return 23
    return 0 if ok else 23

if __name__ == "__main__":
    sys.exit(main())
