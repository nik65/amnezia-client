#!/usr/bin/env python3
"""Proposal N host-runtime tests.

- Baseline RED: K's actual --probe-host main compiled with a test-owned exec
  boundary (not its process unit helper).
- GREEN: N's actual product main compiled with an explicit typed process
  boundary onto the same owned pure worker, exercising the complete workflow.
- Transport: N's bounded adapter on the owned pure worker only (real exit23,
  separate stderr, 64 KiB overflow, deadline/cleanup, missing/relative argv).
"""
import json
import os
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
BUILD = pathlib.Path(os.environ["AMNEZIA_N_BUILD_ROOT"])
WORK = pathlib.Path(os.environ["AMNEZIA_N_WORK_ROOT"])
WORK.mkdir(mode=0o700, exist_ok=False)

results = []


def record(case, ok, detail):
    results.append({"case": case, "ok": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + case + " :: " + detail)


def manifest(name, *, version_id="24.04", codename="noble", required=None,
             modes=None, packages=None, extra_top=None, schema=2,
             architectures=None):
    doc = {
        "schema": schema,
        "distribution": "ubuntu",
        "architectures": architectures if architectures is not None else ["amd64"],
        "releases": [{
            "versionId": version_id,
            "codenames": [codename],
            "packages": packages if packages is not None else [
                {"alternatives": ["goodpkg"], "minimum": "1.0", "reason": "test"}
            ],
        }],
        "commands": {
            "required": required if required is not None else ["sh"],
            "backendModes": modes if modes is not None else [
                {"mode": "wireguard", "alternatives": ["sh"]}
            ],
        },
    }
    if extra_top:
        doc.update(extra_top)
    path = WORK / (name + ".json")
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def run(binary, mpath, *, path_env="/usr/bin:/bin", cwd=None, arch=None,
        extra_args=None, worker=None):
    log = WORK / (binary.name + "." + mpath.stem + ".log")
    if log.exists():
        log.unlink()
    env = {
        "PATH": path_env,
        "HOME": str(WORK),
        "AMNEZIA_TEST_WORKER": str(worker or (BUILD / "probe-fixture")),
        "AMNEZIA_TEST_BOUNDARY_LOG": str(log),
    }
    if arch:
        env["AMNEZIA_TEST_ARCH"] = arch
    argv = [str(binary), "--probe-host", "--runtime-manifest", str(mpath),
            "--ubuntu-version-id", "24.04", "--ubuntu-codename", "noble"]
    argv += extra_args or []
    started = time.monotonic()
    proc = subprocess.run(argv, text=True, capture_output=True, env=env,
                          cwd=str(cwd or WORK), timeout=60)
    elapsed = time.monotonic() - started
    lines = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return proc, lines, elapsed


def json_of(proc):
    try:
        return json.loads(proc.stdout)
    except Exception:
        return None


def expect_n(case, mpath, *, rc, passed=None, log_count=None, arch="amd64", **kw):
    proc, lines, _ = run(BUILD / "bootstrap-main-test", mpath, arch=arch, **kw)
    doc = json_of(proc)
    ok = proc.returncode == rc and doc is not None
    detail = f"rc={proc.returncode} log={len(lines)}"
    if doc is not None:
        ok = ok and doc.get("releaseAccepted") is False
        if passed is not None:
            ok = ok and doc.get("hostProbesPassed") is passed
        detail += f" passed={doc.get('hostProbesPassed')} arch={doc.get('architecture')}"
    if log_count is not None:
        ok = ok and len(lines) == log_count
    record(case, ok, detail + (" stderr=" + proc.stderr.strip() if proc.returncode not in (0, 26) else ""))
    return proc, doc, lines


def expect_refusal(case, mpath, rc, log_count=0):
    proc, lines, _ = run(BUILD / "bootstrap-main-test", mpath)
    ok = proc.returncode == rc and len(lines) == log_count
    record(case, ok, f"rc={proc.returncode} log={len(lines)} stderr={proc.stderr.strip()[:120]}")


def main():
    red = BUILD / "k-red"
    # ---------- baseline RED: K's actual workflow ----------
    p, lines, _ = run(red, manifest("red-default"))
    record("RED_K_default_dpkg_status", p.returncode == 26,
           f"K rc={p.returncode} (canonical expects 0; 22-char status prefix bug)")
    p, lines, _ = run(red, manifest("red-any", modes=[
        {"mode": "a", "alternatives": ["absent-mode-bin"]},
        {"mode": "b", "alternatives": ["sh"]},
    ]))
    record("RED_K_backend_any_of_modes", p.returncode == 26,
           f"K rc={p.returncode} (canonical ANY expects 0; K requires ALL)")
    p, lines, _ = run(red, manifest("red-extra", packages=[],
                                    extra_top={"unexpected": True}))
    record("RED_K_runtime_contract_exact_keys", p.returncode == 0,
           f"K rc={p.returncode} log={len(lines)} (canonical rejects extra key=22 before process)")
    cwd = WORK / "cwd-inject"
    cwd.mkdir(mode=0o700, exist_ok=True)
    tool = cwd / "cwdprobe"
    tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tool.chmod(0o755)
    p, lines, _ = run(red, manifest("red-cwd", required=["cwdprobe"], packages=[]),
                      path_env=":/usr/bin", cwd=cwd)
    record("RED_K_PATH_cwd_injection", p.returncode == 0,
           f"K rc={p.returncode} log={len(lines)} (canonical must not resolve CWD)")

    # ---------- N GREEN: whole actual workflow ----------
    expect_n("N_default_one_mode", manifest("n-default"), rc=0, passed=True, log_count=3)
    expect_n("N_backend_any_of_modes", manifest("n-any", modes=[
        {"mode": "a", "alternatives": ["absent-mode-bin"]},
        {"mode": "b", "alternatives": ["sh"]},
    ]), rc=0, passed=True, log_count=3)
    expect_n("N_successive_alternatives", manifest("n-alt", packages=[
        {"alternatives": ["oldpkg", "goodpkg"], "minimum": "1.0", "reason": "test"}
    ]), rc=0, passed=True, log_count=5)
    expect_n("N_all_alternatives_fail", manifest("n-altbad", packages=[
        {"alternatives": ["oldpkg"], "minimum": "1.0", "reason": "test"}
    ]), rc=26, passed=False, log_count=3)
    expect_n("N_exact_multifield_version", manifest("n-multi", packages=[
        {"alternatives": ["multifield"], "minimum": "1:2.3-4ubuntu4", "reason": "test"}
    ]), rc=0, passed=True, log_count=3)
    expect_n("N_architecture_unexpected", manifest("n-arch"), rc=26, passed=False,
             log_count=3, arch="arm64")
    expect_n("N_required_command_missing", manifest("n-req", required=["absent-required-xyz"],
                                                    packages=[]), rc=26, passed=False, log_count=0)
    expect_n("N_no_backend_mode", manifest("n-mode", modes=[
        {"mode": "a", "alternatives": ["absent-mode-bin"]}
    ], packages=[]), rc=26, passed=False, log_count=0)
    expect_n("N_worker_exit23_is_unmet_not_success", manifest("n-exit23", packages=[
        {"alternatives": ["exit23pkg"], "minimum": "1.0", "reason": "test"}
    ]), rc=26, passed=False, log_count=2)

    # process transport failures refuse closed (27), never a false host pass
    for case, package in (("stderr", "stderrpkg"), ("overflow", "overflowpkg")):
        proc, lines, _ = run(BUILD / "bootstrap-main-test", manifest("n-" + case, packages=[
            {"alternatives": [package], "minimum": "1.0", "reason": "test"}
        ]))
        ok = proc.returncode == 27 and len(lines) == 1 and "hostProbesPassed" not in proc.stdout
        record("N_reject_" + case, ok, f"rc={proc.returncode} log={len(lines)} stderr={proc.stderr.strip()[:80]}")

    # ---------- malformed / missing / type / schema: refusal before process ----------
    expect_refusal("N_missing_manifest", WORK / "absent-manifest.json", 21)
    bad = WORK / "bad-json.json"
    bad.write_text("{not json", encoding="utf-8")
    expect_refusal("N_invalid_json", bad, 22)
    expect_refusal("N_wrong_schema", manifest("n-schema", schema=1), 22)
    expect_refusal("N_extra_top_key", manifest("n-extra2", packages=[], extra_top={"x": 1}), 22)
    expect_refusal("N_arch_not_amd64_only", manifest("n-arch2", packages=[],
                                                     architectures=["amd64", "arm64"]), 22)
    expect_refusal("N_empty_backend_modes", manifest("n-empty-modes", modes=[], packages=[]), 22)
    expect_refusal("N_package_missing_reason", manifest("n-pkg", packages=[
        {"alternatives": ["goodpkg"], "minimum": "1.0"}
    ]), 22)
    expect_refusal("N_package_extra_key", manifest("n-pkg2", packages=[
        {"alternatives": ["goodpkg"], "minimum": "1.0", "reason": "r", "x": 1}
    ]), 22)
    p, lines, _ = run(BUILD / "bootstrap-main-test", manifest("n-args"))
    argv = [str(BUILD / "bootstrap-main-test"), "--probe-host",
            "--runtime-manifest", str(WORK / "n-args.json"),
            "--ubuntu-version-id", "24.04", "--ubuntu-codename", "noble", "--bogus", "1"]
    arglog = WORK / "n-args-unknown.log"
    if arglog.exists():
        arglog.unlink()
    env = dict(os.environ, AMNEZIA_TEST_WORKER=str(BUILD / "probe-fixture"),
               AMNEZIA_TEST_BOUNDARY_LOG=str(arglog))
    proc = subprocess.run(argv, text=True, capture_output=True, cwd=str(WORK), env=env)
    record("N_unknown_argument", proc.returncode == 20 and not arglog.exists(),
           f"rc={proc.returncode}")

    # ---------- real bounded transport on the owned pure worker ----------
    transport = BUILD / "bootstrap-transport"
    worker = BUILD / "probe-fixture"
    p = subprocess.run([str(transport), str(worker), "exit23"], text=True,
                       capture_output=True, timeout=20)
    record("N_transport_real_exit23", p.returncode == 0 and
           "RESULT exit=23" in p.stdout and "out_len=11" in p.stdout and "err_len=0" in p.stdout,
           p.stdout.strip()[:120])
    p = subprocess.run([str(transport), str(worker), "stderr"], text=True,
                       capture_output=True, timeout=20)
    record("N_transport_rejects_stderr", p.returncode == 27 and "REFUSED code=27" in p.stdout,
           p.stdout.strip()[:120])
    p = subprocess.run([str(transport), str(worker), "overflow"], text=True,
                       capture_output=True, timeout=20)
    record("N_transport_rejects_overflow", p.returncode == 27 and "64 KiB" in p.stdout,
           p.stdout.strip()[:120])
    p = subprocess.run([str(transport), str(worker), "missing"], text=True,
                       capture_output=True, timeout=20)
    record("N_transport_missing_binary_127", p.returncode == 0 and "RESULT exit=127" in p.stdout,
           p.stdout.strip()[:120])
    p = subprocess.run([str(transport), str(worker), "relative"], text=True,
                       capture_output=True, timeout=20)
    record("N_transport_rejects_relative", p.returncode == 20 and "absolute" in p.stdout,
           p.stdout.strip()[:120])
    marker = WORK / "late-marker"
    if marker.exists():
        marker.unlink()
    started = time.monotonic()
    p = subprocess.run([str(transport), str(worker), "sleep", str(marker), "800"],
                       text=True, capture_output=True, timeout=20)
    elapsed = time.monotonic() - started
    record("N_transport_deadline_cleanup", p.returncode == 27 and
           "deadline" in p.stdout and elapsed < 4.0 and not marker.exists(),
           f"rc={p.returncode} elapsed={elapsed:.2f}s marker={marker.exists()}")

    failures = [row for row in results if not row["ok"]]
    summary = {"cases": len(results), "failures": len(failures),
               "results": results}
    (WORK.parent / "test-results.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"SUMMARY cases={len(results)} failures={len(failures)}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
