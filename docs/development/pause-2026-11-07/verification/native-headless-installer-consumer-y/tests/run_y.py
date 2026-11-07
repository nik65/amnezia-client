#!/usr/bin/env python3
"""Proposal Y behavioural consumer tests.

The subject is the ACTUAL production script (src/install_headless.sh).  The
runner extracts the exact declared-role consumer function blocks by name and
sources only those functions into a fresh bash child.  The production script is
never executed, sourced as a whole, or syntax-run beyond `bash -n`.

The child path is restricted to a directory holding exactly one typed stub
named amnezia-verify-provisioning-native.  The stub records the argv the
production function really emits and returns a case-controlled exit/output.
It never fabricates native acceptance: success cases are labelled model output
and make no claim about the compiled verifier.

Exit: 0 all cases pass; 23 at least one case failed (missing behaviour on the
base subject is a genuine RED).
"""
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

FUNCTIONS = (
    "y_stage_inputs",
    "y_consume_stage_inputs",
    "y_validate_package",
    "y_probe_host",
    "y_consume_metadata",
)

STUB = r"""#!/bin/bash
set -u
for argument in "$@"; do
    printf '%s\0' "$argument"
done >> "$Y_ARGV_LOG"
printf '\n' >> "$Y_ARGV_LOG"
mode=""
for argument in "$@"; do
    case "$argument" in
        --stage-inputs|--validate-package|--probe-host) mode="$argument" ;;
    esac
done
printf '%s\n' "$mode" >> "$Y_MODE_LOG"
case "$mode" in
    --stage-inputs)
        [ "${Y_STAGE_RC:-0}" = "0" ] || exit "${Y_STAGE_RC}"
        printf 'staged private provisioning inputs: /private/package\n'
        printf 'staged package files: 9\n'
        ;;
    --validate-package)
        [ "${Y_VALIDATE_RC:-0}" = "0" ] || exit "${Y_VALIDATE_RC}"
        printf '%s\n' "${Y_VALIDATE_OUT:-}"
        ;;
    --probe-host)
        [ "${Y_PROBE_RC:-0}" = "0" ] || exit "${Y_PROBE_RC}"
        printf '%s\n' "${Y_PROBE_OUT:-}"
        ;;
esac
exit 0
"""


def extract_functions(text):
    lines = text.splitlines()
    blocks = {}
    for name in FUNCTIONS:
        start = None
        for index, line in enumerate(lines):
            if line == name + "() {":
                start = index
                break
        if start is None:
            continue
        end = None
        for index in range(start + 1, len(lines)):
            if lines[index] == "}":
                end = index
                break
        if end is None:
            continue
        blocks[name] = "\n".join(lines[start:end + 1]) + "\n"
    return blocks


class Case:
    def __init__(self, name):
        self.name = name
        self.ok = False
        self.detail = ""

    def record(self, ok, detail):
        self.ok = bool(ok)
        self.detail = detail
        print(("PASS " if self.ok else "FAIL ") + self.name + " :: " + detail)
        return self.ok


def read_argv(path):
    if not path.exists():
        return []
    calls = []
    data = path.read_bytes()
    for raw in data.split(b"\n"):
        if not raw:
            continue
        calls.append([part.decode("utf-8") for part in raw.split(b"\0") if part != b""])
    return calls


def read_modes(path):
    if not path.exists():
        return []
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line]


def run_case(work, blocks, function, env_extra=None):
    harness = work / "harness.sh"
    blocks_file = work / "blocks.sh"
    blocks_file.write_text("\n".join(blocks[name] for name in FUNCTIONS if name in blocks), encoding="utf-8")
    harness.write_text(
        "#!/bin/bash\n"
        "set -uo pipefail\n"
        "export PATH=\"$Y_STUB_DIR\"\n"
        "if command -v python3 >/dev/null 2>&1; then echo PYTHON3_AVAILABLE >&2; exit 90; fi\n"
        "if command -v dpkg >/dev/null 2>&1; then echo DPKG_AVAILABLE >&2; exit 90; fi\n"
        "if command -v sha256sum >/dev/null 2>&1; then echo SHA256SUM_AVAILABLE >&2; exit 90; fi\n"
        "source \"$Y_BLOCKS\"\n"
        + function + "\n"
        "printf 'RC:%s\\n' \"$?\"\n"
        "printf 'VERSION:%s\\n' \"${Y_PACKAGE_VERSION:-}\"\n",
        encoding="utf-8",
    )
    env = {
        "PATH": str(work / "stub"),
        "HOME": str(work),
        "TMPDIR": str(work),
        "Y_STUB_DIR": str(work / "stub"),
        "Y_BLOCKS": str(blocks_file),
        "Y_ARGV_LOG": str(work / "argv.log"),
        "Y_MODE_LOG": str(work / "mode.log"),
        "BOOTSTRAP_VERIFIER": str(work / "stub" / "amnezia-verify-provisioning-native"),
        "SOURCE_PACKAGE_ROOT": str(work / "source"),
        "PRIVATE_INPUTS_ROOT": str(work / "private"),
        "PACKAGE_ROOT": str(work / "private" / "package"),
        "PUBLIC_KEY": str(work / "key.pem"),
        "VERIFIED_RECEIPT": str(work / "receipt.json"),
        "EXPECTED_KEY_SHA256": "11" * 32,
        "EXPECTED_MANIFEST_SHA256": "22" * 32,
        "EXPECTED_CHECKSUMS_SHA256": "33" * 32,
        "EXPECTED_SIGNED_MANIFEST_SHA256": "44" * 32,
        "ID": "ubuntu",
        "VERSION_ID": "24.04",
        "VERSION_CODENAME": "noble",
        "Y_VALIDATE_OUT": "validated package metadata (host probes deferred): 1.0.0.42\nruntime probe plan: 1 commands, 1 backend modes, 1 package entries (executed=false)",
        "Y_PROBE_OUT": '{"schema":1,"tool":"amnezia-headless-host-probe-v1","hostProbesExecuted":true,"requiredCommands":[{"name":"sh","present":true}],"backendModes":[{"mode":"wireguard","satisfied":true}],"packages":[{"minimum":"1.0","satisfied":true}],"architecture":"amd64","hostProbesPassed":true,"releaseAccepted":false}',
    }
    env.update(env_extra or {})
    proc = subprocess.run(
        ["/bin/bash", str(harness)], cwd=str(work), env=env,
        text=True, capture_output=True, timeout=30,
    )
    return proc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--subject", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=False)
    work = out_dir / "work"
    work.mkdir(mode=0o700)
    (work / "stub").mkdir(mode=0o700)
    stub = work / "stub" / "amnezia-verify-provisioning-native"
    stub.write_text(STUB, encoding="utf-8")
    stub.chmod(0o700)
    (work / "source").mkdir(mode=0o700)
    (work / "private").mkdir(mode=0o700)
    (work / "key.pem").write_text("test-only public key\n", encoding="utf-8")
    (work / "receipt.json").write_text("{}\n", encoding="utf-8")

    subject = pathlib.Path(args.subject).resolve()
    text = subject.read_text(encoding="utf-8")
    cases = []

    syntax = subprocess.run(["/bin/bash", "-n", str(subject)], text=True, capture_output=True)
    c = Case("production-syntax")
    cases.append(c)
    syntax_ok = c.record(syntax.returncode == 0, "bash -n exit %d %s" % (syntax.returncode, syntax.stderr.strip()))

    blocks = extract_functions(text)
    c = Case("extract-actual-consumer-blocks")
    cases.append(c)
    blocks_ok = c.record(
        set(blocks) == set(FUNCTIONS),
        "missing: %s" % sorted(set(FUNCTIONS) - set(blocks)) if set(blocks) != set(FUNCTIONS)
        else "extracted " + ",".join(FUNCTIONS),
    )

    # Behavioural cases only make sense when the actual blocks exist.
    argv_log = work / "argv.log"
    mode_log = work / "mode.log"

    def reset_logs():
        for path in (argv_log, mode_log):
            if path.exists():
                path.unlink()

    def case(name, fn):
        c = Case(name)
        cases.append(c)
        if not (syntax_ok and blocks_ok):
            c.record(False, "missing native consumer behaviour in subject (RED)")
            return
        reset_logs()
        fn(c)

    def stage_exact(c):
        proc = run_case(work, blocks, "y_consume_stage_inputs")
        calls = read_argv(argv_log)
        expected = [
            "--stage-inputs",
            "--source-root", str(work / "source"),
            "--private-root", str(work / "private"),
            "--public-key", str(work / "key.pem"),
            "--verified-receipt", str(work / "receipt.json"),
            "--expected-public-key-sha256", "11" * 32,
            "--expected-package-manifest-sha256", "22" * 32,
            "--expected-checksums-sha256", "33" * 32,
            "--expected-signed-manifest-sha256", "44" * 32,
        ]
        c.record(proc.returncode == 0 and calls == [expected],
                 "exit %d argv=%r stderr=%r" % (proc.returncode, calls[:1], proc.stderr.strip()[:200]))

    def stage_failure(c):
        proc = run_case(work, blocks, "y_consume_stage_inputs", {"Y_STAGE_RC": "1"})
        modes = read_modes(mode_log)
        c.record(proc.returncode == 3 and modes == ["--stage-inputs"]
                 and "failed to stage the private package inputs" in proc.stderr,
                 "exit %d modes=%r stderr=%r" % (proc.returncode, modes, proc.stderr.strip()[:200]))

    def metadata_exact(c):
        proc = run_case(work, blocks, "y_consume_metadata")
        calls = read_argv(argv_log)
        validate = [
            "--validate-package",
            "--package-root", str(work / "private" / "package"),
            "--receipt", str(work / "receipt.json"),
            "--public-key", str(work / "key.pem"),
            "--ubuntu-id", "ubuntu",
            "--ubuntu-version-id", "24.04",
            "--ubuntu-codename", "noble",
            "--expected-public-key-sha256", "11" * 32,
            "--expected-package-manifest-sha256", "22" * 32,
            "--expected-checksums-sha256", "33" * 32,
            "--expected-signed-manifest-sha256", "44" * 32,
        ]
        probe = [
            "--probe-host",
            "--runtime-manifest", str(work / "private" / "package" / "runtime-dependencies.json"),
            "--ubuntu-version-id", "24.04",
            "--ubuntu-codename", "noble",
        ]
        c.record(proc.returncode == 0 and read_modes(mode_log) == ["--validate-package", "--probe-host"]
                 and calls == [validate, probe] and "VERSION:1.0.0.42" in proc.stdout,
                 "exit %d modes=%r calls=%r stdout=%r" % (proc.returncode, read_modes(mode_log), calls, proc.stdout[-160:]))

    def validate_failure(c):
        proc = run_case(work, blocks, "y_consume_metadata", {"Y_VALIDATE_RC": "1"})
        c.record(proc.returncode == 3 and read_modes(mode_log) == ["--validate-package"]
                 and "rejected the package metadata or receipt" in proc.stderr,
                 "exit %d modes=%r stderr=%r" % (proc.returncode, read_modes(mode_log), proc.stderr.strip()[:200]))

    def probe_failure(c):
        proc = run_case(work, blocks, "y_consume_metadata", {"Y_PROBE_RC": "26"})
        c.record(proc.returncode == 3 and read_modes(mode_log) == ["--validate-package", "--probe-host"]
                 and "host probes did not pass" in proc.stderr,
                 "exit %d modes=%r stderr=%r" % (proc.returncode, read_modes(mode_log), proc.stderr.strip()[:200]))

    def probe_false_success(c):
        proc = run_case(work, blocks, "y_consume_metadata", {
            "Y_PROBE_OUT": '{"hostProbesPassed":false,"releaseAccepted":false}',
        })
        c.record(proc.returncode == 3 and "did not report host probes passed" in proc.stderr,
                 "exit %d stderr=%r" % (proc.returncode, proc.stderr.strip()[:200]))

    def invalid_version(c):
        proc = run_case(work, blocks, "y_consume_metadata", {
            "Y_VALIDATE_OUT": "validated package metadata (host probes deferred): 1.0.0",
        })
        c.record(proc.returncode == 3 and read_modes(mode_log) == ["--validate-package"]
                 and "invalid package version" in proc.stderr,
                 "exit %d modes=%r stderr=%r" % (proc.returncode, read_modes(mode_log), proc.stderr.strip()[:200]))

    def denied_boundary(c):
        proc = run_case(work, blocks, "y_stage_inputs")
        # run_case's harness itself refuses when python3/dpkg/sha256sum resolve.
        c.record(proc.returncode == 0 and read_argv(argv_log),
                 "exit %d argv-calls=%d stderr=%r" % (proc.returncode, len(read_argv(argv_log)), proc.stderr.strip()[:200]))

    def call_site_binding(c):
        stage = 'if [[ -n "$BOOTSTRAP_VERIFIER" ]]; then\n    y_consume_stage_inputs\nelif ! python3 -'
        metadata = 'if [[ -n "$BOOTSTRAP_VERIFIER" ]]; then\n    y_consume_metadata\n    PACKAGE_VERSION="$Y_PACKAGE_VERSION"\nelif ! PACKAGE_VERSION="$(python3'
        receipt = 'if [[ -z "$BOOTSTRAP_VERIFIER" ]]; then\nif ! python3 - "$VERIFIED_RECEIPT"'
        legacy_stage = 'elif ! python3 - "$SOURCE_PACKAGE_ROOT"'
        c.record(all(token in text for token in (stage, metadata, receipt, legacy_stage)),
                 "native guards and explicit legacy fallback text present")

    case("stage-inputs-exact-argv", stage_exact)
    case("stage-inputs-failure-no-fallback", stage_failure)
    case("validate-then-probe-exact-argv", metadata_exact)
    case("validate-failure-stops-before-probe", validate_failure)
    case("probe-failure-exit3", probe_failure)
    case("probe-false-success-refused", probe_false_success)
    case("invalid-native-version-refused", invalid_version)
    case("denied-path-boundary", denied_boundary)
    case("call-site-binding", call_site_binding)

    failures = [c for c in cases if not c.ok]
    result = {
        "schema": 1,
        "kind": "native-headless-installer-consumer-y",
        "label": args.label,
        "subject": str(subject),
        "subjectSha256": __import__("hashlib").sha256(subject.read_bytes()).hexdigest(),
        "startedUtc": started,
        "finishedUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cases": [{"case": c.name, "ok": c.ok, "detail": c.detail} for c in cases],
        "caseCount": len(cases),
        "failures": len(failures),
        "exit": 0 if not failures else 23,
        "modelNotActual": "Stub verifier observes real emitted argv and returns case-controlled output; no compiled native verifier ran and no native acceptance is claimed.",
        "productScriptExecuted": False,
    }
    (out_dir / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("RESULT %s cases=%d failures=%d exit=%d" % (args.label, len(cases), len(failures), result["exit"]))
    return result["exit"]


if __name__ == "__main__":
    sys.exit(main())
