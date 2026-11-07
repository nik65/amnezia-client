"""Real installer ELF-check fragment only; no installer/main/binary execution.

Python, native-helper and all external shell commands are fenced before Bash.
Only trusted /usr/bin/readelf and /usr/bin/grep read inert owned ELF data. Runtime
ldd/version/activation/service/transaction statements are excluded structurally.
This proves the pre-activation validation branch, not package or guest acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

PARSER = argparse.ArgumentParser()
PARSER.add_argument("--subject", type=Path, default=Path(__file__).with_name("install_headless.sh"))
PARSER.add_argument("--out", type=Path)
PARSER.add_argument("--work-exit", type=int)
OPTIONS, UNITTEST_ARGS = PARSER.parse_known_args()
SOURCE_BYTES = OPTIONS.subject.read_bytes()
SOURCE = SOURCE_BYTES.decode("utf-8")
SUBJECT_SHA = hashlib.sha256(SOURCE_BYTES).hexdigest()
OUTPUT = OPTIONS.out or Path(tempfile.mkdtemp(prefix="amnezia-elf-check-"))
if OPTIONS.out:
    OUTPUT.mkdir(mode=0o700, exist_ok=False)
START = SOURCE.index("for binary in amneziad amnezia-cli; do\n")
STOP = SOURCE.index('    if ! ldd_output="$(ldd ', START)
FRAGMENT = SOURCE[START:STOP] + "done\n"
if any(token in FRAGMENT for token in ("systemctl", "ldd ", "--version", "NATIVE_HELPER_ARGS=")):
    raise RuntimeError("source fragment crossed the static-check boundary")
(OUTPUT / "actual-fragment.sh").write_text(FRAGMENT)
CASES = []


def elf(machine=62, endian="<", elfclass=2):
    value = bytearray(256)
    value[:9] = bytes((127, 69, 76, 70, elfclass, 1 if endian == "<" else 2, 1, 0, 0))
    struct.pack_into(endian + "HHIQQQIHHHHHH", value, 16,
                     2, machine, 1, 0x400080, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into(endian + "IIQQQQQQ", value, 64,
                     1, 5, 0, 0x400000, 0, 256, 256, 4096)
    return bytes(value)


def exercise(name, data=None, native=False, native_exit=0, readelf_mode="actual"):
    directory = OUTPUT / name
    directory.mkdir(mode=0o700)
    for binary in ("amneziad", "amnezia-cli"):
        (directory / binary).write_bytes(data if data is not None else elf())
    trace = directory / "trace.txt"
    trace.touch(mode=0o600)
    # Functions are installed BEFORE the extracted actual statements execute.
    setup = r'''set -euo pipefail
PACKAGE_ROOT="$1"
TRACE="$2"
ELF_MODE="$3"
MOCK_NATIVE_EXIT="$4"
NATIVE_HELPER="$5"
python3() { printf 'FORBIDDEN_PYTHON\n' >> "$TRACE"; return 90; }
run_native_helper() {
    printf 'native:%s\n' "$1" >> "$TRACE"
    [[ "$1" == "verify-elf64-x86-64" ]] || return 91
    return "$MOCK_NATIVE_EXIT"
}
readelf() {
    printf 'readelf:%s\n' "${2:-}" >> "$TRACE"
    case "$ELF_MODE" in
        fail) return 2 ;;
        missing-machine) printf 'Class: ELF64\n'; return 0 ;;
        missing-class) printf 'Machine: Advanced Micro Devices X86-64\n'; return 0 ;;
        *) /usr/bin/readelf "$@" ;;
    esac
}
grep() { /usr/bin/grep "$@"; }
'''
    program = setup + FRAGMENT
    (directory / "evaluated.sh").write_text(program)
    value = subprocess.run(
        ["/bin/bash", "--noprofile", "--norc", "-c", program, "inert-elf-check",
         str(directory), str(trace), readelf_mode, str(native_exit), "/inert-selected-helper" if native else ""],
        env={"PATH": "/nonexistent", "LC_ALL": "C"},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False,
    )
    (directory / "stdout.bin").write_bytes(value.stdout)
    (directory / "stderr.bin").write_bytes(value.stderr)
    lines = trace.read_text().splitlines()
    CASES.append({"name": name, "native_exit": value.returncode,
                  "trace": lines, "data_sha256": hashlib.sha256((directory / "amnezia-cli").read_bytes()).hexdigest()})
    return value, lines


class InstallerStaticElfTests(unittest.TestCase):
    def check_case(self, name, data=None, native=False, native_exit=0,
                   readelf_mode="actual", expected=0, reads=2, native_calls=0):
        result, lines = exercise(name, data, native, native_exit, readelf_mode)
        self.assertEqual(result.returncode, expected, result.stderr.decode(errors="replace"))
        self.assertNotIn("FORBIDDEN_PYTHON", lines)
        self.assertEqual(sum(line.startswith("readelf:") for line in lines), reads)
        self.assertEqual(sum(line.startswith("native:") for line in lines), native_calls)

    def test_cli_little_endian_uses_only_mandatory_readelf(self):
        self.check_case("cli-little")

    def test_legacy_same_readelf_contract_remains(self):
        self.check_case("legacy-little")

    def test_big_endian_x64_historical_acceptance_is_preserved(self):
        self.check_case("big-endian", elf(endian=">"))

    def test_wrong_architecture_refused_before_second_binary(self):
        self.check_case("wrong-machine", elf(machine=183), expected=3, reads=1)

    def test_elf32_refused(self):
        self.check_case("elf32", elf(elfclass=1), expected=3, reads=1)

    def test_non_elf_refused(self):
        self.check_case("not-elf", b"inert malformed file", expected=3, reads=1)

    def test_truncated_header_refused(self):
        self.check_case("truncated", elf()[:19], expected=3, reads=1)

    def test_readelf_failure_never_falls_back_to_python(self):
        self.check_case("readelf-error", readelf_mode="fail", expected=3, reads=1)

    def test_missing_machine_output_refused(self):
        self.check_case("missing-machine", readelf_mode="missing-machine", expected=3, reads=1)

    def test_missing_class_output_refused(self):
        self.check_case("missing-class", readelf_mode="missing-class", expected=3, reads=1)

    def test_selected_standalone_helper_and_readelf_both_remain(self):
        self.check_case("standalone", native=True, native_calls=2)

    def test_selected_standalone_refusal_has_no_fallback(self):
        self.check_case("standalone-refuse", native=True, native_exit=33, expected=3, reads=0, native_calls=1)

    def test_readelf_remains_mandatory_before_runtime_and_cli_activation(self):
        requirements = SOURCE[SOURCE.index("for required in "):SOURCE.index("TRANSACTION_ROOT=")]
        self.assertIn("readelf", requirements)
        self.assertNotIn("python3", requirements)  # Native paths do not require an interpreter.
        self.assertIn("type -P python3", SOURCE)  # Explicit legacy requirement remains enforced.
        self.assertLess(START, STOP)
        self.assertLess(STOP, SOURCE.index('if ! version_output='))
        self.assertLess(SOURCE.index('if ! version_output='), SOURCE.index('NATIVE_HELPER="${BOOTSTRAP_HELPERS[amnezia-cli]}"'))
        self.assertIn('run_native_helper verify-elf64-x86-64 "$PACKAGE_ROOT/$binary"', FRAGMENT)
        self.assertIn("Class:[[:space:]]*ELF64", FRAGMENT)
        self.assertIn("Machine:[[:space:]]*Advanced Micro Devices X86-64", FRAGMENT)


if __name__ == "__main__":
    primary = None
    code = 1
    result = None
    try:
        if OPTIONS.work_exit is not None:
            raise SystemExit(OPTIONS.work_exit)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(InstallerStaticElfTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        code = 0 if result.wasSuccessful() else 1
    except BaseException as error:
        primary = error
        code = error.code if isinstance(error, SystemExit) and isinstance(error.code, int) else 1
    finally:
        unchanged = OPTIONS.subject.read_bytes() == SOURCE_BYTES
        if not unchanged:
            code = 1
        report = {"native_exit": code, "subject": str(OPTIONS.subject), "subject_sha256": SUBJECT_SHA,
                  "test_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  "subject_unchanged": unchanged, "tests_run": result.testsRun if result else 0,
                  "failures": len(result.failures) if result else 0, "errors": len(result.errors) if result else 0,
                  "injected_work_exit": OPTIONS.work_exit, "cases": CASES,
                  "scope": "actual static ELF fragment and inert helper/Python boundaries only",
                  "installer_or_product_or_helper_executed": False, "runtime_accepted": False}
        (OUTPUT / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"result": str(OUTPUT / "RESULT.json"), "native_exit": code,
                      "tests_run": report["tests_run"], "failures": report["failures"], "errors": report["errors"]}))
    raise SystemExit(code)
