"""Inert tests of authenticated metadata consumption, never installer execution.

Only the actual metadata-consumer function and role-selection fragment run.
Verifier/probe/Python commands are replaced with shell fixtures before Bash
starts. No packaged executable, installer main, compiler, host probe, service,
or VPN operation runs. Native producer wiring is checked as source only.
"""
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "deploy/headless/install_headless.sh").read_text(encoding="utf-8")
PRODUCER = (ROOT / "deploy/headless/native/provisioning_verifier/preauth_modes.cpp").read_text(
    encoding="utf-8")
VERSION = "validated package metadata (host probes deferred): 1.2.3.4"
ROLE = "validated native helper role: "


def source_fragments():
    start = SOURCE.index("y_consume_metadata() {\n")
    end = SOURCE.index("\n}\n", start) + len("\n}\n")
    consumer = SOURCE[start:end]
    start = SOURCE.index('if [[ -n "$BOOTSTRAP_VERIFIER" ]]; then\n'
                         '    NATIVE_HELPER_KIND="$Y_NATIVE_HELPER_KIND"\n')
    end = SOURCE.index('if [[ "$NATIVE_HELPER_KIND" == "amnezia-headless-fs" ]]; then', start)
    return consumer, SOURCE[start:end]


def exercise(metadata, *, metadata_exit=0, metadata_stderr="", probe_exit=0,
             native=True, legacy_role="", legacy_exit=0):
    consumer, selection = source_fragments()
    fixture = r'''set -eu
y_validate_package() {
    printf '%s' "$METADATA_STDOUT"
    printf '%s' "$METADATA_STDERR" >&2
    return "$METADATA_EXIT"
}
y_probe_host() {
    printf 'PROBE_CALLED\n' >&2
    printf '{"hostProbesPassed":true,"releaseAccepted":false}\n'
    return "$PROBE_EXIT"
}
python3() {
    printf 'PYTHON_CALLED\n' >&2
    printf '%s\n' "$LEGACY_ROLE"
    return "$LEGACY_EXIT"
}
PACKAGE_ROOT=/inert-package
Y_PACKAGE_VERSION=not-consumed
'''
    script = fixture + consumer + '\nif [[ -n "$BOOTSTRAP_VERIFIER" ]]; then\n' \
        + '    y_consume_metadata\nfi\n' + selection \
        + '\nprintf "RESULT|%s|%s\\n" "$Y_PACKAGE_VERSION" "$NATIVE_HELPER_KIND"\n'
    return subprocess.run(
        ["/bin/bash", "--noprofile", "--norc", "-c", script],
        env={"PATH": "/nonexistent", "LC_ALL": "C", "METADATA_STDOUT": metadata,
             "METADATA_STDERR": metadata_stderr, "METADATA_EXIT": str(metadata_exit),
             "PROBE_EXIT": str(probe_exit), "BOOTSTRAP_VERIFIER": "inert" if native else "",
             "LEGACY_ROLE": legacy_role, "LEGACY_EXIT": str(legacy_exit)},
        capture_output=True, text=True, timeout=5, check=False)


class InstallerNativeRoleTests(unittest.TestCase):
    def test_native_roles_bypass_python_and_none_does_not_activate_a_helper(self):
        for role, expected in (("none", ""), ("amnezia-headless-fs", "amnezia-headless-fs"),
                               ("amnezia-cli", "amnezia-cli")):
            with self.subTest(role=role):
                result = exercise(VERSION + "\n" + ROLE + role)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "RESULT|1.2.3.4|" + expected + "\n")
                self.assertNotIn("PYTHON_CALLED", result.stderr)
                self.assertEqual(result.stderr.count("PROBE_CALLED"), 1)

    def test_missing_unknown_duplicate_or_noncanonical_roles_fail_without_fallback(self):
        cases = [VERSION, VERSION + "\n" + ROLE,
                 VERSION + "\n" + ROLE + "unknown",
                 VERSION + "\n" + ROLE + "amnezia-cli trailing-data",
                 VERSION + "\n" + ROLE + "amnezia-cli\r",
                 VERSION + "\nprefix " + ROLE + "amnezia-cli",
                 VERSION + "\n" + ROLE + "amnezia-cli\n" + ROLE + "amnezia-cli",
                 VERSION + "\n" + ROLE + "none\n" + ROLE + "amnezia-cli"]
        for metadata in cases:
            with self.subTest(metadata=metadata):
                result = exercise(metadata)
                self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
                self.assertNotIn("RESULT|", result.stdout)
                self.assertNotIn("PYTHON_CALLED", result.stderr)
                self.assertNotIn("PROBE_CALLED", result.stderr)

    def test_old_native_verifier_without_role_is_rejected(self):
        result = exercise(VERSION + "\nruntime probe plan: 1 commands (executed=false)")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertNotIn("PYTHON_CALLED", result.stderr)

    def test_stderr_cannot_supply_or_replace_the_role(self):
        result = exercise(VERSION, metadata_stderr=ROLE + "amnezia-cli\n")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        result = exercise(VERSION + "\n" + ROLE + "none",
                          metadata_stderr=ROLE + "amnezia-cli\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "RESULT|1.2.3.4|\n")

    def test_failed_validation_cannot_activate_a_printed_role_or_probe(self):
        result = exercise(VERSION + "\n" + ROLE + "amnezia-cli", metadata_exit=23)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertNotIn("RESULT|", result.stdout)
        self.assertNotIn("PROBE_CALLED", result.stderr)
        self.assertNotIn("PYTHON_CALLED", result.stderr)

    def test_failed_host_probe_does_not_allow_role_consumption(self):
        result = exercise(VERSION + "\n" + ROLE + "amnezia-cli", probe_exit=23)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertNotIn("RESULT|", result.stdout)
        self.assertNotIn("PYTHON_CALLED", result.stderr)

    def test_missing_duplicate_or_invalid_version_fails_before_probe(self):
        for version in ("", VERSION + "\n" + VERSION, VERSION + " extra", "prefix " + VERSION):
            with self.subTest(version=version):
                result = exercise(version + "\n" + ROLE + "amnezia-cli")
                self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
                self.assertNotIn("PROBE_CALLED", result.stderr)

    def test_legacy_packages_keep_explicit_python_reader_and_role_allowlist(self):
        for role in ("", "amnezia-cli", "amnezia-headless-fs"):
            with self.subTest(role=role):
                result = exercise("", native=False, legacy_role=role)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "RESULT|not-consumed|" + role + "\n")
                self.assertEqual(result.stderr.count("PYTHON_CALLED"), 1)
                self.assertNotIn("PROBE_CALLED", result.stderr)
        result = exercise("", native=False, legacy_role="unknown")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        result = exercise("", native=False, legacy_role="amnezia-cli", legacy_exit=23)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)

    def test_producer_role_record_follows_all_pinned_validations(self):
        start = PRODUCER.index("int run_validate_package(")
        end = PRODUCER.index("\nvoid print_mode_usage(", start)
        function = PRODUCER[start:end]
        record = function.index('std::printf("validated native helper role: %s\\n",')
        self.assertEqual(function.count("validated native helper role:"), 1)
        for marker in ("require_package_manifest_contract(manifest)",
                       "require_receipt_identity(", "require_checksums(package_root, covered)",
                       'fail("native helper/CLI mode is not exactly 0755")',
                       'fail("native verifier does not match the signed role binding")',
                       "write_receipt(receipt_out, output)"):
            self.assertLess(function.index(marker), record)
        self.assertIn('native_helper.empty() ? "none" : native_helper.c_str()', function)
        contract_start = PRODUCER.index("void require_package_manifest_contract(")
        self.assertLess(contract_start, start)
        contract = PRODUCER[contract_start:start]
        self.assertIn("native->text != kNativeHelper && native->text != kNativeCli", contract)


if __name__ == "__main__":
    unittest.main(verbosity=2)
