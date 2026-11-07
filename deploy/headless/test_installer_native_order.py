"""Inert tests of real post-auth installer fragments, never installer execution.

Only the reviewed tree-check function, upgrade block and CLI activation block
are evaluated. Native execution and Python are replaced BEFORE the Bash child
starts; no package executable, filesystem/service operation or installer main
is run. Static checks bind the omitted authentication/runtime phase ordering.
This is a source wiring regression, not installed/runtime acceptance.
"""
import argparse
from pathlib import Path
import subprocess
import unittest


PARSER = argparse.ArgumentParser()
PARSER.add_argument("--subject", type=Path,
                    default=Path(__file__).with_name("install_headless.sh"))
OPTIONS, UNITTEST_ARGS = PARSER.parse_known_args()
SOURCE = OPTIONS.subject.read_text(encoding="utf-8")
TREE_BLOCK = '''if [[ "$MODE" == "upgrade" ]]; then
    for candidate in /var/lib/amnezia /run/amnezia /etc/amnezia /etc/amnezia/profiles; do
        verify_root_private_tree "$candidate" || exit 4
    done
fi
'''
CLI_START = SOURCE.index('if [[ "$NATIVE_HELPER_KIND" == "amnezia-cli" ]]; then\n')
CLI_END = SOURCE.index("\nfi\n", CLI_START) + len("\nfi\n")
CLI_BLOCK = SOURCE[CLI_START:CLI_END]
PATHS = ("/var/lib/amnezia", "/run/amnezia", "/etc/amnezia", "/etc/amnezia/profiles")


def fragments():
    if SOURCE.count(TREE_BLOCK) != 1 or SOURCE.count(CLI_BLOCK) != 1:
        raise ValueError("actual installer blocks are missing or ambiguous")
    start = SOURCE.index("verify_root_private_tree() {\n")
    end = SOURCE.index("\nPY\n}", start) + len("\nPY\n}")
    function = SOURCE[start:end]
    blocks = sorted((SOURCE.index(block), block) for block in (TREE_BLOCK, CLI_BLOCK))
    return function + "\n" + "".join(block for _, block in blocks)


def exercise(kind="amnezia-cli", mode="upgrade", native_exit=0, staged=True):
    # These are explicit post-auth fixture values, NOT real helper trust.
    setup = '''set -eu
PACKAGE_ROOT=/inert-authenticated-package
MODE="$1"
NATIVE_HELPER_KIND="$2"
NATIVE_HELPER=""
NATIVE_HELPER_ARGS=()
declare -A BOOTSTRAP_HELPERS=()
if [[ "$4" == 1 ]]; then
    BOOTSTRAP_HELPERS[amnezia-cli]="$PACKAGE_ROOT/bootstrap-helper/amnezia-cli"
    BOOTSTRAP_HELPERS[amnezia-headless-fs]="$PACKAGE_ROOT/bootstrap-helper/amnezia-headless-fs"
fi
if [[ "$NATIVE_HELPER_KIND" == "amnezia-headless-fs" ]]; then
    NATIVE_HELPER="${BOOTSTRAP_HELPERS[amnezia-headless-fs]:-}"
fi
MOCK_NATIVE_EXIT="$3"
run_native_helper() {
    printf 'NATIVE|%s|%s|%s|%s\\n' "$NATIVE_HELPER" "${NATIVE_HELPER_ARGS[0]:-}" "$1" "$2"
    return "$MOCK_NATIVE_EXIT"
}
require_legacy_python() { return 0; } # Explicit compatibility interpreter fixture.
python3() {
    printf 'PYTHON|%s\\n' "$2"
    return 0
}
'''
    return subprocess.run(
        ["/bin/bash", "--noprofile", "--norc", "-c", setup + fragments(),
         "inert-native-order", mode, kind, str(native_exit), "1" if staged else "0"],
        env={"PATH": "/nonexistent", "LC_ALL": "C"},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5,
        check=False,
    )


class InstallerNativeOrderTests(unittest.TestCase):
    def test_cli_upgrade_uses_actual_native_branch_for_each_tree(self):
        result = exercise()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "NATIVE|/inert-authenticated-package/bootstrap-helper/amnezia-cli|--provisioning-fs|"
            "verify-root-private-tree|" + path for path in PATHS
        ])

    def test_cli_missing_private_snapshot_refuses_before_tree_checks(self):
        result = exercise(staged=False)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("helper was not staged before package use", result.stderr)

    def test_native_refusal_stops_without_python_or_further_tree(self):
        result = exercise(native_exit=33)
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "NATIVE|/inert-authenticated-package/bootstrap-helper/amnezia-cli|--provisioning-fs|"
            "verify-root-private-tree|" + PATHS[0]
        ])

    def test_fresh_does_not_add_upgrade_tree_checks(self):
        result = exercise(mode="fresh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_legacy_fallback_remains_explicit(self):
        result = exercise(kind="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["PYTHON|" + path for path in PATHS])

    def test_already_authenticated_standalone_dispatch_is_preserved(self):
        result = exercise(kind="amnezia-headless-fs")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "NATIVE|/inert-authenticated-package/bootstrap-helper/amnezia-headless-fs||"
            "verify-root-private-tree|" + path for path in PATHS
        ])

    def test_cli_authentication_runtime_activation_tree_mutation_order(self):
        activation = SOURCE.index(CLI_BLOCK)
        tree = SOURCE.index(TREE_BLOCK)
        version = SOURCE.index("if ! version_output=")
        binary_loop = SOURCE.index("for binary in amneziad amnezia-cli; do")
        binary_end = SOURCE.index("done\n", binary_loop)
        for marker in ("native helper does not match authenticated checksums",
                       "supplied trust anchor fingerprint does not match"):
            self.assertLess(SOURCE.index(marker), activation)
        self.assertLess(version, binary_end)
        self.assertLess(binary_end, activation)
        self.assertGreater(tree, activation + len(CLI_BLOCK) - 1)
        first_service_state = SOURCE.index('SERVICE_WAS_ACTIVE=""', activation)
        mutation = SOURCE.index('install -d -o root -g root -m 0700 "$TRANSACTION_BASE"', activation)
        self.assertLess(tree + len(TREE_BLOCK), first_service_state)
        self.assertLess(tree + len(TREE_BLOCK), mutation)
        standalone = SOURCE.index('NATIVE_HELPER="${BOOTSTRAP_HELPERS[amnezia-headless-fs]}"')
        self.assertLess(standalone, tree)

    def test_current_activation_only_uses_authenticated_private_snapshots(self):
        self.assertIn('NATIVE_HELPER="${BOOTSTRAP_HELPERS[amnezia-cli]}"', CLI_BLOCK)
        self.assertIn('if [[ -z "${BOOTSTRAP_HELPERS[amnezia-cli]:-}" ]]', CLI_BLOCK)
        self.assertNotIn('NATIVE_HELPER="$PACKAGE_ROOT/', SOURCE)

    def test_all_available_native_operations_propagate_failure_without_python(self):
        # Execute actual full functions whose native branch precedes all work.
        # Backup validation also has preceding shell metadata checks: only its
        # literal native-dispatch tail is evaluated here, not ownership modeled
        # as real filesystem acceptance.
        operations = (
            ("fsync_path_directory", "fsync-directory", ["/inert/path"]),
            ("fsync_regular_path", "fsync-file", ["/inert/path"]),
            ("write_transaction_journal", "journal-write", ["prepared"]),
            ("read_transaction_journal", "journal-recovery-read", []),
            ("verify_root_private_tree", "verify-root-private-tree", ["/inert/path"]),
            ("verify_recovery_backup", "journal-validate-backup", []),
        )
        for name, command, arguments in operations:
            start = SOURCE.index(name + "() {\n")
            end = SOURCE.index("\nPY\n}", start) + len("\nPY\n}")
            function = SOURCE[start:end]
            if name == "verify_recovery_backup":
                start = function.index('    if [[ -n "$NATIVE_HELPER" ]]; then\n')
                end = function.index('    python3 - ', start)
                function = name + "() {\n" + function[start:end] + "    return 91\n}\n"
            for native_exit in (0, 23):
                with self.subTest(operation=command, native_exit=native_exit):
                    fixture = r'''set -eu
NATIVE_HELPER=/inert-authenticated-private-snapshot/amnezia-cli
NATIVE_HELPER_ARGS=(--provisioning-fs)
TRANSACTION_JOURNAL=/inert/journal.json
run_native_helper() {
    printf 'NATIVE|%s\n' "$1"
    return "$MOCK_NATIVE_EXIT"
}
python3() { printf 'PYTHON_CALLED\n'; return 92; }
'''
                    script = fixture + function + "\n" + name + ' "$@"\n'
                    result = subprocess.run(
                        ["/bin/bash", "--noprofile", "--norc", "-c", script,
                         "inert-native-dispatch", *arguments],
                        env={"PATH": "/nonexistent", "LC_ALL": "C",
                             "MOCK_NATIVE_EXIT": str(native_exit)},
                        capture_output=True, text=True, timeout=5, check=False)
                    self.assertEqual(result.returncode, native_exit, result.stdout + result.stderr)
                    self.assertEqual(result.stdout, "NATIVE|" + command + "\n")
                    self.assertNotIn("PYTHON_CALLED", result.stdout + result.stderr)

    def test_dispatch_still_propagates_native_failure_without_fallback(self):
        function = fragments().split(TREE_BLOCK, 1)[0]
        self.assertIn('run_native_helper verify-root-private-tree "$1"\n        return $?', function)
        self.assertIn('python3 - "$1"', function)


if __name__ == "__main__":
    unittest.main(argv=[str(Path(__file__)), *UNITTEST_ARGS], verbosity=2)
