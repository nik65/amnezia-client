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
CLI_BLOCK = '''if [[ "$NATIVE_HELPER_KIND" == "amnezia-cli" ]]; then
    # Explicit authenticated package capability; never probe an old CLI and
    # silently fall back. Both binaries passed static/runtime checks above.
    NATIVE_HELPER="$PACKAGE_ROOT/amnezia-cli"
    NATIVE_HELPER_ARGS=(--provisioning-fs)
fi
'''
PATHS = ("/var/lib/amnezia", "/run/amnezia", "/etc/amnezia", "/etc/amnezia/profiles")


def fragments():
    if SOURCE.count(TREE_BLOCK) != 1 or SOURCE.count(CLI_BLOCK) != 1:
        raise ValueError("actual installer blocks are missing or ambiguous")
    start = SOURCE.index("verify_root_private_tree() {\n")
    end = SOURCE.index("\nPY\n}", start) + len("\nPY\n}")
    function = SOURCE[start:end]
    blocks = sorted((SOURCE.index(block), block) for block in (TREE_BLOCK, CLI_BLOCK))
    return function + "\n" + "".join(block for _, block in blocks)


def exercise(kind="amnezia-cli", mode="upgrade", native_exit=0):
    # These are explicit post-auth fixture values, NOT real helper trust.
    setup = '''set -eu
PACKAGE_ROOT=/inert-authenticated-package
MODE="$1"
NATIVE_HELPER_KIND="$2"
NATIVE_HELPER=""
NATIVE_HELPER_ARGS=()
if [[ "$NATIVE_HELPER_KIND" == "amnezia-headless-fs" ]]; then
    NATIVE_HELPER="$PACKAGE_ROOT/amnezia-headless-fs"
fi
MOCK_NATIVE_EXIT="$3"
run_native_helper() {
    printf 'NATIVE|%s|%s|%s|%s\\n' "$NATIVE_HELPER" "${NATIVE_HELPER_ARGS[0]:-}" "$1" "$2"
    return "$MOCK_NATIVE_EXIT"
}
python3() {
    printf 'PYTHON|%s\\n' "$2"
    return 0
}
'''
    return subprocess.run(
        ["/bin/bash", "--noprofile", "--norc", "-c", setup + fragments(),
         "inert-native-order", mode, kind, str(native_exit)],
        env={"PATH": "/nonexistent", "LC_ALL": "C"},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5,
        check=False,
    )


class InstallerNativeOrderTests(unittest.TestCase):
    def test_cli_upgrade_uses_actual_native_branch_for_each_tree(self):
        result = exercise()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "NATIVE|/inert-authenticated-package/amnezia-cli|--provisioning-fs|"
            "verify-root-private-tree|" + path for path in PATHS
        ])

    def test_native_refusal_stops_without_python_or_further_tree(self):
        result = exercise(native_exit=33)
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "NATIVE|/inert-authenticated-package/amnezia-cli|--provisioning-fs|"
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
            "NATIVE|/inert-authenticated-package/amnezia-headless-fs||"
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
        standalone = SOURCE.index('NATIVE_HELPER="$PACKAGE_ROOT/amnezia-headless-fs"')
        self.assertLess(standalone, tree)

    def test_dispatch_still_propagates_native_failure_without_fallback(self):
        function = fragments().split(TREE_BLOCK, 1)[0]
        self.assertIn('run_native_helper verify-root-private-tree "$1"\n        return $?', function)
        self.assertIn('python3 - "$1"', function)


if __name__ == "__main__":
    unittest.main(argv=[str(Path(__file__)), *UNITTEST_ARGS], verbosity=2)
