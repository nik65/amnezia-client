"""Actual shell loader/producer fragments on owned filesystem fixtures.

The production constants are replaced ONLY in this test's extracted functions.
A stat shim models UID0 for the fixture and its ancestors; types, modes, sizes,
inodes, links, hashes, flock and the inert protocol worker use real OS calls.
No installer main, global path, service or VPN operation runs. This proves source
wiring/OS behavior under that ownership model, never genuine root acceptance.
"""
import argparse
import hashlib
from pathlib import Path
import os
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "deploy/headless/install_headless.sh").read_text(encoding="utf-8")
ANCHOR_ROOT = "/var/lib/amnezia-headless-provisioning/native-anchor"
LOCK_PATH = "/var/lib/amnezia/updates/update.lock"
PARSER = argparse.ArgumentParser()
PARSER.add_argument("--fixture-root", type=Path, default=ROOT.parent,
                    help="Owned test-policy parent; never a production root override")
OPTIONS, UNITTEST_ARGS = PARSER.parse_known_args()
OPTIONS.fixture_root.mkdir(parents=True, exist_ok=True)


def function(name):
    marker = name + "() {\n"
    if SOURCE.count(marker) != 1:
        raise ValueError("missing/ambiguous actual function: " + name)
    start = SOURCE.index(marker)
    end = SOURCE.index("\n}\n", start) + len("\n}\n")
    return SOURCE[start:end]


STAT_SHIM = r'''
stat() {
    local result path format uid
    result="$(/usr/bin/stat "$@")" || return $?
    format="$2"
    path="${@: -1}"
    # Only this fixture subtree, its explicit ancestors and inherited fixture
    # fd9 participate in the UID model. Every other metadata field is real.
    if [[ "$path" == "$FIXTURE_BASE" || "$path" == "$FIXTURE_BASE/"* || "$path" == /proc/self/fd/9 || "$FIXTURE_BASE/" == "$path/"* || "$path" == / ]]; then
        uid=0
        [[ "$path" != "$WRONG_OWNER_PATH" ]] || uid=42
        if [[ "$format" == %u ]]; then
            result="$uid"
        elif [[ "$format" == %u:* ]]; then
            result="$uid:${result#*:}"
        elif [[ "$format" == '%d:%i:%s:%u:%a:%h' ]]; then
            local dev inode size owner mode links
            IFS=: read -r dev inode size owner mode links <<< "$result"
            result="$dev:$inode:$size:$uid:$mode:$links"
        fi
    fi
    printf '%s\n' "$result"
}
python3() { printf 'UNEXPECTED_PYTHON_FALLBACK' >&2; return 93; }
'''


class InstallerAnchorTests(unittest.TestCase):
    def fixture(self, *, protocol="headless-journal-v1\n", worker_exit=0, present=True):
        temporary = tempfile.TemporaryDirectory(prefix="anchor-shell-fixture-", dir=OPTIONS.fixture_root)
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        base.chmod(0o700)
        namespace = base / "namespace"
        namespace.mkdir(mode=0o700)
        anchor = namespace / "native-anchor"
        lock_parent = base / "transaction" / "updates"
        lock_parent.mkdir(mode=0o700, parents=True)
        lock_parent.parent.chmod(0o700)
        lock = lock_parent / "update.lock"
        lock.write_bytes(b"")
        lock.chmod(0o600)
        marker = base / "WORKER_EXECUTED"
        if present:
            anchor.mkdir(mode=0o700)
            data = ("#!/bin/sh\nprintf called >> " + shlex.quote(str(marker)) + "\n"
                    "[ \"$1\" = --provisioning-fs ] && [ \"$2\" = journal-protocol ] || exit 94\n"
                    "printf '" + "".join("\\%03o" % byte for byte in protocol.encode())
                    + "'\nexit " + str(worker_exit) + "\n").encode()
            digest = hashlib.sha256(data).hexdigest()
            generation = anchor / ("payload-" + digest)
            generation.mkdir(mode=0o700)
            worker = generation / "worker"
            worker.write_bytes(data)
            worker.chmod(0o700)
            pin = generation / "PIN"
            pin.write_text(digest + "\n")
            pin.chmod(0o600)
            current = anchor / "CURRENT"
            current.write_text("headless-journal-v1\n" + digest + "\n")
            current.chmod(0o600)
        return dict(base=base, anchor=anchor, lock=lock, marker=marker)

    def load(self, fixture, *, wrong_owner="", descriptor="valid", source_override="/inert-untrusted-source", limit_zero=False, without_python=False, recovery_entry=False, preexisting_journal=False):
        helpers = function("verify_native_anchor_file") + function("load_native_recovery_anchor")
        # Deliberate fixture policy translation, not a production override API.
        self.assertEqual(helpers.count("local anchor_root=" + ANCHOR_ROOT), 1)
        self.assertEqual(helpers.count("local lock_path=" + LOCK_PATH), 1)
        helpers = helpers.replace("local anchor_root=" + ANCHOR_ROOT,
                                  "local anchor_root=" + shlex.quote(str(fixture["anchor"])))
        helpers = helpers.replace("local lock_path=" + LOCK_PATH,
                                  "local lock_path=" + shlex.quote(str(fixture["lock"])))
        setup = r'''set -eu
exec 9<>"$FIXTURE_LOCK"
flock -n 9
if [[ "$DESCRIPTOR" == missing ]]; then exec 9>&-; fi
if [[ "$DESCRIPTOR" == mismatch ]]; then
    : > "$FIXTURE_BASE/other-lock"
    chmod 600 "$FIXTURE_BASE/other-lock"
    exec 9<>"$FIXTURE_BASE/other-lock"
fi
if [[ "$LIMIT_ZERO" == 1 ]]; then ulimit -S -f 0; ulimit -H -f 0; fi
NATIVE_HELPER=/stale-helper-must-be-cleared
NATIVE_HELPER_ARGS=(stale-prefix)
'''
        if preexisting_journal:
            (fixture["lock"].parent.parent / ".headless-provisioning-journal.json").write_text("inert existing journal")
        if recovery_entry:
            start = SOURCE.index('if [[ "$RECOVER_ONLY" -eq 1 || -e "$TRANSACTION_JOURNAL" || -L "$TRANSACTION_JOURNAL" ]]; then\n')
            end = SOURCE.index("\nfi\n", start) + len("\nfi\n")
            entry = SOURCE[start:end]
        else:
            entry = "load_native_recovery_anchor\n"
        script = setup + STAT_SHIM + function("require_legacy_python") + helpers + entry + r'''
printf 'LOADED|%s|%s\n' "$NATIVE_HELPER" "${NATIVE_HELPER_ARGS[*]}"
'''
        environment = dict(os.environ, FIXTURE_BASE=str(fixture["base"]),
            FIXTURE_LOCK=str(fixture["lock"]), WRONG_OWNER_PATH=str(wrong_owner),
            DESCRIPTOR=descriptor, LIMIT_ZERO="1" if limit_zero else "0", SOURCE_PACKAGE_ROOT=source_override,
            PACKAGE_ROOT=source_override, AMNEZIA_HEADLESS_NATIVE_ANCHOR=source_override,
            RECOVER_ONLY="0" if preexisting_journal else "1",
            TRANSACTION_JOURNAL=str(fixture["lock"].parent.parent / ".headless-provisioning-journal.json"))
        if without_python:
            tools = fixture["base"] / "tools-without-python"
            tools.mkdir()
            for name in ("flock", "chmod", "sha256sum", "awk", "mktemp", "rm", "cmp"):
                (tools / name).symlink_to(Path("/usr/bin") / name)
            environment["PATH"] = str(tools)
        result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", script],
                                env=environment, capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(list(fixture["anchor"].glob(".protocol-check.*")), [])
        return result

    def test_valid_owned_fixture_uses_pinned_worker_and_fixed_prefix(self):
        fixture = self.fixture()
        result = self.load(fixture)
        self.assertEqual(result.returncode, 0, result.stderr)
        worker = next(fixture["anchor"].glob("payload-*/worker"))
        self.assertEqual(result.stdout, "LOADED|" + str(worker) + "|--provisioning-fs\n")
        self.assertEqual(fixture["marker"].read_text(), "called")
        self.assertNotIn("UNEXPECTED_PYTHON_FALLBACK", result.stderr)

    def test_absence_is_explicit_legacy_and_clears_stale_native_selection(self):
        fixture = self.fixture(present=False)
        result = self.load(fixture)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "LOADED||\n")
        self.assertFalse(fixture["marker"].exists())

    def test_partial_malformed_or_untrusted_anchor_refuses_before_execution(self):
        for defect in ("missing-current", "bad-header", "extra-line", "pin-mismatch",
                       "worker-bytes", "worker-mode", "current-mode", "hardlink", "owner",
                       "current-final-nul", "pin-final-nul"):
            with self.subTest(defect=defect):
                fixture = self.fixture()
                current = fixture["anchor"] / "CURRENT"
                worker = next(fixture["anchor"].glob("payload-*/worker"))
                pin = worker.parent / "PIN"
                wrong_owner = ""
                if defect == "missing-current": current.unlink()
                if defect == "bad-header": current.write_text(current.read_text().replace("-v1", "-v2"))
                if defect == "extra-line": current.write_text(current.read_text() + "\n")
                if defect == "pin-mismatch": pin.write_text("0" * 64 + "\n")
                if defect == "current-final-nul": current.write_bytes(current.read_bytes()[:-1] + b"\0")
                if defect == "pin-final-nul": pin.write_bytes(pin.read_bytes()[:-1] + b"\0")
                if defect == "worker-bytes": worker.write_bytes(worker.read_bytes() + b"changed")
                if defect == "worker-mode": worker.chmod(0o755)
                if defect == "current-mode": current.chmod(0o644)
                if defect == "hardlink": os.link(current, fixture["base"] / "current-alias")
                if defect == "owner": wrong_owner = worker
                result = self.load(fixture, wrong_owner=wrong_owner)
                self.assertEqual(result.returncode, 5, result.stdout + result.stderr)
                self.assertFalse(fixture["marker"].exists())
                self.assertNotIn("UNEXPECTED_PYTHON_FALLBACK", result.stderr)

    def test_symlinks_in_generation_or_anchor_ancestors_refuse(self):
        for defect in ("worker", "PIN", "CURRENT", "generation", "namespace"):
            with self.subTest(defect=defect):
                fixture = self.fixture()
                generation = next(fixture["anchor"].glob("payload-*"))
                target = (generation / defect if defect in ("worker", "PIN") else
                          fixture["anchor"] / "CURRENT" if defect == "CURRENT" else
                          generation if defect == "generation" else fixture["anchor"].parent)
                moved = fixture["base"] / ("moved-" + defect)
                target.rename(moved)
                target.symlink_to(moved, target_is_directory=moved.is_dir())
                result = self.load(fixture)
                self.assertEqual(result.returncode, 5, result.stdout + result.stderr)
                self.assertFalse(fixture["marker"].exists())

    def test_inherited_descriptor_is_required_before_worker_execution(self):
        for descriptor in ("missing", "mismatch"):
            with self.subTest(descriptor=descriptor):
                fixture = self.fixture()
                result = self.load(fixture, descriptor=descriptor)
                self.assertEqual(result.returncode, 5, result.stdout + result.stderr)
                self.assertFalse(fixture["marker"].exists())

    def test_authenticated_protocol_refusal_or_extra_stdout_never_falls_back(self):
        for protocol, code in (("headless-journal-v2\n", 0), ("headless-journal-v1\n\n", 0),
                               ("headless-journal-v1\n", 23), ("headless-journal-v1\n\0", 0),
                               ("X" * 2048, 0)):
            with self.subTest(protocol=protocol, code=code):
                fixture = self.fixture(protocol=protocol, worker_exit=code)
                result = self.load(fixture)
                self.assertEqual(result.returncode, 5, result.stdout + result.stderr)
                self.assertEqual(fixture["marker"].read_text(), "called")
                self.assertNotIn("UNEXPECTED_PYTHON_FALLBACK", result.stderr)

    def test_native_recovery_does_not_require_python_but_legacy_recovery_does(self):
        for preexisting in (False, True):
            with self.subTest(preexisting_journal=preexisting):
                native = self.fixture()
                result = self.load(native, without_python=True, recovery_entry=True,
                                   preexisting_journal=preexisting)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(native["marker"].read_text(), "called")
                legacy = self.fixture(present=False)
                result = self.load(legacy, without_python=True, recovery_entry=True,
                                   preexisting_journal=preexisting)
                self.assertEqual(result.returncode, 5, result.stdout + result.stderr)
                self.assertIn("python3 is required for the selected legacy", result.stderr)
                self.assertFalse(legacy["marker"].exists())
                if preexisting:
                    journal = legacy["lock"].parent.parent / ".headless-provisioning-journal.json"
                    self.assertEqual(journal.read_text(), "inert existing journal")

    def test_invalid_native_never_tries_legacy_even_without_python(self):
        fixture = self.fixture()
        (fixture["anchor"] / "CURRENT").write_bytes(b"invalid record")
        result = self.load(fixture, without_python=True, recovery_entry=True,
                           preexisting_journal=True)
        self.assertEqual(result.returncode, 5, result.stdout + result.stderr)
        self.assertIn("refusing legacy fallback", result.stderr)
        self.assertNotIn("python3 is required", result.stderr)
        self.assertFalse(fixture["marker"].exists())

    def test_staging_native_selection_skips_missing_python_and_refusal_never_falls_back(self):
        marker = 'if [[ -z "$BOOTSTRAP_VERIFIER" ]]; then\n    require_legacy_python || exit 3\nfi\n'
        self.assertEqual(SOURCE.count(marker), 1)
        for native, exit_code in ((False, 0), (True, 0), (True, 23)):
            with self.subTest(native=native, exit_code=exit_code):
                script = ("set -eu\n" + function("require_legacy_python")
                          + function("y_consume_stage_inputs") + marker
                          + 'if [[ -n "$BOOTSTRAP_VERIFIER" ]]; then y_consume_stage_inputs; fi\n'
                          + "printf STAGE_READY\n")
                fixture = 'y_stage_inputs() { return "$NATIVE_EXIT"; }\n'
                result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", fixture + script],
                    env={"PATH": "/nonexistent", "BOOTSTRAP_VERIFIER": "native" if native else "",
                         "NATIVE_EXIT": str(exit_code)}, capture_output=True, text=True,
                    timeout=5, check=False)
                self.assertEqual(result.returncode, 0 if native and exit_code == 0 else 3,
                                 result.stdout + result.stderr)
                if native:
                    self.assertNotIn("python3 is required", result.stderr)

    def test_canonical_runtime_python_requirement_matches_verifier_and_cli_variant(self):
        builder = (ROOT / "deploy/headless/build_headless_release.sh").read_text()
        manifest_start = builder.index('cat > "$PACKAGE_DIR/package-manifest.json" <<EOF\n')
        manifest_end = builder.index("\nEOF\n", manifest_start) + len("\nEOF\n")
        runtime_start = builder.index("RUNTIME_PYTHON_COMMAND=")
        runtime_end = builder.index("\nEOF\n", runtime_start) + len("\nEOF\n")
        fragment = builder[manifest_start:manifest_end] + builder[runtime_start:runtime_end]
        self.assertNotIn("cmake ", fragment)
        results = []
        for native in (False, True):
            fixture = self.fixture(present=False)
            package = fixture["base"] / "package"
            package.mkdir()
            verifier_field = (',"nativeVerifier":{"path":"amnezia-verify-provisioning-native",'
                              '"sha256":"' + "a" * 64 + '","size":1}') if native else ""
            result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", "set -eu\n" + fragment],
                env=dict(os.environ, PACKAGE_DIR=str(package), VERSION="9.9.9.9",
                         NATIVE_VERIFIER_FIELD=verifier_field), capture_output=True, text=True,
                timeout=5, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            import json
            manifest = json.loads((package / "package-manifest.json").read_text())
            runtime = json.loads((package / "runtime-dependencies.json").read_text())
            self.assertEqual(manifest["nativeHelper"], "amnezia-cli")
            self.assertEqual("nativeVerifier" in manifest, native)
            self.assertEqual("python3" in runtime["commands"]["required"], not native)
            results.append(runtime)
        results[0]["commands"]["required"].remove("python3")
        self.assertEqual(results[0], results[1])

    def test_protocol_capture_limit_failure_never_executes_worker(self):
        fixture = self.fixture()
        result = self.load(fixture, limit_zero=True)
        self.assertEqual(result.returncode, 5, result.stdout + result.stderr)
        self.assertFalse(fixture["marker"].exists())

    def test_transaction_root_safe_modes_have_explicit_success_status(self):
        for mode, expected in ((0o700, 0), (0o755, 0), (0o770, 1), (0o757, 1)):
            with self.subTest(mode=oct(mode)):
                fixture = self.fixture(present=False)
                transaction_root = fixture["lock"].parent.parent
                transaction_root.chmod(mode)
                script = STAT_SHIM + function("verify_transaction_root") + "\nverify_transaction_root\n"
                result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", script],
                    env=dict(os.environ, FIXTURE_BASE=str(fixture["base"]), WRONG_OWNER_PATH="",
                             TRANSACTION_ROOT=str(transaction_root)),
                    capture_output=True, text=True, timeout=5, check=False)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertFalse(fixture["marker"].exists())

    def producer(self, *, kind="amnezia-cli", pin="a" * 64, native_exit=0, mismatch=False):
        body = function("install_native_recovery_anchor")
        start = SOURCE.index("if ! install_native_recovery_anchor; then\n")
        end = SOURCE.index("\nfi\n", start) + len("\nfi\n")
        guard = SOURCE[start:end]
        setup = r'''set -eu
declare -A BOOTSTRAP_HELPERS=([amnezia-cli]=/inert-authenticated-bootstrap/amnezia-cli)
declare -A BOOTSTRAP_HELPER_DIGESTS=([amnezia-cli]="$TEST_PIN")
NATIVE_HELPER="${BOOTSTRAP_HELPERS[amnezia-cli]}"
[[ "$MISMATCH" != 1 ]] || NATIVE_HELPER=/inert-untrusted-source/amnezia-cli
NATIVE_HELPER_KIND="$TEST_KIND"
NATIVE_HELPER_ARGS=(--provisioning-fs)
run_native_helper() { printf 'NATIVE|%s|%s|%s\n' "$1" "$2" "$3"; return "$NATIVE_EXIT"; }
python3() { printf 'UNEXPECTED_PYTHON_FALLBACK' >&2; return 93; }
sha256sum() { printf 'UNEXPECTED_SELF_HASH_AUTHORITY' >&2; return 94; }
'''
        return subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c",
            setup + body + guard + "printf 'FIRST_JOURNAL_WOULD_START\\n'\n"],
            env=dict(os.environ, TEST_KIND=kind, TEST_PIN=pin, NATIVE_EXIT=str(native_exit),
                     MISMATCH="1" if mismatch else "0"), capture_output=True, text=True, timeout=5, check=False)

    def test_late_producer_passes_retained_independent_pin(self):
        result = self.producer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "NATIVE|anchor-install|/inert-authenticated-bootstrap/amnezia-cli|"
                         + "a" * 64 + "\nFIRST_JOURNAL_WOULD_START\n")

    def test_failed_late_producer_refuses_before_any_journal_without_fallback(self):
        for options in ({"native_exit": 23}, {"pin": ""}, {"pin": "A" * 64}, {"mismatch": True}):
            with self.subTest(options=options):
                result = self.producer(**options)
                self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
                self.assertNotIn("FIRST_JOURNAL_WOULD_START", result.stdout)
                self.assertNotIn("UNEXPECTED_PYTHON_FALLBACK", result.stderr)
                self.assertNotIn("UNEXPECTED_SELF_HASH_AUTHORITY", result.stderr)

    def test_legacy_roles_do_not_infer_new_cli_storage_capability(self):
        for kind in ("", "amnezia-headless-fs"):
            with self.subTest(kind=kind):
                result = self.producer(kind=kind)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "FIRST_JOURNAL_WOULD_START\n")

    def test_source_wiring_uses_fixed_policy_and_authenticated_checksum_retention(self):
        loader = function("load_native_recovery_anchor")
        self.assertNotIn("SOURCE_PACKAGE_ROOT", loader)
        self.assertNotIn("PACKAGE_ROOT", loader)
        self.assertNotIn("AMNEZIA_HEADLESS", loader)
        retain = SOURCE.index('BOOTSTRAP_HELPER_DIGESTS["$name"]="$digest"')
        self.assertLess(SOURCE.index("native helper checksums digest does not match"), retain)
        self.assertLess(SOURCE.index('digest="${rows[0]:0:64}"'), retain)
        self.assertLess(SOURCE.index('sha256sum "$BOOTSTRAP_HELPER_DIR/$name"'), retain)
        producer = SOURCE.index("if ! install_native_recovery_anchor; then\n")
        self.assertLess(producer, SOURCE.index('install -d -o root -g root -m 0700 "$TRANSACTION_BASE"'))
        self.assertLess(producer, SOURCE.index("write_transaction_journal starting"))
        self.assertLess(SOURCE.index("if ! version_output="), producer)
        self.assertNotIn("for required in python3 ", SOURCE)
        self.assertIn("type -P python3", function("require_legacy_python"))


if __name__ == "__main__":
    unittest.main(argv=[str(Path(__file__)), *UNITTEST_ARGS], verbosity=2)
