"""Source-only maintenance identity checks; no executable or remote work runs.

Run with ``python3 -B client/tests/awg_control_maintenance/test_native_maintenance_source_contract.py``.
These checks protect the latch and cleanup wiring. They do not establish C++
compilation, SSH behavior, or privileged runtime acceptance.
"""

import ast
import os
import subprocess
import tempfile
from pathlib import Path
import re
import unittest


SOURCE = Path(__file__).resolve().parents[2] / "core/controllers/selfhosted/installController.cpp"


def body(text, signature):
    if signature not in text:
        raise AssertionError("missing source boundary: " + signature)
    start = text.index(signature)
    opening = text.index("{", start)
    depth = 0
    for position in range(opening, len(text)):
        depth += (text[position] == "{") - (text[position] == "}")
        if depth == 0:
            return text[opening:position + 1]
    raise AssertionError("unterminated source body: " + signature)


class NativeMaintenanceSourceContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = Path(os.environ.get("AMNEZIA_MAINTENANCE_SOURCE", SOURCE))
        text = source.read_text()
        cls.maintenance = body(text, "ErrorCode InstallController::maintainAwgMigrationControls(")
        cls.prepare = body(text, "ErrorCode InstallController::prepareAwgMigration(")
        cls.prepare_cleanup = body(text, "ErrorCode removeAwgPrepareInputs(")
        cls.prepare_drain = body(text, "ErrorCode InstallController::cleanupAwgMigrationPrepareInputs(")

    def test_directory_identity_is_latched_and_subsequent_reads_cannot_replace_it(self):
        stat = body(self.maintenance, "auto statRoot =")
        existing = body(stat, "if (!rootIdentity.isEmpty())")
        self.assertRegex(
            existing,
            r"return\s+observedIdentity\s*==\s*rootIdentity\s*\?\s*"
            r"ErrorCode::NoError\s*:\s*ErrorCode::ServerCheckFailed\s*;",
        )
        self.assertNotRegex(existing, r"\brootIdentity\s*=(?!=)")
        writes = list(re.finditer(r"\brootIdentity\s*=(?!=)", stat))
        self.assertEqual(len(writes), 1)
        self.assertGreater(writes[0].start(), stat.index(existing) + len(existing))
        self.assertIn("rootIdentity = observedIdentity;", stat)

    def test_preexec_recheck_and_cleanup_both_use_the_original_identity(self):
        cleanup = body(self.maintenance, "auto cleanupOwned =")
        self.assertIn("QString::fromLatin1(current.trimmed()) == rootIdentity", cleanup)
        self.assertNotRegex(cleanup, r"\brootIdentity\s*=(?!=)")
        trusted = body(cleanup, "if (rootTrusted)")
        self.assertIn("sudo rm -f --", trusted)
        self.assertIn("sudo rmdir --", trusted)
        recheck = self.maintenance.index("error = statRoot();")
        second = self.maintenance.index("error = statRoot();", recheck + 1)
        self.assertLess(second, self.maintenance.index("sudo '%1' --maintenance"))
        after_recheck = self.maintenance[second:]
        self.assertTrue(after_recheck.startswith(
            "error = statRoot();\n        if (error != ErrorCode::NoError) return finish(error, false);"
        ))

    def test_legacy_cleanup_preserves_each_command_failure_and_attempts_both(self):
        legacy = self.maintenance[self.maintenance.index("const QStringList files "):]
        cleanup = body(legacy, "auto cleanup = [&]() -> ErrorCode")
        self.assertIn('QStringLiteral("rm -f --")', cleanup)
        self.assertIn("for (const QString &name : files)", cleanup)
        self.assertIn("const ErrorCode removeError = session.runScript(credentials, command);", cleanup)
        self.assertIn("const ErrorCode directoryError = session.runScript(credentials,", cleanup)
        self.assertIn('QStringLiteral("rmdir -- \'%1\'")', cleanup)
        self.assertIn("return removeError != ErrorCode::NoError ? removeError : directoryError;", cleanup)
        self.assertNotIn("; rmdir", cleanup)
        self.assertNotIn("rm -rf", cleanup)

    def test_legacy_primary_error_wins_and_cleanup_failure_cannot_be_success(self):
        legacy = self.maintenance[self.maintenance.index("const QStringList files "):]
        finish = body(legacy, "auto finishLegacy =")
        cleanup = finish.index("const ErrorCode cleanupError = cleanup();")
        primary = finish.index("if (primary != ErrorCode::NoError) return primary;")
        reason = finish.index('QStringLiteral("legacy_cleanup_failed")')
        returned = finish.index("return cleanupError;")
        self.assertLess(cleanup, primary)
        self.assertLess(primary, reason)
        self.assertLess(reason, returned)
        self.assertNotIn("return ErrorCode::NoError;", finish)
        self.assertIn("return finishLegacy(ErrorCode::InternalError);", legacy)
        self.assertIn("return finishLegacy(error);", legacy)
        self.assertTrue(legacy.rstrip().endswith("return finishLegacy(validationError);\n}"))

    def test_prepare_cleanup_uses_both_original_identities_and_exact_leaves(self):
        cleanup = self.prepare_cleanup
        self.assertIn("for (const bool privileged : {true, false})", cleanup)
        self.assertIn('roots.value(privileged ? "programIdentity" : "stagingIdentity")', cleanup)
        self.assertIn('QString::fromLatin1(out.trimmed()) == expected', cleanup)
        self.assertIn('first == QByteArrayLiteral("ABSENT")', cleanup)
        self.assertIn('final != QByteArrayLiteral("ABSENT")', cleanup)
        self.assertIn('if (!same()) { failed = true; break; }', cleanup)
        self.assertIn('if (!same()) { failed = true; continue; }', cleanup)
        self.assertNotIn("rm -rf", cleanup)
        self.assertNotIn(" || true", cleanup)
        self.assertIn('if (path.isEmpty()) continue;', cleanup)
        self.assertIn('failed = true; continue; // Never learn ownership', cleanup)
        self.assertIn('"native-feed", "native-collector"', cleanup)
        self.assertIn('"native-feed.upload", "native-collector.upload", "prepare.py", "automatic.py",', cleanup)
        self.assertIn('"trusted_image.py", "service.py", "target.py", "policy.py", "journal.py", "feeds.py", "ready_validation.py"', cleanup)
        self.assertLess(self.prepare_drain.index('removeAwgPrepareInputs('),
                        self.prepare_drain.index('authority->completePrepareCleanup(roots, &authorityError)'))
        self.assertNotIn('commitPrepare(', self.prepare_drain)
        self.assertNotIn('retirePrepare(', self.prepare_drain)

    def test_prepare_ephemeral_ownership_is_durable_before_upload_and_preflight(self):
        persist = self.prepare.index('authority->beginPrepareCleanup(cleanupRoots, &cleanupAuthorityError)')
        self.assertLess(self.prepare.index('cleanupRoots.insert("stagingIdentity", stagingIdentity)'), persist)
        self.assertLess(self.prepare.index('cleanupRoots.insert("programIdentity", programIdentity)'), persist)
        self.assertLess(persist, self.prepare.index('session.uploadFileToHost(credentials, binary.bytes, uploadPath)'))
        self.assertLess(persist, self.prepare.index('script + QStringLiteral(" --preflight")'))
        drain = self.prepare.index('cleanupAwgMigrationPrepareInputs(credentials, source, authority, result)')
        self.assertLess(drain, self.prepare.index('state == QStringLiteral("pendingPrepare")'))
        self.assertLess(drain, self.prepare.index('umask 077; mkdir'))
        self.assertIn('if (prepareCleaned != ErrorCode::NoError) return prepareCleaned;', self.prepare)
        identity = body(self.prepare, 'auto directoryIdentity =')
        self.assertIn('!identity.isEmpty() && identity != value', identity)
        self.assertIn('if (identity.isEmpty()) identity = value;', identity)
        self.assertIn('cleanupIntentAttempted = true;', self.prepare[:persist])
        self.assertIn('if (!saved.ok)', body(self.prepare, 'auto cleanup ='))

    def test_native_operations_drain_prepare_obligation_before_probe_and_main_admission(self):
        drain = self.maintenance.index('cleanupAwgMigrationPrepareInputs(credentials, source, authority, result)')
        self.assertLess(self.maintenance.index('authority->lock(&authorityError)'), drain)
        self.assertLess(drain, self.maintenance.index('cleanupAwgMigrationControlInputs(credentials, source, authority, result, true)'))
        self.assertLess(drain, self.maintenance.index('const auto saved = authority->load()'))
        self.assertIn('if (prepareCleanup != ErrorCode::NoError) return prepareCleanup;', self.maintenance)

    def test_prepare_cleanup_keeps_primary_error_and_all_cleanup_hints(self):
        finish = body(self.prepare, "auto finish =")
        self.assertIn("const ErrorCode cleanupError = cleanup(details);", finish)
        self.assertIn('it.key() != QStringLiteral("reason") || primary == ErrorCode::NoError', finish)
        self.assertIn('result.insert(it.key(), it.value())', finish)
        self.assertIn("return primary != ErrorCode::NoError ? primary : cleanupError;", finish)
        self.assertTrue(self.prepare.rstrip().endswith('return finish(outcome);\n}'))

    def test_actual_cleanup_shell_observes_type_identity_absence_and_exact_removal(self):
        # Run only the production unprivileged templates against owned temporary
        # fixtures. This does not contact SSH or invoke sudo/native programs.
        literals = []
        for match in re.finditer(r'QStringLiteral\(\s*((?:"(?:\\.|[^"\\])*"\s*)+)\)', self.prepare_cleanup):
            literals.append(''.join(ast.literal_eval(part) for part in re.findall(r'"(?:\\.|[^"\\])*"', match.group(1))))
        observe = next(value for value in literals if value.startswith("sh -c 'if [ ! -e"))
        remove = next(value for value in literals if value.startswith("rm -f --"))
        rmdir = next(value for value in literals if value.startswith("rmdir --"))
        def run(template, path, leaf=''):
            return subprocess.run(['sh', '-c', template.replace('%1', str(path)).replace('%2', leaf)],
                                  capture_output=True, text=True)
        with tempfile.TemporaryDirectory(prefix='awg-prepare-cleanup-test-') as fixture:
            root = Path(fixture) / 'owned'
            root.mkdir(mode=0o700)
            (root / 'native-feed').write_text('fixture')
            (root / 'unrecognized').write_text('preserve')
            stat = root.stat()
            expected = f'{stat.st_uid} {stat.st_gid} 700 {stat.st_dev} {stat.st_ino}'
            self.assertEqual(run(observe, root).stdout.strip(), expected)
            self.assertEqual(run(remove, root, 'native-feed').returncode, 0)
            self.assertTrue((root / 'unrecognized').exists())
            self.assertNotEqual(run(rmdir, root).returncode, 0)
            original = Path(fixture) / 'original'
            root.rename(original)
            root.mkdir(mode=0o700)
            self.assertNotEqual(run(observe, root).stdout.strip(), expected)
            root.rmdir()
            root.symlink_to(original, target_is_directory=True)
            self.assertNotEqual(run(observe, root).returncode, 0)
            root.unlink()
            self.assertEqual(run(observe, root).stdout, 'ABSENT')


if __name__ == "__main__":
    unittest.main()
