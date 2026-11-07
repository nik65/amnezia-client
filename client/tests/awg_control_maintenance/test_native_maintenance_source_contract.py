"""Source-only maintenance identity checks; no executable or remote work runs.

Run with ``python3 -B client/tests/awg_control_maintenance/test_native_maintenance_source_contract.py``.
These checks protect the latch and cleanup wiring. They do not establish C++
compilation, SSH behavior, or privileged runtime acceptance.
"""

import os
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

    def test_prepare_cleanup_records_all_four_operations_without_shell_status_masking(self):
        cleanup = body(self.prepare, "auto cleanup = [&]() -> ErrorCode")
        for name in ("programFilesError", "programDirectoryError", "stagingFilesError", "stagingDirectoryError"):
            self.assertIn("const ErrorCode " + name + " = session.runScript(credentials,", cleanup)
            self.assertIn(name + " != ErrorCode::NoError", cleanup)
        self.assertNotIn("; rmdir", cleanup)
        self.assertNotIn("; sudo rmdir", cleanup)
        self.assertNotIn("rm -rf", cleanup)
        self.assertEqual(cleanup.count("return "), 1)
        self.assertTrue(cleanup.rstrip().endswith("return cleanupError;\n    }"))
        self.assertEqual(set(re.findall(r"'%1/([^']+)'", cleanup)), {
            "native-feed", "native-collector", "native-feed.upload", "native-collector.upload",
            "prepare.py", "automatic.py", "trusted_image.py", "service.py", "target.py",
            "policy.py", "journal.py", "feeds.py", "ready_validation.py",
        })
        native = body(cleanup, "if (programDirectoryCreated)")
        self.assertNotIn("stagingFilesError", native)
        self.assertGreater(cleanup.index("const ErrorCode stagingFilesError"), cleanup.index(native) + len(native))

    def test_prepare_cleanup_keeps_primary_error_precedence(self):
        finish = body(self.prepare, "auto finish =")
        self.assertIn("const ErrorCode cleanupError = cleanup();", finish)
        self.assertIn("if (primary == ErrorCode::NoError && cleanupError != ErrorCode::NoError)", finish)
        self.assertIn('QStringLiteral("native_cleanup_failed")', finish)
        self.assertIn("return primary != ErrorCode::NoError ? primary : cleanupError;", finish)


if __name__ == "__main__":
    unittest.main()
