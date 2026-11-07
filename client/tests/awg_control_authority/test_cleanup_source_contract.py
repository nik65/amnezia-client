"""Source/shell-syntax guards; no compiler, remote command or product execution."""
import ast
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = (ROOT / "client/core/controllers/selfhosted/installController.cpp").read_text(encoding="utf-8")
BODY = SOURCE.split("ErrorCode InstallController::cleanupAwgMigrationControlInputs(", 1)[1].split(
    "\nnamespace {", 1)[0]


class CleanupSourceContract(unittest.TestCase):
    def test_scoped_current_record_precedes_remote_access(self):
        session = BODY.index("SshSession session;")
        prefix = BODY[:session]
        self.assertIn("authority->matches(credentials, ContainerUtils::containerToString(source))", prefix)
        self.assertIn("authority->lock(&authorityError)", prefix)
        self.assertIn('saved.record.value(QStringLiteral("state")) != QStringLiteral("current")', prefix)
        self.assertIn('const QString cleanupKey = probeOnly ? QStringLiteral("probeCleanup") : QStringLiteral("cleanup");', prefix)
        self.assertIn("if (!saved.record.contains(cleanupKey)) return ErrorCode::NoError;", prefix)
        self.assertIn("(!probeOnly", prefix)
        self.assertIn("cleanup.size() != 3 + int(hasUpload)", prefix)
        self.assertIn("amnezia::awgControlAuthority::digest(replacement)", prefix)

    def test_identity_is_compared_never_learned_from_new_stat(self):
        self.assertIn('cleanup.value(QStringLiteral("identity")).toString()', BODY)
        self.assertIn("QString::fromLatin1(observed.trimmed()) == expectedIdentity", BODY)
        self.assertNotRegex(BODY, r"expectedIdentity\s*=\s*(?:observed|QString::fromLatin1)")
        self.assertIn("0 0 1777", BODY)
        self.assertIn("0 0 700", BODY)
        self.assertIn("if (!sameRoot())", BODY)
        self.assertIn("[ ! -L", BODY)

    def test_upload_cleanup_is_independent_and_unprivileged(self):
        upload = BODY.index('if (hasUpload && session.runScript(credentials, QStringLiteral("rm -f')
        root_block = BODY.rindex("if (rootTrusted && !rootAbsent)", 0, upload)
        self.assertIn("if (sameRoot())", BODY[root_block:upload])
        self.assertIn('uploadPattern.match(upload).hasMatch()', BODY[:upload])
        self.assertNotIn('sudo rm -f -- \'%1\'").arg(upload)', BODY)

    def test_only_exact_names_and_independent_errors(self):
        for fixed in ["/awg-feed", "/Dockerfile", "/image.iid", "/context-", "/awg-feed-"]:
            self.assertIn(fixed, BODY)
        self.assertNotIn("rm -rf", BODY)
        self.assertNotIn("rm -r", BODY)
        self.assertNotIn(" || true", BODY)
        self.assertIn("removed = false;", BODY)
        proof = BODY.index('finalRoot != QByteArrayLiteral("ABSENT")')
        clear = BODY.index("authority->completeCleanup(directory, expectedIdentity, &authorityError)")
        self.assertLess(proof, clear)
        self.assertIn('result.insert(QStringLiteral("pendingRecovery"), false)', BODY[clear:])
        self.assertIn('result.insert(QStringLiteral("cleanupRequired"), true)', BODY[clear:])

    def test_probe_completion_does_not_settle_or_delete_original_pending_inputs(self):
        self.assertIn('probeOnly ? QStringLiteral("probeCleanup") : QStringLiteral("cleanup")', BODY)
        self.assertIn('!saved.record.value(cleanupKey).isObject()', BODY)
        self.assertIn("authority->completeProbeCleanup(directory, expectedIdentity, &authorityError)", BODY)
        self.assertNotIn('saved.record.value(QStringLiteral("retainedDirectory"))', BODY)
        self.assertNotIn("resolvePendingMaintenance", BODY)
        self.assertNotIn("resolvePendingPrepare", BODY)

    def test_actual_shell_templates_parse_without_execution(self):
        pattern = r'QStringLiteral\(\s*((?:"(?:\\.|[^"\\])*"\s*)+)\)'
        commands = []
        for match in re.finditer(pattern, BODY):
            pieces = re.findall(r'"(?:\\.|[^"\\])*"', match.group(1))
            text = "".join(ast.literal_eval(piece) for piece in pieces)
            if text.startswith(("sudo ", "stat ", "rm ")):
                # Formatting substitutes bounded paths only. bash -n does not
                # execute sudo, SSH, file mutation, or any other command.
                for number in range(1, 9):
                    text = text.replace("%" + str(number), "/tmp/fixture-owned-path")
                commands.append(text)
        self.assertGreaterEqual(len(commands), 6)
        for command in commands:
            with self.subTest(command=command):
                result = subprocess.run(["bash", "-n"], input=command, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
