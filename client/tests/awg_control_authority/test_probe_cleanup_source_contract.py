"""Durable probe ownership and settlement ordering, source-only checks."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = (ROOT / "client/core/controllers/selfhosted/installController.cpp").read_text(encoding="utf-8")
STORE = (ROOT / "client/core/utils/awgControlAuthorityStore.h").read_text(encoding="utf-8")


def between(text, start, end):
    return text.split(start, 1)[1].split(end, 1)[0]


MAINTAIN = between(SOURCE, "ErrorCode InstallController::maintainAwgMigrationControls(",
                   "ErrorCode InstallController::cleanupAwgMigrationControlInputs(")
PREPARE = between(SOURCE, "ErrorCode InstallController::prepareAwgMigration(",
                  "ServerRoutingRulesPublishResult InstallController::publishVersionedServerRoutingRules(")


class ProbeCleanupSourceContract(unittest.TestCase):
    def test_probe_is_durable_after_identity_before_upload_or_execution(self):
        create = MAINTAIN.index('"sudo mkdir -m 0700 -- \'%1\'"')
        identity = MAINTAIN.index("error = statRoot();", create)
        persist = MAINTAIN.index("authority->beginProbeCleanup(directory, rootIdentity, selectedControl->sha256, upload, &probeError)", identity)
        children = MAINTAIN.index('"sudo mkdir -m 0700 -- \'%1\' \'%2\' \'%3\'"', persist)
        upload = MAINTAIN.index("session.uploadFileToHost(credentials, selectedControl->bytes, upload)", persist)
        execute = MAINTAIN.index("error = session.runScript(credentials, command, capture(output", persist)
        self.assertLess(create, identity)
        self.assertLess(identity, persist)
        self.assertLess(persist, children)
        self.assertLess(persist, upload)
        self.assertLess(persist, execute)

    def test_previous_probe_drains_before_new_probe_and_prepare_admission(self):
        drain = MAINTAIN.index("cleanupAwgMigrationControlInputs(credentials, source, authority, result, true)")
        self.assertLess(drain, MAINTAIN.index("authority->beginProbeCleanup("))
        self.assertLess(drain, MAINTAIN.index("const auto nativeBundle"))
        self.assertIn("if (probeCleanup != ErrorCode::NoError) return probeCleanup;", MAINTAIN)
        drain_prepare = PREPARE.index("cleanupAwgMigrationControlInputs(credentials, source, authority, result, true)")
        self.assertLess(drain_prepare, PREPARE.index('saved.record.value("state").toString()'))
        self.assertIn("if (cleaned != ErrorCode::NoError) return cleaned;", PREPARE[drain_prepare:])

    def test_original_input_transfer_is_atomic_and_removes_generic_overlay(self):
        begin = between(STORE, "bool beginMaintenance(", "bool commitMaintenance(")
        compare = begin.index('previous.record.value(QStringLiteral("probeCleanup")).toObject() != recoveryCleanup')
        remove = begin.index('value.remove(QStringLiteral("probeCleanup"));')
        retain = begin.index('value.insert(QStringLiteral("retainedDirectory"), recoveryDirectory)')
        save = begin.index("return write(value, error);")
        self.assertLess(compare, remove)
        self.assertLess(remove, retain)
        self.assertLess(retain, save)
        self.assertEqual(begin.count("return write(value, error);"), 1)

    def test_uncertain_authority_writes_preserve_original_staging(self):
        begin = between(MAINTAIN, "!authority->beginMaintenance(", "probeCleanupCommitted = false;")
        commit = between(MAINTAIN, "!authority->commitMaintenance(", "authorityCleanupCommitted = true;")
        for block in (begin, commit):
            self.assertIn("finish(ErrorCode::ServerCheckFailed, true)", block)
            self.assertNotIn("finish(ErrorCode::ServerCheckFailed, false)", block)
        finish = between(MAINTAIN, "auto finish =", "if (selection.native()) {")
        retain = between(finish, "if (retainRecoveryInputs)", "ErrorCode cleanupError = cleanupOwned();")
        self.assertNotIn("cleanupOwned()", retain)
        self.assertNotIn("completeProbeCleanup", retain)

    def test_nonmaintain_settlement_follows_verified_receipt_and_probe_cleanup(self):
        operation = between(MAINTAIN, "if (selection.operation != AwgMaintenance::Operation::Maintain) {\n            if (error",
                            "const bool pending = result.value")
        validate = operation.index("AwgMaintenance::validNativeOperationReceipt")
        cleaned = operation.index("const ErrorCode cleaned = finish(ErrorCode::NoError, false);")
        refused = operation.index("if (cleaned != ErrorCode::NoError) return cleaned;")
        self.assertLess(validate, cleaned)
        self.assertLess(cleaned, refused)
        for settle in ("authority->resolvePendingMaintenance(", "authority->retirePrepare(", "authority->resolvePendingPrepare("):
            self.assertLess(refused, operation.index(settle))

    def test_probe_ack_removes_only_overlay_without_clearing_transaction(self):
        complete = between(STORE, "bool completeProbeCleanup(", "private:")
        self.assertIn('cleanup.value(QStringLiteral("directory")) != directory', complete)
        self.assertIn('cleanup.value(QStringLiteral("identity")) != identity', complete)
        self.assertIn('value.remove(QStringLiteral("probeCleanup"));', complete)
        self.assertNotIn('value.remove(QStringLiteral("retainedDirectory"))', complete)
        self.assertNotIn('value.remove(QStringLiteral("retainedIdentity"))', complete)
        self.assertNotIn('value.insert(QStringLiteral("state")', complete)


if __name__ == "__main__":
    unittest.main()
