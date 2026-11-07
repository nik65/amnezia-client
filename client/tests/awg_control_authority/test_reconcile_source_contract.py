"""Source-only guards for bounded recovery routing; no C++ or SSH runs.

Native receipt/store tests and the real client build are separate validation
lanes. Passing this file does not establish native or release acceptance.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[3]


def between(text, first, last):
    start = text.index(first)
    return text[start:text.index(last, start + len(first))]


class ReconcileSourceContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.controller = (ROOT / "client/core/controllers/selfhosted/installController.cpp").read_text()
        cls.reconcile = between(cls.controller, "ErrorCode InstallController::reconcileAwgMigrationControls(",
                                "ErrorCode InstallController::prepareAwgMigration(")
        cls.maintain = between(cls.controller, "ErrorCode InstallController::maintainAwgMigrationControls(",
                               "ErrorCode InstallController::cleanupAwgMigrationControlInputs(")
        cls.receipt = (ROOT / "client/core/controllers/selfhosted/awgMaintenanceReceipt.h").read_text()

    def test_pending_maintenance_probes_only_saved_old_and_new_pins(self):
        pending = between(self.reconcile, '} else if (state == QStringLiteral("pendingMaintenance")',
                          'selection.operation = AwgMaintenance::Operation::Recover;')
        self.assertIn('QStringList candidates{saved.record.value("currentSha").toString(), '
                      'saved.record.value("replacementSha").toString()}', pending)
        self.assertIn("candidates.removeDuplicates();", pending)
        self.assertIn("if (!candidates.contains(explicitCurrentPin))", pending)
        self.assertIn("candidates = {explicitCurrentPin};", pending)
        probe = pending[pending.index("for (const QString &candidate : candidates)"):]
        self.assertIn("selection.operation = AwgMaintenance::Operation::Status;", probe)
        self.assertIn("selection.currentControlSha256 = candidate;", probe)
        self.assertIn("if (checked == ErrorCode::NoError) { selected = true; break; }", probe)
        self.assertIn('status.value("cleanupRequired").toBool()', probe)
        self.assertEqual(probe.count("maintainAwgMigrationControls("), 1)
        self.assertNotRegex(probe, r"currentControlSha256\s*=\s*(?:status|result)\.")

    def test_one_recover_after_selection_and_no_new_replacement_in_reconcile(self):
        recover = self.reconcile.index("selection.operation = AwgMaintenance::Operation::Recover;")
        tail = self.reconcile[recover:]
        self.assertIn("if (!selected)", self.reconcile[:recover])
        self.assertEqual(self.reconcile.count("Operation::Recover"), 1)
        self.assertEqual(tail.count("maintainAwgMigrationControls("), 1)
        # Cleanup may iterate safe result fields, but recovery itself must not
        # retry the mutating command under a loop.
        recovery = tail[:tail.index("cleanupAwgMigrationControlInputs(")]
        self.assertNotRegex(recovery, r"\b(?:for|while)\s*\(")
        for forbidden in ("Operation::Maintain", "beginMaintenance(", "beginPrepare(",
                          "loadResourceBundle(", "--native-control-replacement-sha256", "prepareAwgMigration(" ):
            self.assertNotIn(forbidden, self.reconcile)
        self.assertIn("if (recovered != ErrorCode::NoError) return recovered;", tail)
        self.assertIn("cleanupAwgMigrationControlInputs(", tail)

    def test_discovery_is_only_a_single_generation_and_journal_locator(self):
        discovery = between(self.controller, "ErrorCode discoverInterruptedAwgGeneration(", "} // namespace")
        self.assertIn("AwgMaintenance::prepareRecoveryGeneration(output, root,", discovery)
        self.assertIn("trustedRetiredHistory, minimumGeneration)", discovery)
        self.assertIn("if (!candidate) return ErrorCode::ServerCheckFailed;", discovery)
        self.assertIn("generation = *candidate;", discovery)
        self.assertIn("4096 - output.size()", discovery)
        self.assertNotIn("QJsonDocument::fromJson", discovery)
        self.assertIn("return observedAwgJournalSha(credentials, source, generation, journalSha);", discovery)
        for forbidden in ("currentControlSha256", "currentSha", "commitPrepare", "resolvePending", "anchorCurrent"):
            self.assertNotIn(forbidden, discovery)
        digest = between(self.controller, "ErrorCode observedAwgJournalSha(", "ErrorCode discoverInterruptedAwgGeneration(")
        self.assertIn("sudo sha256sum --", digest)
        self.assertIn("fields.size() != 2 || fields[1] != path", digest)
        self.assertNotIn("QJsonDocument::fromJson", digest)

    def test_discovered_prepare_must_use_saved_operation_nonce_and_live_verify(self):
        self.assertIn("const bool discoverPrepare = generation == 0 && journalSha.isEmpty();", self.reconcile)
        discovery = between(self.reconcile, "if (discoverPrepare)", "AwgMaintenance::Selection selection;")
        self.assertIn('state != QStringLiteral("pendingPrepare")', discovery)
        self.assertIn("discoverInterruptedAwgGeneration(credentials, source, generation, journalSha,", discovery)
        self.assertIn('saved.record.value(QStringLiteral("retiredPredecessors")).toArray()', discovery)
        self.assertIn('qMax<qint64>(1, saved.record.value(QStringLiteral("minimumGeneration")).toInteger())', discovery)
        prepare = between(self.reconcile, 'if (state == QStringLiteral("pendingPrepare"))',
                          '} else if (state == QStringLiteral("pendingMaintenance")')
        self.assertIn('selection.currentControlSha256 = saved.record.value("currentSha").toString();', prepare)
        self.assertIn('selection.clientOperationId = saved.record.value("operationId").toString();', prepare)
        self.assertIn("selection.clientOperationId.isEmpty()", prepare)
        inspect = prepare.index("selection.operation = AwgMaintenance::Operation::InspectPrepare;")
        probe = prepare.index("const ErrorCode partial = maintainAwgMigrationControls(", inspect)
        decision = prepare.index("selection.operation = partial == ErrorCode::NoError ? AwgMaintenance::Operation::AbortPrepare", probe)
        self.assertLess(inspect, probe)
        self.assertLess(probe, decision)
        self.assertIn(": AwgMaintenance::Operation::VerifyPrepare;", prepare[decision:])
        self.assertIn('partial != ErrorCode::NoError && inspected.value("cleanupRequired").toBool()', prepare[probe:decision])
        self.assertNotIn("commitPrepare(", self.reconcile)
        self.assertNotIn("resolvePendingPrepare(", self.reconcile)
        validator = self.maintain.index("!AwgMaintenance::validNativeOperationReceipt(")
        settle = self.maintain.index("authority->resolvePendingPrepare(", validator)
        self.assertLess(validator, settle)
        self.assertRegex(self.maintain[validator:settle],
                         r"selection\.operation == AwgMaintenance::Operation::VerifyPrepare\s*&& !$")
        live = between(self.receipt, "inline bool validNativeOperationReceipt(", "inline bool validNativeReceipt(")
        self.assertIn('receipt.value("clientOperationId").toString() != clientOperationId', live)
        self.assertIn('receipt.value("liveVerified").isBool() && receipt.value("liveVerified").toBool()', live)
        self.assertIn('receipt.value("phase").toString() == QStringLiteral("ready")', live)

    def test_status_never_invokes_local_settlement(self):
        for operation, method in (("Recover", "resolvePendingMaintenance"), ("VerifyPrepare", "resolvePendingPrepare")):
            self.assertEqual(self.maintain.count("authority->" + method + "("), 1)
            self.assertRegex(self.maintain,
                rf"if \(selection\.operation == AwgMaintenance::Operation::{operation}\s*&& !authority->{method}\(")
        self.assertNotRegex(self.maintain,
            r"Operation::(?:Status|InspectPrepare)\s*&& !authority->(?:resolve|commit|retire)")

    def test_prepare_retirement_requires_validated_abort_and_exact_saved_identity(self):
        validator = self.maintain.index("!AwgMaintenance::validNativeOperationReceipt(")
        retire = self.maintain.index("authority->retirePrepare(", validator)
        self.assertRegex(self.maintain[validator:retire],
                         r"selection\.operation == AwgMaintenance::Operation::AbortPrepare\s*&& !$")
        call = self.maintain[retire:self.maintain.index(")) {", retire)]
        self.assertIn("generation, selection.currentControlSha256", call)
        self.assertIn('selection.clientOperationId, result.value("journalSha256").toString()', call)
        proof = between(self.receipt, "inline bool validNativeOperationReceipt(", "inline bool validNativeReceipt(")
        self.assertIn('receipt.value("retiredVerified").isBool()', proof)
        self.assertIn('phase == QStringLiteral("aborted") && receipt.value("retiredVerified").toBool()', proof)

    def test_operator_reconcile_returns_without_followup_replacement(self):
        app = (ROOT / "client/amneziaApplication.cpp").read_text()
        route = between(app, "AwgMaintenance::Selection selection;", "ssh_finalize();")
        reconcile = route.index("error = InstallController::reconcileAwgMigrationControls(")
        stop = route.index("authorized = false;", reconcile)
        maintain = route.index("error = InstallController::maintainAwgMigrationControls(", stop)
        self.assertLess(reconcile, stop)
        self.assertLess(stop, maintain)
        self.assertRegex(route[stop:maintain], r"if \(authorized\)\s*$")
        self.assertNotIn("authorized = true;", route[stop:maintain])

    def test_native_prepare_producer_and_consumer_share_string_envelope(self):
        entry = (ROOT / "client/server_scripts/awg_migration/native/prepare_entry.cpp").read_text()
        self.assertRegex(entry, r'"receipt",\s*json_object_new_string\(outcome\.receiptJson\.c_str\(\)\)')
        consumer = between(self.receipt, "inline bool nativePrepareReceipt(", "inline bool validNativeOperationReceipt(")
        self.assertIn('!envelope.value("receipt").isString()', consumer)
        self.assertIn('envelope.value("receipt").toString().toUtf8()', consumer)
        self.assertIn('value.value("clientOperationId").toString() != expectedOperationId', consumer)
        self.assertNotIn('envelope.value("generation")', consumer)


if __name__ == "__main__":
    unittest.main()
