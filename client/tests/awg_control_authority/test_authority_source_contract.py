"""Source contracts for the real CURRENT producer/consumer call sites.

Run with ``python3 -B client/tests/awg_control_authority/test_authority_source_contract.py``.
This suite reads sources only. It does not compile C++, execute the state store,
start a process/SSH operation, or establish platform or release acceptance.
The companion native target remains a separate, deferred validation step.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[3]


def source(path):
    return (ROOT / path).read_text(encoding="utf-8")


def between(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin + len(start))]


class AuthoritySourceContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        controller = source("client/core/controllers/selfhosted/installController.cpp")
        cls.prepare = between(controller, "ErrorCode InstallController::prepareAwgMigration(",
                              "ServerRoutingRulesPublishResult InstallController::publishVersionedServerRoutingRules(")
        cls.maintenance = between(controller, "ErrorCode InstallController::maintainAwgMigrationControls(",
                                  "ErrorCode InstallController::prepareAwgMigration(")
        cls.store = source("client/core/utils/awgControlAuthorityStore.h")
        cls.app = source("client/amneziaApplication.cpp")

    def test_initial_producer_uses_verified_delivered_feed_not_receipt_sha(self):
        prepare = self.prepare
        bundle = prepare.index("amnezia::serverNative::loadResourceBundle()")
        invalid = prepare.index("nativeBundle.present && !nativeBundle.valid", bundle)
        find = prepare.index('nativeFeed = nativeBundle.find(QStringLiteral("awg-feed"), *architecture)')
        begin = prepare.index("authority->beginPrepare(nativeFeed->sha256, &authorityError)")
        commit = prepare.index("authority->commitPrepare(number.toInteger(), nativeFeed->sha256, &authorityError)")
        self.assertLess(bundle, invalid)
        self.assertLess(invalid, find)
        self.assertLess(find, begin)
        self.assertLess(begin, commit)
        self.assertNotRegex(prepare, r"nativeFeed\s*->\s*sha256\s*=(?!=)")
        self.assertNotRegex(prepare, r"(?:beginPrepare|commitPrepare)\([^;]*result\.value")

    def test_prepare_durable_intent_is_after_preflight_before_actual_exec(self):
        prepare = self.prepare
        preflight = prepare.index('script + QStringLiteral(" --preflight")')
        collector = prepare.index("ExportController::prepareMigrationSourceCollector(", preflight)
        begin = prepare.index("authority->beginPrepare(", collector)
        execute = prepare.index("error = session.runScript(credentials, script,", begin)
        self.assertLess(preflight, collector)
        self.assertLess(collector, begin)
        self.assertLess(begin, execute)
        rejected_intent = prepare[begin:execute]
        self.assertIn("return finish(ErrorCode::ServerCheckFailed);", rejected_intent)
        self.assertIn("authority->matches(credentials, ContainerUtils::containerToString(source))", prepare)
        self.assertIn("!authority->lock(&authorityError)", prepare)
        self.assertIn("if (!saved.ok || !saved.missing)", prepare)

    def test_prepare_receipt_is_strict_and_commit_precedes_cleanup(self):
        receipt = between(self.prepare, "if (outcome == ErrorCode::NoError && nativeFeed)",
                          "} else if (outcome == ErrorCode::NoError")
        for expected in (
            'result.value(QStringLiteral("prepared")).isBool()',
            'result.value(QStringLiteral("prepared")).toBool()',
            'result.value(QStringLiteral("legacyRetained")).isBool()',
            'result.value(QStringLiteral("legacyRetained")).toBool()',
            "number.isDouble()", "generationValue >= 1", "generationValue <= 9007199254740991.0",
            "generationValue == static_cast<double>(number.toInteger())",
            "(automatic || number.toInteger() == generation)",
            "if (!prepared || !authority->commitPrepare(",
        ):
            self.assertIn(expected, receipt)
        commit = self.prepare.index("authority->commitPrepare(")
        cleanup = self.prepare.index("const ErrorCode cleanupError = cleanup();", commit)
        self.assertLess(commit, cleanup)
        self.assertIn("if (outcome != ErrorCode::NoError) return outcome;", self.prepare[cleanup:])

    def test_maintenance_replacement_is_from_bundle_and_intent_is_at_exec_boundary(self):
        maintenance = self.maintenance
        self.assertIn("if (!nativeBundle.present || !nativeBundle.valid)", maintenance)
        self.assertIn('selectedControl = nativeBundle.find(QStringLiteral("awg-feed"), *architecture)', maintenance)
        readback = maintenance.index("if (finalError != ErrorCode::NoError || finalReadback != expectedReadback.toUtf8())")
        begin = maintenance.index("authority->beginMaintenance(", readback)
        execute = maintenance.index("error = session.runScript(credentials, command,", begin)
        self.assertLess(readback, begin)
        self.assertLess(begin, execute)
        intent_to_exec = maintenance[begin:execute]
        self.assertIn("generation, selection.currentControlSha256,", intent_to_exec)
        self.assertIn("selectedControl->sha256, expectedJournalSha256, &authorityError", intent_to_exec)
        self.assertIn("&authorityError, directory)", intent_to_exec)
        self.assertIn("return finish(ErrorCode::ServerCheckFailed, false);", intent_to_exec)
        # No intervening remote mutation may slip outside durable pending state.
        self.assertNotIn("session.runScript(", intent_to_exec)

    def test_native_receipt_validation_precedes_current_commit_and_cleanup(self):
        maintenance = self.maintenance
        execute = maintenance.index("error = session.runScript(credentials, command,")
        validate = maintenance.index("!AwgMaintenance::validNativeReceipt(", execute)
        commit = maintenance.index("authority->commitMaintenance(", validate)
        finish = maintenance.index("return finish(ErrorCode::NoError, false);", commit)
        self.assertLess(execute, validate)
        self.assertLess(validate, commit)
        self.assertLess(commit, finish)
        failed_validation = maintenance[validate:commit]
        self.assertIn("return finish(validationError, true);", failed_validation)
        self.assertIn("generation, selection.currentControlSha256, selectedControl->sha256", failed_validation)
        commit_to_cleanup = maintenance[commit:finish]
        self.assertIn("generation, selection.currentControlSha256,", commit_to_cleanup)
        self.assertIn("selectedControl->sha256, &authorityError", commit_to_cleanup)

    def test_lost_reply_does_not_clear_or_reanchor_pending_authority(self):
        for operation in (self.prepare, self.maintenance):
            self.assertNotIn("resolvePendingMaintenance(", operation)
            self.assertNotIn("anchorCurrent(", operation)
            self.assertNotRegex(operation, r"authority\s*->\s*(?:remove|clear|reset|abort|cancel)\s*\(")
        self.assertIn("if (error != ErrorCode::NoError || pending", self.maintenance)
        failed = between(self.maintenance, "if (error != ErrorCode::NoError || pending",
                         "if (!authority->commitMaintenance(")
        self.assertIn("return finish(validationError, true);", failed)
        finish = between(self.maintenance, "auto finish =", "if (selection.native()) {")
        retained = between(finish, "if (retainRecoveryInputs)", "const ErrorCode cleanupError = cleanupOwned();")
        self.assertIn("return primary;", retained)
        self.assertNotIn("authority->", finish)

    def test_omitted_pin_is_parsed_then_resolved_only_from_local_current(self):
        parser = source("client/core/utils/awgMaintenanceCommand.h")
        self.assertIn('if (result.contains("currentControlSha256"))', parser)
        self.assertIn('} else if (result.size() != 5) return {};', parser)
        app = between(self.app, "AwgMaintenance::Selection selection;", "ssh_finalize();")
        self.assertIn("authorized && !selection.currentControlSha256.isEmpty()", app)
        self.assertIn("authority->anchorCurrent(generation, selection.currentControlSha256, &authorityError)", app)
        lock = app.index("authorized = authority->lock(&authorityError);")
        load = app.index("const auto saved = authority->load();", lock)
        use = app.index('selection.currentControlSha256 = saved.record.value("currentSha").toString();', load)
        invoke = app.index("InstallController::maintainAwgMigrationControls(", use)
        self.assertLess(lock, load)
        self.assertLess(load, use)
        self.assertLess(use, invoke)
        for condition in ("saved.ok && !saved.missing", 'saved.record.value("state").toString() == QStringLiteral("current")',
                          'saved.record.value("generation").toInteger() == generation'):
            self.assertIn(condition, app[load:use])
        self.assertIn("if (authorized)", app[use:invoke])

    def test_current_pin_cannot_be_derived_from_journal_or_remote_result(self):
        app = between(self.app, "AwgMaintenance::Selection selection;", "ssh_finalize();")
        assignments = re.findall(r"selection\.currentControlSha256\s*=\s*([^;]+);", app)
        self.assertEqual(assignments, [
            'selected.value("currentControlSha256").toString()',
            'saved.record.value("currentSha").toString()',
        ])
        for operation in (self.prepare, self.maintenance):
            self.assertNotRegex(operation, r"(?:currentControlSha256|currentSha)\s*=\s*(?:result|receipt)\.")
            self.assertNotRegex(operation, r"selection\.currentControlSha256\s*=(?!=)")
        commit = between(self.store, "bool commitMaintenance(", "bool resolvePendingMaintenance(")
        self.assertIn('previous.record.value("currentSha") != oldSha', commit)
        self.assertIn('previous.record.value("replacementSha") != newSha', commit)
        self.assertIn("write(current(number, newSha), error)", commit)

    def test_ui_worker_owns_authority_for_the_entire_prepare_operation(self):
        ui = source("client/ui/controllers/selfhosted/installUiController.cpp")
        create = ui.index("const auto authority = std::make_shared<amnezia::awgControlAuthority::Store>(nullptr,")
        worker = ui.index("QtConcurrent::run([credentials, container, endpointHost, authority]", create)
        call = ui.index("InstallController::prepareAwgMigration(", worker)
        self.assertLess(create, worker)
        self.assertLess(worker, call)
        self.assertIn("result, true, authority.get()", ui[call:ui.index(";", call)])
        declaration = source("client/core/controllers/selfhosted/installController.h")
        self.assertGreaterEqual(declaration.count("amnezia::awgControlAuthority::Store *authority = nullptr"), 2)

    def test_store_uses_dedicated_settings_and_fresh_cache_invalidating_reads(self):
        constructor = between(self.store, "Store(SecureQSettings *settings, QJsonObject scope)",
                              "bool matches(")
        self.assertIn("Q_UNUSED(settings)", constructor)
        self.assertNotIn("m_settings(settings)", constructor)
        self.assertIn("std::make_unique<SecureQSettings>(m_organization, m_application, nullptr,", self.store)
        self.assertIn("SecureQSettings::AccessMode::ReadWrite, true, SecureQSettings::StorageScope::ControlAuthority", self.store)
        self.assertIn("m_settings->readFreshValue(settingsKey(), value)", self.store)
        fresh = between(source("client/secureQSettings.cpp"), "bool SecureQSettings::readFreshValue(",
                        "void SecureQSettings::setValue(")
        sync = fresh.index("m_settings.sync();")
        invalidate = fresh.index("m_cache.remove(", sync)
        missing = fresh.index("if (!m_settings.contains(canonical)) return true;", invalidate)
        read = fresh.index("result = value(canonical);", missing)
        self.assertLess(sync, invalidate)
        self.assertLess(invalidate, missing)
        self.assertLess(missing, read)
        self.assertIn("result = {};", fresh)
        self.assertIn("if (m_settings.status() != QSettings::NoError) return false;", fresh)
        self.assertIn("return result.isValid() && m_settings.status() == QSettings::NoError;", fresh)

    def test_authority_settings_namespace_covers_android_file_and_keychain_material(self):
        settings = source("client/secureQSettings.cpp")
        android = between(settings, "QString androidSettingsFilePath(", "SecureQSettings::SecureQSettings(")
        self.assertIn("scope == SecureQSettings::StorageScope::ControlAuthority", android)
        self.assertIn('? QStringLiteral("control-authority.ini") : QStringLiteral("settings.ini")', android)
        self.assertIn('QStringLiteral(".amnezia-control-authority-write-probe")', android)
        self.assertIn('QStringLiteral("amnezia-control-authority-unavailable.ini")', android)
        constructor = between(settings, "SecureQSettings::SecureQSettings(const QString &organization, const QString &application, QObject *parent,",
                              "SecureQSettings::SecureQSettings(const QString &organization, const QString &application,\n")
        self.assertIn("m_settings(androidSettingsFilePath(storageScope), QSettings::IniFormat, parent)", constructor)
        self.assertIn('m_settings(organization, storageScope == StorageScope::ControlAuthority\n'
                      '          ? application + QStringLiteral("-ControlAuthority") : application, parent)', constructor)
        self.assertIn("if (storageScope == StorageScope::Application", constructor)
        self.assertIn("m_settings.setAtomicSyncRequired(storageScope == StorageScope::ControlAuthority);", constructor)
        self.assertIn("if (storageScope == StorageScope::ControlAuthority) m_settings.setFallbacksEnabled(false);", constructor)
        self.assertIn("QJsonArray{organization, application}", constructor)
        self.assertIn("QCryptographicHash::Sha256", constructor)
        self.assertIn('m_storageScope == StorageScope::ControlAuthority\n'
                      '        ? QStringLiteral("controlAuthorityKeyTag-v1-") + m_keychainScope', settings)
        self.assertIn('m_storageScope == StorageScope::ControlAuthority\n'
                      '        ? QStringLiteral("controlAuthorityIvTag-v1-") + m_keychainScope', settings)

    def test_backend_lock_precedes_settings_construction_and_outlives_it(self):
        lock = between(self.store, "bool lock(", "LoadResult load() const")
        wide_lock = lock.index('const QString path = directory + QStringLiteral("/settings.lock");')
        acquired = lock.index('if (!m_lock->tryLock(0)) return fail(error, "authority_busy");', wide_lock)
        settings = lock.index("std::make_unique<SecureQSettings>(", acquired)
        self.assertLess(wide_lock, acquired)
        self.assertLess(acquired, settings)
        self.assertNotIn("std::make_unique<SecureQSettings>(", lock[:acquired])
        # Members are destroyed in reverse declaration order. Secure settings
        # may flush on destruction and must remain protected by the same lock.
        self.assertLess(self.store.index("std::unique_ptr<QLockFile> m_lock;"),
                        self.store.index("std::unique_ptr<SecureQSettings> m_ownedSettings;"))

    def test_recovery_location_is_persisted_before_mutation_without_changing_current_pin(self):
        begin = between(self.store, "bool beginMaintenance(", "bool commitMaintenance(")
        validate = begin.index("!validRecoveryDirectory(recoveryDirectory)")
        save = begin.index('value.insert(QStringLiteral("retainedDirectory"), recoveryDirectory)')
        write = begin.index("return write(value, error);")
        self.assertLess(validate, save)
        self.assertLess(save, write)
        self.assertIn("auto value = current(number, currentSha);", begin)
        self.assertIn('value.insert(QStringLiteral("state"), QStringLiteral("pendingMaintenance"))', begin)

    def test_failed_operator_output_keeps_only_strict_safe_recovery_details(self):
        receipt = source("client/core/controllers/selfhosted/awgMaintenanceReceipt.h")
        details = between(receipt, "inline QJsonObject failureDetails(", "struct Selection {")
        self.assertIn(r'\\A[a-z][a-z0-9_]{0,159}\\z', details)
        self.assertIn(r'\\A/tmp/amnezia-migration-maintenance-[A-Za-z0-9]{24}\\z', details)
        inserted = re.findall(r'details\.insert\(QStringLiteral\("([^"]+)"\)', details)
        self.assertEqual(set(inserted), {"reason", "retainedDirectory", "pendingRecovery", "cleanupRequired"})
        self.assertIn("return details;", details)
        self.assertNotIn("return receipt;", details)
        self.assertNotRegex(details, r"details\s*=\s*receipt")
        self.assertIn('pending.isBool() ? pending.toBool() : true', details)
        self.assertIn('receipt.value(QStringLiteral("cleanupRequired")).isBool()', details)
        self.assertIn('{"result", ok ? receipt : AwgMaintenance::failureDetails(receipt)}', self.app)


if __name__ == "__main__":
    unittest.main()
