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


def controller_method(text, name):
    start = text.index("ErrorCode InstallController::" + name + "(")
    following = re.search(r"\n(?:ErrorCode|ServerRoutingRulesPublishResult) InstallController::", text[start + 1:])
    if following is None:
        raise AssertionError("missing next controller method after " + name)
    return text[start:start + 1 + following.start()]


class AuthoritySourceContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        controller = source("client/core/controllers/selfhosted/installController.cpp")
        cls.prepare = controller_method(controller, "prepareAwgMigration")
        cls.maintenance = controller_method(controller, "maintainAwgMigrationControls")
        cls.store = source("client/core/utils/awgControlAuthorityStore.h")
        cls.app = source("client/amneziaApplication.cpp")

    def test_initial_producer_uses_verified_delivered_feed_not_receipt_sha(self):
        prepare = self.prepare
        bundle = prepare.index("amnezia::serverNative::loadResourceBundle()")
        invalid = prepare.index("nativeBundle.present && !nativeBundle.valid", bundle)
        find = prepare.index('nativeFeed = nativeBundle.find(QStringLiteral("awg-feed"), *architecture)')
        begin = prepare.index("authority->beginPrepare(nativeFeed->sha256, &authorityError")
        commit = prepare.index("authority->commitPrepare(")
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
        self.assertIn("if (!saved.ok)", prepare)
        self.assertIn("if (!saved.missing)", prepare)
        store_begin = between(self.store, "bool beginPrepare(", "bool commitPrepare(")
        self.assertIn('const bool retired = !previous.missing && previous.record.value("state") == "retiredPrepare";', store_begin)
        self.assertIn('if (!previous.missing && !retired) return fail(error, "authority_already_exists")', store_begin)
        self.assertIn('predecessors.size() >= 32', store_begin)
        self.assertIn('value.insert(QStringLiteral("minimumGeneration"), retiredGeneration + 1)', store_begin)
        self.assertIn('value.insert(QStringLiteral("retiredPredecessors"), predecessors)', store_begin)

    def test_prepare_receipt_is_strict_and_commit_precedes_cleanup(self):
        controller_receipt = between(self.prepare, "if (outcome == ErrorCode::NoError && nativeFeed)",
                                     "} else if (outcome == ErrorCode::NoError")
        self.assertIn("AwgMaintenance::nativePrepareReceipt(result, prepareOperationId,", controller_receipt)
        self.assertIn("generation, automatic, &preparedReceipt)", controller_receipt)
        self.assertIn('commitPrepare(preparedReceipt.value("generation").toInteger(),', controller_receipt)
        self.assertIn("nativeFeed->sha256, &authorityError)", controller_receipt)
        receipt = between(source("client/core/controllers/selfhosted/awgMaintenanceReceipt.h"),
                          "inline bool nativePrepareReceipt(", "inline bool validNativeOperationReceipt(")
        for expected in (
            '*receipt = {};', 'envelope.value("prepared").isBool()',
            '!envelope.value("receipt").isString()', 'expectedOperationId.isEmpty()',
            'envelope.value("receipt").toString().toUtf8()', 'bytes.size() > 16384',
            'QJsonDocument::fromJson(bytes)', 'if (!parsed.isObject()) return false;',
            'const auto value = parsed.object();',
            'value.value("prepared").isBool()', 'value.value("prepared").toBool()',
            'value.value("legacyRetained").isBool()', 'value.value("legacyRetained").toBool()',
            'const auto number = value.value("generation");',
            "number.isDouble()", "generation < 1", "generation > 9007199254740991.0",
            "generation != static_cast<double>(number.toInteger())",
            "(!automatic && number.toInteger() != requestedGeneration)",
            'value.value("clientOperationId").toString() != expectedOperationId',
        ):
            self.assertIn(expected, receipt)
        self.assertNotIn('envelope.value("generation")', receipt)
        self.assertNotIn('envelope.value("clientOperationId")', receipt)
        commit = self.prepare.index("authority->commitPrepare(")
        cleanup = self.prepare.index("return finish(outcome);", commit)
        self.assertLess(commit, cleanup)
        finish = between(self.prepare, "auto finish =", "auto directoryIdentity =")
        self.assertIn("const ErrorCode cleanupError = cleanup(details);", finish)
        self.assertIn("primary != ErrorCode::NoError ? primary : cleanupError", finish)
        self.assertIn("result.insert(it.key(), it.value())", finish)

    def test_prepare_nonce_is_created_by_local_intent_before_remote_command(self):
        store_begin = between(self.store, "bool beginPrepare(", "bool commitPrepare(")
        self.assertIn('value.insert(QStringLiteral("operationId"), QUuid::createUuid().toString(QUuid::WithoutBraces))', store_begin)
        self.assertIn("return write(value, error);", store_begin)
        begin = self.prepare.index("authority->beginPrepare(")
        execute = self.prepare.index("error = session.runScript(credentials, script,", begin)
        intent = self.prepare[begin:execute]
        load = intent.index("const auto intent = authority->load();")
        nonce = intent.index('prepareOperationId = intent.record.value(QStringLiteral("operationId")).toString();')
        verify = intent.index("operation.toString(QUuid::WithoutBraces) != prepareOperationId")
        argument = intent.index('script += QStringLiteral(" --client-operation-id')
        self.assertLess(load, nonce)
        self.assertLess(nonce, verify)
        self.assertLess(verify, argument)
        self.assertNotRegex(intent, r'prepareOperationId\s*=\s*(?:result|receipt)\.')

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
        self.assertIn("&authorityError, directory, rootIdentity, upload)", intent_to_exec)
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
            self.assertNotIn("anchorCurrent(", operation)
            self.assertNotRegex(operation, r"authority\s*->\s*(?:remove|clear|reset|abort|cancel)\s*\(")
        self.assertNotIn("resolvePendingPrepare(", self.prepare)
        self.assertIn("if (error != ErrorCode::NoError || pending", self.maintenance)
        failed = between(self.maintenance, "if (error != ErrorCode::NoError || pending",
                         "if (!authority->commitMaintenance(")
        self.assertIn("return finish(validationError, true);", failed)
        self.assertNotIn("resolvePendingMaintenance(", failed)
        self.assertNotIn("resolvePendingPrepare(", failed)
        finish = between(self.maintenance, "auto finish =", "};\n")
        retained = between(finish, "if (retainRecoveryInputs)", "ErrorCode cleanupError = cleanupOwned();")
        self.assertIn("return primary;", retained)
        self.assertNotIn("authority->", retained)

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
            local_assignments = re.findall(r"selection\.currentControlSha256\s*=\s*([^;]+);", operation)
            for assignment in local_assignments:
                self.assertEqual(assignment, 'current.record.value("currentSha").toString()')
        commit = between(self.store, "bool commitMaintenance(", "bool resolvePendingMaintenance(")
        self.assertIn('previous.record.value("currentSha") != oldSha', commit)
        self.assertIn('previous.record.value("replacementSha") != newSha', commit)
        self.assertIn("writeMaintenanceCurrent(previous.record, number, newSha, error)", commit)

    def test_current_commit_preserves_cleanup_obligation_and_prepare_operation(self):
        current = between(self.store, "bool writeMaintenanceCurrent(", "bool validRecord(")
        self.assertIn("auto value = current(number, sha);", current)
        self.assertIn('value.insert(QStringLiteral("prepareOperationId"), pending.value(QStringLiteral("prepareOperationId")))', current)
        self.assertIn('if (pending.contains(QStringLiteral("retainedDirectory")))', current)
        self.assertIn('!pending.contains(QStringLiteral("retainedIdentity"))', current)
        self.assertIn('return fail(error, "authority_recovery_identity_required")', current)
        for source_field in ("retainedDirectory", "retainedIdentity", "replacementSha", "retainedUpload"):
            self.assertIn(f'pending.value(QStringLiteral("{source_field}"))', current)
        self.assertIn('value.insert(QStringLiteral("cleanup"), cleanup)', current)
        self.assertIn("return write(value, error);", current)

    def test_status_receipts_are_distinct_from_live_recovery_authorization(self):
        receipt = between(source("client/core/controllers/selfhosted/awgMaintenanceReceipt.h"),
                          "inline bool validNativeOperationReceipt(", "inline bool validNativeReceipt(")
        self.assertIn('return mode == QStringLiteral("status")', receipt)
        self.assertIn('mode == QStringLiteral("recover") || mode == QStringLiteral("verify")', receipt)
        self.assertIn('!receipt.value("pendingRecovery").toBool()', receipt)
        self.assertIn('receipt.value("phase").toString() == QStringLiteral("ready")', receipt)
        self.assertIn('receipt.value("liveVerified").isBool() && receipt.value("liveVerified").toBool()', receipt)
        self.assertIn('receipt.value("clientOperationId").toString() != clientOperationId', receipt)
        # A successfully parsed status is still read-only. Only the explicitly
        # selected, validated live operation may settle its corresponding intent.
        parsed = self.maintenance.index("result = QJsonDocument::fromJson(output.trimmed()).object();")
        validate = self.maintenance.index("!AwgMaintenance::validNativeOperationReceipt(", parsed)
        recover = self.maintenance.index("authority->resolvePendingMaintenance(", validate)
        verify = self.maintenance.index("authority->resolvePendingPrepare(", validate)
        self.assertLess(validate, recover)
        self.assertLess(validate, verify)
        self.assertRegex(self.maintenance[validate:],
                         r"if \(selection\.operation == AwgMaintenance::Operation::Recover\s*"
                         r"&& !authority->resolvePendingMaintenance\(")
        self.assertRegex(self.maintenance[validate:],
                         r"if \(selection\.operation == AwgMaintenance::Operation::VerifyPrepare\s*"
                         r"&& !authority->resolvePendingPrepare\(")

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
        self.assertIn('const QString fixedPath = QDir(directory).filePath(QStringLiteral("control-authority.ini"));', android)
        self.assertIn('QStringLiteral(".amnezia-control-authority-write-probe")', android)
        self.assertIn('QStringLiteral("/__amnezia_control_authority_unavailable__/control-authority.ini")', android)
        constructor = between(settings, "SecureQSettings::SecureQSettings(const QString &organization, const QString &application, QObject *parent,",
                              "SecureQSettings::SecureQSettings(const QString &organization, const QString &application,\n")
        self.assertIn("m_settings(androidSettingsFilePath(storageScope, &m_storageAvailable), QSettings::IniFormat, parent)", constructor)
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

    def test_android_authority_never_moves_to_a_different_writable_backend(self):
        settings = source("client/secureQSettings.cpp")
        helper = between(settings, "QString androidSettingsFilePath(", "SecureQSettings::SecureQSettings(")
        authority = between(helper, "if (scope == SecureQSettings::StorageScope::ControlAuthority)",
                            "// Do not construct QSettings with an empty filename.")
        self.assertEqual(authority.count("QStandardPaths::writableLocation("), 1)
        self.assertIn("QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation)", authority)
        for alternative in ("AppLocalDataLocation", "AppDataLocation", "TempLocation", "QDir::tempPath", "candidates"):
            self.assertNotIn(alternative, authority)
        self.assertIn("*available = false;", authority)
        self.assertIn("base.isEmpty() || !QDir::isAbsolutePath(base)", authority)
        self.assertIn("*available = probeOk;", authority)
        self.assertEqual(authority.count("return fixedPath;"), 3)
        # The existing application backend keeps its heuristic locations.
        application = helper[helper.index("// Do not construct QSettings with an empty filename."):]
        for location in ("AppConfigLocation", "AppLocalDataLocation", "AppDataLocation", "TempLocation"):
            self.assertIn("QStandardPaths::" + location, application)
        self.assertIn('QStringLiteral("settings.ini")', application)
        self.assertIn('QStringLiteral("amnezia-settings-unavailable.ini")', application)

    def test_unavailable_authority_never_becomes_fresh_missing_or_writes_keys(self):
        settings = source("client/secureQSettings.cpp")
        declaration = source("client/secureQSettings.h")
        self.assertLess(declaration.index("bool m_storageAvailable = true;"), declaration.index("QSettings m_settings;"))
        constructor = between(settings, "SecureQSettings::SecureQSettings(const QString &organization, const QString &application, QObject *parent,",
                              "SecureQSettings::SecureQSettings(const QString &organization, const QString &application,\n")
        self.assertLess(constructor.index("m_storageAvailable(true)"), constructor.index("m_settings("))
        unavailable = constructor.index("if (!m_storageAvailable) return;")
        self.assertLess(unavailable, constructor.index("m_settings.allKeys()"))
        self.assertLess(unavailable, constructor.index("migrateEncryptedSettings()"))
        fresh = between(settings, "bool SecureQSettings::readFreshValue(", "void SecureQSettings::setValue(")
        self.assertLess(fresh.index("if (!m_storageAvailable) return false;"), fresh.index("m_settings.sync();"))
        for start, end, guard in (
            ("QVariant SecureQSettings::value(", "bool SecureQSettings::readFreshValue(", "return defaultValue;"),
            ("void SecureQSettings::setValue(", "void SecureQSettings::remove(", "return;"),
            ("void SecureQSettings::remove(", "QByteArray SecureQSettings::backupAppConfig(", "return;"),
            ("QByteArray SecureQSettings::backupAppConfig(", "bool SecureQSettings::restoreAppConfig(", "return {};"),
            ("bool SecureQSettings::restoreAppConfig(", "bool SecureQSettings::isExcludedFromBackup(", "return false;"),
            ("void SecureQSettings::clearSettings(", "QByteArray SecureQSettings::encryptText(", "return;"),
        ):
            method = between(settings, start, end)
            gate = method.index("if (!m_storageAvailable) " + guard)
            if "m_settings." in method:
                self.assertLess(gate, method.index("m_settings."))
        load = between(self.store, "LoadResult load() const", "bool beginPrepare(")
        failure = load.index("if (!m_settings->readFreshValue(settingsKey(), value))")
        missing = load.index("if (!value.isValid()) return {true, true", failure)
        self.assertIn('return {false, false, {}, QStringLiteral("authority_read_failed")};', load[failure:missing])

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
        self.assertIn("!currentMatches(previous.record, number, currentSha)", begin)
        self.assertIn("auto value = previous.record;", begin)
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
