#include <QtTest>
#include <QJsonArray>
#include "core/controllers/selfhosted/awgMaintenanceReceipt.h"
#include "core/controllers/selfhosted/awgPrepareRecoveryLocator.h"
#include "core/utils/operatorCommand.h"

namespace {
const QString prepareOperation = QStringLiteral("ce7b6aa4-439a-4e74-9ed8-7f5a87c2cb5f");
QJsonObject preparedReceipt()
{
    return {{"prepared", true}, {"generation", 7}, {"peerCount", 2},
            {"serverPublicKey", "fixture-server"}, {"signingPublicKey", "fixture-signing"},
            {"legacyRetained", true}, {"clientOperationId", prepareOperation}};
}
QJsonObject preparedEnvelope(const QJsonObject &receipt)
{
    // Match prepare_entry.cpp: receipt is a serialized JSON string, not an
    // object, and generation/legacyRetained are not top-level success fields.
    return {{"prepared", true},
            {"receipt", QString::fromUtf8(QJsonDocument(receipt).toJson(QJsonDocument::Compact))}};
}
QJsonObject operationReceipt(const QString &mode)
{
    return {{"ok", true}, {"mode", mode}, {"source", "amnezia-awg2"}, {"generation", 7},
            {"native", true}, {"pendingRecovery", false}, {"phase", "ready"}, {"liveVerified", true},
            {"clientOperationId", prepareOperation}, {"controlHashes", QJsonObject{{"awg-feed", QString(64, 'a')}}},
            {"journalSha256", QString(64, 'b')}};
}
}

class ReceiptTests : public QObject {
    Q_OBJECT
private slots:
    // Exercise the production Qt receipt helpers without SSH or native effects.
    void readsActualNativePrepareEnvelope()
    {
        const auto nested = preparedReceipt();
        const auto envelope = preparedEnvelope(nested);
        QJsonObject result;
        QVERIFY(AwgMaintenance::nativePrepareReceipt(envelope, prepareOperation, 7, false, &result));
        QCOMPARE(result, nested);
        QVERIFY(!envelope.contains("generation"));
        QVERIFY(!envelope.contains("legacyRetained"));
        QVERIFY(AwgMaintenance::nativePrepareReceipt(envelope, prepareOperation, 0, true, &result));
        QVERIFY(!AwgMaintenance::nativePrepareReceipt(envelope, prepareOperation, 8, false, &result));
        QVERIFY(result.isEmpty());
        QVERIFY(!AwgMaintenance::nativePrepareReceipt(envelope, QString(), 7, false, &result));
        QVERIFY(!AwgMaintenance::nativePrepareReceipt(envelope, prepareOperation, 7, false, nullptr));
    }
    void rejectsMissingWrongTypeAndMalformedNestedPrepareReceipt()
    {
        const auto valid = preparedEnvelope(preparedReceipt());
        const QList<QJsonValue> invalid{QJsonValue(), true, 7, QJsonObject{}, QJsonArray{},
            "", "{", "[]", "null", "\"not an object\"", "{\"prepared\":true", QString(16385, 'x')};
        for (const auto &value : invalid) {
            auto changed = valid;
            changed.insert("receipt", value);
            QJsonObject result{{"previous", "must be cleared"}};
            QVERIFY2(!AwgMaintenance::nativePrepareReceipt(changed, prepareOperation, 7, false, &result),
                     qPrintable(QString::fromUtf8(QJsonDocument(changed).toJson(QJsonDocument::Compact).left(200))));
            QVERIFY(result.isEmpty());
        }
        auto missing = valid;
        missing.remove("receipt");
        QJsonObject result;
        QVERIFY(!AwgMaintenance::nativePrepareReceipt(missing, prepareOperation, 7, false, &result));
        for (const QJsonValue &value : {QJsonValue(), QJsonValue(false), QJsonValue("true"), QJsonValue(1)}) {
            auto changed = valid;
            changed.insert("prepared", value);
            QVERIFY(!AwgMaintenance::nativePrepareReceipt(changed, prepareOperation, 7, false, &result));
        }
    }
    void topLevelPrepareMetadataCannotRepairInvalidNestedReceipt()
    {
        const auto original = preparedReceipt();
        const QList<QPair<QString, QJsonValue>> changes{{"prepared", false}, {"prepared", "true"},
            {"legacyRetained", false}, {"legacyRetained", 1}, {"generation", 0},
            {"generation", true}, {"generation", 7.5}, {"generation", 8},
            {"generation", 9007199254740992.0}, {"clientOperationId", "foreign-operation"},
            {"clientOperationId", 7}};
        for (const auto &change : changes) {
            auto nested = original;
            nested.insert(change.first, change.second);
            auto spoofed = preparedEnvelope(nested);
            spoofed.insert("generation", 7);
            spoofed.insert("legacyRetained", true);
            spoofed.insert("clientOperationId", prepareOperation);
            QJsonObject result{{"previous", true}};
            QVERIFY2(!AwgMaintenance::nativePrepareReceipt(spoofed, prepareOperation, 7, false, &result),
                     qPrintable(change.first));
            QVERIFY(result.isEmpty());
        }
        for (const QString &missing : {QString("prepared"), QString("legacyRetained"),
                                      QString("generation"), QString("clientOperationId")}) {
            auto nested = original;
            nested.remove(missing);
            auto spoofed = preparedEnvelope(nested);
            spoofed.insert(missing, original.value(missing));
            QJsonObject result;
            QVERIFY2(!AwgMaintenance::nativePrepareReceipt(spoofed, prepareOperation, 7, false, &result), qPrintable(missing));
        }
    }
    void statusIsReadOnlyAndRecoveryRequiresLiveProof()
    {
        auto status = operationReceipt("status");
        status.insert("pendingRecovery", true);
        status.insert("phase", "maintenance_pending");
        status.remove("liveVerified");
        QVERIFY(AwgMaintenance::validNativeOperationReceipt(status, "status", "amnezia-awg2", 7,
                                                           QString(64, 'a'), prepareOperation));
        // A status reply can describe uncertainty, but cannot masquerade as
        // the live verification/recovery receipt that settles local pending.
        QVERIFY(!AwgMaintenance::validNativeOperationReceipt(status, "recover", "amnezia-awg2", 7,
                                                            QString(64, 'a'), prepareOperation));
        for (const QString &mode : {QString("recover"), QString("verify")}) {
            const auto valid = operationReceipt(mode);
            QVERIFY(AwgMaintenance::validNativeOperationReceipt(valid, mode, "amnezia-awg2", 7,
                                                               QString(64, 'a'), prepareOperation));
            const QList<QPair<QString, QJsonValue>> changes{{"pendingRecovery", true}, {"pendingRecovery", "false"},
                {"phase", "not_ready"}, {"phase", "ready\n"}, {"liveVerified", false}, {"liveVerified", "true"},
                {"clientOperationId", "foreign-operation"}, {"generation", 8}, {"generation", true},
                {"source", "amnezia-awg"}, {"controlHashes", QJsonObject{{"awg-feed", QString(64, 'c')}}},
                {"controlHashes", QJsonObject{{"awg-feed", QString(64, 'a')}, {"extra", QString(64, 'a')}}}};
            for (const auto &change : changes) {
                auto changed = valid;
                changed.insert(change.first, change.second);
                QVERIFY2(!AwgMaintenance::validNativeOperationReceipt(changed, mode, "amnezia-awg2", 7,
                                                                     QString(64, 'a'), prepareOperation),
                         qPrintable(mode + ":" + change.first));
            }
            auto missingLiveProof = valid;
            missingLiveProof.remove("liveVerified");
            QVERIFY(!AwgMaintenance::validNativeOperationReceipt(missingLiveProof, mode, "amnezia-awg2", 7,
                                                                QString(64, 'a'), prepareOperation));
        }
    }
    void partialPrepareInspectionRequiresExactUnretiredNonLiveProof()
    {
        for (const QString &phase : {QString("preparing"), QString("creating"), QString("activating"), QString("aborted")}) {
            auto valid = operationReceipt("inspect-prepare");
            valid.insert("phase", phase);
            valid.insert("liveVerified", false);
            valid.insert("retiredVerified", false);
            QVERIFY(AwgMaintenance::validNativeOperationReceipt(valid, "inspect-prepare", "amnezia-awg2", 7,
                                                               QString(64, 'a'), prepareOperation));
            const QList<QPair<QString, QJsonValue>> changes{{"ok", false}, {"ok", "true"},
                {"mode", "abort-prepare"}, {"source", "amnezia-awg"}, {"generation", 8},
                {"generation", "7"}, {"generation", true}, {"native", false},
                {"pendingRecovery", true}, {"pendingRecovery", "false"}, {"phase", "ready"},
                {"phase", "foreign"}, {"liveVerified", true}, {"liveVerified", "false"},
                {"retiredVerified", true}, {"retiredVerified", "false"},
                {"clientOperationId", "foreign-operation"}, {"clientOperationId", ""},
                {"controlHashes", QJsonObject{{"awg-feed", QString(64, 'c')}}},
                {"controlHashes", QJsonObject{{"awg-feed", QString(64, 'a')}, {"extra", QString(64, 'a')}}},
                {"journalSha256", QString(64, 'b') + '\n'}};
            for (const auto &change : changes) {
                auto wrong = valid;
                wrong.insert(change.first, change.second);
                QVERIFY2(!AwgMaintenance::validNativeOperationReceipt(wrong, "inspect-prepare", "amnezia-awg2", 7,
                                                                     QString(64, 'a'), prepareOperation),
                         qPrintable(phase + ":" + change.first));
            }
            QVERIFY(!AwgMaintenance::validNativeOperationReceipt(valid, "inspect-prepare", "amnezia-awg2", 7,
                                                                QString(64, 'a'), QString()));
            for (const auto &key : valid.keys()) {
                auto missing = valid;
                missing.remove(key);
                QVERIFY2(!AwgMaintenance::validNativeOperationReceipt(missing, "inspect-prepare", "amnezia-awg2", 7,
                                                                     QString(64, 'a'), prepareOperation), qPrintable(key));
            }
        }
    }
    void prepareAbortRequiresExactRetiredProofAndCannotClaimLiveActivation()
    {
        auto valid = operationReceipt("abort-prepare");
        valid.insert("phase", "aborted");
        valid.insert("liveVerified", false);
        valid.insert("retiredVerified", true);
        QVERIFY(AwgMaintenance::validNativeOperationReceipt(valid, "abort-prepare", "amnezia-awg2", 7,
                                                           QString(64, 'a'), prepareOperation));
        const QList<QPair<QString, QJsonValue>> changes{{"retiredVerified", false}, {"retiredVerified", "true"},
            {"phase", "preparing"}, {"phase", "creating"}, {"phase", "activating"}, {"phase", "ready"},
            {"phase", "aborted\n"}, {"liveVerified", true}, {"liveVerified", "false"},
            {"pendingRecovery", true}, {"clientOperationId", "foreign-operation"},
            {"generation", 8}, {"generation", 7.5}, {"generation", true},
            {"controlHashes", QJsonObject{{"awg-feed", QString(64, 'c')}}},
            {"journalSha256", QString(64, 'b') + '\n'}};
        for (const auto &change : changes) {
            auto wrong = valid;
            wrong.insert(change.first, change.second);
            QVERIFY2(!AwgMaintenance::validNativeOperationReceipt(wrong, "abort-prepare", "amnezia-awg2", 7,
                                                                 QString(64, 'a'), prepareOperation), qPrintable(change.first));
        }
        QVERIFY(!AwgMaintenance::validNativeOperationReceipt(valid, "abort-prepare", "amnezia-awg2", 7,
                                                            QString(64, 'c'), prepareOperation));
        QVERIFY(!AwgMaintenance::validNativeOperationReceipt(valid, "abort-prepare", "amnezia-awg2", 7,
                                                            QString(64, 'a'), QString()));
        QVERIFY(!AwgMaintenance::validNativeOperationReceipt(valid, "verify", "amnezia-awg2", 7,
                                                            QString(64, 'a'), prepareOperation));
        QVERIFY(!AwgMaintenance::validNativeOperationReceipt(valid, "recover", "amnezia-awg2", 7,
                                                            QString(64, 'a'), prepareOperation));
    }
    void locatesInterruptedRetryAmongTrustedRetiredPredecessors()
    {
        const QString root = QStringLiteral("/opt/amnezia/awg-migration/amnezia-awg2/");
        const auto row = [&](qint64 number) { return root.toLatin1() + QByteArray::number(number) + '\n'; };
        const QJsonArray retired{QJsonObject{{"generation", 1}}, QJsonObject{{"generation", 2}}};
        auto found = AwgMaintenance::prepareRecoveryGeneration(row(1) + row(3) + row(2), root, retired, 3);
        QVERIFY(found.has_value());
        QCOMPARE(*found, qint64(3));
        found = AwgMaintenance::prepareRecoveryGeneration(row(8), root, retired, 3);
        QVERIFY(found.has_value());
        QCOMPARE(*found, qint64(8));
        QVERIFY(!AwgMaintenance::prepareRecoveryGeneration(row(1) + row(2), root, retired, 3));
        QVERIFY(!AwgMaintenance::prepareRecoveryGeneration(row(1) + row(3) + row(4), root, retired, 3));
        QVERIFY(!AwgMaintenance::prepareRecoveryGeneration(row(1) + row(1) + row(3), root, retired, 3));
        QVERIFY(!AwgMaintenance::prepareRecoveryGeneration(row(1) + row(2) + row(3), root, retired, 4));
        QVERIFY(!AwgMaintenance::prepareRecoveryGeneration(row(1), root, {}, 2));
        found = AwgMaintenance::prepareRecoveryGeneration(row(7), root);
        QVERIFY(found.has_value());
        QCOMPARE(*found, qint64(7));
    }
    void interruptedLocatorRejectsMalformedAmbiguousAndTruncatedScans()
    {
        const QString root = QStringLiteral("/opt/amnezia/awg-migration/amnezia-awg/");
        const QByteArray prefix = root.toLatin1();
        const QList<QByteArray> invalid{QByteArray(), prefix + "1", prefix + "01\n", prefix + "0\n",
            prefix + "+1\n", prefix + "-1\n", prefix + "1.0\n", prefix + "1e0\n", prefix + "1 \n",
            prefix + "1\r\n", prefix + "../1\n", prefix + "1/transaction.json\n", prefix + "1\n\n",
            prefix + "1\n" + prefix + "1\n", prefix + "1\n" + prefix + "2\n",
            prefix + "9007199254740992\n", prefix + QByteArray(80, '9') + '\n',
            QByteArray("/opt/amnezia/awg-migration/amnezia-awg2/1\n"), QByteArray(4097, 'x')};
        for (const auto &scan : invalid)
            QVERIFY2(!AwgMaintenance::prepareRecoveryGeneration(scan, root), scan.constData());
        QByteArray embeddedNul = prefix + "1";
        embeddedNul.append('\0'); embeddedNul.append('\n');
        QVERIFY(!AwgMaintenance::prepareRecoveryGeneration(embeddedNul, root));
        QVERIFY(!AwgMaintenance::prepareRecoveryGeneration(prefix + "1\n", "/tmp/untrusted/"));
        QVERIFY(!AwgMaintenance::prepareRecoveryGeneration(prefix + "1\n", root + "/"));
        QVERIFY(!AwgMaintenance::prepareRecoveryGeneration(prefix + "1\n", root, {}, 0));
    }
    void interruptedLocatorBoundsTrustedHistoryAndFindOutput()
    {
        const QString root = QStringLiteral("/opt/amnezia/awg-migration/amnezia-awg2/");
        const auto row = [&](qint64 number) { return root.toLatin1() + QByteArray::number(number) + '\n'; };
        QJsonArray history;
        QByteArray output;
        for (int i = 1; i <= 32; ++i) { history.append(QJsonObject{{"generation", i}}); output += row(i); }
        const auto found = AwgMaintenance::prepareRecoveryGeneration(output + row(33), root, history, 33);
        QVERIFY(found.has_value());
        QCOMPARE(*found, qint64(33));
        QVERIFY(!AwgMaintenance::prepareRecoveryGeneration(output, root, history, 33));
        QVERIFY(!AwgMaintenance::prepareRecoveryGeneration(output + row(33) + row(34), root, history, 33));
        history.append(QJsonObject{{"generation", 33}});
        QVERIFY(!AwgMaintenance::prepareRecoveryGeneration(row(34), root, history, 34));
        const QList<QJsonArray> invalidHistories{QJsonArray{true}, QJsonArray{QJsonObject{}},
            QJsonArray{QJsonObject{{"generation", true}}}, QJsonArray{QJsonObject{{"generation", "1"}}},
            QJsonArray{QJsonObject{{"generation", 1.5}}}, QJsonArray{QJsonObject{{"generation", -1}}},
            QJsonArray{QJsonObject{{"generation", 2}}, QJsonObject{{"generation", 1}}},
            QJsonArray{QJsonObject{{"generation", 1}}, QJsonObject{{"generation", 1}}}};
        for (const auto &invalid : invalidHistories)
            QVERIFY(!AwgMaintenance::prepareRecoveryGeneration(row(3), root, invalid, 3));
        QVERIFY(!AwgMaintenance::prepareRecoveryGeneration(row(3), root, QJsonArray{QJsonObject{{"generation", 2}}}, 2));
    }
    void parsesExplicitMaintenanceAndRejectsAmbiguity() {
        using namespace amnezia::operatorMode;
        const QString request = QStringLiteral("{\"serverId\":\"selected\",\"source\":\"amnezia-awg2\",\"generation\":1,\"expectedJournalSha256\":\"%1\"}").arg(QString(64, 'a'));
        QVERIFY(!parseAwgMaintenanceArgument(request).isEmpty());
        const QString localCurrent = request.left(request.size() - 1)
                + QStringLiteral(",\"nativeControlVariant\":\"native-control-http-v1\"}");
        QVERIFY(!parseAwgMaintenanceArgument(localCurrent).isEmpty());
        const QString explicitCurrent = localCurrent.left(localCurrent.size() - 1)
                + QStringLiteral(",\"currentControlSha256\":\"%1\"}").arg(QString(64, 'b'));
        QVERIFY(!parseAwgMaintenanceArgument(explicitCurrent).isEmpty());
        QVERIFY(parseAwgMaintenanceArgument(QString(explicitCurrent).replace(QString(64, 'b'), QString())).isEmpty());
        auto maximum = request;
        maximum.replace("\"generation\":1", "\"generation\":9007199254740991");
        QVERIFY(!parseAwgMaintenanceArgument(maximum).isEmpty());
        QStringList invalid {request + "x", "[]", "{}", request.left(request.size() - 1) + ",}",
            request.left(request.size() - 1) + ",\"serverId\":\"other\"}",
            request.left(request.size() - 1) + ",\"server\\u0049d\":\"other\"}",
            request.left(request.size() - 1) + ",\"unknown\":\"value\"}"};
        for (const QString &replacement : {QString("true"), QString("0"), QString("-1"), QString("01"),
                QString("1.0"), QString("1e0"), QString("9007199254740992"), QString("{}"), QString("null")}) {
            auto changed = request;
            changed.replace("\"generation\":1", "\"generation\":" + replacement);
            invalid.append(changed);
        }
        invalid.append(QString(4097, ' '));
        for (const auto &value : invalid) QVERIFY(parseAwgMaintenanceArgument(value).isEmpty());
        QByteArray executable("AmneziaVPN");
        QByteArray argument = ("--maintain-awg-controls=" + request).toUtf8();
        char *arguments[] {executable.data(), argument.data()};
        const auto parsed = parseArguments(2, arguments);
        QVERIFY(parsed.hasOperatorArguments);
        QVERIFY(parsed.valid);
        QCOMPARE(parsed.request.type, CommandType::MaintainAwgControls);
        QCOMPARE(commandType("maintain-awg-controls"), CommandType::None);
        QByteArray foreign("--connect=1");
        char *mixed[] {executable.data(), argument.data(), foreign.data()};
        QVERIFY(!parseArguments(3, mixed).valid);
        QByteArray second("--status");
        char *multiple[] {executable.data(), argument.data(), second.data()};
        QVERIFY(!parseArguments(3, multiple).valid);
    }
    void failureOutputPreservesOnlySafeRecoveryHints() {
        const QString owned = "/tmp/amnezia-migration-maintenance-" + QString(24, 'a');
        const QJsonObject raw{{"reason", "native_cleanup_failed"}, {"retainedDirectory", owned},
                              {"password", "must-not-escape"}, {"raw", "ssh-output"}};
        const auto safe = AwgMaintenance::failureDetails(raw);
        QCOMPARE(safe.value("reason").toString(), QString("native_cleanup_failed"));
        QCOMPARE(safe.value("retainedDirectory").toString(), owned);
        QVERIFY(safe.value("pendingRecovery").toBool());
        QCOMPARE(safe.size(), 3);
        for (const QString &path : {QString("/tmp/../etc"), owned + "/child", owned + "\n", QString("/home/user/private")}) {
            const auto rejected = AwgMaintenance::failureDetails({{"reason", "bad\noutput"}, {"retainedDirectory", path}});
            QVERIFY(rejected.isEmpty());
        }
    }
    void failureOutputPreservesPrepareCleanupWithoutInventingRecovery() {
        const QString staging = "/tmp/amnezia-migration-" + QString(24, 'a');
        const QString programs = "/tmp/amnezia-migration-programs-" + QString(24, 'B');
        const QJsonObject raw{{"reason", "prepare_failed"}, {"retainedPrepareDirectory", staging},
            {"retainedProgramDirectory", programs}, {"cleanupRequired", true},
            {"password", "must-not-escape"}, {"pendingRecovery", false}};
        const auto safe = AwgMaintenance::failureDetails(raw);
        QCOMPARE(safe.size(), 4);
        QCOMPARE(safe.value("reason").toString(), QString("prepare_failed"));
        QCOMPARE(safe.value("retainedPrepareDirectory").toString(), staging);
        QCOMPARE(safe.value("retainedProgramDirectory").toString(), programs);
        QVERIFY(safe.value("cleanupRequired").toBool());
        QVERIFY(!safe.contains("pendingRecovery"));
        for (const QString &path : {QString("/tmp/../etc"), staging + "/child", staging + "\n",
                                   programs + "/native-feed", QString("/home/user/private")}) {
            const auto rejected = AwgMaintenance::failureDetails({{"retainedPrepareDirectory", path},
                {"retainedProgramDirectory", path}, {"cleanupRequired", true}});
            QVERIFY(rejected.isEmpty());
        }
        const auto mistyped = AwgMaintenance::failureDetails({{"retainedPrepareDirectory", staging},
            {"cleanupRequired", "true"}});
        QVERIFY(!mistyped.contains("cleanupRequired"));
    }
    void acceptsExactUploadedRecipe() {
        const QJsonObject hashes{{"service.py", QString(64, 'a')}, {"target.py", QString(64, 'b')}};
        const QJsonObject receipt{{"maintained", true}, {"loaded", true}, {"source", "amnezia-awg2"},
            {"generation", 1}, {"controlHashes", hashes}, {"journalSha256", QString(64, 'c')}};
        QVERIFY(AwgMaintenance::validReceipt(receipt, "amnezia-awg2", 1, hashes));
    }
    void maintenanceDigestsRejectTrailingNewline() {
        const QString oldSha(64, 'a'), newSha(64, 'b'), journal(64, 'c');
        QJsonObject native{{"ok", true}, {"mode", "maintain"}, {"source", "amnezia-awg2"},
            {"generation", 1}, {"native", true}, {"pendingRecovery", false},
            {"controlHashes", QJsonObject{{"awg-feed", newSha}}}, {"journalSha256", journal}};
        QVERIFY(AwgMaintenance::validNativeReceipt(native, "amnezia-awg2", 1, oldSha, newSha));
        QVERIFY(!AwgMaintenance::validNativeReceipt(native, "amnezia-awg2", 1, oldSha + '\n', newSha));
        auto changedHash = native;
        changedHash.insert("controlHashes", QJsonObject{{"awg-feed", newSha + '\n'}});
        QVERIFY(!AwgMaintenance::validNativeReceipt(changedHash, "amnezia-awg2", 1, oldSha, newSha + '\n'));
        native.insert("journalSha256", journal + '\n');
        QVERIFY(!AwgMaintenance::validNativeReceipt(native, "amnezia-awg2", 1, oldSha, newSha));
        const QJsonObject hashes{{"service.py", oldSha}, {"target.py", newSha}};
        const QJsonObject legacy{{"maintained", true}, {"loaded", true}, {"source", "amnezia-awg2"},
            {"generation", 1}, {"controlHashes", hashes}, {"journalSha256", journal + '\n'}};
        QVERIFY(!AwgMaintenance::validReceipt(legacy, "amnezia-awg2", 1, hashes));
    }
    void rejectsWrongScopeRecipeAndMissingLoadedProof() {
        const QJsonObject hashes{{"service.py", QString(64, 'a')}, {"target.py", QString(64, 'b')}};
        const QJsonObject receipt{{"maintained", true}, {"loaded", true}, {"source", "amnezia-awg2"},
            {"generation", 1}, {"controlHashes", hashes}, {"journalSha256", QString(64, 'c')}};
        const QList<QPair<QString, QJsonValue>> changes{{"maintained", false}, {"loaded", false},
            {"loaded", "true"}, {"source", "amnezia-awg"}, {"generation", 2}, {"generation", true},
            {"controlHashes", QJsonObject{{"service.py", QString(64, 'a')}}},
            {"controlHashes", QJsonObject{{"service.py", QString(64, 'c')}, {"target.py", QString(64, 'b')}}},
            {"journalSha256", QString(63, 'c')}, {"journalSha256", QString(64, 'C')}};
        for (const auto &change : changes) {
            auto changed = receipt;
            changed.insert(change.first, change.second);
            QVERIFY2(!AwgMaintenance::validReceipt(changed, "amnezia-awg2", 1, hashes), qPrintable(change.first));
        }
        for (const auto &key : receipt.keys()) {
            auto changed = receipt;
            changed.remove(key);
            QVERIFY2(!AwgMaintenance::validReceipt(changed, "amnezia-awg2", 1, hashes), qPrintable(key));
        }
    }
};
QTEST_GUILESS_MAIN(ReceiptTests)
#include "tst_receipt.moc"
