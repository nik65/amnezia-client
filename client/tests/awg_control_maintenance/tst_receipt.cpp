#include <QtTest>
#include "core/controllers/selfhosted/awgMaintenanceReceipt.h"
#include "core/utils/operatorCommand.h"

class ReceiptTests : public QObject {
    Q_OBJECT
private slots:
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
    void acceptsExactUploadedRecipe() {
        const QJsonObject hashes{{"service.py", QString(64, 'a')}, {"target.py", QString(64, 'b')}};
        const QJsonObject receipt{{"maintained", true}, {"loaded", true}, {"source", "amnezia-awg2"},
            {"generation", 1}, {"controlHashes", hashes}, {"journalSha256", QString(64, 'c')}};
        QVERIFY(AwgMaintenance::validReceipt(receipt, "amnezia-awg2", 1, hashes));
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
