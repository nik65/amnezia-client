#include <QtTest>

#include <QTemporaryDir>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCryptographicHash>

#include "headlessUpdateManager.h"

using namespace amnezia::headless;

class HeadlessUpdateTest : public QObject
{
    Q_OBJECT

private slots:
    void disabledUpdatesDoNotTouchNetworkOrStateUnexpectedly()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        HeadlessUpdateManager manager({},
                                      temporaryDirectory.filePath(QStringLiteral("updates.json")),
                                      temporaryDirectory.path(), false);
        Profile profile;
        profile.autoUpdate = false;

        const HeadlessUpdateResult result = manager.checkAndApply(
                profile, QStringLiteral("5.0.1.6"));
        QVERIFY(result.ok);
        QCOMPARE(result.code, QStringLiteral("disabled"));
        QCOMPARE(manager.status().value(QStringLiteral("state")).toString(),
                 QStringLiteral("disabled"));
        QVERIFY(!manager.status().value(QStringLiteral("rollbackAvailable")).toBool());
    }

    void incompleteJournalFailsClosedAndIsVisible()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("state.json"));
        const QString updates = temporaryDirectory.filePath(QStringLiteral("updates"));
        QVERIFY(QDir().mkpath(updates));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("state"), QStringLiteral("restart_pending") },
            { QStringLiteral("lastCheckedAt"), QString() },
            { QStringLiteral("lastAppliedVersion"), QStringLiteral("5.0.1.16") },
            { QStringLiteral("rollbackDirectory"), QString() },
            { QStringLiteral("rollbackVersion"), QString() },
            { QStringLiteral("rollbackHashes"), QJsonObject() },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("updateRoot"), QDir(updates).canonicalPath() },
            { QStringLiteral("lastError"), QString() },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();
        QFile journal(QDir(updates).filePath(QStringLiteral("transaction.json")));
        QVERIFY(journal.open(QIODevice::WriteOnly));
        QVERIFY(journal.write(QByteArrayLiteral("{\"phase\":\"replaced\"}")) > 0);
        journal.close();

        HeadlessUpdateManager manager({}, statePath, temporaryDirectory.path(), false);
        QVERIFY(manager.status().value(QStringLiteral("recoveryRequired")).toBool());
        const HeadlessUpdateResult result = manager.checkAndApply(Profile {},
                                                                   QStringLiteral("5.0.1.16"));
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("recovery_required"));
    }

    void restartPendingJournalIsAcknowledgedOnlyAfterBinaryHealthCheck()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        for (const QString &name : { QStringLiteral("amneziad"), QStringLiteral("amnezia-cli") }) {
            QFile binary(temporaryDirectory.filePath(name));
            QVERIFY(binary.open(QIODevice::WriteOnly));
            QVERIFY(binary.write("test") > 0);
            binary.close();
        }
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("state.json"));
        const QString updates = temporaryDirectory.filePath(QStringLiteral("updates"));
        QVERIFY(QDir().mkpath(updates));
        const QString transaction = QDir(updates).filePath(QStringLiteral("transaction-test"));
        QVERIFY(QDir().mkpath(transaction));
        const QString rollback = QDir(updates).filePath(QStringLiteral("rollback-test"));
        QVERIFY(QDir().mkpath(rollback));
        const QString digest = QString::fromLatin1(QCryptographicHash::hash(
                QByteArrayLiteral("old"), QCryptographicHash::Sha256).toHex());
        const QString candidateDigest = QString::fromLatin1(QCryptographicHash::hash(
                QByteArrayLiteral("test"), QCryptographicHash::Sha256).toHex());
        for (const QString &name : { QStringLiteral("amneziad"), QStringLiteral("amnezia-cli") }) {
            QFile backup(QDir(rollback).filePath(name));
            QVERIFY(backup.open(QIODevice::WriteOnly));
            QVERIFY(backup.write("old") > 0);
            backup.close();
        }
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("state"), QStringLiteral("restart_pending") },
            { QStringLiteral("lastCheckedAt"), QString() },
            { QStringLiteral("lastAppliedVersion"), QStringLiteral("5.0.1.16") },
            { QStringLiteral("rollbackDirectory"), QString() },
            { QStringLiteral("rollbackVersion"), QString() },
            { QStringLiteral("rollbackHashes"), QJsonObject() },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("updateRoot"), QDir(updates).canonicalPath() },
            { QStringLiteral("lastError"), QString() },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();
        QFile journal(QDir(updates).filePath(QStringLiteral("transaction.json")));
        QVERIFY(journal.open(QIODevice::WriteOnly));
        QVERIFY(journal.write(QJsonDocument(QJsonObject {
            { QStringLiteral("phase"), QStringLiteral("restart_pending") },
            { QStringLiteral("version"), 1 },
            { QStringLiteral("candidateVersion"), QStringLiteral("5.0.1.16") },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("transactionDirectory"), transaction },
            { QStringLiteral("rollbackDirectory"), rollback },
            { QStringLiteral("currentVersion"), QStringLiteral("5.0.1.6") },
            { QStringLiteral("rollbackHashes"), QJsonObject {
                { QStringLiteral("amneziad"), digest },
                { QStringLiteral("amnezia-cli"), digest },
            } },
            { QStringLiteral("candidateHashes"), QJsonObject {
                { QStringLiteral("amneziad"), candidateDigest },
                { QStringLiteral("amnezia-cli"), candidateDigest },
            } },
            { QStringLiteral("candidateSizes"), QJsonObject {
                { QStringLiteral("amneziad"), 4 },
                { QStringLiteral("amnezia-cli"), 4 },
            } },
        }).toJson(QJsonDocument::Compact)) > 0);
        journal.close();

        HeadlessUpdateManager manager({}, statePath, temporaryDirectory.path(), false);
        const HeadlessUpdateResult result = manager.checkAndApply(Profile {},
                                                                   QStringLiteral("5.0.1.16"));
        QVERIFY(result.ok);
        QCOMPARE(result.code, QStringLiteral("disabled"));
        QVERIFY(!QFileInfo::exists(QDir(updates).filePath(QStringLiteral("transaction.json"))));
        QVERIFY(QFileInfo::exists(QDir(updates).filePath(QStringLiteral("rollback-receipt.json"))));
        QCOMPARE(manager.status().value(QStringLiteral("state")).toString(),
                 QStringLiteral("disabled"));
        HeadlessUpdateManager reloaded({}, statePath, temporaryDirectory.path(), false);
        QVERIFY(!reloaded.status().value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(reloaded.status().value(QStringLiteral("rollbackAvailable")).toBool());
    }

    void unknownPersistedStateFailsClosed()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("state.json"));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("state"), QStringLiteral("operator_override") },
            { QStringLiteral("lastCheckedAt"), QString() },
            { QStringLiteral("lastAppliedVersion"), QString() },
            { QStringLiteral("rollbackDirectory"), QString() },
            { QStringLiteral("rollbackVersion"), QString() },
            { QStringLiteral("rollbackHashes"), QJsonObject() },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("updateRoot"), temporaryDirectory.filePath(QStringLiteral("updates")) },
            { QStringLiteral("lastError"), QString() },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();
        HeadlessUpdateManager manager({}, statePath, temporaryDirectory.path(), false);
        QVERIFY(manager.status().value(QStringLiteral("recoveryRequired")).toBool());
        QCOMPARE(manager.status().value(QStringLiteral("state")).toString(),
                 QStringLiteral("recovery_required"));
    }

    void malformedStableVersionFailsClosed()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("state.json"));
        const QString updates = temporaryDirectory.filePath(QStringLiteral("updates"));
        QVERIFY(QDir().mkpath(updates));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("state"), QStringLiteral("updated") },
            { QStringLiteral("lastCheckedAt"), QString() },
            { QStringLiteral("lastAppliedVersion"), QStringLiteral("5.0.1.not-a-version") },
            { QStringLiteral("rollbackDirectory"), QString() },
            { QStringLiteral("rollbackVersion"), QString() },
            { QStringLiteral("rollbackHashes"), QJsonObject() },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("updateRoot"), QDir(updates).canonicalPath() },
            { QStringLiteral("lastError"), QString() },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();

        HeadlessUpdateManager manager({}, statePath, temporaryDirectory.path(), false);
        QVERIFY(manager.status().value(QStringLiteral("recoveryRequired")).toBool());
        QCOMPARE(manager.status().value(QStringLiteral("state")).toString(),
                 QStringLiteral("recovery_required"));
    }

    void missingRollbackReceiptFailsClosed()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("state.json"));
        const QString updates = temporaryDirectory.filePath(QStringLiteral("updates"));
        QVERIFY(QDir().mkpath(updates));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("state"), QStringLiteral("disabled") },
            { QStringLiteral("lastCheckedAt"), QString() },
            { QStringLiteral("lastAppliedVersion"), QStringLiteral("5.0.1.12") },
            { QStringLiteral("rollbackDirectory"), temporaryDirectory.filePath(QStringLiteral("gone")) },
            { QStringLiteral("rollbackVersion"), QStringLiteral("5.0.1.11") },
            { QStringLiteral("rollbackHashes"), QJsonObject {
                { QStringLiteral("amneziad"), QString(64, QLatin1Char('a')) },
                { QStringLiteral("amnezia-cli"), QString(64, QLatin1Char('b')) },
            } },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("updateRoot"), QDir(updates).canonicalPath() },
            { QStringLiteral("lastError"), QString() },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();

        HeadlessUpdateManager manager({}, statePath, temporaryDirectory.path(), false);
        QVERIFY(manager.status().value(QStringLiteral("recoveryRequired")).toBool());
        QCOMPARE(manager.status().value(QStringLiteral("state")).toString(),
                 QStringLiteral("recovery_required"));
    }
};

QTEST_MAIN(HeadlessUpdateTest)
#include "tst_headless_updates.moc"
