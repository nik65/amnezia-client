#include <QtTest>

#include <QTemporaryDir>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCryptographicHash>
#include <QStringList>

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
        // The automatic update archive is binary-only.  The systemd unit is
        // carried by the separate manual provisioning bundle.
        const QStringList managedFiles { QStringLiteral("amneziad"), QStringLiteral("amnezia-cli") };
        for (const QString &name : managedFiles) {
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
        for (const QString &name : managedFiles) {
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
            { QStringLiteral("operation"), QStringLiteral("update") },
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
        QVERIFY(!QFileInfo::exists(transaction));
        QVERIFY(QFileInfo::exists(QDir(updates).filePath(QStringLiteral("rollback-receipt.json"))));
        QCOMPARE(manager.status().value(QStringLiteral("state")).toString(),
                 QStringLiteral("disabled"));
        HeadlessUpdateManager reloaded({}, statePath, temporaryDirectory.path(), false);
        QVERIFY(!reloaded.status().value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(reloaded.status().value(QStringLiteral("rollbackAvailable")).toBool());
    }

    void appliedStateIsStableAcrossReload()
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
            { QStringLiteral("state"), QStringLiteral("applied") },
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

        HeadlessUpdateManager manager({}, statePath, temporaryDirectory.path(), false);
        QVERIFY(!manager.status().value(QStringLiteral("recoveryRequired")).toBool());
        QCOMPARE(manager.status().value(QStringLiteral("state")).toString(),
                 QStringLiteral("applied"));
        HeadlessUpdateManager reloaded({}, statePath, temporaryDirectory.path(), false);
        QVERIFY(!reloaded.status().value(QStringLiteral("recoveryRequired")).toBool());
        QCOMPARE(reloaded.status().value(QStringLiteral("lastAppliedVersion")).toString(),
                 QStringLiteral("5.0.1.16"));
    }

    void rollbackAcknowledgementCleansEvidenceAfterStateCommit()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("state.json"));
        const QString updates = temporaryDirectory.filePath(QStringLiteral("updates"));
        const QString transaction = QDir(updates).filePath(QStringLiteral("transaction-rollback"));
        const QString rollback = QDir(updates).filePath(QStringLiteral("rollback-rollback"));
        QVERIFY(QDir().mkpath(transaction));
        QVERIFY(QDir().mkpath(rollback));
        const QString digest = QString::fromLatin1(QCryptographicHash::hash(
                QByteArrayLiteral("old"), QCryptographicHash::Sha256).toHex());
        for (const QString &name : { QStringLiteral("amneziad"), QStringLiteral("amnezia-cli") }) {
            QFile installed(temporaryDirectory.filePath(name));
            QVERIFY(installed.open(QIODevice::WriteOnly));
            QVERIFY(installed.write("old") > 0);
            installed.close();
            QFile backup(QDir(rollback).filePath(name));
            QVERIFY(backup.open(QIODevice::WriteOnly));
            QVERIFY(backup.write("old") > 0);
            backup.close();
        }
        const QJsonObject hashes {
            { QStringLiteral("amneziad"), digest },
            { QStringLiteral("amnezia-cli"), digest },
        };
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("state"), QStringLiteral("rolled_back") },
            { QStringLiteral("lastCheckedAt"), QString() },
            { QStringLiteral("lastAppliedVersion"), QStringLiteral("5.0.1.11") },
            { QStringLiteral("rollbackDirectory"), rollback },
            { QStringLiteral("rollbackVersion"), QStringLiteral("5.0.1.11") },
            { QStringLiteral("rollbackHashes"), hashes },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("updateRoot"), QDir(updates).canonicalPath() },
            { QStringLiteral("lastError"), QString() },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();
        QFile journal(QDir(updates).filePath(QStringLiteral("transaction.json")));
        QVERIFY(journal.open(QIODevice::WriteOnly));
        QVERIFY(journal.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 1 },
            { QStringLiteral("operation"), QStringLiteral("rollback") },
            { QStringLiteral("phase"), QStringLiteral("rollback_acknowledged") },
            { QStringLiteral("candidateVersion"), QStringLiteral("5.0.1.11") },
            { QStringLiteral("currentVersion"), QStringLiteral("5.0.1.11") },
            { QStringLiteral("transactionDirectory"), transaction },
            { QStringLiteral("rollbackDirectory"), rollback },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("rollbackHashes"), hashes },
            { QStringLiteral("candidateHashes"), hashes },
            { QStringLiteral("candidateSizes"), QJsonObject {
                { QStringLiteral("amneziad"), 3 },
                { QStringLiteral("amnezia-cli"), 3 },
            } },
        }).toJson(QJsonDocument::Compact)) > 0);
        journal.close();

        HeadlessUpdateManager manager({}, statePath, temporaryDirectory.path(), false);
        QVERIFY(!manager.status().value(QStringLiteral("recoveryRequired")).toBool());
        const HeadlessUpdateResult result = manager.checkAndApply(Profile {},
                                                                   QStringLiteral("5.0.1.11"));
        QVERIFY(result.ok);
        QVERIFY(!QFileInfo::exists(QDir(updates).filePath(QStringLiteral("transaction.json"))));
        QVERIFY(!QFileInfo::exists(transaction));
        QVERIFY(!QFileInfo::exists(rollback));
        QVERIFY(!manager.status().value(QStringLiteral("rollbackAvailable")).toBool());
    }

    void legacyAppliedStateIsMigratedToVersionTwo()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("state.json"));
        const QString updates = temporaryDirectory.filePath(QStringLiteral("updates"));
        QVERIFY(QDir().mkpath(updates));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 1 },
            { QStringLiteral("state"), QStringLiteral("applied") },
            { QStringLiteral("lastCheckedAt"), QString() },
            { QStringLiteral("lastAppliedVersion"), QStringLiteral("5.0.1.16") },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();

        HeadlessUpdateManager manager({}, statePath, temporaryDirectory.path(), false);
        QVERIFY(!manager.status().value(QStringLiteral("recoveryRequired")).toBool());
        QFile migrated(statePath);
        QVERIFY(migrated.open(QIODevice::ReadOnly));
        QJsonParseError parseError;
        const QJsonDocument document = QJsonDocument::fromJson(migrated.readAll(), &parseError);
        QVERIFY(parseError.error == QJsonParseError::NoError);
        QCOMPARE(document.object().value(QStringLiteral("version")).toInt(), 2);
        QCOMPARE(document.object().value(QStringLiteral("state")).toString(),
                 QStringLiteral("applied"));
    }

    void orphanRollbackReceiptFailsClosed()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("state.json"));
        const QString updates = temporaryDirectory.filePath(QStringLiteral("updates"));
        const QString rollback = QDir(updates).filePath(QStringLiteral("rollback-orphan"));
        QVERIFY(QDir().mkpath(rollback));
        const QString digest = QString::fromLatin1(QCryptographicHash::hash(
                QByteArrayLiteral("old"), QCryptographicHash::Sha256).toHex());
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
            { QStringLiteral("state"), QStringLiteral("disabled") },
            { QStringLiteral("lastCheckedAt"), QString() },
            { QStringLiteral("lastAppliedVersion"), QString() },
            { QStringLiteral("rollbackDirectory"), QString() },
            { QStringLiteral("rollbackVersion"), QString() },
            { QStringLiteral("rollbackHashes"), QJsonObject() },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("updateRoot"), QDir(updates).canonicalPath() },
            { QStringLiteral("lastError"), QString() },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();
        QFile receipt(QDir(updates).filePath(QStringLiteral("rollback-receipt.json")));
        QVERIFY(receipt.open(QIODevice::WriteOnly));
        QVERIFY(receipt.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 1 },
            { QStringLiteral("rollbackDirectory"), rollback },
            { QStringLiteral("rollbackVersion"), QStringLiteral("5.0.1.11") },
            { QStringLiteral("rollbackHashes"), QJsonObject {
                { QStringLiteral("amneziad"), digest },
                { QStringLiteral("amnezia-cli"), digest },
            } },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("updateRoot"), QDir(updates).canonicalPath() },
        }).toJson(QJsonDocument::Compact)) > 0);
        receipt.close();

        HeadlessUpdateManager manager({}, statePath, temporaryDirectory.path(), false);
        QVERIFY(manager.status().value(QStringLiteral("recoveryRequired")).toBool());
        QCOMPARE(manager.status().value(QStringLiteral("state")).toString(),
                 QStringLiteral("recovery_required"));
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

    void retiredThreeFileReceiptIsStableAndExplicit()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("state.json"));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        const QString digest(64, QLatin1Char('a'));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("state"), QStringLiteral("updated") },
            { QStringLiteral("lastCheckedAt"), QString() },
            { QStringLiteral("lastAppliedVersion"), QStringLiteral("5.0.1.11") },
            { QStringLiteral("rollbackDirectory"), QString() },
            { QStringLiteral("rollbackVersion"), QString() },
            { QStringLiteral("rollbackHashes"), QJsonObject {
                { QStringLiteral("amneziad"), digest },
                { QStringLiteral("amnezia-cli"), digest },
                { QStringLiteral("amneziad.service"), digest },
            } },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("updateRoot"), temporaryDirectory.filePath(QStringLiteral("updates")) },
            { QStringLiteral("lastError"), QString() },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();
        HeadlessUpdateManager manager({}, statePath, temporaryDirectory.path(), false);
        QVERIFY(!manager.status().value(QStringLiteral("recoveryRequired")).toBool());
        QCOMPARE(manager.status().value(QStringLiteral("state")).toString(),
                 QStringLiteral("unsupported_payload_contract"));
        const HeadlessUpdateResult result = manager.checkAndApply(Profile {},
                                                                   QStringLiteral("5.0.1.11"));
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("unsupported_payload_contract"));
        QFile preserved(statePath);
        QVERIFY(preserved.open(QIODevice::ReadOnly));
        QJsonParseError parseError;
        const QJsonObject preservedState = QJsonDocument::fromJson(
                preserved.readAll(), &parseError).object();
        QVERIFY(parseError.error == QJsonParseError::NoError);
        QCOMPARE(preservedState.value(QStringLiteral("rollbackHashes")).toObject().size(), 3);
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

    void rollbackJournalRequiresExplicitOperation()
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
            { QStringLiteral("state"), QStringLiteral("rolled_back") },
            { QStringLiteral("lastCheckedAt"), QString() },
            { QStringLiteral("lastAppliedVersion"), QStringLiteral("5.0.1.11") },
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
            { QStringLiteral("version"), 1 },
            { QStringLiteral("phase"), QStringLiteral("rollback_acknowledged") },
        }).toJson(QJsonDocument::Compact)) > 0);
        journal.close();

        HeadlessUpdateManager manager({}, statePath, temporaryDirectory.path(), false);
        QVERIFY(manager.status().value(QStringLiteral("recoveryRequired")).toBool());
        QCOMPARE(manager.status().value(QStringLiteral("state")).toString(),
                 QStringLiteral("recovery_required"));
    }

    void stableStateRequiresAllVersionTwoFields()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("state.json"));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("state"), QStringLiteral("disabled") },
            { QStringLiteral("lastCheckedAt"), QString() },
            { QStringLiteral("lastAppliedVersion"), QString() },
            { QStringLiteral("rollbackDirectory"), QString() },
            { QStringLiteral("rollbackVersion"), QString() },
            { QStringLiteral("rollbackHashes"), QJsonObject() },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("updateRoot"), temporaryDirectory.filePath(QStringLiteral("updates")) },
            // lastError is intentionally absent: v2 receipts are not partial.
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();

        HeadlessUpdateManager manager({}, statePath, temporaryDirectory.path(), false);
        QVERIFY(manager.status().value(QStringLiteral("recoveryRequired")).toBool());
        QCOMPARE(manager.status().value(QStringLiteral("state")).toString(),
                 QStringLiteral("recovery_required"));
    }

    void rollbackFailedBlocksAutomaticUpdate()
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
            { QStringLiteral("state"), QStringLiteral("rollback_failed") },
            { QStringLiteral("lastCheckedAt"), QString() },
            { QStringLiteral("lastAppliedVersion"), QStringLiteral("5.0.1.16") },
            { QStringLiteral("rollbackDirectory"), QString() },
            { QStringLiteral("rollbackVersion"), QString() },
            { QStringLiteral("rollbackHashes"), QJsonObject() },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("updateRoot"), QDir(updates).canonicalPath() },
            { QStringLiteral("lastError"), QStringLiteral("restart failed") },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();

        HeadlessUpdateManager manager({}, statePath, temporaryDirectory.path(), false);
        const HeadlessUpdateResult result = manager.checkAndApply(Profile {},
                                                                   QStringLiteral("5.0.1.16"));
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("recovery_required"));
        QCOMPARE(manager.status().value(QStringLiteral("state")).toString(),
                 QStringLiteral("recovery_required"));
    }
};

QTEST_MAIN(HeadlessUpdateTest)
#include "tst_headless_updates.moc"
