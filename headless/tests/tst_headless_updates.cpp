#include <QtTest>

#include <QTemporaryDir>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCryptographicHash>
#include <QStringList>

#include "headlessUpdateManager.h"

using namespace amnezia::headless;

class SuccessfulCommandRunner final : public CommandRunner
{
public:
    bool isAvailable(const QString &) const override { return true; }

    QString resolveExecutable(const QStringList &candidates) const override
    {
        return candidates.isEmpty() ? QString() : candidates.first();
    }

    CommandResult run(const QString &, const QStringList &) override
    {
        return { true, 0, {}, {} };
    }

    CommandResult start(const QString &, const QString &, const QStringList &) override
    {
        return { true, 0, {}, {} };
    }

    CommandResult stop(const QString &) override
    {
        return { true, 0, {}, {} };
    }
};

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

        HeadlessUpdateManager reloaded({},
                                       temporaryDirectory.filePath(QStringLiteral("updates.json")),
                                       temporaryDirectory.path(), false);
        QVERIFY(!reloaded.status().value(QStringLiteral("recoveryRequired")).toBool());
        QCOMPARE(reloaded.status().value(QStringLiteral("state")).toString(),
                 QStringLiteral("disabled"));
    }

    void updateStorageIsPrivateAfterCreation()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("state.json"));
        HeadlessUpdateManager manager({}, statePath, temporaryDirectory.path(), false);
        const QFileInfo updates(QDir(temporaryDirectory.path()).filePath(QStringLiteral("updates")));
        QVERIFY(updates.isDir());
#ifndef Q_OS_WIN
        QVERIFY((updates.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther)) == 0);
        QVERIFY((updates.permissions() & (QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                          | QFileDevice::ExeOwner))
                == (QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
#endif
        QVERIFY(!manager.status().value(QStringLiteral("recoveryRequired")).toBool());
    }

    void durableGarbageMarkerRetiresOrphanWithoutBlockingStableState()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("state.json"));
        const QString updates = temporaryDirectory.filePath(QStringLiteral("updates"));
        QVERIFY(QDir().mkpath(updates));
        const QString orphan = QDir(updates).filePath(QStringLiteral("transaction-orphan"));
        QVERIFY(QDir().mkpath(orphan));
        const QString orphanCurrent = QDir(updates).filePath(
                QStringLiteral("rollback-current-orphan"));
        QVERIFY(QDir().mkpath(orphanCurrent));
        QFile orphanFile(QDir(orphan).filePath(QStringLiteral("artifact.tar.gz")));
        QVERIFY(orphanFile.open(QIODevice::WriteOnly));
        QVERIFY(orphanFile.write("orphan") > 0);
        orphanFile.close();

        QFile marker(QDir(updates).filePath(QStringLiteral("garbage-collection.json")));
        QVERIFY(marker.open(QIODevice::WriteOnly));
        QVERIFY(marker.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 1 },
            { QStringLiteral("paths"), QJsonArray { orphan } },
        }).toJson(QJsonDocument::Compact)) > 0);
        marker.close();

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
        QVERIFY(!QFileInfo::exists(orphan));
        QVERIFY(!QFileInfo::exists(orphanCurrent));
        QVERIFY(!QFileInfo::exists(QDir(updates).filePath(QStringLiteral("garbage-collection.json"))));
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

    void preparedJournalAdoptsRollbackBeforeMixedPairCheck()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("state.json"));
        const QString updates = temporaryDirectory.filePath(QStringLiteral("updates"));
        const QString transaction = QDir(updates).filePath(QStringLiteral("transaction-prepared"));
        const QString rollback = QDir(updates).filePath(QStringLiteral("rollback-prepared"));
        const QString previousRollback = QDir(updates).filePath(QStringLiteral("rollback-previous"));
        QVERIFY(QDir().mkpath(transaction));
        QVERIFY(QDir().mkpath(rollback));
        QVERIFY(QDir().mkpath(previousRollback));

        const QString oldDigest = QString::fromLatin1(QCryptographicHash::hash(
                QByteArrayLiteral("old"), QCryptographicHash::Sha256).toHex());
        const QString newDigest = QString::fromLatin1(QCryptographicHash::hash(
                QByteArrayLiteral("new"), QCryptographicHash::Sha256).toHex());
        const QJsonObject oldHashes {
            { QStringLiteral("amneziad"), oldDigest },
            { QStringLiteral("amnezia-cli"), oldDigest },
        };
        const QJsonObject newHashes {
            { QStringLiteral("amneziad"), newDigest },
            { QStringLiteral("amnezia-cli"), newDigest },
        };
        for (const QString &name : { QStringLiteral("amneziad"), QStringLiteral("amnezia-cli") }) {
            QFile installed(temporaryDirectory.filePath(name));
            QVERIFY(installed.open(QIODevice::WriteOnly));
            QVERIFY(installed.write(name == QStringLiteral("amneziad") ? "new" : "old") > 0);
            installed.close();
            QFile backup(QDir(rollback).filePath(name));
            QVERIFY(backup.open(QIODevice::WriteOnly));
            QVERIFY(backup.write("old") > 0);
            backup.close();
            QFile previousBackup(QDir(previousRollback).filePath(name));
            QVERIFY(previousBackup.open(QIODevice::WriteOnly));
            QVERIFY(previousBackup.write("previous") > 0);
            previousBackup.close();
        }

        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("state"), QStringLiteral("disabled") },
            { QStringLiteral("lastCheckedAt"), QString() },
            { QStringLiteral("lastAppliedVersion"), QString() },
            { QStringLiteral("rollbackDirectory"), previousRollback },
            { QStringLiteral("rollbackVersion"), QStringLiteral("5.0.1.5") },
            { QStringLiteral("rollbackHashes"), QJsonObject {
                { QStringLiteral("amneziad"), QString::fromLatin1(QCryptographicHash::hash(
                    QByteArrayLiteral("previous"), QCryptographicHash::Sha256).toHex()) },
                { QStringLiteral("amnezia-cli"), QString::fromLatin1(QCryptographicHash::hash(
                    QByteArrayLiteral("previous"), QCryptographicHash::Sha256).toHex()) },
            } },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("updateRoot"), QDir(updates).canonicalPath() },
            { QStringLiteral("lastError"), QString() },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();

        QFile journal(QDir(updates).filePath(QStringLiteral("transaction.json")));
        QVERIFY(journal.open(QIODevice::WriteOnly));
        QVERIFY(journal.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 1 },
            { QStringLiteral("operation"), QStringLiteral("update") },
            { QStringLiteral("phase"), QStringLiteral("prepared") },
            { QStringLiteral("candidateVersion"), QStringLiteral("5.0.1.16") },
            { QStringLiteral("currentVersion"), QStringLiteral("5.0.1.6") },
            { QStringLiteral("transactionDirectory"), transaction },
            { QStringLiteral("rollbackDirectory"), rollback },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("rollbackHashes"), oldHashes },
            { QStringLiteral("candidateHashes"), newHashes },
            { QStringLiteral("candidateSizes"), QJsonObject {
                { QStringLiteral("amneziad"), 3 },
                { QStringLiteral("amnezia-cli"), 3 },
            } },
        }).toJson(QJsonDocument::Compact)) > 0);
        journal.close();

        auto runner = std::make_shared<SuccessfulCommandRunner>();
        HeadlessUpdateManager manager(runner, statePath, temporaryDirectory.path(), false);
        QVERIFY(manager.status().value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(manager.status().value(QStringLiteral("rollbackAvailable")).toBool());

        const HeadlessUpdateResult result = manager.rollback();
        QVERIFY(result.ok);
        QCOMPARE(result.code, QStringLiteral("rollback_restart_pending"));
        for (const QString &name : { QStringLiteral("amneziad"), QStringLiteral("amnezia-cli") }) {
            QFile installed(temporaryDirectory.filePath(name));
            QVERIFY(installed.open(QIODevice::ReadOnly));
            QCOMPARE(installed.readAll(), QByteArrayLiteral("old"));
            QFile rollbackBackup(QDir(rollback).filePath(name));
            QVERIFY(rollbackBackup.open(QIODevice::ReadOnly));
            QCOMPARE(QString::fromLatin1(QCryptographicHash::hash(
                         rollbackBackup.readAll(), QCryptographicHash::Sha256).toHex()),
                     oldDigest);
        }
        // The receipt from the previous completed update remains intact while
        // the prepared transaction is recovered.  It is not disposable until
        // the new transaction reaches its durable commit point.
        QVERIFY(QFileInfo::exists(previousRollback));
#ifndef Q_OS_WIN
        const QFileDevice::Permissions daemonPermissions = QFileInfo(
                temporaryDirectory.filePath(QStringLiteral("amneziad"))).permissions();
        QVERIFY((daemonPermissions & (QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                      | QFileDevice::ExeOwner))
                == (QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
        QVERIFY((daemonPermissions & (QFileDevice::ReadGroup | QFileDevice::WriteGroup
                                      | QFileDevice::ExeGroup | QFileDevice::ReadOther
                                      | QFileDevice::WriteOther | QFileDevice::ExeOther)) == 0);
        const QFileDevice::Permissions cliPermissions = QFileInfo(
                temporaryDirectory.filePath(QStringLiteral("amnezia-cli"))).permissions();
        QVERIFY((cliPermissions & (QFileDevice::ReadGroup | QFileDevice::ExeGroup
                                   | QFileDevice::ReadOther | QFileDevice::ExeOther))
                == (QFileDevice::ReadGroup | QFileDevice::ExeGroup
                    | QFileDevice::ReadOther | QFileDevice::ExeOther));
        QVERIFY((cliPermissions & (QFileDevice::WriteGroup | QFileDevice::WriteOther)) == 0);
#endif
    }

    void laterRollbackReplacementFailureRestoresEarlierFileAndKeepsBackupHashes()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("state.json"));
        const QString updates = temporaryDirectory.filePath(QStringLiteral("updates"));
        const QString transaction = QDir(updates).filePath(QStringLiteral("transaction-mixed"));
        const QString rollback = QDir(updates).filePath(QStringLiteral("rollback-mixed"));
        const QString current = QDir(updates).filePath(QStringLiteral("rollback-current-mixed"));
        QVERIFY(QDir().mkpath(transaction));
        QVERIFY(QDir().mkpath(rollback));
        QVERIFY(QDir().mkpath(current));

        const QString oldDigest = QString::fromLatin1(QCryptographicHash::hash(
                QByteArrayLiteral("old"), QCryptographicHash::Sha256).toHex());
        const QString currentDigest = QString::fromLatin1(QCryptographicHash::hash(
                QByteArrayLiteral("new"), QCryptographicHash::Sha256).toHex());
        const QJsonObject oldHashes {
            { QStringLiteral("amneziad"), oldDigest },
            { QStringLiteral("amnezia-cli"), oldDigest },
        };
        const QJsonObject currentHashes {
            { QStringLiteral("amneziad"), currentDigest },
            { QStringLiteral("amnezia-cli"), currentDigest },
        };
        const QJsonObject sizes {
            { QStringLiteral("amneziad"), 3 },
            { QStringLiteral("amnezia-cli"), 3 },
        };
        for (const QString &name : { QStringLiteral("amneziad"), QStringLiteral("amnezia-cli") }) {
            QFile backup(QDir(rollback).filePath(name));
            QVERIFY(backup.open(QIODevice::WriteOnly));
            QVERIFY(backup.write("old") > 0);
            backup.close();
            QFile previous(QDir(current).filePath(name));
            QVERIFY(previous.open(QIODevice::WriteOnly));
            QVERIFY(previous.write("new") > 0);
            previous.close();
        }
        QFile installed(temporaryDirectory.filePath(QStringLiteral("amneziad")));
        QVERIFY(installed.open(QIODevice::WriteOnly));
        QVERIFY(installed.write("new") > 0);
        installed.close();
        QVERIFY(QDir().mkpath(temporaryDirectory.filePath(QStringLiteral("amnezia-cli"))));

        auto writeJson = [](const QString &path, const QJsonObject &object) {
            QFile file(path);
            if (!file.open(QIODevice::WriteOnly)) return false;
            return file.write(QJsonDocument(object).toJson(QJsonDocument::Compact)) > 0;
        };
        QVERIFY(writeJson(statePath, QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("state"), QStringLiteral("rollback_restart_pending") },
            { QStringLiteral("lastCheckedAt"), QString() },
            { QStringLiteral("lastAppliedVersion"), QStringLiteral("5.0.1.16") },
            { QStringLiteral("rollbackDirectory"), rollback },
            { QStringLiteral("rollbackVersion"), QStringLiteral("5.0.1.6") },
            { QStringLiteral("rollbackHashes"), oldHashes },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("updateRoot"), QDir(updates).canonicalPath() },
            { QStringLiteral("lastError"), QString() },
        }));
        QVERIFY(writeJson(QDir(updates).filePath(QStringLiteral("transaction.json")), QJsonObject {
            { QStringLiteral("version"), 1 },
            { QStringLiteral("operation"), QStringLiteral("rollback") },
            { QStringLiteral("phase"), QStringLiteral("rollback_restart_pending") },
            { QStringLiteral("candidateVersion"), QStringLiteral("5.0.1.6") },
            { QStringLiteral("currentVersion"), QStringLiteral("5.0.1.6") },
            { QStringLiteral("transactionDirectory"), transaction },
            { QStringLiteral("rollbackDirectory"), rollback },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("rollbackHashes"), oldHashes },
            { QStringLiteral("candidateHashes"), oldHashes },
            { QStringLiteral("candidateSizes"), sizes },
            { QStringLiteral("previousDirectory"), current },
            { QStringLiteral("previousHashes"), currentHashes },
            { QStringLiteral("previousSizes"), sizes },
        }));

        auto runner = std::make_shared<SuccessfulCommandRunner>();
        HeadlessUpdateManager manager(runner, statePath, temporaryDirectory.path(), false);
        const HeadlessUpdateResult failed = manager.rollback();
        QVERIFY(!failed.ok);
        QCOMPARE(failed.code, QStringLiteral("rollback_failed"));

        QFile restored(temporaryDirectory.filePath(QStringLiteral("amneziad")));
        QVERIFY(restored.open(QIODevice::ReadOnly));
        QCOMPARE(restored.readAll(), QByteArrayLiteral("new"));
        QVERIFY(QFileInfo(temporaryDirectory.filePath(QStringLiteral("amnezia-cli"))).isDir());
        for (const QString &name : { QStringLiteral("amneziad"), QStringLiteral("amnezia-cli") }) {
            QFile backup(QDir(rollback).filePath(name));
            QVERIFY(backup.open(QIODevice::ReadOnly));
            QCOMPARE(QString::fromLatin1(QCryptographicHash::hash(
                         backup.readAll(), QCryptographicHash::Sha256).toHex()),
                     oldDigest);
        }
        QFile journal(QDir(updates).filePath(QStringLiteral("transaction.json")));
        QVERIFY(journal.open(QIODevice::ReadOnly));
        QJsonParseError parseError;
        const QJsonObject journalObject = QJsonDocument::fromJson(
                journal.readAll(), &parseError).object();
        QVERIFY(parseError.error == QJsonParseError::NoError);
        QCOMPARE(journalObject.value(QStringLiteral("phase")).toString(),
                 QStringLiteral("replaced"));

        QVERIFY(QDir(temporaryDirectory.filePath(QStringLiteral("amnezia-cli"))).removeRecursively());
        QFile repaired(temporaryDirectory.filePath(QStringLiteral("amnezia-cli")));
        QVERIFY(repaired.open(QIODevice::WriteOnly));
        QVERIFY(repaired.write("new") > 0);
        repaired.close();
        const HeadlessUpdateResult retried = manager.rollback();
        QVERIFY(retried.ok);
        QCOMPARE(retried.code, QStringLiteral("rollback_restart_pending"));
        for (const QString &name : { QStringLiteral("amneziad"), QStringLiteral("amnezia-cli") }) {
            QFile rollbackInstalled(temporaryDirectory.filePath(name));
            QVERIFY(rollbackInstalled.open(QIODevice::ReadOnly));
            QCOMPARE(rollbackInstalled.readAll(), QByteArrayLiteral("old"));
        }
    }

    void acknowledgedUpdateCleanupContinuesExplicitRollback()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("state.json"));
        const QString updates = temporaryDirectory.filePath(QStringLiteral("updates"));
        const QString transaction = QDir(updates).filePath(QStringLiteral("transaction-acknowledged"));
        const QString rollback = QDir(updates).filePath(QStringLiteral("rollback-acknowledged"));
        QVERIFY(QDir().mkpath(transaction));
        QVERIFY(QDir().mkpath(rollback));
        const QString oldDigest = QString::fromLatin1(QCryptographicHash::hash(
                QByteArrayLiteral("old"), QCryptographicHash::Sha256).toHex());
        const QString newDigest = QString::fromLatin1(QCryptographicHash::hash(
                QByteArrayLiteral("new"), QCryptographicHash::Sha256).toHex());
        const QJsonObject oldHashes {
            { QStringLiteral("amneziad"), oldDigest },
            { QStringLiteral("amnezia-cli"), oldDigest },
        };
        for (const QString &name : { QStringLiteral("amneziad"), QStringLiteral("amnezia-cli") }) {
            QFile installed(temporaryDirectory.filePath(name));
            QVERIFY(installed.open(QIODevice::WriteOnly));
            QVERIFY(installed.write("new") > 0);
            installed.close();
            QFile backup(QDir(rollback).filePath(name));
            QVERIFY(backup.open(QIODevice::WriteOnly));
            QVERIFY(backup.write("old") > 0);
            backup.close();
        }
        const QJsonObject candidateHashes {
            { QStringLiteral("amneziad"), newDigest },
            { QStringLiteral("amnezia-cli"), newDigest },
        };
        auto writeJson = [](const QString &path, const QJsonObject &object) {
            QFile file(path);
            if (!file.open(QIODevice::WriteOnly)) return false;
            return file.write(QJsonDocument(object).toJson(QJsonDocument::Compact)) > 0;
        };
        QVERIFY(writeJson(statePath, QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("state"), QStringLiteral("updated") },
            { QStringLiteral("lastCheckedAt"), QString() },
            { QStringLiteral("lastAppliedVersion"), QStringLiteral("5.0.1.16") },
            { QStringLiteral("rollbackDirectory"), rollback },
            { QStringLiteral("rollbackVersion"), QStringLiteral("5.0.1.6") },
            { QStringLiteral("rollbackHashes"), oldHashes },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("updateRoot"), QDir(updates).canonicalPath() },
            { QStringLiteral("lastError"), QString() },
        }));
        QVERIFY(writeJson(QDir(updates).filePath(QStringLiteral("transaction.json")), QJsonObject {
            { QStringLiteral("version"), 1 },
            { QStringLiteral("operation"), QStringLiteral("update") },
            { QStringLiteral("phase"), QStringLiteral("acknowledged") },
            { QStringLiteral("candidateVersion"), QStringLiteral("5.0.1.16") },
            { QStringLiteral("currentVersion"), QStringLiteral("5.0.1.6") },
            { QStringLiteral("transactionDirectory"), transaction },
            { QStringLiteral("rollbackDirectory"), rollback },
            { QStringLiteral("installDirectory"), temporaryDirectory.path() },
            { QStringLiteral("rollbackHashes"), oldHashes },
            { QStringLiteral("candidateHashes"), candidateHashes },
            { QStringLiteral("candidateSizes"), QJsonObject {
                { QStringLiteral("amneziad"), 3 },
                { QStringLiteral("amnezia-cli"), 3 },
            } },
        }));

        HeadlessUpdateManager manager(std::make_shared<SuccessfulCommandRunner>(),
                                      statePath, temporaryDirectory.path(), false);
        const HeadlessUpdateResult result = manager.rollback();
        QVERIFY(result.ok);
        QCOMPARE(result.code, QStringLiteral("rollback_restart_pending"));
        QVERIFY(!QFileInfo::exists(QDir(updates).filePath(QStringLiteral("transaction-acknowledged"))));
        for (const QString &name : { QStringLiteral("amneziad"), QStringLiteral("amnezia-cli") }) {
            QFile installed(temporaryDirectory.filePath(name));
            QVERIFY(installed.open(QIODevice::ReadOnly));
            QCOMPARE(installed.readAll(), QByteArrayLiteral("old"));
        }
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

        // Cleanup is safe to repeat after the state/journal/sidecar commit
        // sequence, including after a daemon restart.
        HeadlessUpdateManager reloaded({}, statePath, temporaryDirectory.path(), false);
        QVERIFY(!reloaded.status().value(QStringLiteral("recoveryRequired")).toBool());
        const HeadlessUpdateResult repeated = reloaded.checkAndApply(
                Profile {}, QStringLiteral("5.0.1.11"));
        QVERIFY(repeated.ok);
        QCOMPARE(repeated.code, QStringLiteral("disabled"));
        QVERIFY(!QFileInfo::exists(QDir(updates).filePath(QStringLiteral("transaction.json"))));
        QVERIFY(!QFileInfo::exists(QDir(updates).filePath(QStringLiteral("rollback-receipt.json"))));
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

    void staleRollbackReceiptAfterStableStateIsIgnoredAndRetired()
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
        QVERIFY(!manager.status().value(QStringLiteral("recoveryRequired")).toBool());
        QCOMPARE(manager.status().value(QStringLiteral("state")).toString(),
                 QStringLiteral("disabled"));
        QVERIFY(!manager.status().value(QStringLiteral("rollbackAvailable")).toBool());
        QVERIFY(!QFileInfo::exists(QDir(updates).filePath(QStringLiteral("rollback-receipt.json"))));
        // The sidecar has no authority over unrelated evidence directories.
        QVERIFY(QFileInfo::exists(rollback));
    }

    void appliedStateRequiresLastAppliedVersion()
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
            { QStringLiteral("lastAppliedVersion"), QString() },
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
