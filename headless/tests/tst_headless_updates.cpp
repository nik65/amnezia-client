#include <QtTest>

#include <QTemporaryDir>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>

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
                                      temporaryDirectory.path());
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
            { QStringLiteral("state"), QStringLiteral("restart_pending") },
            { QStringLiteral("lastAppliedVersion"), QStringLiteral("5.0.1.16") },
            { QStringLiteral("rollbackDirectory"), QString() },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();
        QFile journal(QDir(updates).filePath(QStringLiteral("transaction.json")));
        QVERIFY(journal.open(QIODevice::WriteOnly));
        QVERIFY(journal.write(QByteArrayLiteral("{\"phase\":\"replaced\"}")) > 0);
        journal.close();

        HeadlessUpdateManager manager({}, statePath, temporaryDirectory.path());
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
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("state"), QStringLiteral("restart_pending") },
            { QStringLiteral("lastAppliedVersion"), QStringLiteral("5.0.1.16") },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();
        QFile journal(QDir(updates).filePath(QStringLiteral("transaction.json")));
        QVERIFY(journal.open(QIODevice::WriteOnly));
        QVERIFY(journal.write(QByteArrayLiteral("{\"phase\":\"restart_pending\"}")) > 0);
        journal.close();

        HeadlessUpdateManager manager({}, statePath, temporaryDirectory.path());
        const HeadlessUpdateResult result = manager.checkAndApply(Profile {},
                                                                   QStringLiteral("5.0.1.16"));
        QVERIFY(result.ok);
        QCOMPARE(result.code, QStringLiteral("disabled"));
        QVERIFY(!QFileInfo::exists(QDir(updates).filePath(QStringLiteral("transaction.json"))));
        QCOMPARE(manager.status().value(QStringLiteral("state")).toString(),
                 QStringLiteral("disabled"));
    }
};

QTEST_MAIN(HeadlessUpdateTest)
#include "tst_headless_updates.moc"
