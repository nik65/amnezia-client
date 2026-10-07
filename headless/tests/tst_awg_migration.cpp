#include <QtTest>
#include <QTemporaryDir>
#include <QFile>
#include "awgMigrationManager.h"
using namespace amnezia::headless;

class AwgMigrationTest : public QObject {
    Q_OBJECT
private slots:
    void interruptedAttemptPreservesReplayWatermark() {
        QTemporaryDir directory;
        AwgMigrationManager manager(directory.filePath("migration"), {}, false);
        QString error;
        QVERIFY(manager.load(&error));
        Profile profile;
        profile.id = QStringLiteral("existing-peer");
        QVERIFY(manager.secureDirectory(manager.profileRoot(profile)));
        QVERIFY(manager.writeState(profile, {{"phase", "trying"}, {"highestGeneration", 17}, {"sourceHash", "original"}}));
        AwgMigrationManager restarted(directory.filePath("migration"), {}, false);
        QVERIFY(restarted.load(&error));
        const auto state = restarted.state(profile);
        QCOMPARE(state.value("phase").toString(), QStringLiteral("rolled_back"));
        QCOMPARE(state.value("highestGeneration").toInt(), 17);
        QString path, sha;
        QVERIFY(!restarted.candidate(profile, path, sha));
    }
    void unsafeJournalNeverBecomesCandidate() {
        QTemporaryDir directory;
        AwgMigrationManager manager(directory.filePath("migration"), {}, false);
        QString error;
        QVERIFY(manager.load(&error));
        Profile profile;
        profile.id = QStringLiteral("existing-peer");
        QVERIFY(manager.secureDirectory(manager.profileRoot(profile)));
        QVERIFY(manager.writeState(profile, {{"phase", "staged"}, {"highestGeneration", 5}}));
        const QString journal = QDir(manager.profileRoot(profile)).filePath("journal.json");
        QVERIFY(QFile::setPermissions(journal, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::WriteGroup));
        AwgMigrationManager restarted(directory.filePath("migration"), {}, false);
        QVERIFY(!restarted.load(&error));
        QString path, sha;
        QVERIFY(!restarted.candidate(profile, path, sha));
    }
    void publicReadPermissionsRejectCredentialMaterial() {
        QTemporaryDir directory;
        const QString credential = directory.filePath("client-logs.json");
        QFile file(credential);
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write("{}");
        file.close();
        QVERIFY(file.setPermissions(QFileDevice::ReadOwner | QFileDevice::ReadOther));
        AwgMigrationManager manager(directory.filePath("migration"), credential, false);
        QByteArray bytes;
        QVERIFY(!manager.read(credential, bytes));
    }
};
QTEST_MAIN(AwgMigrationTest)
#include "tst_awg_migration.moc"
