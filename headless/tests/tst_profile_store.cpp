#include <QtTest>

#include <QFile>
#include <QTemporaryDir>

#include "profileStore.h"

using namespace amnezia::headless;

class ProfileStoreTest : public QObject
{
    Q_OBJECT

private slots:
    void savesAndLoadsMetadataWithoutConfigContents()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString storePath = temporaryDirectory.filePath(QStringLiteral("profiles.json"));

        ProfileStore store(storePath);
        Profile profile;
        profile.id = QStringLiteral("work");
        profile.name = QStringLiteral("Work VPN");
        profile.protocol = QStringLiteral("wireguard");
        profile.configPath = QStringLiteral("/etc/amnezia/work.conf");
        profile.dnsServers = { QStringLiteral("10.8.1.0") };
        profile.dnsDomains = { QStringLiteral("~local") };
        profile.autoConnect = true;
        QVERIFY2(store.add(profile), qPrintable(store.lastError()));
        QVERIFY(QFile::exists(storePath));

        const QByteArray persisted = [&storePath]() {
            QFile file(storePath);
            if (!file.open(QIODevice::ReadOnly)) {
                return QByteArray {};
            }
            return file.readAll();
        }();
        QVERIFY(!persisted.contains("private_key"));
        QVERIFY(!persisted.contains("preshared_key"));

        ProfileStore loaded(storePath);
        QVERIFY2(loaded.load(), qPrintable(loaded.lastError()));
        const QList<Profile> profiles = loaded.profiles();
        QCOMPARE(profiles.size(), 1);
        QCOMPARE(profiles.constFirst().id, profile.id);
        QCOMPARE(profiles.constFirst().configPath, profile.configPath);
        QCOMPARE(profiles.constFirst().autoConnect, true);
        QCOMPARE(profiles.constFirst().dnsServers, profile.dnsServers);
        QCOMPARE(profiles.constFirst().dnsDomains, profile.dnsDomains);
    }

    void rejectsDuplicateIdsAndUnsupportedProtocols()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        ProfileStore store(temporaryDirectory.filePath(QStringLiteral("profiles.json")));

        Profile profile;
        profile.id = QStringLiteral("same");
        profile.name = QStringLiteral("Profile");
        profile.protocol = QStringLiteral("wireguard");
        profile.configPath = QStringLiteral("/tmp/work.conf");
        QVERIFY2(store.add(profile), qPrintable(store.lastError()));
        QVERIFY(!store.add(profile));
        QCOMPARE(store.lastError(), QStringLiteral("profile id already exists"));

        profile.id = QStringLiteral("unsupported");
        profile.protocol = QStringLiteral("unknown");
        QVERIFY(!store.add(profile));
        QCOMPARE(store.lastError(), QStringLiteral("unsupported profile protocol"));
    }

#ifndef Q_OS_WIN
    void defaultPathUsesXdgStateDirectory()
    {
        const QByteArray previousStateHome = qgetenv("XDG_STATE_HOME");
        const QByteArray previousHome = qgetenv("HOME");
        qunsetenv("XDG_STATE_HOME");
        qputenv("HOME", QByteArrayLiteral("/tmp/amnezia-headless-test-home"));

        const ProfileStore store;
        QCOMPARE(store.path(),
                 QStringLiteral("/tmp/amnezia-headless-test-home/.local/state/amnezia/profiles.json"));

        if (previousStateHome.isNull()) {
            qunsetenv("XDG_STATE_HOME");
        } else {
            qputenv("XDG_STATE_HOME", previousStateHome);
        }
        if (previousHome.isNull()) {
            qunsetenv("HOME");
        } else {
            qputenv("HOME", previousHome);
        }
    }
#endif
};

QTEST_MAIN(ProfileStoreTest)
#include "tst_profile_store.moc"
