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

    void enforcesSerializedSizeAndPreservesLastGoodStore()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const QString path = directory.filePath(QStringLiteral("profiles.json"));
        ProfileStore store(path);
        Profile profile;
        profile.id = QStringLiteral("boundary");
        profile.name = QStringLiteral("Boundary");
        profile.protocol = QStringLiteral("wireguard");
        profile.configPath = QStringLiteral("/tmp/config");
        const auto serialized = [&store](const Profile &value) {
            return QJsonDocument(QJsonObject {
                { QStringLiteral("version"), 1 },
                { QStringLiteral("profiles"), QJsonArray { store.toJson(value) } },
            }).toJson(QJsonDocument::Indented);
        };
        constexpr qsizetype limit = 16 * 1024 * 1024;
        profile.configPath += QString(limit - serialized(profile).size(), QLatin1Char('a'));
        QCOMPARE(serialized(profile).size(), limit);
        QVERIFY2(store.add(profile), qPrintable(store.lastError()));
        QFile file(path);
        QVERIFY(file.open(QIODevice::ReadOnly));
        const QByteArray lastGood = file.readAll();
        file.close();
        QCOMPARE(lastGood.size(), limit);
        ProfileStore reloaded(path);
        QVERIFY2(reloaded.load(), qPrintable(reloaded.lastError()));
        QCOMPARE(reloaded.profiles().size(), 1);

        Profile extra = profile;
        extra.id = QStringLiteral("extra");
        extra.configPath = QStringLiteral("/tmp/extra");
        QVERIFY(!store.add(extra));
        QCOMPARE(store.lastError(), QStringLiteral("profile store exceeds the size limit"));
        QCOMPARE(store.profiles().size(), 1);
        QVERIFY(!store.contains(extra.id));
        QVERIFY(file.open(QIODevice::ReadOnly));
        QCOMPARE(file.readAll(), lastGood);
        file.close();
        QVERIFY(reloaded.load());
        QCOMPARE(reloaded.profiles().size(), 1);

        // A single byte above the cap must also fail before replacing an empty store.
        const QString abovePath = directory.filePath(QStringLiteral("above.json"));
        ProfileStore above(abovePath);
        profile.configPath += QLatin1Char('a');
        QCOMPARE(serialized(profile).size(), limit + 1);
        QVERIFY(!above.add(profile));
        QVERIFY(above.profiles().isEmpty());
        QVERIFY(!QFile::exists(abovePath));
    }

    void rollsBackMutationsWhenSavingFails()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const QString path = directory.filePath(QStringLiteral("profiles.json"));
        ProfileStore store(path);
        Profile profile;
        profile.id = QStringLiteral("first");
        profile.name = QStringLiteral("First");
        profile.protocol = QStringLiteral("wireguard");
        profile.configPath = QStringLiteral("/tmp/first");
        QVERIFY(store.add(profile));
        profile.id = QStringLiteral("second");
        QVERIFY(store.add(profile));
        const QString preservedPath = directory.filePath(QStringLiteral("preserved.json"));
        QVERIFY(QFile::rename(path, preservedPath));
        QVERIFY(QDir().mkdir(path)); // Deterministic failure even when tests run as root.
        QVERIFY(!store.remove(QStringLiteral("first")));
        QCOMPARE(store.profiles().size(), 2);
        QCOMPARE(store.profiles().at(0).id, QStringLiteral("first"));
        QCOMPARE(store.profiles().at(1).id, QStringLiteral("second"));
        profile.id = QStringLiteral("third");
        QVERIFY(!store.add(profile));
        QCOMPARE(store.profiles().size(), 2);
        QVERIFY(!store.contains(profile.id));
        QVERIFY(QDir().rmdir(path));
        QVERIFY(QFile::rename(preservedPath, path));
        ProfileStore reloaded(path);
        QVERIFY(reloaded.load());
        QCOMPARE(reloaded.profiles().size(), 2);
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
