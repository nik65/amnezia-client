#include <QtTest>
#include <QTemporaryDir>
#include <QFile>
#ifdef Q_OS_LINUX
#include <unistd.h>
#include <grp.h>
#endif
#include "awgMigrationManager.h"
using namespace amnezia::headless;

class AwgMigrationTest : public QObject {
    Q_OBJECT
    static amnezia::awgMigration::Binding binding() {
        return {QString::fromLatin1(QByteArray(32, 's').toBase64()), QString::fromLatin1(QByteArray(32, 'p').toBase64()),
                QStringLiteral("amnezia-awg2"), QString(64, QLatin1Char('a')), QStringLiteral("0123456789abcdef0123456789abcdef"), 0};
    }
    static QJsonObject offer(qint64 generation, qint64 expiresAt) {
        const auto b = binding();
        return {{"schema", 1}, {"serverPublicKey", b.serverPublicKey}, {"peerPublicKey", b.peerPublicKey},
            {"containerId", b.containerId}, {"sourceFingerprint", b.sourceFingerprint}, {"nonce", b.nonce},
            {"generation", generation}, {"expiresAt", expiresAt},
            {"target", QJsonObject {{"endpoint", "203.0.113.7:51822"}, {"clientAddress", "10.8.1.2/32"},
                {"parameters", QJsonObject {{"HeaderProtectionKey", QString::fromLatin1(QByteArray(32, 'h').toBase64())},
                    {"S1", "16"}, {"S2", "16"}, {"S3", "16"}, {"S4", "16"}}}}},
            {"challenge", QJsonObject {{"address", "172.29.172.251"}, {"port", 18082}, {"nonce", "test-challenge"}}}};
    }
    static QJsonObject sign(const QJsonObject &payload, QByteArray &publicKey) {
        const QByteArray seed(32, 'k');
        EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
            reinterpret_cast<const unsigned char *>(seed.constData()), seed.size());
        EVP_MD_CTX *context = EVP_MD_CTX_new();
        const QByteArray bytes = QJsonDocument(payload).toJson(QJsonDocument::Compact);
        publicKey.resize(32);
        size_t publicSize = 32, signatureSize = 64;
        QByteArray signature(64, '\0');
        const bool ok = key && context
            && EVP_PKEY_get_raw_public_key(key, reinterpret_cast<unsigned char *>(publicKey.data()), &publicSize) == 1
            && EVP_DigestSignInit(context, nullptr, nullptr, nullptr, key) == 1
            && EVP_DigestSign(context, reinterpret_cast<unsigned char *>(signature.data()), &signatureSize,
                reinterpret_cast<const unsigned char *>(bytes.constData()), bytes.size()) == 1;
        EVP_MD_CTX_free(context); EVP_PKEY_free(key);
        if (!ok || publicSize != 32 || signatureSize != 64) return {};
        return {{"payload", QString::fromLatin1(bytes.toBase64())}, {"signature", QString::fromLatin1(signature.toBase64())}};
    }
private slots:
    void legacyReadRejectsUnsafeGroupWriteSymlinkAndOutsideRoot() {
        QTemporaryDir directory;
        const QString root = directory.filePath("profiles");
        QVERIFY(QDir().mkdir(root));
        AwgMigrationManager manager(directory.filePath("migration"), {}, false, root);
        const QString source = QDir(root).filePath("legacy.conf");
        QVERIFY(manager.save(source, QByteArray("private-source")));
        QByteArray bytes;
        QVERIFY(manager.readLegacy(source, bytes));
        QCOMPARE(bytes, QByteArray("private-source"));
        QVERIFY(QFile::setPermissions(source, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::WriteGroup));
        QVERIFY(!manager.readLegacy(source, bytes));
        QVERIFY(QFile::setPermissions(source, QFileDevice::ReadOwner | QFileDevice::WriteOwner));
        const QString outside = directory.filePath("outside.conf");
        QVERIFY(manager.save(outside, QByteArray("foreign-source")));
        QVERIFY(!manager.readLegacy(outside, bytes));
        const QString link = QDir(root).filePath("link.conf");
        QVERIFY(QFile::link(source, link));
        QVERIFY(!manager.readLegacy(link, bytes));
        QVERIFY(QFile::setPermissions(root, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner | QFileDevice::WriteGroup));
        QVERIFY(!manager.readLegacy(source, bytes));
    }
    void rootTrustedGroup640IsLegacyOnlyAndForeignGroupIsRejected() {
#ifdef Q_OS_LINUX
        if (::geteuid() != 0) QSKIP("root group fixture requires an owned disposable Linux guest");
        QTemporaryDir directory;
        const QString root = directory.filePath("profiles");
        QVERIFY(QDir().mkdir(root));
        QVERIFY(QFile::setPermissions(root, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
        AwgMigrationManager manager(directory.filePath("migration"), {}, true, root);
        const QString source = QDir(root).filePath("legacy.conf");
        QVERIFY(manager.save(source, QByteArray("private-source")));
        QVERIFY(::chown(source.toLocal8Bit().constData(), 0, 0) == 0);
        QVERIFY(QFile::setPermissions(source, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ReadGroup));
        QByteArray bytes;
        QVERIFY(manager.readLegacy(source, bytes));
        QVERIFY(!manager.read(source, bytes)); // Private material remains 0600.
        uint arbitraryGroup = 424242;
        const group *trusted = ::getgrnam("amnezia");
        if (trusted && trusted->gr_gid == arbitraryGroup) ++arbitraryGroup;
        QVERIFY(::chown(source.toLocal8Bit().constData(), 0, arbitraryGroup) == 0);
        QVERIFY(!manager.readLegacy(source, bytes));
#else
        QSKIP("Linux ownership contract");
#endif
    }
    void productionEnrollmentRequestMatchesRealServerFixture() {
        QFile file(QString::fromUtf8(AWG_MIGRATION_WIRE_FIXTURE_PATH));
        QVERIFY(file.open(QIODevice::ReadOnly));
        const auto fixture = QJsonDocument::fromJson(file.readAll()).object();
        const auto values = fixture.value("binding").toObject();
        const amnezia::awgMigration::Binding b {values.value("serverPublicKey").toString(), values.value("peerPublicKey").toString(),
            values.value("containerId").toString(), values.value("sourceFingerprint").toString(), values.value("nonce").toString(), 0};
        QCOMPARE(AwgMigrationManager::enrollmentRequest(b), fixture.value("request").toObject());
    }
    void expiredStageRenewsSameTargetButNeverAttemptedGeneration() {
        QTemporaryDir directory;
        AwgMigrationManager manager(directory.filePath("migration"), {}, false);
        QString error;
        QVERIFY(manager.load(&error));
        Profile profile;
        profile.id = QStringLiteral("existing-peer");
        profile.protocol = QStringLiteral("amneziawg");
        profile.configPath = directory.filePath("original.conf");
        const QByteArray original("original-private-profile");
        QVERIFY(manager.save(profile.configPath, original));
        QVERIFY(manager.secureDirectory(manager.profileRoot(profile)));
        const QString candidate = QDir(manager.profileRoot(profile)).filePath("amn0.conf");
        QVERIFY(manager.save(candidate, QByteArray("candidate-private-profile")));
        const qint64 now = QDateTime::currentSecsSinceEpoch();
        const auto expired = offer(7, now - 1);
        QByteArray signer;
        const auto envelope = sign(expired, signer);
        QVERIFY(!envelope.isEmpty());
        QJsonObject journal {{"phase", "staged"}, {"highestGeneration", 0}, {"stagedGeneration", 7},
            {"stagedTargetHash", amnezia::awgMigration::digest(expired.value("target").toObject())},
            {"sourceHash", QString::fromLatin1(QCryptographicHash::hash(original, QCryptographicHash::Sha256).toHex())},
            {"candidatePath", candidate}, {"candidateHash", QString::fromLatin1(QCryptographicHash::hash("candidate-private-profile", QCryptographicHash::Sha256).toHex())},
            {"offer", expired}, {"envelope", envelope}, {"signingPublicKey", QString::fromLatin1(signer.toBase64())}, {"grant", "old-grant"}};
        QVERIFY(manager.writeState(profile, journal));
        QString selected, sha;
        QVERIFY(!manager.candidate(profile, selected, sha));
        journal = manager.state(profile);
        QCOMPARE(journal.value("phase").toString(), QStringLiteral("expired"));
        QCOMPARE(journal.value("highestGeneration").toInt(), 0);
        QCOMPARE(journal.value("signingPublicKey").toString(), QString::fromLatin1(signer.toBase64()));
        QVERIFY(!journal.contains("grant"));
        auto refreshed = offer(7, now + 3600);
        QVERIFY(AwgMigrationManager::validateRefreshedOffer(refreshed, journal, binding(), now));
        auto changed = refreshed;
        auto target = changed.value("target").toObject(); target.insert("endpoint", "203.0.113.8:51822"); changed.insert("target", target);
        QVERIFY(!AwgMigrationManager::validateRefreshedOffer(changed, journal, binding(), now));
        journal.insert("phase", "staged"); journal.insert("offer", refreshed);
        QVERIFY(manager.writeState(profile, journal));
        QVERIFY(manager.begin(profile));
        QVERIFY(manager.abandon(profile));
        const auto attempted = manager.state(profile);
        QCOMPARE(attempted.value("highestGeneration").toInt(), 7);
        auto b = binding(); b.highestGeneration = 7;
        QVERIFY(!AwgMigrationManager::validateRefreshedOffer(refreshed, attempted, b, now));
        QVERIFY(AwgMigrationManager::validateRefreshedOffer(offer(8, now + 3600), attempted, b, now));
    }
    void sourceCasMismatchRetiresStageWithoutClearingWatermarkOrPin() {
        QTemporaryDir directory;
        AwgMigrationManager manager(directory.filePath("migration"), {}, false);
        QString error; QVERIFY(manager.load(&error));
        Profile profile; profile.id = "peer"; profile.protocol = "amneziawg"; profile.configPath = directory.filePath("original.conf");
        QVERIFY(manager.save(profile.configPath, QByteArray("changed-profile")));
        QVERIFY(manager.secureDirectory(manager.profileRoot(profile)));
        const auto staged = offer(9, QDateTime::currentSecsSinceEpoch() + 3600);
        QVERIFY(manager.writeState(profile, {{"phase", "staged"}, {"highestGeneration", 8}, {"stagedGeneration", 9},
            {"sourceHash", "old-source"}, {"signingPublicKey", "retained-pin"}, {"offer", staged}}));
        QString path, sha; QVERIFY(!manager.candidate(profile, path, sha));
        const auto state = manager.state(profile);
        QCOMPARE(state.value("phase").toString(), QStringLiteral("expired"));
        QCOMPARE(state.value("highestGeneration").toInt(), 8);
        QCOMPARE(state.value("signingPublicKey").toString(), QStringLiteral("retained-pin"));
        QCOMPARE(state.value("stagedTargetHash").toString(), amnezia::awgMigration::digest(staged.value("target").toObject()));
    }
    void committedAckCrashAndRenewalPreserveProofAndRejectChangedBindings() {
        QTemporaryDir directory;
        AwgMigrationManager manager(directory.filePath("migration"), {}, false);
        QString error; QVERIFY(manager.load(&error));
        Profile profile; profile.id = "peer";
        QVERIFY(manager.secureDirectory(manager.profileRoot(profile)));
        const qint64 now = QDateTime::currentSecsSinceEpoch();
        const auto committedOffer = offer(7, now - 86400);
        const QJsonObject proof {{"payload", "retained-signed-proof"}, {"signature", "retained-signature"}};
        QJsonObject journal {{"phase", "committed"}, {"highestGeneration", 7}, {"ackPending", true},
            {"offer", committedOffer}, {"challengeReceipt", proof}, {"grant", "expired-grant"}, {"signingPublicKey", "pinned"}};
        QVERIFY(manager.writeState(profile, journal));
        AwgMigrationManager restarted(directory.filePath("migration"), {}, false);
        QVERIFY(restarted.load(&error));
        QCOMPARE(restarted.state(profile), journal);
        QJsonObject renewal {{"schema", 1}, {"serverPublicKey", committedOffer.value("serverPublicKey")},
            {"peerPublicKey", committedOffer.value("peerPublicKey")}, {"containerId", committedOffer.value("containerId")},
            {"generation", 7}, {"sourceFingerprint", committedOffer.value("sourceFingerprint")}, {"nonce", "fresh-nonce"},
            {"grant", "new-grant"}, {"targetHash", amnezia::awgMigration::digest(committedOffer.value("target").toObject())}, {"expiresAt", now + 3600}};
        QVERIFY(AwgMigrationManager::validateRenewal(renewal, journal, "fresh-nonce", now));
        for (const auto &name : {"peerPublicKey", "serverPublicKey", "containerId", "nonce", "sourceFingerprint", "targetHash"}) {
            auto changed = renewal; changed.insert(name, "foreign");
            QVERIFY(!AwgMigrationManager::validateRenewal(changed, journal, "fresh-nonce", now));
        }
        auto changed = renewal; changed.insert("generation", 8);
        QVERIFY(!AwgMigrationManager::validateRenewal(changed, journal, "fresh-nonce", now));
        changed = renewal; changed.insert("expiresAt", now - 1);
        QVERIFY(!AwgMigrationManager::validateRenewal(changed, journal, "fresh-nonce", now));
        QCOMPARE(restarted.state(profile).value("challengeReceipt").toObject(), proof);
        QVERIFY(restarted.state(profile).value("ackPending").toBool());
    }
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
