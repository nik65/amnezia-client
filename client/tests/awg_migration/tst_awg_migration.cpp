#include <QtTest>
#include "../../../common/awgMigration.h"
#include "../../../common/awgBackendObservation.h"
#include "../../../common/awgMigrationSecretStore.h"
#include <QTemporaryDir>
#include "core/utils/migrationTeardownContext.h"
#include "core/models/protocols/awgProtocolConfig.h"

using namespace amnezia::awgMigration;
class AwgMigrationTests : public QObject {
    Q_OBJECT
private slots:
    void retainedTeardownAfterActiveWrapperCleared_data()
    {
        QTest::addColumn<bool>("android");
        QTest::newRow("desktop IPC") << false;
        QTest::newRow("Android JNI observation") << true;
    }
    void retainedTeardownAfterActiveWrapperCleared()
    {
        QFETCH(bool, android);
        quint64 epoch = 41;
        bool ownerDestroyed = false;
        bool fallback = false;
        int completions = 0;
        QSharedPointer<QObject> active(new QObject);
        QObject::connect(active.data(), &QObject::destroyed, [&]() { ownerDestroyed = true; });
        const quint64 originalEpoch = epoch++;
        QPointer<MigrationTeardownContext> retirement = new MigrationTeardownContext(active, "session-A", originalEpoch,
                epoch, true, [&]() { return epoch; }, [&](bool confirmed) {
                    ++completions;
                    fallback = confirmed;
                    QVERIFY(ownerDestroyed); // release owned IPC receiver before fallback
                }, this);
        active.clear(); // production clears its active slot before native stop completes
        QVERIFY(!ownerDestroyed);
        retirement->observe("foreign-session", originalEpoch, true);
        retirement->observe("session-A", originalEpoch - 1, true);
        QCOMPARE(completions, 0);
        QTimer::singleShot(0, retirement, [retirement, android, originalEpoch]() {
            if (android) retirement->observeAndroid(QJsonObject{{"connectionNonce", "session-A"},
                        {"nativeCleanupConfirmed", true}}, originalEpoch);
            else retirement->observe("session-A", originalEpoch, true);
        });
        QTRY_COMPARE(completions, 1);
        QVERIFY(fallback);
        QTRY_VERIFY(retirement.isNull());
    }
    void retainedTeardownFailureNeverAuthorizesFallback_data()
    {
        QTest::addColumn<QString>("failure");
        for (const auto &failure : {"timeout", "native-error", "routes-failed", "epoch-retired"})
            QTest::newRow(failure) << QString(failure);
    }
    void retainedTeardownFailureNeverAuthorizesFallback()
    {
        QFETCH(QString, failure);
        quint64 epoch = 2;
        int completions = 0;
        bool fallback = true;
        QSharedPointer<QObject> active(new QObject);
        auto *retirement = new MigrationTeardownContext(active, "session-A", 1, 2, failure != "routes-failed",
                [&]() { return epoch; }, [&](bool confirmed) { ++completions; fallback = confirmed; }, this);
        active.clear();
        if (failure == "epoch-retired") ++epoch;
        if (failure == "timeout") retirement->expire();
        else retirement->observe("session-A", 1, failure != "native-error");
        QCOMPARE(completions, 1);
        QVERIFY(!fallback);
        retirement->observe("session-A", 1, true); // deferred duplicate cannot reverse failure
        QCOMPARE(completions, 1);
        QVERIFY(!fallback);
    }
    void protectedMigrationStoreRejectsTamperingAndForeignPaths()
    {
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const auto key = awgMigrationSecretStore::key(dir.path());
        QCOMPARE(key.size(), 32);
        const QByteArray plain("{\"grant\":\"confidential\",\"highestGeneration\":7}");
        const auto encrypted = awgMigrationSecretStore::crypt(plain, key, true);
        QVERIFY(!encrypted.contains("confidential"));
        QCOMPARE(awgMigrationSecretStore::crypt(encrypted, key, false), plain);
        auto damaged = encrypted;
        damaged[damaged.size() - 1] = char(damaged.back() ^ 1);
        QVERIFY(awgMigrationSecretStore::crypt(damaged, key, false).isEmpty());
        QVERIFY(awgMigrationSecretStore::crypt(encrypted, QByteArray(32, 'x'), false).isEmpty());
        const auto path = dir.path() + "/journal";
        QVERIFY(awgMigrationSecretStore::atomicWrite(path, encrypted));
        QByteArray read;
        QVERIFY(awgMigrationSecretStore::privateFile(path, &read));
        QCOMPARE(read, encrypted);
        QVERIFY(QFile::setPermissions(path, QFile::ReadOwner | QFile::WriteOwner | QFile::ReadGroup));
        QVERIFY(!awgMigrationSecretStore::privateFile(path, &read));
        QVERIFY(!awgMigrationSecretStore::atomicWrite(path, encrypted));
        const auto link = dir.path() + "/link";
        QVERIFY(QFile::link(path, link));
        QVERIFY(!awgMigrationSecretStore::privateFile(link, &read));
        QVERIFY(!awgMigrationSecretStore::atomicWrite(link, encrypted));
        QVERIFY(QFile::remove(dir.path() + "/key"));
        QVERIFY(awgMigrationSecretStore::key(dir.path()).isEmpty());
#else
        QSKIP("Linux migration secret-store permission contract");
#endif
    }
    void nativeParametersProveAppliedValuesWithoutLeakingKey()
    {
        const QByteArray key(32, 'k');
        const auto native = QString("header_protection_key=%1\ns1=16\nrandom_trailers=0\ndisable_cookies=1\nprivate_key=must-not-escape\n")
                .arg(QString::fromLatin1(key.toHex()));
        const auto observed = amnezia::awgBackendObservation::parameterDigests(native);
        QCOMPARE(observed.value("HeaderProtectionKey").toString(),
                 amnezia::awgBackendObservation::digest("HeaderProtectionKey", QString::fromLatin1(key.toBase64())));
        QCOMPARE(observed.value("RandomTrailers").toString(), amnezia::awgBackendObservation::digest("RandomTrailers", "false"));
        QVERIFY(observed.value("S1").toString() != amnezia::awgBackendObservation::digest("S1", "12"));
        QCOMPARE(observed.value("ContentPaddingAddition").toString(), amnezia::awgBackendObservation::digest("ContentPaddingAddition", "0"));
        QVERIFY(!QJsonDocument(observed).toJson().contains("must-not-escape"));
        QVERIFY(!QJsonDocument(observed).toJson().contains(key.toHex()));
    }
    void signedEnvelopeRejectsMutation()
    {
        EVP_PKEY_CTX *generator = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        QVERIFY(generator);
        QVERIFY(EVP_PKEY_keygen_init(generator) == 1);
        EVP_PKEY *key = nullptr;
        QVERIFY(EVP_PKEY_keygen(generator, &key) == 1);
        EVP_PKEY_CTX_free(generator);
        QByteArray publicKey(32, '\0');
        size_t publicSize = 32;
        QVERIFY(EVP_PKEY_get_raw_public_key(key, reinterpret_cast<unsigned char *>(publicKey.data()), &publicSize) == 1);
        const QByteArray bytes = "{\"schema\":1}";
        QByteArray signature(64, '\0');
        size_t signatureSize = 64;
        EVP_MD_CTX *context = EVP_MD_CTX_new();
        QVERIFY(EVP_DigestSignInit(context, nullptr, nullptr, nullptr, key) == 1);
        QVERIFY(EVP_DigestSign(context, reinterpret_cast<unsigned char *>(signature.data()), &signatureSize,
                reinterpret_cast<const unsigned char *>(bytes.constData()), bytes.size()) == 1);
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(key);
        QJsonObject envelope{{"payload", QString::fromLatin1(bytes.toBase64())},
                             {"signature", QString::fromLatin1(signature.toBase64())}};
        QJsonObject payload;
        QVERIFY(verifyEnvelope(envelope, publicKey, payload));
        QCOMPARE(payload.value("schema").toInt(), 1);
        envelope["payload"] = QString::fromLatin1(QByteArray("{\"schema\":2}").toBase64());
        QVERIFY(!verifyEnvelope(envelope, publicKey, payload));
        QVERIFY(payload.isEmpty());
        envelope["extra"] = true;
        QVERIFY(!verifyEnvelope(envelope, publicKey, payload));
    }
    void offerRejectsReplayIdentityAndUnknownParameters()
    {
        Binding binding{"server", "peer", "amnezia-awg", "fingerprint", "nonce", 3};
        const qint64 now = 1000;
        QJsonObject parameters{{"HeaderProtectionKey", QString::fromLatin1(QByteArray(32, 'x').toBase64())},
                               {"S1", "12"}, {"S2", "12"}, {"S3", "12"}, {"S4", "12"},
                               {"RandomTrailers", "false"}, {"DisableCookies", "0"}};
        QJsonObject offer{{"schema", 1}, {"serverPublicKey", "server"}, {"peerPublicKey", "peer"},
                {"containerId", "amnezia-awg"}, {"sourceFingerprint", "fingerprint"}, {"nonce", "nonce"},
                {"generation", 4}, {"expiresAt", 1100},
                {"target", QJsonObject{{"endpoint", "server.example:51822"}, {"clientAddress", "10.8.0.2/32"}, {"parameters", parameters}}},
                {"challenge", QJsonObject{{"address", "172.29.172.251"}, {"port", 18082}, {"nonce", "challenge"}}}};
        QVERIFY(validateOffer(offer, binding, now));
        auto mutated = offer;
        mutated["generation"] = 3;
        QVERIFY(!validateOffer(mutated, binding, now));
        mutated = offer; mutated["peerPublicKey"] = "another-peer";
        QVERIFY(!validateOffer(mutated, binding, now));
        mutated = offer; mutated["expiresAt"] = 1000;
        QVERIFY(!validateOffer(mutated, binding, now));
        parameters["client_priv_key"] = "injection";
        auto target = offer["target"].toObject(); target["parameters"] = parameters; mutated = offer; mutated["target"] = target;
        QVERIFY(!validateOffer(mutated, binding, now));
    }
    void sourceIdentityPreservesPrivateDataBoundary()
    {
        QJsonObject source{{"client_pub_key", "peer"}, {"server_pub_key", "server"}, {"psk_key", "psk"},
                {"client_priv_key", "private"}, {"dns1", "10.8.0.1"}, {"config", "private native config"}};
        const auto fingerprint = sourceFingerprint(source);
        source["client_priv_key"] = "another-private"; source["dns1"] = "10.8.0.9"; source["config"] = "other native";
        QCOMPARE(sourceFingerprint(source), fingerprint);
        source["psk_key"] = "different-psk";
        QVERIFY(sourceFingerprint(source) != fingerprint);
    }
    void awgDisabledValuesRoundTrip()
    {
        QJsonObject fields{{"RandomTrailers", "false"}, {"DisableCookies", "0"}, {"ContentPaddingAddition", "0"}};
        amnezia::AwgProtocolConfig model;
        model.serverConfig = amnezia::AwgServerConfig::fromJson(fields);
        QCOMPARE(model.serverProtocolVersion(), QString("3.1"));
        QCOMPARE(model.serverConfig.toJson().value("DisableCookies").toString(), QString("0"));
        QVERIFY(!amnezia::AwgProtocolConfig::isToggleEnabled("false"));
        QVERIFY(!amnezia::AwgProtocolConfig::isToggleEnabled("0"));
        QVERIFY(amnezia::AwgProtocolConfig::isToggleEnabled("on"));
    }
};
QTEST_GUILESS_MAIN(AwgMigrationTests)
#include "tst_awg_migration.moc"
