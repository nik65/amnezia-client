#include <QtTest>
#include "core/controllers/awgMigrationController.h"
#include "../../../common/awgMigration.h"
#include "../../../common/awgBackendObservation.h"
#include <memory>
using namespace amnezia::awgMigration;

class AwgMigrationControllerTests : public QObject {
    Q_OBJECT
    SecureServersRepository repository;
    SecureAppSettingsRepository settings;
    EVP_PKEY *key = nullptr;
    QString signer;
    QJsonObject connection, originalProfile, target, offer;
    QStringList requests;
    bool expiredProof = false, corruptOffer = false, acknowledge = true;
    QJsonObject sign(const QJsonObject &payload) {
        const auto bytes = QJsonDocument(payload).toJson(QJsonDocument::Compact);
        QByteArray signature(64, '\0'); size_t length = signature.size();
        auto context = EVP_MD_CTX_new();
        const bool ok = context && EVP_DigestSignInit(context, nullptr, nullptr, nullptr, key) == 1
            && EVP_DigestSign(context, reinterpret_cast<unsigned char *>(signature.data()), &length,
                reinterpret_cast<const unsigned char *>(bytes.constData()), bytes.size()) == 1;
        EVP_MD_CTX_free(context);
        if (!ok) qFatal("Fixture Ed25519 signing failed");
        return {{"payload", QString::fromLatin1(bytes.toBase64())},
                {"signature", QString::fromLatin1(signature.toBase64())}};
    }
    std::unique_ptr<AwgMigrationController> controller() {
        auto result = std::make_unique<AwgMigrationController>(&repository, &settings, nullptr);
        result->testRequest = [this](const QString &path, const QJsonObject &body,
                                    std::function<void(const QJsonObject &)> reply) {
            requests.append(path);
            const auto config = connection.value("awg_config_data").toObject();
            if (path.endsWith("bootstrap")) {
                reply({{"schema", 1}, {"serverPublicKey", config.value("server_pub_key")},
                    {"containerId", "amnezia-awg"}, {"peerPublicKey", config.value("client_pub_key")},
                    {"sourceFingerprint", body.value("sourceFingerprint")}, {"nonce", body.value("nonce")},
                    {"grant", "fresh-grant"}, {"signingPublicKey", signer}, {"generation", 7},
                    {"expiresAt", double(QDateTime::currentSecsSinceEpoch() + 600)}});
            } else if (path.endsWith("offer")) {
                offer = {{"schema", 1}, {"serverPublicKey", config.value("server_pub_key")},
                    {"peerPublicKey", config.value("client_pub_key")}, {"containerId", "amnezia-awg"},
                    {"sourceFingerprint", body.value("sourceFingerprint")}, {"nonce", body.value("nonce")},
                    {"generation", 7}, {"expiresAt", double(QDateTime::currentSecsSinceEpoch() + 600)},
                    {"target", target}, {"challenge", QJsonObject{{"address", "172.29.172.251"},
                        {"port", 18082}, {"nonce", "fresh-challenge"}}}};
                auto envelope = sign(offer);
                if (corruptOffer) envelope["signature"] = QString::fromLatin1(QByteArray(64, 'x').toBase64());
                reply(envelope);
            } else if (path.endsWith("challenge")) {
                reply(sign({{"schema", 1}, {"serverPublicKey", config.value("server_pub_key")},
                    {"containerId", "amnezia-awg"}, {"peerPublicKey", config.value("client_pub_key")},
                    {"generation", 7}, {"nonce", "fresh-challenge"}, {"targetAddress", "10.8.1.2"},
                    {"expiresAt", double(QDateTime::currentSecsSinceEpoch() + (expiredProof ? -1 : 600))}}));
            } else if (path.endsWith("renew")) {
                reply(sign({{"schema", 1}, {"serverPublicKey", offer.value("serverPublicKey")},
                    {"peerPublicKey", offer.value("peerPublicKey")}, {"containerId", offer.value("containerId")},
                    {"generation", offer.value("generation")}, {"nonce", body.value("nonce")},
                    {"grant", "renewed-grant"}, {"sourceFingerprint", offer.value("sourceFingerprint")},
                    {"targetHash", digest(offer.value("target").toObject())},
                    {"expiresAt", double(QDateTime::currentSecsSinceEpoch() + 600)}}));
            } else if (path.endsWith("ack")) reply({{"acknowledged", acknowledge}});
            else qFatal("Unexpected test-boundary request");
        };
        return result;
    }
    QJsonObject observation(const AwgMigrationController &controller, int count = 10) {
        const auto params = target.value("parameters").toObject();
        QJsonObject digests;
        for (auto it = params.begin(); it != params.end(); ++it)
            digests[it.key()] = amnezia::awgBackendObservation::digest(it.key(), it.value().toString());
        return {{"migrationActivationToken", controller.activationToken()},
            {"deviceIpv4Address", target.value("clientAddress").toString().section('/', 0, 0)},
            {"lastHandshakeMs", QString::number(QDateTime::currentMSecsSinceEpoch())},
            {"peerPublicKey", connection.value("awg_config_data").toObject().value("server_pub_key")},
            {"awg3Capable", true}, {"rxBytes", count}, {"txBytes", count}, {"parameterDigests", digests},
            {"headerProtectionKeyHash", QString::fromLatin1(QCryptographicHash::hash(
                strictBase64(params.value("HeaderProtectionKey").toString()), QCryptographicHash::Sha256).toHex())}};
    }
    void recover() {
        auto current = controller();
        current->beginActivation("server");
        current->prepare("server", connection, false);
        if (!current->cleanupCompleted("server", current->activationToken(), 42)) qFatal("Recovery fixture failed");
    }
    void stage(AwgMigrationController &current) {
        current.beginActivation("server");
        current.prepare("server", connection);
        current.observe("server", 43, observation(current));
    }
private slots:
    void init() {
        auto generator = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        QVERIFY(generator);
        QVERIFY(EVP_PKEY_keygen_init(generator) == 1);
        QVERIFY(EVP_PKEY_keygen(generator, &key) == 1);
        EVP_PKEY_CTX_free(generator);
        QByteArray publicKey(32, '\0'); size_t length = publicKey.size();
        QVERIFY(EVP_PKEY_get_raw_public_key(key, reinterpret_cast<unsigned char *>(publicKey.data()), &length) == 1);
        signer = QString::fromLatin1(publicKey.toBase64());
        const QString peer = QString::fromLatin1(QByteArray(32, 'p').toBase64());
        const QString server = QString::fromLatin1(QByteArray(32, 's').toBase64());
        const QJsonObject config{{"hostName", "old.example"}, {"port", 51820}, {"client_ip", "10.8.1.2/32"},
            {"client_pub_key", peer}, {"server_pub_key", server}, {"psk_key", "fixture-psk"},
            {"config", "[Interface]\nAddress = 10.8.1.2/32\n[Peer]\nEndpoint = old.example:51820\n"}};
        connection = {{"awg_config_data", config}, {"hostName", "old.example"}};
        originalProfile = {{"defaultContainer", "amnezia-awg"}, {"name", "preserved-label"},
            {"dns", "fixture-dns"}, {"routes", "fixture-routes"},
            {"containers", QJsonArray{QJsonObject{{"container", "amnezia-awg"}, {"awg", QJsonObject{
                {"last_config", QString::fromUtf8(QJsonDocument(config).toJson(QJsonDocument::Compact))},
                {"protocol_version", "2"}}}}}}};
        target = {{"endpoint", "new.example:51822"}, {"clientAddress", "10.8.1.2/32"},
            {"parameters", QJsonObject{{"HeaderProtectionKey", QString::fromLatin1(QByteArray(32, 'h').toBase64())},
                {"S1", "16"}, {"S2", "16"}, {"S3", "16"}, {"S4", "16"}}}};
        repository.profile = originalProfile;
        repository.journal = {{"state", "recovery_required"}, {"sourceHash", digest(originalProfile)},
            {"sourceFingerprint", sourceFingerprint(config)}, {"signingPublicKey", signer},
            {"highestGeneration", 7}, {"stagedGeneration", 7}, {"stagedTargetHash", digest(target)},
            {"nonce", "retired-nonce"}, {"grant", "retired-grant"},
            {"offer", QJsonObject{{"generation", 7}, {"nonce", "retired-nonce"}, {"target", target}}}};
        repository.writesAllowed = repository.casAllowed = true;
        repository.writes = repository.swaps = 0; repository.states.clear(); requests.clear();
        expiredProof = corruptOffer = false; acknowledge = true;
    }
    void cleanup() { EVP_PKEY_free(key); key = nullptr; }
    void restartRecoveryCompletesActualController() {
        recover();
        QVERIFY(repository.journal.contains("recoveryAuthorization"));
        auto restarted = controller(); stage(*restarted);
        QCOMPARE(repository.journal.value("state").toString(), QString("staged"));
        QVERIFY(repository.journal.value("nonce").toString() != "retired-nonce");
        QCOMPARE(repository.journal.value("grant").toString(), QString("fresh-grant"));
        restarted.reset();
        auto trial = controller(); trial->beginActivation("server");
        const auto candidate = trial->prepare("server", connection);
        QCOMPARE(candidate.value("hostName").toString(), QString("new.example"));
        QCOMPARE(repository.journal.value("state").toString(), QString("trial"));
        QVERIFY(!repository.journal.contains("recoveryAuthorization"));
        QCOMPARE(repository.journal.value("highestGeneration").toInt(), 7);
        QCOMPARE(repository.profile, originalProfile);
        trial->observe("server", 44, observation(*trial));
        QCOMPARE(repository.journal.value("state").toString(), QString("trial"));
        QVERIFY(repository.journal.contains("challengeReceipt"));
        QCOMPARE(repository.swaps, 0);
        trial->observe("server", 44, observation(*trial, 20));
        QCOMPARE(repository.swaps, 1);
        QCOMPARE(repository.journal.value("state").toString(), QString("committed"));
        QVERIFY(repository.states.indexOf("committing") < repository.states.indexOf("ack_pending"));
        QVERIFY(requests.contains("/migration/v1/ack"));
        QCOMPARE(repository.profile.value("dns"), originalProfile.value("dns"));
        QCOMPARE(repository.profile.value("routes"), originalProfile.value("routes"));
        const auto cached = QJsonDocument::fromJson(repository.profile.value("containers").toArray()[0].toObject()
            .value("awg").toObject().value("last_config").toString().toUtf8()).object();
        QCOMPARE(cached.value("psk_key").toString(), QString("fixture-psk"));
    }
    void cleanupAndJournalFailuresFailClosed() {
        auto current = controller(); current->beginActivation("server"); current->prepare("server", connection, false);
        const auto before = repository.journal; const auto token = current->activationToken();
        QVERIFY(!current->cleanupCompleted("server", "stale-token", 42));
        QVERIFY(!current->cleanupCompleted("server", token, 0));
        QVERIFY(!current->cleanupCompleted("foreign", token, 42));
        QCOMPARE(repository.writes, 0);
        repository.writesAllowed = false;
        QVERIFY(!current->cleanupCompleted("server", token, 42));
        QCOMPARE(repository.journal, before);
        repository.writesAllowed = true;
        QVERIFY(current->cleanupCompleted("server", token, 42));
        QVERIFY(!current->cleanupCompleted("server", token, 43));
        auto restart = controller(); stage(*restart);
        const auto staged = repository.journal;
        repository.writesAllowed = false; restart->beginActivation("server");
        QCOMPARE(restart->prepare("server", connection).value("hostName").toString(), QString("old.example"));
        QCOMPARE(repository.journal, staged);
    }
    void invalidSignatureAndExpiredChallengeCannotCommit() {
        recover(); auto current = controller(); corruptOffer = true; stage(*current);
        QCOMPARE(repository.journal.value("state").toString(), QString("enrolled"));
        QVERIFY(!repository.journal.contains("offer"));
        corruptOffer = false; current.reset(); current = controller(); stage(*current);
        QCOMPARE(repository.journal.value("state").toString(), QString("staged"));
        current->beginActivation("server"); current->prepare("server", connection);
        expiredProof = true;
        current->observe("server", 44, observation(*current));
        current->observe("server", 44, observation(*current, 20));
        QCOMPARE(repository.swaps, 0);
        QVERIFY(!repository.journal.contains("challengeReceipt"));
        QVERIFY(!requests.contains("/migration/v1/ack"));
    }
    void consumedAuthorizationCannotStartSecondSameGenerationTrial() {
        recover(); auto current = controller(); stage(*current);
        current->beginActivation("server"); current->prepare("server", connection);
        QCOMPARE(repository.journal.value("state").toString(), QString("trial"));
        QVERIFY(!repository.journal.contains("recoveryAuthorization"));
        current.reset(); current = controller();
        current->beginActivation("server");
        QCOMPARE(current->prepare("server", connection).value("hostName").toString(), QString("old.example"));
        QCOMPARE(repository.journal.value("state").toString(), QString("rolled_back"));
        current->observe("server", 45, observation(*current));
        QCOMPARE(repository.journal.value("lastFailureReason").toString(), QString("offer_generation"));
        QCOMPARE(repository.journal.value("highestGeneration").toInt(), 7);
        QCOMPARE(repository.swaps, 0);
    }
    void staleObservationAndCasFailureCannotAcknowledge() {
        recover(); auto current = controller(); stage(*current);
        current->beginActivation("server"); current->prepare("server", connection);
        auto stale = observation(*current); stale["migrationActivationToken"] = "retired-activation";
        const auto before = requests.size(); current->observe("server", 44, stale);
        QCOMPARE(requests.size(), before);
        current->observe("server", 44, observation(*current));
        repository.casAllowed = false;
        current->observe("server", 44, observation(*current, 20));
        QCOMPARE(repository.swaps, 1);
        QCOMPARE(repository.profile, originalProfile);
        QCOMPARE(repository.journal.value("state").toString(), QString("rolled_back"));
        QVERIFY(!requests.contains("/migration/v1/ack"));
    }
    void staleEpochCannotCommitAndAckMustBePositive() {
        recover(); auto current = controller(); stage(*current);
        current->beginActivation("server"); current->prepare("server", connection);
        current->observe("server", 44, observation(*current));
        current->observe("server", 43, observation(*current, 20));
        QCOMPARE(repository.swaps, 0);
        QCOMPARE(repository.journal.value("state").toString(), QString("rolled_back"));
        // A separate fresh authorized attempt exercises actual ACK handling.
        current.reset(); EVP_PKEY_free(key); key = nullptr;
        init(); recover(); current = controller(); stage(*current);
        current->beginActivation("server"); current->prepare("server", connection);
        acknowledge = false; current->observe("server", 44, observation(*current));
        current->observe("server", 44, observation(*current, 20));
        QCOMPARE(repository.swaps, 1);
        QCOMPARE(repository.journal.value("state").toString(), QString("ack_pending"));
        QVERIFY(requests.contains("/migration/v1/ack"));
    }
    void adoptedCommittedTargetRetriesPendingAck_data() {
        QTest::addColumn<bool>("expiredGrant");
        QTest::addColumn<bool>("interruptedCommit");
        QTest::addColumn<bool>("renewalStoreFailure");
        QTest::newRow("valid grant") << false << false << false;
        QTest::newRow("expired grant renews signed receipt") << true << false << false;
        QTest::newRow("CAS completed before ack-pending persistence") << false << true << false;
        QTest::newRow("interrupted commit with expired grant") << true << true << false;
        QTest::newRow("renewal write failure preserves durable and RAM grant") << true << false << true;
    }
    void adoptedCommittedTargetRetriesPendingAck() {
        QFETCH(bool, expiredGrant);
        QFETCH(bool, interruptedCommit);
        QFETCH(bool, renewalStoreFailure);
        recover(); auto current = controller(); stage(*current);
        current->beginActivation("server"); current->prepare("server", connection);
        acknowledge = false;
        current->observe("server", 44, observation(*current));
        current->observe("server", 44, observation(*current, 20));
        QCOMPARE(repository.journal.value("state").toString(), QString("ack_pending"));
        QCOMPARE(repository.swaps, 1);
        const auto committedProfile = repository.profile;
        if (expiredGrant) {
            repository.journal["grantExpiresAt"] = double(QDateTime::currentSecsSinceEpoch() - 1);
            auto receiptPayload = QJsonDocument::fromJson(QByteArray::fromBase64(repository.journal.value("challengeReceipt")
                .toObject().value("payload").toString().toLatin1())).object();
            receiptPayload["expiresAt"] = double(QDateTime::currentSecsSinceEpoch() - 1);
            repository.journal["challengeReceipt"] = sign(receiptPayload);
        }
        const auto receipt = repository.journal.value("challengeReceipt");
        if (interruptedCommit) repository.journal["state"] = "committing";
        current.reset(); requests.clear(); acknowledge = true;
        const auto cached = QJsonDocument::fromJson(repository.profile.value("containers").toArray()[0].toObject()
            .value("awg").toObject().value("last_config").toString().toUtf8()).object();
        auto adoptedConnection = connection;
        adoptedConnection["awg_config_data"] = cached;
        adoptedConnection["hostName"] = cached.value("hostName");
        current = controller(); current->beginActivation("server");
        const auto adopted = current->prepare("server", adoptedConnection, false);
        QCOMPARE(adopted.value("hostName").toString(), QString("new.example"));
        const auto beforeRenewal = current->testJournal();
        if (renewalStoreFailure) repository.writesAllowed = false;
        current->observe("server", 45, observation(*current, 30));
        if (renewalStoreFailure) {
            QCOMPARE(repository.journal, beforeRenewal);
            QCOMPARE(current->testJournal(), beforeRenewal);
            QCOMPARE(requests, QStringList{"/migration/v1/renew"});
            QCOMPARE(repository.profile, committedProfile);
            QCOMPARE(repository.swaps, 1);
            return;
        }
        QCOMPARE(repository.journal.value("state").toString(), QString("committed"));
        QCOMPARE(requests.contains("/migration/v1/renew"), expiredGrant);
        QVERIFY(requests.contains("/migration/v1/ack"));
        QVERIFY(!requests.contains("/migration/v1/bootstrap"));
        QVERIFY(!requests.contains("/migration/v1/offer"));
        QCOMPARE(repository.journal.value("challengeReceipt"), receipt);
        QCOMPARE(repository.swaps, 1);
        QCOMPARE(repository.profile, committedProfile);
    }
    void adoptedPendingAckRejectsUnprovenTarget_data() {
        QTest::addColumn<QString>("mutation");
        for (const auto &name : {"profile", "candidate-hash", "native-parameters", "native-key", "native-address", "peer", "receipt"})
            QTest::newRow(name) << QString(name);
    }
    void adoptedPendingAckRejectsUnprovenTarget() {
        QFETCH(QString, mutation);
        recover(); auto current = controller(); stage(*current);
        current->beginActivation("server"); current->prepare("server", connection);
        acknowledge = false;
        current->observe("server", 44, observation(*current));
        current->observe("server", 44, observation(*current, 20));
        QCOMPARE(repository.journal.value("state").toString(), QString("ack_pending"));
        auto cached = QJsonDocument::fromJson(repository.profile.value("containers").toArray()[0].toObject()
            .value("awg").toObject().value("last_config").toString().toUtf8()).object();
        auto adoptedConnection = connection; adoptedConnection["awg_config_data"] = cached;
        adoptedConnection["hostName"] = cached.value("hostName");
        if (mutation == "profile") repository.profile["name"] = "edited-by-user";
        if (mutation == "candidate-hash") repository.journal["candidateHash"] = "foreign-profile";
        if (mutation == "receipt") repository.journal["challengeReceipt"] = QJsonObject{};
        const auto expectedProfile = repository.profile;
        current.reset(); requests.clear(); acknowledge = true;
        current = controller(); current->beginActivation("server"); current->prepare("server", adoptedConnection, false);
        auto native = observation(*current, 30);
        if (mutation == "native-parameters") native["parameterDigests"] = QJsonObject{};
        if (mutation == "native-key") native["headerProtectionKeyHash"] = "foreign-key";
        if (mutation == "native-address") native["deviceIpv4Address"] = "10.8.1.99";
        if (mutation == "peer") native["peerPublicKey"] = "foreign-peer";
        current->observe("server", 45, native);
        QVERIFY(requests.isEmpty());
        QCOMPARE(repository.journal.value("state").toString(), QString("ack_pending"));
        QCOMPARE(repository.profile, expectedProfile);
        QCOMPARE(repository.swaps, 1);
    }
    void adoptedInterruptedCommitDoesNotGuessOrSkipFailedJournalWrite_data() {
        QTest::addColumn<bool>("editedProfile");
        QTest::newRow("candidate profile but persistence unavailable") << false;
        QTest::newRow("unknown user profile") << true;
    }
    void adoptedInterruptedCommitDoesNotGuessOrSkipFailedJournalWrite() {
        QFETCH(bool, editedProfile);
        recover(); auto current = controller(); stage(*current);
        current->beginActivation("server"); current->prepare("server", connection);
        acknowledge = false;
        current->observe("server", 44, observation(*current));
        current->observe("server", 44, observation(*current, 20));
        QCOMPARE(repository.journal.value("state").toString(), QString("ack_pending"));
        repository.journal["state"] = "committing";
        if (editedProfile) repository.profile["name"] = "user-edited";
        const auto profile = repository.profile;
        const auto journal = repository.journal;
        auto cached = QJsonDocument::fromJson(profile.value("containers").toArray()[0].toObject()
            .value("awg").toObject().value("last_config").toString().toUtf8()).object();
        auto adoptedConnection = connection; adoptedConnection["awg_config_data"] = cached;
        adoptedConnection["hostName"] = cached.value("hostName");
        current.reset(); requests.clear(); acknowledge = true;
        if (!editedProfile) repository.writesAllowed = false;
        current = controller(); current->beginActivation("server");
        current->prepare("server", adoptedConnection, false);
        current->observe("server", 45, observation(*current, 30));
        QVERIFY(requests.isEmpty());
        QCOMPARE(repository.journal, journal);
        QCOMPARE(repository.profile, profile);
        QCOMPARE(repository.swaps, 1);
    }
    void invalidObservationCannotPoisonTrialEpoch_data() {
        QTest::addColumn<bool>("wrongPeer");
        QTest::newRow("wrong peer") << true;
        QTest::newRow("stale handshake") << false;
    }
    void invalidObservationCannotPoisonTrialEpoch() {
        QFETCH(bool, wrongPeer);
        recover(); auto current = controller(); stage(*current);
        current->beginActivation("server"); current->prepare("server", connection);
        requests.clear();
        auto invalid = observation(*current);
        if (wrongPeer) invalid["peerPublicKey"] = "foreign-peer";
        else invalid["lastHandshakeMs"] = "1";
        current->observe("server", 99, invalid);
        QVERIFY(requests.isEmpty());
        QCOMPARE(repository.journal.value("state").toString(), QString("trial"));
        current->observe("server", 44, observation(*current));
        QVERIFY(requests.contains("/migration/v1/challenge"));
        current->observe("server", 44, observation(*current, 20));
        QCOMPARE(repository.journal.value("state").toString(), QString("committed"));
        QCOMPARE(repository.swaps, 1);
    }
};
QTEST_GUILESS_MAIN(AwgMigrationControllerTests)
#include "tst_awg_migration_controller.moc"
