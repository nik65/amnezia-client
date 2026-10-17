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
};
QTEST_GUILESS_MAIN(AwgMigrationControllerTests)
#include "tst_awg_migration_controller.moc"
