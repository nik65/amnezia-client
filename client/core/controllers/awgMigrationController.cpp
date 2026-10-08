#include "awgMigrationController.h"
#include "../../../common/awgMigration.h"
#include "../../../common/awgMigrationTransport.h"
#include "../../../common/awgBackendObservation.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/serverConfigUtils.h"
#include <QTcpSocket>
#include <QNetworkProxy>
#include <QHostAddress>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QNetworkInterface>
#ifdef Q_OS_WIN
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(Q_OS_LINUX) || defined(Q_OS_ANDROID)
#include <sys/socket.h>
#include <net/if.h>
#endif

using namespace amnezia::awgMigration;
namespace {
QJsonObject client(const QJsonObject &connection) { return connection.value("awg_config_data").toObject(); }
QJsonObject patchClient(QJsonObject current, const QJsonObject &offer)
{
    const auto target = offer.value("target").toObject();
    const auto endpoint = target.value("endpoint").toString();
    const auto split = endpoint.lastIndexOf(':');
    if (split <= 0) return {};
    current["hostName"] = endpoint.left(split);
    current["port"] = endpoint.mid(split + 1).toInt();
    const auto address = target.value("clientAddress").toString();
    if (current.value("client_ip").toString().section('/', 0, 0) != address.section('/', 0, 0))
        current["client_ip"] = address;
    const auto parameters = target.value("parameters").toObject();
    for (const auto &key : parameterKeys()) current.remove(key);
    for (auto it = parameters.begin(); it != parameters.end(); ++it) current[it.key()] = it.value();
    // Keep native exports consistent with the JSON used by the backend.
    QStringList lines;
    for (const auto &line : current.value("config").toString().split('\n')) {
        const auto key = line.section('=', 0, 0).trimmed();
        if (parameterKeys().contains(key)) continue;
        if (key == "Endpoint") lines.append("Endpoint = " + endpoint);
        else if (key == "Address" && line.section('=', 1).trimmed().section('/', 0, 0) != address.section('/', 0, 0))
            lines.append("Address = " + address);
        else {
            lines.append(line);
            if (line.trimmed() == "[Interface]") {
                for (auto it = parameters.begin(); it != parameters.end(); ++it)
                    lines.append(it.key() + " = " + it.value().toString());
            }
        }
    }
    current["config"] = lines.join('\n');
    return current;
}
QJsonObject committedProfile(QJsonObject profile, const QJsonObject &offer)
{
    auto containers = profile.value("containers").toArray();
    bool patched = false;
    for (int i = 0; i < containers.size(); ++i) {
        auto container = containers[i].toObject();
        if (container.value("container") != profile.value("defaultContainer")) continue;
        auto awg = container.value("awg").toObject();
        if (awg.isEmpty()) continue;
        auto cached = QJsonDocument::fromJson(awg.value("last_config").toString().toUtf8()).object();
        if (cached.isEmpty()) continue;
        cached = patchClient(cached, offer);
        if (cached.isEmpty()) return {};
        awg["last_config"] = QString::fromUtf8(QJsonDocument(cached).toJson(QJsonDocument::Compact));
        const auto parameters = offer.value("target").toObject().value("parameters").toObject();
        for (const auto &key : parameterKeys()) awg.remove(key);
        for (auto it = parameters.begin(); it != parameters.end(); ++it) awg[it.key()] = it.value();
        awg["protocol_version"] = "3.1";
        awg["port"] = QString::number(cached.value("port").toInt());
        container["awg"] = awg;
        containers[i] = container;
        patched = true;
    }
    if (!patched) return {};
    profile["containers"] = containers;
    return profile;
}
}
AwgMigrationController::AwgMigrationController(SecureServersRepository *servers,
        SecureAppSettingsRepository *settings, QObject *parent)
    : QObject(parent), m_servers(servers), m_settings(settings)
{
    m_deadline.setSingleShot(true);
    m_deadline.setInterval(25000);
    connect(&m_deadline, &QTimer::timeout, this, [this]() { failed(); });
    connect(m_servers, &SecureServersRepository::serverRemoved, this, [this](const QString &id, int) {
        if (id == m_serverId) cancel();
    });
    connect(m_servers, &SecureServersRepository::serverEdited, this, [this](const QString &id) {
        if (id == m_serverId && !m_committingProfile && !m_sourceProfile.isEmpty()
            && digest(m_servers->serverJson(m_servers->indexOfServerId(id))) != digest(m_sourceProfile)) {
            recordFailure("profile_changed");
            cancel();
        }
    });
}
bool AwgMigrationController::persist(const QString &state)
{
    m_journal["state"] = state;
    return m_servers->writeMigrationJournal(m_serverId, m_journal);
}
void AwgMigrationController::recordFailure(const QString &reason, int httpStatus)
{
    if (m_serverId.isEmpty() || m_cancelled) return;
    if (m_journal.value("lastFailureReason").toString() == reason
        && m_journal.value("lastHttpStatus").toInt() == httpStatus) return;
    m_journal["lastFailureReason"] = reason;
    m_journal["lastHttpStatus"] = httpStatus;
    m_journal["lastFailureAt"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
    m_servers->writeMigrationJournal(m_serverId, m_journal);
}
void AwgMigrationController::clearFailure()
{
    if (!m_journal.contains("lastFailureReason")) return;
    m_journal.remove("lastFailureReason");
    m_journal.remove("lastHttpStatus");
    m_journal.remove("lastFailureAt");
    m_servers->writeMigrationJournal(m_serverId, m_journal);
}
QJsonObject AwgMigrationController::prepare(const QString &serverId, const QJsonObject &connection, bool allowTrial)
{
    if (allowTrial) cancel();
    else {
        // Adopting a live service tunnel must not rewrite an existing trial.
        ++m_callbackGeneration;
        m_busy = false;
        m_deadline.stop();
        m_trial = false;
    }
    m_allowTrial = allowTrial;
    m_cancelled = false;
    m_serverId = serverId;
    m_originalConnection = connection;
    m_startedAt = QDateTime::currentMSecsSinceEpoch();
    m_pollAfter = 0;
    m_epoch = 0;
    m_observation = {};
    m_journal = m_servers->migrationJournal(serverId);
    m_sourceProfile = m_servers->serverJson(m_servers->indexOfServerId(serverId));
    if (client(connection).isEmpty() || !allowTrial) return connection;
    if (m_journal.value("state") == "committing") {
        persist(digest(m_sourceProfile) == m_journal.value("candidateHash").toString()
                    ? "ack_pending" : "rolled_back");
        return connection;
    }
    if (m_journal.value("state") == "trial") {
        // The original stored profile was never overwritten during the trial.
        persist("rolled_back");
        return connection;
    }
    if (m_journal.value("state") == "staged"
        && m_journal.value("sourceHash").toString() != digest(m_sourceProfile)
        && m_journal.value("sourceFingerprint").toString() == sourceFingerprint(client(connection))) {
        // Rebase a still-valid wire offer over current user DNS/routes/labels.
        // The new complete profile is the CAS source; no stale snapshot wins.
        m_journal["sourceHash"] = digest(m_sourceProfile);
        if (!persist("staged")) return connection;
    }
    if (m_journal.value("state") != "staged" || m_journal.value("sourceHash").toString() != digest(m_sourceProfile))
        return connection;
    if (!m_journal.value("capabilityConfirmed").toBool()) return connection;
    const auto offer = m_journal.value("offer").toObject();
    if (offer.value("expiresAt").toDouble() <= QDateTime::currentSecsSinceEpoch()) {
        m_journal.remove("grant");
        m_journal.remove("nonce");
        m_journal.remove("offer");
        persist("expired");
        return connection;
    }
    const auto patched = patchClient(client(connection), offer);
    m_journal["highestGeneration"] = offer.value("generation");
    if (patched.isEmpty() || !persist("trial")) return connection;
    QJsonObject candidate = connection;
    candidate["awg_config_data"] = patched;
    candidate["hostName"] = patched.value("hostName");
    m_trial = true;
    m_initialRx = m_initialTx = -1;
    m_deadline.start();
    return candidate;
}
void AwgMigrationController::cancel()
{
    ++m_callbackGeneration;
    m_cancelled = true;
    m_busy = false;
    m_deadline.stop();
    if (m_trial) persist("rolled_back");
    m_trial = false;
}
void AwgMigrationController::failed()
{
    if (!m_trial || m_cancelled) return;
    const auto legacy = m_originalConnection;
    cancel();
    if (reconnectLegacy) reconnectLegacy(legacy);
}
void AwgMigrationController::observe(const QString &serverId, quint64 epoch, const QJsonObject &observation)
{
    if (m_cancelled || serverId != m_serverId || client(m_originalConnection).isEmpty()) return;
    if (m_epoch && m_epoch != epoch) { recordFailure("connection_epoch_changed"); cancel(); return; }
    m_epoch = epoch;
    bool ok = false;
    const auto handshake = observation.value("lastHandshakeMs").toString().toLongLong(&ok);
    if (!ok || handshake < (m_startedAt / 1000) * 1000 || handshake > QDateTime::currentMSecsSinceEpoch() + 5000
        || observation.value("peerPublicKey").toString() != client(m_originalConnection).value("server_pub_key").toString()) return;
    m_observation = observation;
    if (m_busy) return;
    if (!observation.value("awg3Capable").toBool()) return;
    m_journal["capabilityConfirmed"] = true;
    if (!m_trial) {
        if (QDateTime::currentSecsSinceEpoch() < m_pollAfter) return;
        m_pollAfter = QDateTime::currentSecsSinceEpoch() + 60;
        enrollOrFetch(); return;
    }
    const auto actualKeyHash = observation.value("headerProtectionKeyHash").toString();
    const auto expectedKey = strictBase64(m_journal.value("offer").toObject().value("target").toObject()
            .value("parameters").toObject().value("HeaderProtectionKey").toString(), 32);
    if (actualKeyHash != QString::fromLatin1(QCryptographicHash::hash(expectedKey, QCryptographicHash::Sha256).toHex())) return;
    const auto parameters = m_journal.value("offer").toObject().value("target").toObject().value("parameters").toObject();
    const auto observedParameters = observation.value("parameterDigests").toObject();
    for (auto it = parameters.begin(); it != parameters.end(); ++it) {
        if (observedParameters.value(it.key()).toString() != amnezia::awgBackendObservation::digest(it.key(), it.value().toString())) return;
    }
    const auto rx = observation.value("rxBytes").toDouble(-1), tx = observation.value("txBytes").toDouble(-1);
    if (m_initialRx < 0) { m_initialRx = rx; m_initialTx = tx; }
    if (!m_journal.value("challengeReceipt").toObject().isEmpty()) {
        if (rx <= m_initialRx || tx <= m_initialTx) return;
        const auto profile = committedProfile(m_sourceProfile, m_journal.value("offer").toObject());
        m_journal["candidateHash"] = digest(profile);
        if (profile.isEmpty() || !persist("committing")) { failed(); return; }
        m_committingProfile = true;
        const bool committed = m_servers->compareAndSwapServer(m_serverId, m_journal.value("sourceHash").toString(), profile);
        m_committingProfile = false;
        if (!committed) { failed(); return; }
        m_trial = false;
        m_deadline.stop();
        if (persist("ack_pending")) acknowledge();
        return;
    }
    challenge();
}
void AwgMigrationController::request(const QString &path, const QJsonObject &body,
                                    std::function<void(const QJsonObject &)> callback)
{
    const auto local = QHostAddress(m_observation.value("deviceIpv4Address").toString().section('/', 0, 0));
    if (local.isNull() || local.protocol() != QAbstractSocket::IPv4Protocol) { recordFailure("control_source_address_unavailable"); return; }
    const auto generation = m_callbackGeneration;
    const auto id = m_serverId;
    auto socket = new QTcpSocket(this);
    socket->setProxy(QNetworkProxy::NoProxy);
    if (!socket->bind(local)) { recordFailure("control_source_bind_failed"); socket->deleteLater(); return; }
    QNetworkInterface tunnel;
    for (const auto &adapter : QNetworkInterface::allInterfaces()) {
        for (const auto &entry : adapter.addressEntries()) {
            if (entry.ip() == local) tunnel = adapter;
        }
    }
    if (!tunnel.isValid() || !tunnel.flags().testFlag(QNetworkInterface::IsUp)) {
        recordFailure("control_interface_unavailable"); socket->deleteLater(); return;
    }
#ifdef Q_OS_WIN
    const DWORD interfaceIndex = htonl(static_cast<u_long>(tunnel.index()));
    if (::setsockopt(static_cast<SOCKET>(socket->socketDescriptor()), IPPROTO_IP, IP_UNICAST_IF,
            reinterpret_cast<const char *>(&interfaceIndex), sizeof(interfaceIndex)) != 0) {
        recordFailure("control_interface_bind_failed"); socket->deleteLater(); return;
    }
#elif defined(Q_OS_LINUX) || defined(Q_OS_ANDROID)
    const QByteArray interfaceName = tunnel.name().toUtf8();
    if (::setsockopt(static_cast<int>(socket->socketDescriptor()), SOL_SOCKET, SO_BINDTODEVICE,
            interfaceName.constData(), interfaceName.size() + 1) != 0) {
        recordFailure("control_interface_bind_failed"); socket->deleteLater(); return;
    }
#else
    socket->deleteLater(); return;
#endif
    auto timer = new QTimer(socket);
    timer->setSingleShot(true);
    timer->start(5000);
    m_busy = true;
    auto buffer = std::make_shared<QByteArray>();
    auto finish = [this, socket, generation]() {
        if (generation == m_callbackGeneration) m_busy = false;
        socket->abort(); socket->deleteLater();
    };
    connect(timer, &QTimer::timeout, socket, [this, generation, finish]() {
        if (generation == m_callbackGeneration) recordFailure("control_request_timeout");
        finish();
    });
    connect(socket, &QTcpSocket::errorOccurred, socket, [this, generation, finish](QAbstractSocket::SocketError error) {
        if (generation == m_callbackGeneration && m_busy)
            recordFailure(error == QAbstractSocket::RemoteHostClosedError ? "control_peer_closed" : "control_socket_failed");
        finish();
    });
    const auto bytes = QJsonDocument(body).toJson(QJsonDocument::Compact);
    const auto logs = m_originalConnection.value("clientLogs").toObject();
    const auto clientId = logs.value("clientId").toString();
    auto token = logs.value("token").toString();
    if (token.isEmpty()) token = m_settings->remoteLogToken(m_serverId + ':' + clientId);
    const QByteArray grant = m_journal.value("grant").toString().toUtf8();
    if (clientId.size() != 64 || token.isEmpty()) { recordFailure("control_auth_unavailable"); finish(); return; }
    if (clientId.contains('\r') || clientId.contains('\n') || token.contains('\r') || token.contains('\n')
        || grant.contains('\r') || grant.contains('\n')) { recordFailure("control_auth_header_invalid"); finish(); return; }
    connect(socket, &QTcpSocket::connected, socket, [socket, path, bytes, clientId, token, grant]() {
        QByteArray request = "POST " + path.toUtf8() + " HTTP/1.1\r\nHost: 172.29.172.251\r\nConnection: close\r\nContent-Type: application/json\r\n";
        request += "X-Amnezia-Client-Id: " + clientId.toUtf8() + "\r\nX-Amnezia-Log-Token: " + token.toUtf8() + "\r\n";
        request += "X-Amnezia-Migration-Grant: " + grant + "\r\nContent-Length: " + QByteArray::number(bytes.size()) + "\r\n\r\n" + bytes;
        socket->write(request);
    });
    connect(socket, &QTcpSocket::readyRead, socket, [this, socket, buffer, generation, id, callback, finish]() {
        buffer->append(socket->readAll());
        const auto reply = parseControlReply(*buffer, MaximumDocumentBytes);
        if (reply.state == ControlReply::Pending) return;
        if (reply.state == ControlReply::Failed) {
            if (generation == m_callbackGeneration) recordFailure(reply.reason, reply.httpStatus);
            finish(); return;
        }
        finish();
        if (generation == m_callbackGeneration && id == m_serverId && !m_cancelled) {
            clearFailure();
            callback(reply.payload);
        }
    });
    m_journal["lastRequestAt"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
    m_servers->writeMigrationJournal(m_serverId, m_journal);
    socket->connectToHost(QHostAddress("172.29.172.251"), 18082);
}
void AwgMigrationController::enrollOrFetch()
{
    if (!m_allowTrial && !passiveMigrationRequestAllowed(m_journal.value("state").toString())) return;
    const auto kind = m_servers->serverKind(m_serverId);
    if (kind != serverConfigUtils::ConfigType::SelfHostedAdmin
        && kind != serverConfigUtils::ConfigType::SelfHostedUser) return;
    if (m_journal.value("state") == "staged" || m_journal.value("state") == "committed"
        || m_journal.value("state") == "recovery_required"
        || m_journal.value("state") == "secret_store_unavailable") return;
    const auto configuration = client(m_originalConnection);
    if (m_journal.value("state") == "ack_pending") { acknowledge(); return; }
    if (m_journal.value("grantExpiresAt").toDouble() > 0
        && m_journal.value("grantExpiresAt").toDouble() <= QDateTime::currentSecsSinceEpoch()) {
        m_journal.remove("grant");
        m_journal.remove("nonce");
        m_journal.remove("challengeReceipt");
    }
    if (m_journal.value("nonce").toString().isEmpty()) {
        m_journal["nonce"] = QString::number(QRandomGenerator::system()->generate64(), 16).rightJustified(16, '0')
                + QString::number(QRandomGenerator::system()->generate64(), 16).rightJustified(16, '0');
        m_journal["sourceHash"] = digest(m_sourceProfile);
        m_journal["sourceFingerprint"] = sourceFingerprint(configuration);
        if (!persist("enrolling")) return;
    }
    const QJsonObject binding{{"schema", Schema}, {"peerPublicKey", configuration.value("client_pub_key")},
        {"sourceFingerprint", m_journal.value("sourceFingerprint")}, {"nonce", m_journal.value("nonce")}};
    if (m_journal.value("grant").toString().isEmpty()) {
        request("/migration/v1/bootstrap", binding, [this, configuration, binding](const QJsonObject &reply) {
            if (!hasExactKeys(reply, {"schema", "serverPublicKey", "containerId", "peerPublicKey", "sourceFingerprint",
                                     "nonce", "grant", "signingPublicKey", "generation", "expiresAt"})
                || reply.value("schema").toInt() != Schema || reply.value("nonce") != binding.value("nonce")
                || reply.value("sourceFingerprint") != binding.value("sourceFingerprint")
                || reply.value("peerPublicKey") != binding.value("peerPublicKey")
                || reply.value("serverPublicKey") != configuration.value("server_pub_key")
                || reply.value("containerId") != m_sourceProfile.value("defaultContainer")
                || reply.value("expiresAt").toDouble() <= QDateTime::currentSecsSinceEpoch()
                || strictBase64(reply.value("signingPublicKey").toString(), 32).isEmpty()
                || reply.value("grant").toString().isEmpty()) { recordFailure("bootstrap_binding_rejected", 200); return; }
            if (!m_journal.value("signingPublicKey").toString().isEmpty()
                && m_journal.value("signingPublicKey") != reply.value("signingPublicKey")) { recordFailure("bootstrap_signer_changed", 200); return; }
            for (const auto &key : {"grant", "signingPublicKey", "containerId", "serverPublicKey", "peerPublicKey"}) m_journal[key] = reply.value(key);
            m_journal["grantExpiresAt"] = reply.value("expiresAt");
            if (persist("enrolled")) enrollOrFetch();
        });
        return;
    }
    if (m_journal.value("state") == "ack_pending") { acknowledge(); return; }
    request("/migration/v1/offer", binding, [this](const QJsonObject &envelope) {
        QJsonObject offer;
        if (!verifyEnvelope(envelope, strictBase64(m_journal.value("signingPublicKey").toString(), 32), offer)) return;
        Binding binding{m_journal.value("serverPublicKey").toString(), m_journal.value("peerPublicKey").toString(),
            m_journal.value("containerId").toString(), m_journal.value("sourceFingerprint").toString(),
            m_journal.value("nonce").toString(), qMax(static_cast<qint64>(m_journal.value("highestGeneration").toDouble()),
                    static_cast<qint64>(m_journal.value("stagedGeneration").toDouble()) - 1)};
        if (!validateOffer(offer, binding, QDateTime::currentSecsSinceEpoch())
            || m_journal.value("sourceHash").toString() != digest(m_servers->serverJson(m_servers->indexOfServerId(m_serverId)))) return;
        if (offer.value("generation") == m_journal.value("stagedGeneration")
            && digest(offer.value("target").toObject()) != m_journal.value("stagedTargetHash").toString()) return;
        m_journal.remove("challengeReceipt");
        m_journal["offer"] = offer;
        m_journal["stagedGeneration"] = offer.value("generation");
        m_journal["stagedTargetHash"] = digest(offer.value("target").toObject());
        persist("staged");
    });
}
void AwgMigrationController::challenge()
{
    const auto offer = m_journal.value("offer").toObject();
    const auto challenge = offer.value("challenge").toObject();
    if (challenge.value("address").toString() != "172.29.172.251" || challenge.value("port").toInt() != 18082) return;
    const QJsonObject body{{"schema", Schema}, {"grant", m_journal.value("grant")},
        {"nonce", challenge.value("nonce")}, {"generation", offer.value("generation")}, {"peerPublicKey", offer.value("peerPublicKey")}};
    request("/migration/v1/challenge", body, [this, offer, challenge](const QJsonObject &envelope) {
        QJsonObject receipt;
        if (!verifyEnvelope(envelope, strictBase64(m_journal.value("signingPublicKey").toString(), 32), receipt)
            || !hasExactKeys(receipt, {"schema", "serverPublicKey", "containerId", "peerPublicKey", "generation", "expiresAt", "nonce", "targetAddress"})
            || receipt.value("schema").toInt() != Schema
            || receipt.value("nonce") != challenge.value("nonce") || receipt.value("generation") != offer.value("generation")
            || receipt.value("peerPublicKey") != offer.value("peerPublicKey")
            || receipt.value("serverPublicKey") != offer.value("serverPublicKey")
            || receipt.value("containerId") != offer.value("containerId")
            || receipt.value("targetAddress").toString() != offer.value("target").toObject().value("clientAddress").toString().section('/', 0, 0)
            || receipt.value("expiresAt").toDouble() <= QDateTime::currentSecsSinceEpoch()) return;
        // Wait for a later native observation proving both counters advanced
        // on this same candidate epoch before the persistent profile CAS.
        m_journal["challengeReceipt"] = envelope;
        persist("trial");
    });
}
void AwgMigrationController::acknowledge()
{
    const auto offer = m_journal.value("offer").toObject();
    if (m_journal.value("grantExpiresAt").toDouble() <= QDateTime::currentSecsSinceEpoch()) {
        const QString nonce = QString::number(QRandomGenerator::system()->generate64(), 16).rightJustified(16, '0')
                + QString::number(QRandomGenerator::system()->generate64(), 16).rightJustified(16, '0');
        const QJsonObject renewal{{"schema", Schema}, {"grant", m_journal.value("grant")},
            {"peerPublicKey", offer.value("peerPublicKey")}, {"generation", offer.value("generation")},
            {"nonce", nonce}, {"challengeReceipt", m_journal.value("challengeReceipt")}};
        request("/migration/v1/renew", renewal, [this, offer, nonce](const QJsonObject &envelope) {
            QJsonObject proof;
            if (!verifyEnvelope(envelope, strictBase64(m_journal.value("signingPublicKey").toString(), 32), proof)
                || !hasExactKeys(proof, {"schema", "serverPublicKey", "peerPublicKey", "containerId", "generation",
                                        "nonce", "grant", "sourceFingerprint", "targetHash", "expiresAt"})
                || proof.value("schema").toInt() != Schema || proof.value("nonce").toString() != nonce
                || proof.value("serverPublicKey") != offer.value("serverPublicKey")
                || proof.value("peerPublicKey") != offer.value("peerPublicKey")
                || proof.value("containerId") != offer.value("containerId")
                || proof.value("generation") != offer.value("generation")
                || proof.value("sourceFingerprint") != offer.value("sourceFingerprint")
                || proof.value("targetHash").toString() != digest(offer.value("target").toObject())
                || proof.value("expiresAt").toDouble() <= QDateTime::currentSecsSinceEpoch()
                || proof.value("grant").toString().isEmpty()) return;
            m_journal["grant"] = proof.value("grant");
            m_journal["grantExpiresAt"] = proof.value("expiresAt");
            if (persist("ack_pending")) acknowledge();
        });
        return;
    }
    const QJsonObject body{{"schema", Schema}, {"grant", m_journal.value("grant")},
        {"generation", offer.value("generation")}, {"peerPublicKey", offer.value("peerPublicKey")},
        {"challengeReceipt", m_journal.value("challengeReceipt")}};
    request("/migration/v1/ack", body, [this](const QJsonObject &reply) {
        if (reply.value("acknowledged").toBool()) persist("committed");
    });
}
