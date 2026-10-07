#include "awgMigrationManager.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSaveFile>
#include <QUuid>
#include <QElapsedTimer>
#include <openssl/evp.h>
#ifdef Q_OS_LINUX
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#endif

namespace amnezia::headless {
namespace {
constexpr auto Listener = "172.29.172.251";
constexpr int Port = 18082;
QString hash(const QByteArray &bytes) { return QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex()); }
QString nativeName(const QString &key) {
    if (key == QStringLiteral("Hpk")) return QStringLiteral("HeaderProtectionKey");
    if (key == QStringLiteral("Cpa")) return QStringLiteral("ContentPaddingAddition");
    return key;
}
QString nativeParameter(const QString &key) {
    if (key == QStringLiteral("HeaderProtectionKey")) return QStringLiteral("Hpk");
    if (key == QStringLiteral("ContentPaddingAddition")) return QStringLiteral("Cpa");
    return key;
}
}

AwgMigrationManager::AwgMigrationManager(QString root, QString credentialsPath, bool requireRoot)
    : m_root(std::move(root)), m_credentialsPath(std::move(credentialsPath)), m_requireRoot(requireRoot) {}

bool AwgMigrationManager::secureDirectory(const QString &path) const
{
    QFileInfo info(path);
    if (info.exists() && (info.isSymLink() || !info.isDir()
        || (m_requireRoot && info.ownerId() != 0)
        || info.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther))) return false;
    if (!info.exists() && !QDir().mkdir(path)) return false;
    if (!QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner)) return false;
    info.refresh();
    return info.canonicalFilePath() == info.absoluteFilePath()
        && (!m_requireRoot || info.ownerId() == 0);
}
bool AwgMigrationManager::read(const QString &path, QByteArray &bytes) const
{
    const QFileInfo info(path);
    if (!info.isFile() || info.isSymLink() || info.canonicalFilePath() != info.absoluteFilePath()
        || (m_requireRoot && info.ownerId() != 0)
        || info.permissions() & (QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ExeGroup
                                 | QFileDevice::ReadOther | QFileDevice::WriteOther | QFileDevice::ExeOther)) return false;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() > 1024 * 1024) return false;
    bytes = file.readAll();
    return file.error() == QFileDevice::NoError;
}
bool AwgMigrationManager::save(const QString &path, const QByteArray &bytes) const
{
    QFileInfo before(path);
    if (before.exists() && (before.isSymLink() || !before.isFile())) return false;
    QSaveFile file(path);
    file.setDirectWriteFallback(false);
    if (!file.open(QIODevice::WriteOnly)
        || !file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner)
        || file.write(bytes) != bytes.size() || !file.commit()) return false;
    return true;
}
QString AwgMigrationManager::profileRoot(const Profile &profile) const { return QDir(m_root).filePath(hash(profile.id.toUtf8())); }
QJsonObject AwgMigrationManager::state(const Profile &profile) const {
    QByteArray bytes;
    if (!read(QDir(profileRoot(profile)).filePath(QStringLiteral("journal.json")), bytes)) return {};
    return QJsonDocument::fromJson(bytes).object();
}
bool AwgMigrationManager::writeState(const Profile &profile, const QJsonObject &value) {
    return save(QDir(profileRoot(profile)).filePath(QStringLiteral("journal.json")), QJsonDocument(value).toJson(QJsonDocument::Compact));
}
bool AwgMigrationManager::load(QString *error) {
    if (!secureDirectory(m_root)) {
        if (error) *error = QStringLiteral("migration cache is unsafe");
        return false;
    }
    // Startup is read-only with respect to networking. Interrupted attempts
    // remain unavailable until daemon ownership recovery has completed.
    for (const auto &entry : QDir(m_root).entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot)) {
        if (entry.isSymLink() || !secureDirectory(entry.absoluteFilePath())) {
            if (error) *error = QStringLiteral("migration journal directory is unsafe");
            return false;
        }
        QByteArray bytes;
        if (!read(QDir(entry.absoluteFilePath()).filePath(QStringLiteral("journal.json")), bytes)) {
            if (error) *error = QStringLiteral("migration journal is unreadable");
            return false;
        }
        QJsonParseError parse;
        const auto doc = QJsonDocument::fromJson(bytes, &parse);
        if (parse.error != QJsonParseError::NoError || !doc.isObject()) {
            if (error) *error = QStringLiteral("migration journal is invalid");
            return false;
        }
        auto value = doc.object();
        const QString phase = value.value("phase").toString();
        const double generation = value.value("highestGeneration").toDouble(-1);
        if (!QStringList {QStringLiteral("staged"), QStringLiteral("expired"), QStringLiteral("trying"), QStringLiteral("committed"), QStringLiteral("rolled_back")}.contains(phase)
            || generation < 0 || generation > 9007199254740991.0 || generation != static_cast<qint64>(generation)) {
            if (error) *error = QStringLiteral("migration phase or generation watermark is invalid");
            return false;
        }
        if (value.value("phase").toString() == QStringLiteral("trying")) {
            value.insert("phase", value.value("previousPhase").toString() == QStringLiteral("committed")
                ? QStringLiteral("committed") : QStringLiteral("rolled_back"));
            // The generation watermark deliberately survives rollback.
            if (!save(QDir(entry.absoluteFilePath()).filePath(QStringLiteral("journal.json")), QJsonDocument(value).toJson(QJsonDocument::Compact))) return false;
        }
    }
    return true;
}

bool AwgMigrationManager::source(const Profile &profile, QByteArray &bytes, QJsonObject &identity,
                                amnezia::awgMigration::Binding &binding) const
{
    if (profile.protocol != QStringLiteral("amneziawg") || !read(profile.configPath, bytes)) return false;
    QMap<QString, QString> iface, peer;
    QString section;
    int peers = 0;
    for (const QString &raw : QString::fromUtf8(bytes).split(QLatin1Char('\n'))) {
        const QString line = raw.trimmed();
        if (line.isEmpty() || line.startsWith(QLatin1Char('#'))) continue;
        if (line.startsWith(QLatin1Char('['))) {
            section = line;
            if (section == QStringLiteral("[Peer]")) ++peers;
            continue;
        }
        const int separator = line.indexOf(QLatin1Char('='));
        if (separator < 1) return false;
        auto &fields = section == QStringLiteral("[Interface]") ? iface : peer;
        const QString name = line.left(separator).trimmed();
        if (fields.contains(name)) return false;
        fields.insert(name, line.mid(separator + 1).trimmed());
    }
    if (peers != 1 || iface.contains(QStringLiteral("Hpk"))) return false;
    const QByteArray privateKey = amnezia::awgMigration::strictBase64(iface.value(QStringLiteral("PrivateKey")), 32);
    if (privateKey.isEmpty()) return false;
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
        reinterpret_cast<const unsigned char *>(privateKey.constData()), 32);
    QByteArray publicKey(32, '\0');
    size_t size = 32;
    const bool derived = key && EVP_PKEY_get_raw_public_key(key, reinterpret_cast<unsigned char *>(publicKey.data()), &size) == 1 && size == 32;
    EVP_PKEY_free(key);
    if (!derived) return false;
    binding.peerPublicKey = QString::fromLatin1(publicKey.toBase64());
    binding.serverPublicKey = peer.value(QStringLiteral("PublicKey"));
    if (amnezia::awgMigration::strictBase64(binding.serverPublicKey, 32).isEmpty()) return false;
    const QString endpoint = peer.value(QStringLiteral("Endpoint"));
    const int split = endpoint.lastIndexOf(QLatin1Char(':'));
    if (split < 1) return false;
    identity.insert("hostName", endpoint.left(split));
    identity.insert("port", endpoint.mid(split + 1));
    identity.insert("client_ip", iface.value(QStringLiteral("Address")).section(QLatin1Char('/'), 0, 0));
    identity.insert("client_pub_key", binding.peerPublicKey);
    identity.insert("server_pub_key", binding.serverPublicKey);
    if (!peer.value(QStringLiteral("PresharedKey")).isEmpty()) identity.insert("psk_key", peer.value(QStringLiteral("PresharedKey")));
    for (auto entry = iface.cbegin(); entry != iface.cend(); ++entry) {
        const QString name = nativeName(entry.key());
        if (amnezia::awgMigration::parameterKeys().contains(name)) identity.insert(name, entry.value());
    }
    binding.sourceFingerprint = amnezia::awgMigration::sourceFingerprint(identity);
    QByteArray credentials;
    if (!read(m_credentialsPath, credentials)) return false;
    const auto target = QJsonDocument::fromJson(credentials).object().value("clientLogs").toObject();
    if (target.value("token").toString().isEmpty()) return false;
    for (const auto &container : {QStringLiteral("amnezia-awg"), QStringLiteral("amnezia-awg2")}) {
        if (hash((container + QLatin1Char('\t') + binding.peerPublicKey).toUtf8()) == target.value("clientId").toString()) binding.containerId = container;
    }
    return !binding.containerId.isEmpty();
}

bool AwgMigrationManager::exchange(const QString &interfaceName, const QString &address, int port,
                                 const QString &path, const QJsonObject &body, const QJsonObject &headers,
                                 QJsonObject &response) const
{
    response = {};
#ifdef Q_OS_LINUX
    const QHostAddress destination(address);
    const QByteArray device = interfaceName.toLatin1();
    if (destination.protocol() != QAbstractSocket::IPv4Protocol || port < 1 || port > 65535
        || !QRegularExpression(QStringLiteral("^[a-zA-Z0-9_.-]{1,15}$")).match(interfaceName).hasMatch()
        || !path.startsWith(QStringLiteral("/migration/v1/"))) return false;
    const int socket = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (socket < 0) return false;
    auto close = [&]() { ::close(socket); };
    if (::setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, device.constData(), device.size() + 1) != 0) { close(); return false; }
    sockaddr_in target {};
    target.sin_family = AF_INET;
    target.sin_port = htons(static_cast<unsigned short>(port));
    target.sin_addr.s_addr = htonl(destination.toIPv4Address());
    const int connection = ::connect(socket, reinterpret_cast<sockaddr *>(&target), sizeof(target));
    if (connection != 0 && errno != EINPROGRESS) { close(); return false; }
    QElapsedTimer deadline;
    deadline.start();
    auto wait = [&](short events) {
        pollfd descriptor { socket, events, 0 };
        const int remaining = 5000 - static_cast<int>(deadline.elapsed());
        return remaining > 0 && ::poll(&descriptor, 1, remaining) > 0 && descriptor.revents & events;
    };
    if (!wait(POLLOUT)) { close(); return false; }
    int failure = 0;
    socklen_t failureLength = sizeof(failure);
    if (::getsockopt(socket, SOL_SOCKET, SO_ERROR, &failure, &failureLength) != 0 || failure != 0) { close(); return false; }
    const QByteArray data = QJsonDocument(body).toJson(QJsonDocument::Compact);
    QByteArray request = "POST " + path.toLatin1() + " HTTP/1.1\r\nHost: " + address.toLatin1()
        + "\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: " + QByteArray::number(data.size()) + "\r\n";
    for (auto item = headers.begin(); item != headers.end(); ++item) {
        const QByteArray value = item.value().toString().toUtf8();
        if (value.contains('\r') || value.contains('\n') || value.size() > 4096) { close(); return false; }
        request += item.key().toLatin1() + ": " + value + "\r\n";
    }
    request += "\r\n" + data;
    qsizetype sent = 0;
    while (sent < request.size()) {
        if (!wait(POLLOUT)) { close(); return false; }
        const auto count = ::send(socket, request.constData() + sent, request.size() - sent, MSG_NOSIGNAL);
        if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (count <= 0) { close(); return false; }
        sent += count;
    }
    QByteArray reply;
    while (deadline.elapsed() < 5000) {
        if (!wait(POLLIN)) { close(); return false; }
        char buffer[4096];
        const auto count = ::recv(socket, buffer, sizeof(buffer), 0);
        if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (count < 0) { close(); return false; }
        if (count == 0) break;
        reply.append(buffer, count);
        if (reply.size() > amnezia::awgMigration::MaximumDocumentBytes + 8192) { close(); return false; }
        const int separator = reply.indexOf("\r\n\r\n");
        if (separator >= 0) {
            const auto match = QRegularExpression(QStringLiteral("(?im)^content-length: ([0-9]+)\\r?$")).match(QString::fromLatin1(reply.left(separator)));
            if (match.hasMatch() && reply.size() >= separator + 4 + match.captured(1).toInt()) break;
        }
    }
    close();
    const int separator = reply.indexOf("\r\n\r\n");
    if (separator < 0 || (!reply.startsWith("HTTP/1.1 200 ") && !reply.startsWith("HTTP/1.0 200 "))) return false;
    const QByteArray header = reply.left(separator).toLower();
    if (header.contains("transfer-encoding:") || header.contains("location:")) return false;
    const auto match = QRegularExpression(QStringLiteral("(?im)^content-length: ([0-9]+)\\r?$")).match(QString::fromLatin1(header));
    if (!match.hasMatch() || reply.size() - separator - 4 != match.captured(1).toInt()) return false;
    QJsonParseError parse;
    const auto document = QJsonDocument::fromJson(reply.mid(separator + 4), &parse);
    if (parse.error != QJsonParseError::NoError || !document.isObject()) return false;
    response = document.object();
    return true;
#else
    Q_UNUSED(interfaceName); Q_UNUSED(address); Q_UNUSED(port); Q_UNUSED(path); Q_UNUSED(body); Q_UNUSED(headers);
    return false;
#endif
}

QJsonObject AwgMigrationManager::enrollmentRequest(const amnezia::awgMigration::Binding &binding)
{
    return {{"schema", amnezia::awgMigration::Schema}, {"peerPublicKey", binding.peerPublicKey},
            {"sourceFingerprint", binding.sourceFingerprint}, {"nonce", binding.nonce}};
}
bool AwgMigrationManager::retireStaged(const Profile &profile, QJsonObject &journal)
{
    if (journal.value("phase").toString() != QStringLiteral("staged")) return true;
    const auto offer = journal.value("offer").toObject();
    if (!journal.contains("stagedGeneration")) journal.insert("stagedGeneration", offer.value("generation"));
    if (!journal.contains("stagedTargetHash")) journal.insert("stagedTargetHash", amnezia::awgMigration::digest(offer.value("target").toObject()));
    for (const auto &name : {"offer", "envelope", "grant", "grantExpiresAt", "bindingNonce", "candidatePath", "candidateHash"}) journal.remove(name);
    journal.insert("phase", "expired");
    return writeState(profile, journal);
}
bool AwgMigrationManager::validateRefreshedOffer(const QJsonObject &offer, const QJsonObject &previous,
                                               const amnezia::awgMigration::Binding &binding, qint64 now)
{
    auto next = binding;
    const qint64 staged = previous.value("stagedGeneration").toVariant().toLongLong();
    next.highestGeneration = qMax(next.highestGeneration, staged - 1);
    if (!amnezia::awgMigration::validateOffer(offer, next, now)) return false;
    return offer.value("generation").toVariant().toLongLong() != staged
        || amnezia::awgMigration::digest(offer.value("target").toObject()) == previous.value("stagedTargetHash").toString();
}
bool AwgMigrationManager::enroll(const Profile &profile, const QString &interfaceName, VpnBackend *backend)
{
    if (state(profile).value("phase").toString() == QStringLiteral("committed")) return backend && acknowledge(profile, *backend);
    QByteArray sourceBytes, credentials;
    QJsonObject identity;
    amnezia::awgMigration::Binding binding;
    if (!source(profile, sourceBytes, identity, binding) || !read(m_credentialsPath, credentials)) return false;
    auto previous = state(profile);
    if (previous.value("phase").toString() == QStringLiteral("staged")) {
        QString path, sha;
        if (candidate(profile, path, sha)) return true;
        previous = state(profile);
        if (previous.value("phase").toString() == QStringLiteral("staged") && !retireStaged(profile, previous)) return false;
    }
    binding.highestGeneration = previous.value("highestGeneration").toVariant().toLongLong();
    binding.nonce = QUuid::createUuid().toString(QUuid::Id128);
    const auto logs = QJsonDocument::fromJson(credentials).object().value("clientLogs").toObject();
    QJsonObject headers { {"X-Amnezia-Client-Id", logs.value("clientId")}, {"X-Amnezia-Log-Token", logs.value("token")} };
    const QJsonObject request = enrollmentRequest(binding);
    QJsonObject bootstrap;
    if (!exchange(interfaceName, QString::fromLatin1(Listener), Port, QStringLiteral("/migration/v1/bootstrap"), request, headers, bootstrap)) return false;
    const QByteArray key = amnezia::awgMigration::strictBase64(bootstrap.value("signingPublicKey").toString(), 32);
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    if (!amnezia::awgMigration::hasExactKeys(bootstrap, {"schema", "serverPublicKey", "peerPublicKey", "containerId", "sourceFingerprint", "nonce", "grant", "signingPublicKey", "generation", "expiresAt"})
        || bootstrap.value("schema").toInt(-1) != 1 || key.isEmpty()
        || bootstrap.value("serverPublicKey").toString() != binding.serverPublicKey
        || bootstrap.value("peerPublicKey").toString() != binding.peerPublicKey
        || bootstrap.value("containerId").toString() != binding.containerId
        || bootstrap.value("sourceFingerprint").toString() != binding.sourceFingerprint
        || bootstrap.value("nonce").toString() != binding.nonce
        || bootstrap.value("grant").toString().isEmpty() || bootstrap.value("grant").toString().size() > 4096
        || bootstrap.value("expiresAt").toDouble() <= now) return false;
    const QByteArray pinned = amnezia::awgMigration::strictBase64(previous.value("signingPublicKey").toString(), 32);
    if (!pinned.isEmpty() && pinned != key) return false;
    headers.insert("X-Amnezia-Migration-Grant", bootstrap.value("grant"));
    QJsonObject envelope, offer;
    if (!exchange(interfaceName, QString::fromLatin1(Listener), Port, QStringLiteral("/migration/v1/offer"), request, headers, envelope)
        || !amnezia::awgMigration::verifyEnvelope(envelope, key, offer)
        || !validateRefreshedOffer(offer, previous, binding, now)) return false;
    const auto target = offer.value("target").toObject();
    const QString endpoint = target.value("endpoint").toString();
    const auto endpointMatch = QRegularExpression(QStringLiteral("^([0-9.]+):([0-9]{1,5})$")).match(endpoint);
    const QHostAddress endpointAddress(endpointMatch.captured(1));
    bool validPort = false;
    const int endpointPort = endpointMatch.captured(2).toInt(&validPort);
    const QString address = target.value("clientAddress").toString();
    const auto challenge = offer.value("challenge").toObject();
    if (!endpointMatch.hasMatch() || endpointAddress.protocol() != QAbstractSocket::IPv4Protocol
        || !validPort || endpointPort < 1 || endpointPort > 65535
        || !QRegularExpression(QStringLiteral("^[0-9.]+/(?:[0-9]|[12][0-9]|3[0-2])$")).match(address).hasMatch()
        || QHostAddress(address.section(QLatin1Char('/'), 0, 0)).protocol() != QAbstractSocket::IPv4Protocol
        || challenge.value("address").toString() != QString::fromLatin1(Listener)
        || challenge.value("port").toInt() != Port) return false;
    // Only explicitly permitted interface parameters, endpoint and the assigned
    // address may change. Native hooks, peer keys, PSK, DNS and route directives
    // are copied from the original bytes.
    const auto parameters = target.value("parameters").toObject();
    QByteArray candidate;
    QString section;
    for (const QString &raw : QString::fromUtf8(sourceBytes).split(QLatin1Char('\n'))) {
        const QString line = raw.trimmed();
        if (line.startsWith(QLatin1Char('['))) {
            if (section == QStringLiteral("[Interface]")) {
                for (auto field = parameters.begin(); field != parameters.end(); ++field) candidate += nativeParameter(field.key()).toUtf8() + " = " + field.value().toString().toUtf8() + '\n';
            }
            section = line;
        }
        const int separator = line.indexOf(QLatin1Char('='));
        const QString name = separator > 0 ? line.left(separator).trimmed() : QString();
        if (section == QStringLiteral("[Interface]") && amnezia::awgMigration::parameterKeys().contains(nativeName(name))) continue;
        if (section == QStringLiteral("[Interface]") && name == QStringLiteral("Address")) candidate += "Address = " + address.toUtf8() + '\n';
        else if (section == QStringLiteral("[Peer]") && name == QStringLiteral("Endpoint")) candidate += "Endpoint = " + endpoint.toUtf8() + '\n';
        else candidate += raw.toUtf8() + '\n';
    }
    const QString root = profileRoot(profile);
    const QString interface = profile.interfaceName.isEmpty() ? QStringLiteral("amn0") : profile.interfaceName;
    if (!QRegularExpression(QStringLiteral("^[a-zA-Z0-9_.-]{1,15}$")).match(interface).hasMatch()
        || !secureDirectory(root)) return false;
    const QString path = QDir(root).filePath(interface + QStringLiteral(".conf"));
    QJsonObject journal { {"phase", "staged"}, {"sourceHash", hash(sourceBytes)}, {"sourcePath", profile.configPath},
        {"candidatePath", path}, {"candidateHash", hash(candidate)}, {"offer", offer}, {"envelope", envelope},
        {"signingPublicKey", bootstrap.value("signingPublicKey")}, {"grant", bootstrap.value("grant")},
        {"highestGeneration", previous.value("highestGeneration").toDouble(0)}, {"bindingNonce", binding.nonce},
        {"stagedGeneration", offer.value("generation")}, {"stagedTargetHash", amnezia::awgMigration::digest(target)},
        {"grantExpiresAt", bootstrap.value("expiresAt")} };
    // Backup and candidate exist before the journal makes the attempt selectable.
    if (!save(QDir(root).filePath(QStringLiteral("legacy.conf")), sourceBytes) || !save(path, candidate)
        || !writeState(profile, journal)) return false;
    m_lastState = QStringLiteral("staged");
    return true;
}
bool AwgMigrationManager::candidate(const Profile &profile, QString &path, QString &sourceHash)
{
    if (profile.protocol != QStringLiteral("amneziawg")) return false;
    auto journal = state(profile);
    const QString phase = journal.value("phase").toString();
    if (phase != QStringLiteral("staged") && phase != QStringLiteral("committed")) return false;
    QByteArray original, candidateBytes;
    if (!read(profile.configPath, original) || hash(original) != journal.value("sourceHash").toString()) {
        if (phase == QStringLiteral("staged")) retireStaged(profile, journal);
        return false;
    }
    path = journal.value("candidatePath").toString();
    if (QFileInfo(path).absolutePath() != profileRoot(profile) || !read(path, candidateBytes)
        || hash(candidateBytes) != journal.value("candidateHash").toString()) return false;
    QJsonObject offer;
    if (!amnezia::awgMigration::verifyEnvelope(journal.value("envelope").toObject(),
        amnezia::awgMigration::strictBase64(journal.value("signingPublicKey").toString(), 32), offer)
        || offer != journal.value("offer").toObject()) return false;
    if (phase == QStringLiteral("staged") && offer.value("expiresAt").toDouble() <= QDateTime::currentSecsSinceEpoch()) {
        retireStaged(profile, journal);
        return false;
    }
    sourceHash = journal.value("sourceHash").toString();
    return true;
}
bool AwgMigrationManager::begin(const Profile &profile) {
    auto journal = state(profile);
    journal.insert("previousPhase", journal.value("phase"));
    journal.insert("highestGeneration", qMax(journal.value("highestGeneration").toDouble(0),
                                             journal.value("offer").toObject().value("generation").toDouble(0)));
    journal.insert("phase", "trying");
    return writeState(profile, journal);
}
bool AwgMigrationManager::verify(const Profile &profile, VpnBackend &backend, qint64 startedAt) {
    auto journal = state(profile);
    // A committed profile already has a signed traffic receipt. The short
    // enrollment grant must not become the lifetime of the VPN profile.
    if (journal.value("previousPhase").toString() == QStringLiteral("committed"))
        return backend.migrationParametersApplied([&]() {
            QMap<QString, QString> values;
            const auto fields = journal.value("offer").toObject().value("target").toObject().value("parameters").toObject();
            for (auto field = fields.begin(); field != fields.end(); ++field) values.insert(nativeParameter(field.key()), field.value().toString());
            return values;
        }());
    const auto offer = journal.value("offer").toObject();
    const auto parameters = offer.value("target").toObject().value("parameters").toObject();
    QMap<QString, QString> native;
    for (auto field = parameters.begin(); field != parameters.end(); ++field) native.insert(nativeParameter(field.key()), field.value().toString());
    if (!backend.migrationParametersApplied(native)) { m_lastState = QStringLiteral("backend_unsupported"); return false; }
    const auto challenge = offer.value("challenge").toObject();
    QJsonObject request { {"schema", 1}, {"grant", journal.value("grant")}, {"generation", offer.value("generation")},
        {"peerPublicKey", offer.value("peerPublicKey")}, {"nonce", challenge.value("nonce")} };
    QJsonObject envelope, receipt;
    if (!exchange(backend.activeInterface(), challenge.value("address").toString(), challenge.value("port").toInt(),
        QStringLiteral("/migration/v1/challenge"), request, {{"X-Amnezia-Migration-Grant", journal.value("grant")}}, envelope)
        || !amnezia::awgMigration::verifyEnvelope(envelope,
            amnezia::awgMigration::strictBase64(journal.value("signingPublicKey").toString(), 32), receipt)
        || !amnezia::awgMigration::hasExactKeys(receipt, {"schema", "serverPublicKey", "peerPublicKey", "containerId", "generation", "nonce", "targetAddress", "expiresAt"})
        || receipt.value("schema").toInt() != 1
        || receipt.value("serverPublicKey") != offer.value("serverPublicKey")
        || receipt.value("peerPublicKey") != offer.value("peerPublicKey")
        || receipt.value("containerId") != offer.value("containerId")
        || receipt.value("generation") != offer.value("generation")
        || receipt.value("nonce") != challenge.value("nonce")
        || receipt.value("targetAddress").toString() != offer.value("target").toObject().value("clientAddress").toString().section(QLatin1Char('/'), 0, 0)
        || receipt.value("expiresAt").toDouble() <= QDateTime::currentSecsSinceEpoch()
        || !backend.migrationHandshakeObserved(offer.value("serverPublicKey").toString(), startedAt)) return false;
    journal.insert("challengeReceipt", envelope);
    return writeState(profile, journal);
}
bool AwgMigrationManager::commit(const Profile &profile) {
    auto journal = state(profile);
    QByteArray original;
    if (!read(profile.configPath, original) || hash(original) != journal.value("sourceHash").toString()) return false;
    journal.insert("phase", "committed");
    if (journal.value("previousPhase").toString() != QStringLiteral("committed")) journal.insert("ackPending", true);
    m_lastState = QStringLiteral("committed");
    return writeState(profile, journal);
}
bool AwgMigrationManager::abandon(const Profile &profile) {
    auto journal = state(profile);
    journal.insert("phase", "rolled_back");
    m_lastState = QStringLiteral("rolled_back");
    return writeState(profile, journal);
}
bool AwgMigrationManager::validateRenewal(const QJsonObject &renewal, const QJsonObject &journal,
                                        const QString &nonce, qint64 now)
{
    const auto offer = journal.value("offer").toObject();
    if (!amnezia::awgMigration::hasExactKeys(renewal, {"schema", "serverPublicKey", "peerPublicKey", "containerId", "generation", "nonce", "grant", "sourceFingerprint", "targetHash", "expiresAt"})
        || renewal.value("schema").toInt(-1) != 1 || renewal.value("nonce").toString() != nonce
        || renewal.value("expiresAt").toDouble(-1) <= now
        || renewal.value("expiresAt").toDouble(-1) > now + 86400 + 5
        || renewal.value("grant").toString().isEmpty() || renewal.value("grant").toString().size() > 4096
        || renewal.value("targetHash").toString() != amnezia::awgMigration::digest(offer.value("target").toObject())) return false;
    for (const auto &field : {"serverPublicKey", "peerPublicKey", "containerId", "generation", "sourceFingerprint"})
        if (renewal.value(field) != offer.value(field)) return false;
    return true;
}
bool AwgMigrationManager::acknowledge(const Profile &profile, VpnBackend &backend) {
    auto journal = state(profile);
    if (journal.value("phase").toString() != QStringLiteral("committed")) return false;
    if (!journal.value("ackPending").toBool()) return true;
    const auto offer = journal.value("offer").toObject();
    QMap<QString, QString> parameters;
    const auto fields = offer.value("target").toObject().value("parameters").toObject();
    for (auto field = fields.begin(); field != fields.end(); ++field) parameters.insert(nativeParameter(field.key()), field.value().toString());
    // A legacy connection must never send or confirm the committed candidate ACK.
    if (!backend.migrationParametersApplied(parameters)) return false;
    const QString interfaceName = backend.activeInterface();
    QJsonObject response;
    const auto sendAck = [&]() {
        const QJsonObject request { {"schema", 1}, {"grant", journal.value("grant")}, {"generation", offer.value("generation")},
            {"peerPublicKey", offer.value("peerPublicKey")}, {"challengeReceipt", journal.value("challengeReceipt")} };
        return exchange(interfaceName, QString::fromLatin1(Listener), Port, QStringLiteral("/migration/v1/ack"), request,
            {{"X-Amnezia-Migration-Grant", journal.value("grant")}}, response)
            && response.value("ok").isBool() && response.value("ok").toBool()
            && response.value("acknowledged").isBool() && response.value("acknowledged").toBool();
    };
    const qint64 checkedAt = QDateTime::currentSecsSinceEpoch();
    const bool expiredGrant = journal.value("grantExpiresAt").toDouble(0) <= checkedAt;
    if (!expiredGrant && !sendAck()) return false;
    if (expiredGrant) {
        const qint64 now = QDateTime::currentSecsSinceEpoch();
        if (!backend.migrationHandshakeObserved(offer.value("serverPublicKey").toString(), now - 120)) return false;
        QByteArray credentialBytes;
        if (!read(m_credentialsPath, credentialBytes)) return false;
        const auto logs = QJsonDocument::fromJson(credentialBytes).object().value("clientLogs").toObject();
        const QString expectedClient = hash((offer.value("containerId").toString() + QLatin1Char('\t') + offer.value("peerPublicKey").toString()).toUtf8());
        if (logs.value("clientId").toString() != expectedClient || logs.value("token").toString().isEmpty()) return false;
        const QString nonce = QUuid::createUuid().toString(QUuid::Id128);
        const QJsonObject request {{"schema", 1}, {"grant", journal.value("grant")},
            {"peerPublicKey", offer.value("peerPublicKey")}, {"generation", offer.value("generation")},
            {"nonce", nonce}, {"challengeReceipt", journal.value("challengeReceipt")}};
        QJsonObject envelope, renewal;
        if (!exchange(interfaceName, QString::fromLatin1(Listener), Port, QStringLiteral("/migration/v1/renew"), request,
                {{"X-Amnezia-Client-Id", logs.value("clientId")}, {"X-Amnezia-Log-Token", logs.value("token")}}, envelope)
            || !amnezia::awgMigration::verifyEnvelope(envelope,
                amnezia::awgMigration::strictBase64(journal.value("signingPublicKey").toString(), 32), renewal)
            || !validateRenewal(renewal, journal, nonce, now)) return false;
        journal.insert("grant", renewal.value("grant"));
        journal.insert("grantExpiresAt", renewal.value("expiresAt"));
        journal.insert("renewalReceipt", envelope);
        // Save renewed authorization before network delivery. A crash resumes
        // the same committed generation, target and original proof receipt.
        if (!writeState(profile, journal) || !sendAck()) return false;
    }
    journal.insert("ackPending", false);
    return writeState(profile, journal);
}
QJsonObject AwgMigrationManager::status() const { return { {"state", m_lastState} }; }
}
