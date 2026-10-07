#include "embeddedAwgBackend.h"
#include "../common/awgMigration.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLocalSocket>
#include <QSaveFile>
#include <QElapsedTimer>
#include <QThread>
#include <QHostAddress>
#include <QRegularExpression>
#include <QProcessEnvironment>
#ifdef AMNEZIA_EMBEDDED_AWG3_SHA256
static void initializeEmbeddedAwgResources() { Q_INIT_RESOURCE(headless_awg3); }
#endif

namespace amnezia::headless {
namespace {
QString sha(const QByteArray &bytes) { return QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex()); }
bool privatePath(const QString &path, bool directory) {
    const QFileInfo info(path);
    return !info.isSymLink() && info.canonicalFilePath() == info.absoluteFilePath()
        && (directory ? info.isDir() : info.isFile()) && info.ownerId() == 0
        && !(info.permissions() & (QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ExeGroup
                                   | QFileDevice::ReadOther | QFileDevice::WriteOther | QFileDevice::ExeOther));
}
}
EmbeddedAwgBackend::EmbeddedAwgBackend(std::shared_ptr<CommandRunner> runner) : m_runner(std::move(runner)) {}
bool EmbeddedAwgBackend::available() {
#ifdef AMNEZIA_EMBEDDED_AWG3_SHA256
    initializeEmbeddedAwgResources();
    return QFile::exists(QStringLiteral(":/amnezia/awg3/amneziawg-go"));
#else
    return false;
#endif
}
QString EmbeddedAwgBackend::uapiName(const QString &key) {
    const QMap<QString, QString> names {
        {"Hpk", "header_protection_key"}, {"HeaderProtectionKey", "header_protection_key"},
        {"Cpa", "content_padding_addition"}, {"ContentPaddingAddition", "content_padding_addition"},
        {"RekeyAfterTime", "rekey_after_time"}, {"RekeyTimeout", "rekey_timeout"},
        {"RejectAfterTime", "reject_after_time"}, {"KeepaliveTimeout", "keepalive_timeout"},
        {"MaxHandshakeAttempts", "max_handshake_attempts"}, {"RandomTrailers", "random_trailers"}, {"DisableCookies", "disable_cookies"},
        {"PrivateKey", "private_key"}, {"ListenPort", "listen_port"}, {"FwMark", "fwmark"},
        {"PublicKey", "public_key"}, {"PresharedKey", "preshared_key"}, {"Endpoint", "endpoint"},
        {"PersistentKeepalive", "persistent_keepalive_interval"}
    };
    if (names.contains(key)) return names.value(key);
    const auto allowed = amnezia::awgMigration::parameterKeys();
    return allowed.contains(key) ? key.toLower() : QString();
}
bool EmbeddedAwgBackend::exchange(const QByteArray &request, QByteArray &reply) const {
    reply.clear();
    const QFileInfo socketInfo(m_socketPath);
    if (!socketInfo.exists() || socketInfo.isSymLink() || socketInfo.ownerId() != 0
        || socketInfo.permissions() & (QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ExeGroup
                                      | QFileDevice::ReadOther | QFileDevice::WriteOther | QFileDevice::ExeOther)) return false;
    QLocalSocket socket;
    socket.connectToServer(m_socketPath);
    QElapsedTimer timer;
    timer.start();
    if (!socket.waitForConnected(1000) || socket.write(request) != request.size()) return false;
    while (socket.bytesToWrite() > 0) {
        if (!socket.waitForBytesWritten(1000) || timer.elapsed() > 5000) return false;
    }
    while (timer.elapsed() < 5000) {
        reply += socket.readAll();
        if (reply.size() > 1024 * 1024) return false;
        if (reply.endsWith("\n\n")) return reply.endsWith("errno=0\n\n");
        if (!socket.waitForReadyRead(1000) && socket.state() == QLocalSocket::UnconnectedState) return false;
    }
    return false;
}
BackendResult EmbeddedAwgBackend::start(const Profile &profile, const QString &configPath, const QString &cacheRoot) {
    auto fail = [](const char *reason) { return BackendResult {false, QStringLiteral("embedded_awg3_failed"), QString::fromLatin1(reason)}; };
    if (!available() || !privatePath(cacheRoot, true) || !privatePath(configPath, false)) return fail("embedded backend or private configuration is unavailable");
    m_interface = profile.interfaceName.isEmpty() ? QStringLiteral("amn0") : profile.interfaceName;
    if (!QRegularExpression(QStringLiteral("^[a-zA-Z0-9_.-]{1,15}$")).match(m_interface).hasMatch()) return fail("invalid native interface");
    const QString ip = m_runner->resolveExecutable({QStringLiteral("ip"), QStringLiteral("/usr/sbin/ip"), QStringLiteral("/sbin/ip")});
    if (ip.isEmpty() || m_runner->runCaptured(ip, {"link", "show", "dev", m_interface}).ok) return fail("native interface is already present or unavailable");
    QFile configuration(configPath);
    if (!configuration.open(QIODevice::ReadOnly) || configuration.size() > 1024 * 1024) return fail("candidate configuration is unreadable");
    QByteArray request("set=1\nreplace_peers=true\n");
    QStringList addresses, dns;
    QString mtu = QStringLiteral("1420");
    QString section;
    int peers = 0;
    QSet<QString> seen;
    for (const QString &raw : QString::fromUtf8(configuration.readAll()).split(QLatin1Char('\n'))) {
        const QString line = raw.trimmed();
        if (line.isEmpty() || line.startsWith(QLatin1Char('#'))) continue;
        if (line.startsWith(QLatin1Char('['))) {
            section = line;
            if (section == QStringLiteral("[Peer]")) ++peers;
            if (section != QStringLiteral("[Interface]") && section != QStringLiteral("[Peer]")) return fail("unknown candidate section");
            continue;
        }
        const int separator = line.indexOf(QLatin1Char('='));
        if (separator < 1) return fail("invalid candidate field");
        const QString name = line.left(separator).trimmed();
        QString value = line.mid(separator + 1).trimmed();
        if (seen.contains(section + name)) return fail("duplicate candidate field");
        seen.insert(section + name);
        if (section == QStringLiteral("[Interface]") && name == QStringLiteral("Address")) { addresses = value.split(QLatin1Char(',')); continue; }
        if (section == QStringLiteral("[Interface]") && name == QStringLiteral("DNS")) { dns = value.split(QLatin1Char(',')); continue; }
        if (section == QStringLiteral("[Interface]") && name == QStringLiteral("MTU")) { mtu = value; continue; }
        if (section == QStringLiteral("[Interface]") && name == QStringLiteral("Table")) {
            if (value != QStringLiteral("off") && value != QStringLiteral("auto")) return fail("custom native route tables require operator migration");
            continue;
        }
        if (section == QStringLiteral("[Peer]") && name == QStringLiteral("AllowedIPs")) {
            for (const QString &prefix : value.split(QLatin1Char(','))) {
                const auto network = QHostAddress::parseSubnet(prefix.trimmed());
                if (network.first.isNull() || network.second < 0) return fail("invalid candidate allowed IP");
                request += "allowed_ip=" + prefix.trimmed().toLatin1() + '\n';
            }
            continue;
        }
        const QString nameUapi = uapiName(name);
        if (nameUapi.isEmpty()) return fail("candidate hooks or unsupported native fields require operator migration");
        if (nameUapi == QStringLiteral("private_key") || nameUapi == QStringLiteral("public_key")
            || nameUapi == QStringLiteral("preshared_key") || nameUapi == QStringLiteral("header_protection_key")) {
            const auto key = amnezia::awgMigration::strictBase64(value, 32);
            if (key.isEmpty()) return fail("invalid candidate key encoding");
            if (nameUapi == QStringLiteral("public_key")) m_peer = value;
            value = QString::fromLatin1(key.toHex());
        }
        if (nameUapi == QStringLiteral("fwmark")) {
            bool valid = false;
            const quint32 mark = value.toUInt(&valid, 0);
            if (!valid) return fail("invalid candidate fwmark");
            value = QString::number(mark);
        }
        request += nameUapi.toLatin1() + '=' + value.toUtf8() + '\n';
    }
    request += '\n';
    bool mtuValid = false;
    const int mtuNumber = mtu.toInt(&mtuValid);
    if (peers != 1 || m_peer.isEmpty() || addresses.isEmpty() || !mtuValid || mtuNumber < 576 || mtuNumber > 65535) return fail("candidate topology is unsupported");
    for (QString &address : addresses) {
        address = address.trimmed();
        const auto prefix = QHostAddress::parseSubnet(address);
        if (prefix.first.isNull() || prefix.second < 0) return fail("invalid candidate address");
    }
    for (QString &address : dns) { address = address.trimmed(); if (QHostAddress(address).isNull()) return fail("native DNS must use literal addresses"); }
    const QString runtime = QStringLiteral("/run/amnezia/awg3");
    if (!QFileInfo(runtime).exists()) {
        if (!QDir().mkdir(runtime) || !QFile::setPermissions(runtime, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner)) return fail("private UAPI directory is unavailable");
    }
    if (!privatePath(runtime, true)) return fail("private UAPI directory is unsafe");
    m_socketPath = QDir(runtime).filePath(m_interface + QStringLiteral(".sock"));
    if (QFileInfo(m_socketPath).exists() || QFileInfo(m_socketPath).isSymLink()) return fail("UAPI socket already exists; recovery is required");
    QFile resource(QStringLiteral(":/amnezia/awg3/amneziawg-go"));
    if (!resource.open(QIODevice::ReadOnly)) return fail("embedded AWG3 resource is unreadable");
    const QByteArray bytes = resource.readAll();
#ifdef AMNEZIA_EMBEDDED_AWG3_SHA256
    if (sha(bytes) != QString::fromLatin1(AMNEZIA_EMBEDDED_AWG3_SHA256)) return fail("embedded AWG3 resource hash mismatch");
#else
    return fail("embedded AWG3 resource is not built");
#endif
    const QString binary = QDir(cacheRoot).filePath(QStringLiteral("amneziawg-go"));
    const QFileInfo binaryInfo(binary);
    if (binaryInfo.exists() && !privatePath(binary, false)) return fail("private backend executable is unsafe");
    QSaveFile extracted(binary);
    extracted.setDirectWriteFallback(false);
    if (!extracted.open(QIODevice::WriteOnly) || !extracted.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner)
        || extracted.write(bytes) != bytes.size() || !extracted.commit()) return fail("private backend extraction failed");
    QFile installed(binary);
    if (!installed.open(QIODevice::ReadOnly) || sha(installed.readAll()) != sha(bytes)) return fail("private backend bytes changed");
    QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
    for (const auto &name : {"NOTIFY_SOCKET", "WATCHDOG_PID", "WATCHDOG_USEC", "WG_TUN_FD", "WG_UAPI_FD", "WG_TUN_NAME_FILE"}) environment.remove(QString::fromLatin1(name));
    environment.insert(QStringLiteral("WG_PROCESS_FOREGROUND"), QStringLiteral("1"));
    environment.insert(QStringLiteral("LOG_LEVEL"), QStringLiteral("silent"));
    m_process.setProcessEnvironment(environment);
    m_process.setStandardOutputFile(QProcess::nullDevice());
    m_process.setStandardErrorFile(QProcess::nullDevice());
    m_process.start(binary, {QStringLiteral("-f"), m_interface});
    if (!m_process.waitForStarted(3000)) return fail("private backend did not start");
    QByteArray reply;
    QElapsedTimer ready;
    ready.start();
    bool applied = false;
    while (ready.elapsed() < 5000 && alive()) {
        if (exchange(request, reply)) { applied = true; break; }
        QThread::msleep(50);
    }
    if (!applied) return fail("private backend did not accept the candidate configuration");
    for (const QString &address : addresses) {
        if (!m_runner->run(ip, {"address", "add", address, "dev", m_interface}).ok) return fail("candidate address setup failed");
    }
    if (!m_runner->run(ip, {"link", "set", "dev", m_interface, "mtu", mtu, "up"}).ok) return fail("candidate native interface setup failed");
    if (!dns.isEmpty() && profile.dnsServers.isEmpty()) {
        const QString resolvectl = m_runner->resolveExecutable({QStringLiteral("resolvectl")});
        if (resolvectl.isEmpty() || !m_runner->run(resolvectl, QStringList {"dns", m_interface} + dns).ok) return fail("candidate native DNS setup failed");
        m_dnsOwned = true;
        if (!m_runner->run(resolvectl, {"domain", m_interface, "~."}).ok) return fail("candidate native DNS domains failed");
    }
    return {true, {}, {}};
}
bool EmbeddedAwgBackend::alive() const { return m_process.state() != QProcess::NotRunning; }
BackendResult EmbeddedAwgBackend::stop() {
    if (m_dnsOwned) {
        const QString resolvectl = m_runner->resolveExecutable({QStringLiteral("resolvectl")});
        if (resolvectl.isEmpty() || !m_runner->run(resolvectl, {"revert", m_interface}).ok)
            return {false, QStringLiteral("cleanup_failed"), QStringLiteral("private backend DNS cleanup failed")};
        m_dnsOwned = false;
    }
    if (alive()) {
        m_process.terminate();
        if (!m_process.waitForFinished(2000)) {
            m_process.kill();
            if (!m_process.waitForFinished(2000)) return {false, QStringLiteral("cleanup_failed"), QStringLiteral("private backend process did not stop")};
        }
    }
    const QString ip = m_runner->resolveExecutable({QStringLiteral("ip"), QStringLiteral("/usr/sbin/ip"), QStringLiteral("/sbin/ip")});
    if (ip.isEmpty() || (!m_interface.isEmpty() && m_runner->runCaptured(ip, {"link", "show", "dev", m_interface}).ok))
        return {false, QStringLiteral("cleanup_failed"), QStringLiteral("private native interface remains present")};
    return {true, {}, {}};
}
bool EmbeddedAwgBackend::snapshot(QMap<QString, QString> &device, QMap<QString, qint64> &handshakes) const {
    device.clear(); handshakes.clear();
    QByteArray reply;
    if (!alive() || !exchange("get=1\n\n", reply)) return false;
    QString peer;
    for (const QByteArray &line : reply.split('\n')) {
        const int split = line.indexOf('=');
        if (split < 1) continue;
        const QString name = QString::fromLatin1(line.left(split));
        const QString value = QString::fromLatin1(line.mid(split + 1));
        if (name == QStringLiteral("public_key")) peer = value;
        else if (name == QStringLiteral("last_handshake_time_sec")) handshakes.insert(peer, value.toLongLong());
        else if (peer.isEmpty()) device.insert(name, value);
    }
    return device.contains(QStringLiteral("header_protection_key"));
}
bool EmbeddedAwgBackend::configured() const {
    QMap<QString, QString> values; QMap<QString, qint64> handshakes;
    return snapshot(values, handshakes);
}
bool EmbeddedAwgBackend::handshake(const QString &peer, qint64 startedAt) const {
    QMap<QString, QString> values; QMap<QString, qint64> handshakes;
    if (!snapshot(values, handshakes)) return false;
    const auto key = amnezia::awgMigration::strictBase64(peer, 32);
    const qint64 value = handshakes.value(QString::fromLatin1(key.toHex()));
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    return !key.isEmpty() && value >= startedAt && value > 0 && value <= now + 5 && now - value <= 180;
}
bool EmbeddedAwgBackend::parametersApplied(const QMap<QString, QString> &parameters) const {
    QMap<QString, QString> values; QMap<QString, qint64> handshakes;
    if (!snapshot(values, handshakes)) return false;
    for (auto parameter = parameters.cbegin(); parameter != parameters.cend(); ++parameter) {
        const QString name = uapiName(parameter.key());
        QString expected = parameter.value();
        if (name == QStringLiteral("header_protection_key")) expected = QString::fromLatin1(amnezia::awgMigration::strictBase64(expected, 32).toHex());
        if (name == QStringLiteral("random_trailers") || name == QStringLiteral("disable_cookies")) expected = (expected == QStringLiteral("true") || expected == QStringLiteral("1")) ? QStringLiteral("1") : QStringLiteral("0");
        if (name.isEmpty()) return false;
        // Upstream get omits zero-valued numeric fields; the mandatory header
        // protection key and padding are always checked as explicit values.
        if (!values.contains(name) && expected == QStringLiteral("0")
            && name != QStringLiteral("header_protection_key")) continue;
        if (!values.contains(name) || values.value(name) != expected) return false;
    }
    return true;
}
}
