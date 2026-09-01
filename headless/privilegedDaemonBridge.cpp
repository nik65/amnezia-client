#include "privilegedDaemonBridge.h"

#include <QFileInfo>
#include <QJsonDocument>
#include <QLocalSocket>

#include <memory>

#if defined(Q_OS_LINUX)
#include <cerrno>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace amnezia::headless
{
namespace
{

void setError(QString *error, const QString &message)
{
    if (error) {
        *error = message;
    }
}

BridgeResult makeFailure(const QString &code, const QString &message)
{
    return { false, code, message };
}

} // namespace

bool UnixPrivilegedPeerVerifier::verify(QLocalSocket *socket, QString *error) const
{
    if (!socket || socket->state() != QLocalSocket::ConnectedState) {
        setError(error, QStringLiteral("privileged daemon socket is not connected"));
        return false;
    }

#if defined(Q_OS_LINUX)
    const qintptr descriptor = socket->socketDescriptor();
    if (descriptor < 0) {
        setError(error, QStringLiteral("invalid privileged daemon socket descriptor"));
        return false;
    }

    struct ucred peer {};
    socklen_t peerSize = sizeof(peer);
    if (::getsockopt(static_cast<int>(descriptor), SOL_SOCKET, SO_PEERCRED,
                     &peer, &peerSize) != 0) {
        setError(error, QStringLiteral("unable to query privileged daemon peer credentials"));
        return false;
    }
    if (peer.uid != 0 || peer.pid <= 0) {
        setError(error, QStringLiteral("privileged daemon peer is not root-owned"));
        return false;
    }

    const QString executablePath = QStringLiteral("/proc/%1/exe").arg(peer.pid);
    const QString resolvedPath = QFileInfo(executablePath).symLinkTarget();
    if (resolvedPath.isEmpty()) {
        setError(error, QStringLiteral("unable to resolve privileged daemon executable"));
        return false;
    }

    const QFileInfo executable(resolvedPath);
    if (!executable.isFile() || executable.ownerId() != 0
        || (executable.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther))) {
        setError(error, QStringLiteral("privileged daemon executable is not protected"));
        return false;
    }
    return true;
#else
    setError(error, QStringLiteral("privileged peer verification is unavailable on this platform"));
    return false;
#endif
}

PrivilegedDaemonBridge::PrivilegedDaemonBridge(
    QString socketPath,
    std::shared_ptr<PrivilegedPeerVerifier> peerVerifier,
    int timeoutMilliseconds)
    : m_socketPath(std::move(socketPath)),
      m_peerVerifier(peerVerifier ? std::move(peerVerifier)
                                  : std::make_shared<UnixPrivilegedPeerVerifier>()),
      m_timeoutMilliseconds(qBound(100, timeoutMilliseconds, 30'000))
{
}

BridgeResult PrivilegedDaemonBridge::activate(const QJsonObject &configuration)
{
    if (configuration.isEmpty()) {
        return failure(QStringLiteral("invalid_parameters"),
                       QStringLiteral("activate requires a non-empty configuration"));
    }

    QJsonObject command = configuration;
    command.insert(QStringLiteral("type"), QStringLiteral("activate"));
    QJsonObject response;
    const BridgeResult result = exchange(command, QStringLiteral("connected"), response);
    if (!result.ok) {
        return result;
    }
    return { true, {}, {} };
}

BridgeResult PrivilegedDaemonBridge::deactivate()
{
    QJsonObject response;
    const BridgeResult result = exchange(
        QJsonObject { { QStringLiteral("type"), QStringLiteral("deactivate") } },
        QStringLiteral("disconnected"), response);
    return result.ok ? BridgeResult { true, {}, {} } : result;
}

BridgeResult PrivilegedDaemonBridge::status(QJsonObject &result)
{
    QJsonObject response;
    const BridgeResult exchangeResult = exchange(
        QJsonObject { { QStringLiteral("type"), QStringLiteral("status") } },
        QStringLiteral("status"), response);
    if (!exchangeResult.ok) {
        return exchangeResult;
    }
    response.remove(QStringLiteral("protocolVersion"));
    result = response;
    return { true, {}, {} };
}

BridgeResult PrivilegedDaemonBridge::logs(QString &result)
{
    QJsonObject response;
    const BridgeResult exchangeResult = exchange(
        QJsonObject { { QStringLiteral("type"), QStringLiteral("logs") } },
        QStringLiteral("logs"), response);
    if (!exchangeResult.ok) {
        return exchangeResult;
    }
    result = response.value(QStringLiteral("logs")).toString();
    return { true, {}, {} };
}

BridgeResult PrivilegedDaemonBridge::lastError() const
{
    return m_lastError;
}

QString PrivilegedDaemonBridge::socketPath() const
{
    return m_socketPath;
}

BridgeResult PrivilegedDaemonBridge::failure(const QString &code, const QString &message)
{
    m_lastError = makeFailure(code, message);
    return m_lastError;
}

BridgeResult PrivilegedDaemonBridge::exchange(const QJsonObject &command,
                                              const QString &expectedType,
                                              QJsonObject &response)
{
    m_lastError = {};
    std::unique_ptr<QLocalSocket> socket;
    BridgeResult result = connectSocket(socket);
    if (!result.ok) {
        return result;
    }

    const QByteArray frame = QJsonDocument(versionedCommand(command))
                                 .toJson(QJsonDocument::Compact) + QByteArrayLiteral("\n");
    if (frame.size() > MaximumPrivilegedDaemonFrameSize) {
        return failure(QStringLiteral("frame_too_large"),
                       QStringLiteral("privileged daemon request frame is too large"));
    }
    if (socket->write(frame) != frame.size() || !socket->waitForBytesWritten(m_timeoutMilliseconds)) {
        return failure(QStringLiteral("write_failed"),
                       QStringLiteral("unable to write to privileged daemon"));
    }

    result = readFrame(socket.get(), response);
    if (!result.ok) {
        return result;
    }
    if (!isExpectedResponse(response, expectedType)) {
        const QString remoteType = response.value(QStringLiteral("type")).toString();
        if (remoteType == QStringLiteral("error")) {
            return failure(QStringLiteral("remote_error"),
                           response.value(QStringLiteral("message")).toString(
                               QStringLiteral("privileged daemon returned an error")));
        }
        return failure(QStringLiteral("protocol_error"),
                       QStringLiteral("unexpected privileged daemon response type: %1")
                           .arg(remoteType));
    }
    return { true, {}, {} };
}

BridgeResult PrivilegedDaemonBridge::connectSocket(std::unique_ptr<QLocalSocket> &socket) const
{
    if (m_socketPath.trimmed().isEmpty()) {
        return makeFailure(QStringLiteral("invalid_socket"),
                           QStringLiteral("privileged daemon socket path is empty"));
    }

    socket = std::make_unique<QLocalSocket>();
    socket->connectToServer(m_socketPath, QIODevice::ReadWrite);
    if (!socket->waitForConnected(m_timeoutMilliseconds)) {
        return makeFailure(QStringLiteral("connect_failed"),
                           QStringLiteral("unable to connect to privileged daemon: %1")
                               .arg(socket->errorString()));
    }

    QString verificationError;
    if (!m_peerVerifier->verify(socket.get(), &verificationError)) {
        socket->abort();
        return makeFailure(QStringLiteral("unauthorized_peer"),
                           verificationError.isEmpty()
                               ? QStringLiteral("privileged daemon peer verification failed")
                               : verificationError);
    }
    return { true, {}, {} };
}

BridgeResult PrivilegedDaemonBridge::readFrame(QLocalSocket *socket,
                                               QJsonObject &response) const
{
    QByteArray buffer;
    while (buffer.size() <= MaximumPrivilegedDaemonFrameSize) {
        buffer.append(socket->readAll());
        const qsizetype newline = buffer.indexOf('\n');
        if (newline >= 0) {
            if (newline + 1 > MaximumPrivilegedDaemonFrameSize) {
                return makeFailure(QStringLiteral("frame_too_large"),
                                   QStringLiteral("privileged daemon response frame is too large"));
            }
            const QJsonDocument document =
                QJsonDocument::fromJson(buffer.left(newline).trimmed());
            if (!document.isObject()) {
                return makeFailure(QStringLiteral("protocol_error"),
                                   QStringLiteral("privileged daemon response is not a JSON object"));
            }
            response = document.object();
            if (response.value(QStringLiteral("protocolVersion")).toInt(-1)
                != PrivilegedDaemonProtocolVersion) {
                return makeFailure(QStringLiteral("protocol_mismatch"),
                                   QStringLiteral("privileged daemon protocol version mismatch"));
            }
            return { true, {}, {} };
        }
        if (!socket->waitForReadyRead(m_timeoutMilliseconds)) {
            return makeFailure(QStringLiteral("read_failed"),
                               QStringLiteral("timed out waiting for privileged daemon response"));
        }
    }
    return makeFailure(QStringLiteral("frame_too_large"),
                       QStringLiteral("privileged daemon response frame is too large"));
}

QJsonObject PrivilegedDaemonBridge::versionedCommand(const QJsonObject &command)
{
    QJsonObject versioned = command;
    versioned.insert(QStringLiteral("protocolVersion"), PrivilegedDaemonProtocolVersion);
    return versioned;
}

bool PrivilegedDaemonBridge::isExpectedResponse(const QJsonObject &response,
                                                const QString &expectedType)
{
    return response.value(QStringLiteral("protocolVersion")).toInt(-1)
               == PrivilegedDaemonProtocolVersion
        && response.value(QStringLiteral("type")).toString() == expectedType;
}

} // namespace amnezia::headless
