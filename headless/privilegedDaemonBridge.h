#ifndef AMNEZIA_HEADLESS_PRIVILEGED_DAEMON_BRIDGE_H
#define AMNEZIA_HEADLESS_PRIVILEGED_DAEMON_BRIDGE_H

#include <QJsonObject>
#include <QString>

#include <memory>

class QLocalSocket;

namespace amnezia::headless
{

constexpr int PrivilegedDaemonProtocolVersion = 2;
constexpr qsizetype MaximumPrivilegedDaemonFrameSize = 1024 * 1024;

struct BridgeResult
{
    bool ok = false;
    QString code;
    QString message;
};

class PrivilegedPeerVerifier
{
public:
    virtual ~PrivilegedPeerVerifier() = default;
    virtual bool verify(QLocalSocket *socket, QString *error) const = 0;
};

class UnixPrivilegedPeerVerifier final : public PrivilegedPeerVerifier
{
public:
    bool verify(QLocalSocket *socket, QString *error) const override;
};

class PrivilegedDaemonBridge final
{
public:
    explicit PrivilegedDaemonBridge(
        QString socketPath,
        std::shared_ptr<PrivilegedPeerVerifier> peerVerifier = {},
        int timeoutMilliseconds = 5000);

    BridgeResult activate(const QJsonObject &configuration);
    BridgeResult deactivate();
    BridgeResult status(QJsonObject &result);
    BridgeResult logs(QString &result);

    BridgeResult lastError() const;
    QString socketPath() const;

private:
    BridgeResult failure(const QString &code, const QString &message);
    BridgeResult exchange(const QJsonObject &command,
                          const QString &expectedType,
                          QJsonObject &response);
    BridgeResult connectSocket(std::unique_ptr<QLocalSocket> &socket) const;
    BridgeResult readFrame(QLocalSocket *socket, QJsonObject &response) const;
    static QJsonObject versionedCommand(const QJsonObject &command);
    static bool isExpectedResponse(const QJsonObject &response,
                                   const QString &expectedType);

    QString m_socketPath;
    std::shared_ptr<PrivilegedPeerVerifier> m_peerVerifier;
    int m_timeoutMilliseconds = 5000;
    BridgeResult m_lastError;
};

} // namespace amnezia::headless

#endif // AMNEZIA_HEADLESS_PRIVILEGED_DAEMON_BRIDGE_H
