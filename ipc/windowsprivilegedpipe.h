#ifndef WINDOWSPRIVILEGEDPIPE_H
#define WINDOWSPRIVILEGEDPIPE_H

#include <QLocalServer>
#include <QLocalSocket>
#include <QObject>
#include <QString>

#ifdef Q_OS_WIN

#include <memory>

namespace amnezia::ipc {

// QLocalServer's Windows backend creates remotely reachable named pipes and
// grants FILE_ALL_ACCESS to every allowed client. Privileged endpoints need a
// native acceptor so remote SMB clients are rejected and connector-opened
// client handles never receive FILE_CREATE_PIPE_INSTANCE.
class WindowsPrivilegedPipeServer final : public QObject
{
    Q_OBJECT

public:
    explicit WindowsPrivilegedPipeServer(QObject *parent = nullptr);
    ~WindowsPrivilegedPipeServer() override;

    [[nodiscard]] bool listen(const QString &name);
    void close();

    [[nodiscard]] bool hasPendingConnections() const;
    [[nodiscard]] bool isListening() const;
    [[nodiscard]] QLocalSocket *nextPendingConnection();
    [[nodiscard]] QString errorString() const;
    [[nodiscard]] QString serverName() const;
    [[nodiscard]] QString fullServerName() const;

    void setMaxPendingConnections(int maximum);
    [[nodiscard]] int maxPendingConnections() const;

    // One overlapped accept remains outstanding while prior accepted sockets
    // stay alive. The pipe owner alone receives the duplex/create rights needed
    // for additional instances; non-owner Interactive clients retain data-only
    // access. A same-owner process shares the owner's availability capability,
    // while peer PID/executable authentication remains the trust boundary.
    void setListenBacklogSize(int size);
    [[nodiscard]] int listenBacklogSize() const;

    // Capability endpoints disable automatic re-arming until a rejected peer
    // is followed by an explicit resumeAccepting().
    void setAutoRearm(bool enabled);
    [[nodiscard]] bool autoRearm() const;
    [[nodiscard]] bool resumeAccepting();

signals:
    void newConnection();

private:
    class Private;
    std::unique_ptr<Private> d;
};

using PrivilegedLocalServer = WindowsPrivilegedPipeServer;

// Open only a local NPFS path with the exact data/synchronization rights that
// QLocalSocket needs. In particular, never request GENERIC_WRITE because its
// FILE_APPEND_DATA bit is FILE_CREATE_PIPE_INSTANCE for named pipes.
[[nodiscard]] bool connectWindowsPrivilegedPipe(QLocalSocket *socket, const QString &name,
                                                int timeoutMilliseconds,
                                                QString *errorMessage = nullptr);

[[nodiscard]] bool isWindowsPrivilegedPipeSocket(const QLocalSocket *socket);

} // namespace amnezia::ipc

#else

namespace amnezia::ipc {
using PrivilegedLocalServer = QLocalServer;
} // namespace amnezia::ipc

#endif

#endif // WINDOWSPRIVILEGEDPIPE_H
