#ifndef LOCALPEERAUTHENTICATION_H
#define LOCALPEERAUTHENTICATION_H

#include <QString>
#include <QtGlobal>

#include <limits>

class QLocalSocket;

namespace amnezia::ipc {

struct LocalPeerIdentity
{
    qint64 processId = -1;
    QString userIdentifier;
    QString logonIdentifier;
    QString executablePath;
    quint32 sessionId = (std::numeric_limits<quint32>::max)();

    [[nodiscard]] bool isValid() const
    {
        return processId > 0 && !userIdentifier.isEmpty() && !executablePath.isEmpty();
    }
};

// Resolve kernel-authenticated identity from an already accepted local socket.
// Failure is intentionally fail-closed; callers must not hand the socket to a
// protocol parser when this function returns false.
[[nodiscard]] bool queryLocalPeerIdentity(QLocalSocket *socket, LocalPeerIdentity &identity,
                                          QString *errorMessage = nullptr);
[[nodiscard]] bool queryLocalServerIdentity(QLocalSocket *socket, LocalPeerIdentity &identity,
                                            QString *errorMessage = nullptr);

[[nodiscard]] QString currentProcessUserIdentifier(QString *errorMessage = nullptr);
[[nodiscard]] QString canonicalExecutablePath(const QString &path);
[[nodiscard]] bool executablePathsMatch(const QString &actualPath, const QString &expectedPath);

// The privileged service accepts the unelevated GUI only when the kernel peer
// identity resolves to the packaged client executable and the install cannot
// be replaced by that peer. macOS additionally checks the running code against
// the expected executable's designated code-signing requirement.
[[nodiscard]] bool authorizePrivilegedClient(QLocalSocket *socket, const QString &expectedExecutablePath,
                                             LocalPeerIdentity *identity = nullptr,
                                             QString *errorMessage = nullptr);
[[nodiscard]] bool authorizePrivilegedServer(QLocalSocket *socket, const QString &expectedExecutablePath,
                                             const QString &windowsServiceName,
                                             LocalPeerIdentity *identity = nullptr,
                                             QString *errorMessage = nullptr);

[[nodiscard]] QString installedClientExecutablePath();
[[nodiscard]] QString installedServiceExecutablePath();
[[nodiscard]] bool preparePrivilegedIpcRuntime(QString *errorMessage = nullptr);
[[nodiscard]] bool removeStalePrivilegedSocket(const QString &path,
                                               QString *errorMessage = nullptr);

} // namespace amnezia::ipc

#endif // LOCALPEERAUTHENTICATION_H
