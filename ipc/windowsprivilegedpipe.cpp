#include "windowsprivilegedpipe.h"

#ifdef Q_OS_WIN

#include <QDeadlineTimer>
#include <QHash>
#include <QMutex>
#include <QMutexLocker>
#include <QPointer>
#include <QQueue>
#include <QVariant>
#include <QWinEventNotifier>

#include <aclapi.h>
#include <windows.h>

#include <array>

namespace amnezia::ipc {
namespace {

constexpr auto privilegedPipeProperty = "amneziaWindowsPrivilegedPipe";
constexpr DWORD clientPipeAccess =
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;

QMutex privilegedHandlesMutex;
QHash<const QLocalSocket *, qintptr> privilegedSockets;

void setError(QString *errorMessage, const QString &value)
{
    if (errorMessage) {
        *errorMessage = value;
    }
}

QString windowsError(const QString &operation, DWORD error = GetLastError())
{
    LPWSTR buffer = nullptr;
    const DWORD length = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
                    | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    QString detail;
    if (length != 0 && buffer) {
        detail = QString::fromWCharArray(buffer, static_cast<qsizetype>(length)).trimmed();
        LocalFree(buffer);
    } else {
        detail = QStringLiteral("Windows error %1").arg(error);
    }
    return QStringLiteral("%1: %2").arg(operation, detail);
}

QString localPipePath(const QString &name, QString *errorMessage)
{
    const QString localPrefix = QStringLiteral("\\\\.\\pipe\\");
    if (name.startsWith(localPrefix, Qt::CaseInsensitive)) {
        const QString leaf = name.mid(localPrefix.size());
        if (!leaf.isEmpty() && !leaf.contains(QLatin1Char('/'))
            && !leaf.contains(QLatin1Char('\\'))) {
            return localPrefix + leaf;
        }
        setError(errorMessage, QStringLiteral("Invalid local named-pipe name"));
        return {};
    }
    if (name.startsWith(QStringLiteral("\\\\"))) {
        setError(errorMessage, QStringLiteral("Remote named-pipe paths are forbidden"));
        return {};
    }
    if (name.isEmpty() || name.contains(QLatin1Char('/')) || name.contains(QLatin1Char('\\'))) {
        setError(errorMessage, QStringLiteral("Invalid local named-pipe name"));
        return {};
    }
    return localPrefix + name;
}

void registerPrivilegedSocket(QLocalSocket *socket)
{
    const qintptr descriptor = socket ? socket->socketDescriptor() : -1;
    if (descriptor == -1) {
        return;
    }
    {
        QMutexLocker locker(&privilegedHandlesMutex);
        privilegedSockets.insert(socket, descriptor);
    }
    auto unregister = [socket, descriptor] {
        QMutexLocker locker(&privilegedHandlesMutex);
        const auto existing = privilegedSockets.constFind(socket);
        if (existing != privilegedSockets.cend() && existing.value() == descriptor) {
            privilegedSockets.remove(socket);
        }
    };
    QObject::connect(socket, &QLocalSocket::disconnected, socket, unregister,
                     Qt::DirectConnection);
    QObject::connect(socket, &QObject::destroyed, unregister);
}

struct PipeSecurity
{
    SECURITY_DESCRIPTOR descriptor {};
    SECURITY_ATTRIBUTES attributes {};
    PACL acl = nullptr;

    ~PipeSecurity()
    {
        if (acl) {
            LocalFree(acl);
        }
    }
};

bool createWellKnownSidBuffer(WELL_KNOWN_SID_TYPE type,
                              std::array<BYTE, SECURITY_MAX_SID_SIZE> &buffer,
                              QString *errorMessage)
{
    DWORD size = static_cast<DWORD>(buffer.size());
    if (!CreateWellKnownSid(type, nullptr, buffer.data(), &size)) {
        setError(errorMessage, windowsError(QStringLiteral("CreateWellKnownSid")));
        return false;
    }
    return true;
}

bool buildPipeSecurity(PipeSecurity &security, QString *errorMessage)
{
    alignas(DWORD) std::array<BYTE, SECURITY_MAX_SID_SIZE> networkSid {};
    alignas(DWORD) std::array<BYTE, SECURITY_MAX_SID_SIZE> systemSid {};
    alignas(DWORD) std::array<BYTE, SECURITY_MAX_SID_SIZE> administratorsSid {};
    alignas(DWORD) std::array<BYTE, SECURITY_MAX_SID_SIZE> ownerRightsSid {};
    alignas(DWORD) std::array<BYTE, SECURITY_MAX_SID_SIZE> interactiveSid {};
    if (!createWellKnownSidBuffer(WinNetworkSid, networkSid, errorMessage)
        || !createWellKnownSidBuffer(WinLocalSystemSid, systemSid, errorMessage)
        || !createWellKnownSidBuffer(WinBuiltinAdministratorsSid, administratorsSid, errorMessage)
        || !createWellKnownSidBuffer(WinCreatorOwnerRightsSid, ownerRightsSid, errorMessage)
        || !createWellKnownSidBuffer(WinInteractiveSid, interactiveSid, errorMessage)) {
        return false;
    }

    std::array<EXPLICIT_ACCESSW, 5> entries {};
    entries[0].grfAccessPermissions = FILE_ALL_ACCESS;
    entries[0].grfAccessMode = DENY_ACCESS;
    entries[0].grfInheritance = NO_INHERITANCE;
    BuildTrusteeWithSidW(&entries[0].Trustee, networkSid.data());

    entries[1].grfAccessPermissions = FILE_ALL_ACCESS;
    entries[1].grfAccessMode = SET_ACCESS;
    entries[1].grfInheritance = NO_INHERITANCE;
    BuildTrusteeWithSidW(&entries[1].Trustee, systemSid.data());

    entries[2].grfAccessPermissions = FILE_ALL_ACCESS;
    entries[2].grfAccessMode = SET_ACCESS;
    entries[2].grfInheritance = NO_INHERITANCE;
    BuildTrusteeWithSidW(&entries[2].Trustee, administratorsSid.data());

    // CreateNamedPipe checks both FILE_CREATE_PIPE_INSTANCE and the access
    // implied by PIPE_ACCESS_DUPLEX for every later instance. Restrict those
    // server rights to the object owner. The Interactive ACE below remains
    // data-only, so an Interactive peer that is not the object owner cannot
    // create pipe instances.
    entries[3].grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
    entries[3].grfAccessMode = SET_ACCESS;
    entries[3].grfInheritance = NO_INHERITANCE;
    BuildTrusteeWithSidW(&entries[3].Trustee, ownerRightsSid.data());

    entries[4].grfAccessPermissions = clientPipeAccess;
    entries[4].grfAccessMode = SET_ACCESS;
    entries[4].grfInheritance = NO_INHERITANCE;
    BuildTrusteeWithSidW(&entries[4].Trustee, interactiveSid.data());

    const DWORD aclStatus = SetEntriesInAclW(static_cast<ULONG>(entries.size()), entries.data(),
                                              nullptr, &security.acl);
    if (aclStatus != ERROR_SUCCESS || !security.acl) {
        setError(errorMessage, windowsError(QStringLiteral("SetEntriesInAcl"), aclStatus));
        return false;
    }
    if (!InitializeSecurityDescriptor(&security.descriptor, SECURITY_DESCRIPTOR_REVISION)
        || !SetSecurityDescriptorDacl(&security.descriptor, TRUE, security.acl, FALSE)) {
        setError(errorMessage, windowsError(QStringLiteral("SetSecurityDescriptorDacl")));
        return false;
    }

    security.attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    security.attributes.lpSecurityDescriptor = &security.descriptor;
    security.attributes.bInheritHandle = FALSE;
    return true;
}

void closePipeHandle(HANDLE handle)
{
    if (handle != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(handle);
        CloseHandle(handle);
    }
}

} // namespace

class WindowsPrivilegedPipeServer::Private
{
public:
    explicit Private(WindowsPrivilegedPipeServer *owner)
        : q(owner)
    {
    }

    ~Private()
    {
        close();
    }

    bool listen(const QString &requestedName)
    {
        close();
        error.clear();
        QString pathError;
        fullName = localPipePath(requestedName, &pathError);
        if (fullName.isEmpty()) {
            error = pathError;
            return false;
        }
        name = requestedName;

        event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!event) {
            error = windowsError(QStringLiteral("CreateEvent"));
            close();
            return false;
        }
        notifier = new QWinEventNotifier(event, q);
        QObject::connect(notifier, &QWinEventNotifier::activated, q,
                         [this] { acceptReady(); });

        listening = true;
        if (!createListener(true)) {
            close();
            return false;
        }
        notifier->setEnabled(true);
        return true;
    }

    bool createListener(bool firstInstance)
    {
        PipeSecurity security;
        QString securityError;
        if (!buildPipeSecurity(security, &securityError)) {
            error = securityError;
            return false;
        }

        DWORD openMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if (firstInstance) {
            openMode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        listener = CreateNamedPipeW(
                reinterpret_cast<LPCWSTR>(fullName.utf16()), openMode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES, 0, 0, 3000, &security.attributes);
        if (listener == INVALID_HANDLE_VALUE) {
            error = windowsError(QStringLiteral("CreateNamedPipe"));
            return false;
        }
        return beginAccept();
    }

    bool beginAccept()
    {
        if (listener == INVALID_HANDLE_VALUE || !event) {
            error = QStringLiteral("Named-pipe listener is not available");
            return false;
        }

        ResetEvent(event);
        ZeroMemory(&overlapped, sizeof(overlapped));
        overlapped.hEvent = event;
        connectionReady = false;
        connectPending = false;
        if (ConnectNamedPipe(listener, &overlapped)) {
            connectionReady = true;
            SetEvent(event);
            return true;
        }

        const DWORD connectError = GetLastError();
        if (connectError == ERROR_IO_PENDING) {
            connectPending = true;
            return true;
        }
        if (connectError == ERROR_PIPE_CONNECTED) {
            connectionReady = true;
            SetEvent(event);
            return true;
        }

        error = windowsError(QStringLiteral("ConnectNamedPipe"), connectError);
        closePipeHandle(listener);
        listener = INVALID_HANDLE_VALUE;
        return false;
    }

    void stopAfterListenerError()
    {
        listening = false;
        waitingForRearm = false;
        if (notifier) {
            notifier->setEnabled(false);
        }
        if (listener != INVALID_HANDLE_VALUE) {
            closePipeHandle(listener);
            listener = INVALID_HANDLE_VALUE;
        }
        connectionReady = false;
        connectPending = false;
    }

    void prunePendingConnections()
    {
        for (auto it = pending.begin(); it != pending.end();) {
            if (it->isNull()) {
                it = pending.erase(it);
            } else {
                ++it;
            }
        }
    }

    void acceptReady()
    {
        if (!listening || listener == INVALID_HANDLE_VALUE || !notifier) {
            return;
        }
        notifier->setEnabled(false);

        DWORD transferred = 0;
        if (!connectionReady
            && !GetOverlappedResult(listener, &overlapped, &transferred, FALSE)) {
            const DWORD resultError = GetLastError();
            if (resultError == ERROR_IO_INCOMPLETE) {
                notifier->setEnabled(true);
                return;
            }
            error = windowsError(QStringLiteral("GetOverlappedResult"), resultError);
            stopAfterListenerError();
            return;
        }

        connectionReady = false;
        connectPending = false;
        ResetEvent(event);

        prunePendingConnections();
        if (pending.size() >= maximumPendingConnections) {
            closePipeHandle(listener);
            listener = INVALID_HANDLE_VALUE;
            waitingForRearm = !automaticRearm;
            if (automaticRearm && !createListener(false)) {
                stopAfterListenerError();
                return;
            }
            if (automaticRearm) {
                notifier->setEnabled(true);
            }
            return;
        }

        const HANDLE accepted = listener;
        listener = INVALID_HANDLE_VALUE;
        waitingForRearm = !automaticRearm;
        if (automaticRearm) {
            if (!createListener(false)) {
                listening = false;
                waitingForRearm = false;
                notifier->setEnabled(false);
            } else {
                notifier->setEnabled(true);
            }
        }

        auto *socket = new QLocalSocket(q);
        if (!socket->setSocketDescriptor(reinterpret_cast<qintptr>(accepted),
                                         QLocalSocket::ConnectedState,
                                         QIODevice::ReadWrite)) {
            CloseHandle(accepted);
            socket->deleteLater();
            return;
        }
        socket->setProperty(privilegedPipeProperty, true);
        registerPrivilegedSocket(socket);

        pending.enqueue(socket);
        emit q->newConnection();
    }

    bool resumeAccepting()
    {
        if (!listening || listener != INVALID_HANDLE_VALUE || !waitingForRearm || !notifier) {
            return false;
        }
        waitingForRearm = false;
        if (!createListener(false)) {
            stopAfterListenerError();
            return false;
        }
        notifier->setEnabled(true);
        return true;
    }

    void close()
    {
        listening = false;
        if (notifier) {
            notifier->setEnabled(false);
            notifier->setHandle(nullptr);
            notifier->deleteLater();
            notifier = nullptr;
        }
        if (listener != INVALID_HANDLE_VALUE) {
            if (connectPending) {
                CancelIoEx(listener, &overlapped);
                DWORD transferred = 0;
                GetOverlappedResult(listener, &overlapped, &transferred, TRUE);
            }
            closePipeHandle(listener);
            listener = INVALID_HANDLE_VALUE;
        }
        if (event) {
            CloseHandle(event);
            event = nullptr;
        }
        while (!pending.isEmpty()) {
            const QPointer<QLocalSocket> socket = pending.dequeue();
            if (socket) {
                socket->abort();
                socket->deleteLater();
            }
        }
        connectionReady = false;
        connectPending = false;
        waitingForRearm = false;
        name.clear();
        fullName.clear();
    }

    WindowsPrivilegedPipeServer *q = nullptr;
    QString name;
    QString fullName;
    QString error;
    HANDLE listener = INVALID_HANDLE_VALUE;
    HANDLE event = nullptr;
    OVERLAPPED overlapped {};
    QWinEventNotifier *notifier = nullptr;
    QQueue<QPointer<QLocalSocket>> pending;
    int maximumPendingConnections = 16;
    bool listening = false;
    bool connectionReady = false;
    bool connectPending = false;
    bool automaticRearm = true;
    bool waitingForRearm = false;
};

WindowsPrivilegedPipeServer::WindowsPrivilegedPipeServer(QObject *parent)
    : QObject(parent), d(std::make_unique<Private>(this))
{
}

WindowsPrivilegedPipeServer::~WindowsPrivilegedPipeServer() = default;

bool WindowsPrivilegedPipeServer::listen(const QString &name)
{
    return d->listen(name);
}

void WindowsPrivilegedPipeServer::close()
{
    d->close();
}

bool WindowsPrivilegedPipeServer::hasPendingConnections() const
{
    for (const QPointer<QLocalSocket> &socket : d->pending) {
        if (socket) {
            return true;
        }
    }
    return false;
}

bool WindowsPrivilegedPipeServer::isListening() const
{
    return d->listening;
}

QLocalSocket *WindowsPrivilegedPipeServer::nextPendingConnection()
{
    while (!d->pending.isEmpty()) {
        const QPointer<QLocalSocket> socket = d->pending.dequeue();
        if (socket) {
            return socket.data();
        }
    }
    return nullptr;
}

QString WindowsPrivilegedPipeServer::errorString() const
{
    return d->error;
}

QString WindowsPrivilegedPipeServer::serverName() const
{
    return d->name;
}

QString WindowsPrivilegedPipeServer::fullServerName() const
{
    return d->fullName;
}

void WindowsPrivilegedPipeServer::setMaxPendingConnections(int maximum)
{
    d->maximumPendingConnections = qMax(1, maximum);
}

int WindowsPrivilegedPipeServer::maxPendingConnections() const
{
    return d->maximumPendingConnections;
}

void WindowsPrivilegedPipeServer::setListenBacklogSize(int size)
{
    Q_UNUSED(size)
    // The native acceptor intentionally maintains one outstanding listener.
}

int WindowsPrivilegedPipeServer::listenBacklogSize() const
{
    return 1;
}

void WindowsPrivilegedPipeServer::setAutoRearm(bool enabled)
{
    d->automaticRearm = enabled;
}

bool WindowsPrivilegedPipeServer::autoRearm() const
{
    return d->automaticRearm;
}

bool WindowsPrivilegedPipeServer::resumeAccepting()
{
    return d->resumeAccepting();
}

bool connectWindowsPrivilegedPipe(QLocalSocket *socket, const QString &name,
                                  int timeoutMilliseconds, QString *errorMessage)
{
    if (!socket || socket->state() != QLocalSocket::UnconnectedState) {
        setError(errorMessage, QStringLiteral("Local socket is not ready for a native connection"));
        return false;
    }

    const QString path = localPipePath(name, errorMessage);
    if (path.isEmpty()) {
        return false;
    }

    QDeadlineTimer deadline(qMax(0, timeoutMilliseconds));
    HANDLE handle = INVALID_HANDLE_VALUE;
    DWORD openError = ERROR_SUCCESS;
    do {
        handle = CreateFileW(
                reinterpret_cast<LPCWSTR>(path.utf16()), clientPipeAccess, 0, nullptr,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (handle != INVALID_HANDLE_VALUE) {
            break;
        }
        openError = GetLastError();
        if (openError != ERROR_PIPE_BUSY || deadline.hasExpired()) {
            break;
        }
        const qint64 remaining = deadline.remainingTime();
        const DWORD wait = static_cast<DWORD>(
                qBound<qint64>(qint64(1), remaining, qint64(5000)));
        if (!WaitNamedPipeW(reinterpret_cast<LPCWSTR>(path.utf16()), wait)) {
            openError = GetLastError();
            if (openError != ERROR_SEM_TIMEOUT) {
                break;
            }
        }
    } while (!deadline.hasExpired());

    if (handle == INVALID_HANDLE_VALUE) {
        setError(errorMessage, windowsError(QStringLiteral("CreateFile(named pipe)"), openError));
        return false;
    }

    if (!socket->setSocketDescriptor(reinterpret_cast<qintptr>(handle),
                                     QLocalSocket::ConnectedState, QIODevice::ReadWrite)) {
        CloseHandle(handle);
        setError(errorMessage, QStringLiteral("Unable to adopt native named-pipe handle"));
        return false;
    }
    socket->setProperty(privilegedPipeProperty, true);
    registerPrivilegedSocket(socket);
    return true;
}

bool isWindowsPrivilegedPipeSocket(const QLocalSocket *socket)
{
    if (!socket || !socket->property(privilegedPipeProperty).toBool()
        || socket->socketDescriptor() == -1) {
        return false;
    }
    QMutexLocker locker(&privilegedHandlesMutex);
    return privilegedSockets.value(socket, -1) == socket->socketDescriptor();
}

} // namespace amnezia::ipc

#endif
