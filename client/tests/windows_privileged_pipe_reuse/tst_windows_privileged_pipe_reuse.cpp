#include <QCoreApplication>
#include <QDeadlineTimer>
#include <QEventLoop>
#include <QLocalSocket>
#include <QString>
#include <QTextStream>
#include <QUuid>
#include <QVector>

#include <aclapi.h>
#include <authz.h>
#include <windows.h>

#include <array>

#include "localpeerauthentication.h"
#include "windowsprivilegedpipe.h"

namespace {

constexpr DWORD expectedClientAccess =
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
constexpr DWORD expectedOwnerInstanceAccess = FILE_GENERIC_READ | FILE_GENERIC_WRITE;

class TestRunner
{
public:
    void check(bool condition, const char *expression, int line, const QString &detail = {})
    {
        ++m_assertions;
        if (condition) {
            return;
        }

        ++m_failures;
        QTextStream stream(stderr);
        stream << "FAIL line " << line << ": " << expression;
        if (!detail.isEmpty()) {
            stream << " (" << detail << ')';
        }
        stream << Qt::endl;
    }

    int finish() const
    {
        QTextStream stream(m_failures == 0 ? stdout : stderr);
        stream << (m_failures == 0 ? "PASS" : "FAIL") << ": " << m_assertions
               << " assertions, " << m_failures << " failures" << Qt::endl;
        return m_failures == 0 ? 0 : 1;
    }

private:
    int m_assertions = 0;
    int m_failures = 0;
};

#define CHECK(expression) runner.check((expression), #expression, __LINE__)
#define CHECK_DETAIL(expression, detail) \
    runner.check((expression), #expression, __LINE__, (detail))

QString windowsError(const QString &operation, DWORD error = GetLastError())
{
    return QStringLiteral("%1 failed with Windows error %2").arg(operation).arg(error);
}

bool waitForPendingConnection(amnezia::ipc::WindowsPrivilegedPipeServer &server,
                              int timeoutMilliseconds)
{
    QDeadlineTimer deadline(timeoutMilliseconds);
    while (!server.hasPendingConnections() && !deadline.hasExpired()) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
    }
    return server.hasPendingConnections();
}

bool waitForDisconnected(QLocalSocket *socket, int timeoutMilliseconds)
{
    if (!socket) {
        return false;
    }
    QDeadlineTimer deadline(timeoutMilliseconds);
    while (socket->state() != QLocalSocket::UnconnectedState && !deadline.hasExpired()) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
    }
    return socket->state() == QLocalSocket::UnconnectedState;
}

bool writeAll(QLocalSocket *socket, const QByteArray &payload, QString *errorMessage)
{
    if (!socket || socket->write(payload) != payload.size()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to queue the complete pipe payload");
        }
        return false;
    }
    socket->flush();
    if (socket->bytesToWrite() != 0 && !socket->waitForBytesWritten(2000)) {
        if (errorMessage) {
            *errorMessage = socket->errorString();
        }
        return false;
    }
    return true;
}

bool readExactly(QLocalSocket *socket, qsizetype size, QByteArray *result,
                 QString *errorMessage)
{
    if (!socket || !result) {
        return false;
    }

    result->clear();
    QDeadlineTimer deadline(2000);
    while (result->size() < size && !deadline.hasExpired()) {
        if (socket->bytesAvailable() == 0) {
            const qint64 remaining = deadline.remainingTime();
            if (remaining <= 0
                || !socket->waitForReadyRead(static_cast<int>(qMin<qint64>(remaining, 2000)))) {
                continue;
            }
        }
        result->append(socket->read(size - result->size()));
    }
    if (result->size() == size) {
        return true;
    }
    if (errorMessage) {
        *errorMessage = socket->errorString();
    }
    return false;
}

bool authenticatePair(QLocalSocket *client, QLocalSocket *accepted, QString *errorMessage)
{
    amnezia::ipc::LocalPeerIdentity clientIdentity;
    if (!amnezia::ipc::queryLocalPeerIdentity(accepted, clientIdentity, errorMessage)) {
        return false;
    }
    amnezia::ipc::LocalPeerIdentity serverIdentity;
    if (!amnezia::ipc::queryLocalServerIdentity(client, serverIdentity, errorMessage)) {
        return false;
    }

    const qint64 currentPid = QCoreApplication::applicationPid();
    const QString currentUser = amnezia::ipc::currentProcessUserIdentifier(errorMessage);
    return clientIdentity.isValid() && serverIdentity.isValid()
            && clientIdentity.processId == currentPid && serverIdentity.processId == currentPid
            && !currentUser.isEmpty()
            && clientIdentity.userIdentifier.compare(currentUser, Qt::CaseInsensitive) == 0
            && serverIdentity.userIdentifier.compare(currentUser, Qt::CaseInsensitive) == 0
            && amnezia::ipc::executablePathsMatch(clientIdentity.executablePath,
                                                  QCoreApplication::applicationFilePath())
            && amnezia::ipc::executablePathsMatch(serverIdentity.executablePath,
                                                  QCoreApplication::applicationFilePath());
}

bool roundTrip(QLocalSocket *client, QLocalSocket *accepted, const QByteArray &tag,
               QString *errorMessage)
{
    const QByteArray request = QByteArrayLiteral("request:") + tag;
    const QByteArray response = QByteArrayLiteral("response:") + tag;
    QByteArray received;
    return writeAll(client, request, errorMessage)
            && readExactly(accepted, request.size(), &received, errorMessage)
            && received == request
            && writeAll(accepted, response, errorMessage)
            && readExactly(client, response.size(), &received, errorMessage)
            && received == response;
}

struct SecurityDescriptorView
{
    SecurityDescriptorView() = default;
    SecurityDescriptorView(const SecurityDescriptorView &) = delete;
    SecurityDescriptorView &operator=(const SecurityDescriptorView &) = delete;

    ~SecurityDescriptorView()
    {
        if (descriptor) {
            LocalFree(descriptor);
        }
    }

    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
};

bool readPipeSecurityDescriptor(QLocalSocket *accepted, SecurityDescriptorView *view,
                                QString *errorMessage)
{
    if (!accepted || !view || accepted->socketDescriptor() == -1) {
        return false;
    }
    const DWORD status = GetSecurityInfo(
            reinterpret_cast<HANDLE>(accepted->socketDescriptor()), SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &view->owner, nullptr,
            &view->dacl, nullptr, &view->descriptor);
    if (status == ERROR_SUCCESS && view->owner && view->dacl && view->descriptor) {
        return true;
    }
    if (errorMessage) {
        *errorMessage = windowsError(QStringLiteral("GetSecurityInfo(named pipe)"), status);
    }
    return false;
}

bool isExpectedPipeDacl(const SecurityDescriptorView &view, QString *errorMessage)
{
    if (!view.dacl || view.dacl->AceCount != 5) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unexpected named-pipe ACE count");
        }
        return false;
    }

    bool networkDeny = false;
    bool systemAllow = false;
    bool administratorsAllow = false;
    bool ownerRightsAllow = false;
    bool interactiveAllow = false;
    for (DWORD index = 0; index < view.dacl->AceCount; ++index) {
        void *rawAce = nullptr;
        if (!GetAce(view.dacl, index, &rawAce) || !rawAce) {
            if (errorMessage) {
                *errorMessage = windowsError(QStringLiteral("GetAce"));
            }
            return false;
        }

        const auto *header = static_cast<const ACE_HEADER *>(rawAce);
        if (header->AceFlags != 0
            || (header->AceType != ACCESS_ALLOWED_ACE_TYPE
                && header->AceType != ACCESS_DENIED_ACE_TYPE)) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Unexpected named-pipe ACE type or flags");
            }
            return false;
        }

        const auto *ace = static_cast<const ACCESS_ALLOWED_ACE *>(rawAce);
        const PSID sid = const_cast<DWORD *>(&ace->SidStart);
        const DWORD mask = ace->Mask;
        if (IsWellKnownSid(sid, WinNetworkSid)) {
            networkDeny = header->AceType == ACCESS_DENIED_ACE_TYPE
                    && mask == FILE_ALL_ACCESS;
        } else if (IsWellKnownSid(sid, WinLocalSystemSid)) {
            systemAllow = header->AceType == ACCESS_ALLOWED_ACE_TYPE
                    && mask == FILE_ALL_ACCESS;
        } else if (IsWellKnownSid(sid, WinBuiltinAdministratorsSid)) {
            administratorsAllow = header->AceType == ACCESS_ALLOWED_ACE_TYPE
                    && mask == FILE_ALL_ACCESS;
        } else if (IsWellKnownSid(sid, WinCreatorOwnerRightsSid)) {
            ownerRightsAllow = header->AceType == ACCESS_ALLOWED_ACE_TYPE
                    && mask == expectedOwnerInstanceAccess;
        } else if (IsWellKnownSid(sid, WinInteractiveSid)) {
            interactiveAllow = header->AceType == ACCESS_ALLOWED_ACE_TYPE
                    && mask == expectedClientAccess;
        } else {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Unexpected SID in named-pipe DACL");
            }
            return false;
        }
    }

    if (networkDeny && systemAllow && administratorsAllow && ownerRightsAllow
        && interactiveAllow) {
        return true;
    }
    if (errorMessage) {
        *errorMessage = QStringLiteral("Named-pipe DACL masks do not match the contract");
    }
    return false;
}

bool authzAccess(AUTHZ_CLIENT_CONTEXT_HANDLE context, PSECURITY_DESCRIPTOR descriptor,
                 ACCESS_MASK desiredAccess, ACCESS_MASK *grantedAccess, DWORD *accessError,
                 QString *errorMessage)
{
    AUTHZ_ACCESS_REQUEST request {};
    request.DesiredAccess = desiredAccess;
    AUTHZ_ACCESS_REPLY reply {};
    reply.ResultListLength = 1;
    reply.GrantedAccessMask = grantedAccess;
    reply.Error = accessError;
    if (AuthzAccessCheck(0, context, &request, nullptr, descriptor, nullptr, 0, &reply,
                         nullptr)) {
        return true;
    }
    if (errorMessage) {
        *errorMessage = windowsError(QStringLiteral("AuthzAccessCheck"));
    }
    return false;
}

bool probeInteractiveNonOwnerAccess(const SecurityDescriptorView &view, QString *errorMessage)
{
    alignas(DWORD) std::array<BYTE, SECURITY_MAX_SID_SIZE> anonymousSid {};
    alignas(DWORD) std::array<BYTE, SECURITY_MAX_SID_SIZE> interactiveSid {};
    DWORD anonymousSize = static_cast<DWORD>(anonymousSid.size());
    DWORD interactiveSize = static_cast<DWORD>(interactiveSid.size());
    if (!CreateWellKnownSid(WinAnonymousSid, nullptr, anonymousSid.data(), &anonymousSize)
        || !CreateWellKnownSid(WinInteractiveSid, nullptr, interactiveSid.data(),
                               &interactiveSize)) {
        if (errorMessage) {
            *errorMessage = windowsError(QStringLiteral("CreateWellKnownSid"));
        }
        return false;
    }
    if (EqualSid(view.owner, anonymousSid.data())) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Synthetic non-owner unexpectedly owns the pipe");
        }
        return false;
    }

    AUTHZ_RESOURCE_MANAGER_HANDLE resourceManager = nullptr;
    AUTHZ_CLIENT_CONTEXT_HANDLE baseContext = nullptr;
    AUTHZ_CLIENT_CONTEXT_HANDLE interactiveContext = nullptr;
    bool result = false;
    do {
        if (!AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, nullptr, nullptr, nullptr,
                                            L"Amnezia pipe ACL test", &resourceManager)) {
            if (errorMessage) {
                *errorMessage = windowsError(QStringLiteral("AuthzInitializeResourceManager"));
            }
            break;
        }

        LUID identifier {};
        if (!AuthzInitializeContextFromSid(AUTHZ_SKIP_TOKEN_GROUPS, anonymousSid.data(),
                                           resourceManager, nullptr, identifier, nullptr,
                                           &baseContext)) {
            if (errorMessage) {
                *errorMessage = windowsError(QStringLiteral("AuthzInitializeContextFromSid"));
            }
            break;
        }

        SID_AND_ATTRIBUTES group { interactiveSid.data(), SE_GROUP_ENABLED };
        if (!AuthzAddSidsToContext(baseContext, &group, 1, nullptr, 0,
                                   &interactiveContext)) {
            if (errorMessage) {
                *errorMessage = windowsError(QStringLiteral("AuthzAddSidsToContext"));
            }
            break;
        }

        ACCESS_MASK maximumGranted = 0;
        DWORD maximumError = ERROR_SUCCESS;
        if (!authzAccess(interactiveContext, view.descriptor, MAXIMUM_ALLOWED,
                         &maximumGranted, &maximumError, errorMessage)
            || maximumError != ERROR_SUCCESS
            || (maximumGranted & expectedClientAccess) != expectedClientAccess
            || (maximumGranted & FILE_CREATE_PIPE_INSTANCE) != 0) {
            if (errorMessage && errorMessage->isEmpty()) {
                *errorMessage = QStringLiteral("Interactive non-owner maximum access is unsafe");
            }
            break;
        }

        ACCESS_MASK createGranted = 0;
        DWORD createError = ERROR_SUCCESS;
        if (!authzAccess(interactiveContext, view.descriptor, FILE_CREATE_PIPE_INSTANCE,
                         &createGranted, &createError, errorMessage)
            || createError != ERROR_ACCESS_DENIED || createGranted != 0) {
            if (errorMessage && errorMessage->isEmpty()) {
                *errorMessage = QStringLiteral("Interactive non-owner can create a pipe instance");
            }
            break;
        }
        result = true;
    } while (false);

    if (interactiveContext) {
        AuthzFreeContext(interactiveContext);
    }
    if (baseContext) {
        AuthzFreeContext(baseContext);
    }
    if (resourceManager) {
        AuthzFreeResourceManager(resourceManager);
    }
    return result;
}

bool reserveHandleValue(qintptr target, QVector<HANDLE> *reservations)
{
    if (!reservations || target == -1) {
        return false;
    }
    for (int attempt = 0; attempt < 4096; ++attempt) {
        const HANDLE handle = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (!handle) {
            return false;
        }
        reservations->append(handle);
        if (reinterpret_cast<qintptr>(handle) == target) {
            return true;
        }
    }
    return false;
}

bool releaseReservedValue(qintptr target, QVector<HANDLE> *reservations)
{
    if (!reservations) {
        return false;
    }
    for (qsizetype index = 0; index < reservations->size(); ++index) {
        if (reinterpret_cast<qintptr>(reservations->at(index)) == target) {
            const HANDLE handle = reservations->takeAt(index);
            return CloseHandle(handle) != FALSE;
        }
    }
    return false;
}

void releaseReservations(QVector<HANDLE> *reservations)
{
    if (!reservations) {
        return;
    }
    for (const HANDLE handle : *reservations) {
        CloseHandle(handle);
    }
    reservations->clear();
}

QLocalSocket *takeAccepted(amnezia::ipc::WindowsPrivilegedPipeServer &server,
                           TestRunner &runner)
{
    runner.check(waitForPendingConnection(server, 2000),
                 "waitForPendingConnection(server, 2000)", __LINE__, server.errorString());
    QLocalSocket *accepted = server.nextPendingConnection();
    runner.check(accepted != nullptr, "accepted != nullptr", __LINE__);
    return accepted;
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    TestRunner runner;

    const QString serverName = QStringLiteral("amnezia-pipe-reuse-%1-%2")
            .arg(QCoreApplication::applicationPid())
            .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
    amnezia::ipc::WindowsPrivilegedPipeServer server;
    CHECK_DETAIL(server.listen(serverName), server.errorString());
    CHECK(server.isListening());

    // Keep the first accepted pipe alive while connecting the second client.
    // This exercises the owner-only creation of another server instance.
    QLocalSocket simultaneousClientOne;
    QString error;
    CHECK_DETAIL(amnezia::ipc::connectWindowsPrivilegedPipe(
                         &simultaneousClientOne, serverName, 2000, &error),
                 error);
    QLocalSocket *simultaneousAcceptedOne = takeAccepted(server, runner);
    CHECK(simultaneousAcceptedOne != nullptr);
    CHECK(simultaneousAcceptedOne
          && simultaneousAcceptedOne->state() == QLocalSocket::ConnectedState);

    QLocalSocket simultaneousClientTwo;
    error.clear();
    CHECK_DETAIL(amnezia::ipc::connectWindowsPrivilegedPipe(
                         &simultaneousClientTwo, serverName, 2000, &error),
                 error);
    QLocalSocket *simultaneousAcceptedTwo = takeAccepted(server, runner);
    CHECK(simultaneousAcceptedTwo != nullptr);
    CHECK(simultaneousAcceptedOne
          && simultaneousAcceptedOne->state() == QLocalSocket::ConnectedState);
    CHECK(simultaneousAcceptedTwo
          && simultaneousAcceptedTwo->state() == QLocalSocket::ConnectedState);

    if (simultaneousAcceptedOne && simultaneousAcceptedTwo) {
        CHECK(amnezia::ipc::isWindowsPrivilegedPipeSocket(&simultaneousClientOne));
        CHECK(amnezia::ipc::isWindowsPrivilegedPipeSocket(&simultaneousClientTwo));
        CHECK(amnezia::ipc::isWindowsPrivilegedPipeSocket(simultaneousAcceptedOne));
        CHECK(amnezia::ipc::isWindowsPrivilegedPipeSocket(simultaneousAcceptedTwo));
        error.clear();
        CHECK_DETAIL(authenticatePair(&simultaneousClientOne, simultaneousAcceptedOne, &error),
                     error);
        error.clear();
        CHECK_DETAIL(authenticatePair(&simultaneousClientTwo, simultaneousAcceptedTwo, &error),
                     error);
        error.clear();
        CHECK_DETAIL(roundTrip(&simultaneousClientOne, simultaneousAcceptedOne,
                               QByteArrayLiteral("simultaneous-one"), &error),
                     error);
        error.clear();
        CHECK_DETAIL(roundTrip(&simultaneousClientTwo, simultaneousAcceptedTwo,
                               QByteArrayLiteral("simultaneous-two"), &error),
                     error);

        SecurityDescriptorView security;
        error.clear();
        CHECK_DETAIL(readPipeSecurityDescriptor(simultaneousAcceptedOne, &security, &error),
                     error);
        if (security.descriptor) {
            error.clear();
            CHECK_DETAIL(isExpectedPipeDacl(security, &error), error);
            error.clear();
            CHECK_DETAIL(probeInteractiveNonOwnerAccess(security, &error), error);
        }
    }

    simultaneousClientOne.abort();
    simultaneousClientTwo.abort();
    if (simultaneousAcceptedOne) {
        CHECK(waitForDisconnected(simultaneousAcceptedOne, 2000));
        delete simultaneousAcceptedOne;
    }
    if (simultaneousAcceptedTwo) {
        CHECK(waitForDisconnected(simultaneousAcceptedTwo, 2000));
        delete simultaneousAcceptedTwo;
    }

    // Three sequential authenticated round trips. The first accepted QObject
    // deliberately survives disconnection. Its freed descriptor is reserved,
    // then released immediately before the second accept creates the following
    // listener, forcing that listener to reuse the numeric HANDLE. Once the
    // third connection adopts it, destroying the stale first QObject must not
    // unregister the live socket's marker.
    QLocalSocket sequentialClientOne;
    error.clear();
    CHECK_DETAIL(amnezia::ipc::connectWindowsPrivilegedPipe(
                         &sequentialClientOne, serverName, 2000, &error),
                 error);
    QLocalSocket *sequentialAcceptedOne = takeAccepted(server, runner);
    qintptr reusedDescriptor = -1;
    if (sequentialAcceptedOne) {
        reusedDescriptor = sequentialAcceptedOne->socketDescriptor();
        error.clear();
        CHECK_DETAIL(authenticatePair(&sequentialClientOne, sequentialAcceptedOne, &error),
                     error);
        error.clear();
        CHECK_DETAIL(roundTrip(&sequentialClientOne, sequentialAcceptedOne,
                               QByteArrayLiteral("sequential-one"), &error),
                     error);
    }
    sequentialClientOne.abort();
    CHECK(sequentialAcceptedOne && waitForDisconnected(sequentialAcceptedOne, 2000));

    QVector<HANDLE> reservations;
    CHECK(reserveHandleValue(reusedDescriptor, &reservations));
    QLocalSocket sequentialClientTwo;
    error.clear();
    CHECK_DETAIL(amnezia::ipc::connectWindowsPrivilegedPipe(
                         &sequentialClientTwo, serverName, 2000, &error),
                 error);
    CHECK(releaseReservedValue(reusedDescriptor, &reservations));
    QLocalSocket *sequentialAcceptedTwo = takeAccepted(server, runner);
    releaseReservations(&reservations);
    if (sequentialAcceptedTwo) {
        error.clear();
        CHECK_DETAIL(authenticatePair(&sequentialClientTwo, sequentialAcceptedTwo, &error),
                     error);
        error.clear();
        CHECK_DETAIL(roundTrip(&sequentialClientTwo, sequentialAcceptedTwo,
                               QByteArrayLiteral("sequential-two"), &error),
                     error);
    }
    sequentialClientTwo.abort();
    CHECK(sequentialAcceptedTwo && waitForDisconnected(sequentialAcceptedTwo, 2000));

    QLocalSocket sequentialClientThree;
    error.clear();
    CHECK_DETAIL(amnezia::ipc::connectWindowsPrivilegedPipe(
                         &sequentialClientThree, serverName, 2000, &error),
                 error);
    QLocalSocket *sequentialAcceptedThree = takeAccepted(server, runner);
    if (sequentialAcceptedThree) {
        CHECK(sequentialAcceptedThree->socketDescriptor() == reusedDescriptor);
        CHECK(amnezia::ipc::isWindowsPrivilegedPipeSocket(sequentialAcceptedThree));
        delete sequentialAcceptedOne;
        sequentialAcceptedOne = nullptr;
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
        CHECK(amnezia::ipc::isWindowsPrivilegedPipeSocket(sequentialAcceptedThree));
        error.clear();
        CHECK_DETAIL(authenticatePair(&sequentialClientThree, sequentialAcceptedThree, &error),
                     error);
        error.clear();
        CHECK_DETAIL(roundTrip(&sequentialClientThree, sequentialAcceptedThree,
                               QByteArrayLiteral("sequential-three"), &error),
                     error);
    }

    if (sequentialAcceptedTwo) {
        delete sequentialAcceptedTwo;
        sequentialAcceptedTwo = nullptr;
    }
    if (sequentialAcceptedThree) {
        server.close();
        CHECK(!server.isListening());
        error.clear();
        CHECK_DETAIL(roundTrip(&sequentialClientThree, sequentialAcceptedThree,
                               QByteArrayLiteral("after-server-close"), &error),
                     error);
        sequentialClientThree.abort();
        CHECK(waitForDisconnected(sequentialAcceptedThree, 2000));
        delete sequentialAcceptedThree;
    } else {
        server.close();
    }
    if (sequentialAcceptedOne) {
        delete sequentialAcceptedOne;
    }

    CHECK(!server.isListening());

    // Capability endpoints intentionally wait for an explicit re-arm after a
    // rejected peer. Keep this path covered while the default server uses the
    // multi-instance auto-rearm behavior above.
    const QString capabilityName = QStringLiteral("amnezia-pipe-capability-%1-%2")
            .arg(QCoreApplication::applicationPid())
            .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
    amnezia::ipc::WindowsPrivilegedPipeServer capabilityServer;
    capabilityServer.setAutoRearm(false);
    CHECK(!capabilityServer.autoRearm());
    CHECK_DETAIL(capabilityServer.listen(capabilityName), capabilityServer.errorString());

    QLocalSocket rejectedClient;
    error.clear();
    CHECK_DETAIL(amnezia::ipc::connectWindowsPrivilegedPipe(
                         &rejectedClient, capabilityName, 2000, &error),
                 error);
    QLocalSocket *rejectedAccepted = takeAccepted(capabilityServer, runner);
    rejectedClient.abort();
    CHECK(rejectedAccepted && waitForDisconnected(rejectedAccepted, 2000));
    CHECK_DETAIL(capabilityServer.resumeAccepting(), capabilityServer.errorString());
    delete rejectedAccepted;

    QLocalSocket resumedClient;
    error.clear();
    CHECK_DETAIL(amnezia::ipc::connectWindowsPrivilegedPipe(
                         &resumedClient, capabilityName, 2000, &error),
                 error);
    QLocalSocket *resumedAccepted = takeAccepted(capabilityServer, runner);
    if (resumedAccepted) {
        error.clear();
        CHECK_DETAIL(authenticatePair(&resumedClient, resumedAccepted, &error), error);
        error.clear();
        CHECK_DETAIL(roundTrip(&resumedClient, resumedAccepted,
                               QByteArrayLiteral("explicit-rearm"), &error),
                     error);
    }
    capabilityServer.close();
    resumedClient.abort();
    if (resumedAccepted) {
        CHECK(waitForDisconnected(resumedAccepted, 2000));
        delete resumedAccepted;
    }

    return runner.finish();
}
