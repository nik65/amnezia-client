#include "localpeerauthentication.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLocalServer>
#include <QLocalSocket>

#include <string>
#include <vector>

#include "windowsprivilegedpipe.h"

#ifdef Q_OS_WIN
#  include <aclapi.h>
#  include <sddl.h>
#  include <windows.h>
#elif defined(Q_OS_LINUX)
#  include <sys/socket.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <unistd.h>
#elif defined(Q_OS_MACOS) || defined(Q_OS_MAC)
#  include <CoreFoundation/CoreFoundation.h>
#  include <Security/Security.h>
#  include <libproc.h>
#  include <sys/socket.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <sys/un.h>
#  include <unistd.h>
#endif

namespace amnezia::ipc {
namespace {

void setError(QString *errorMessage, const QString &value)
{
    if (errorMessage) {
        *errorMessage = value;
    }
}

#ifdef Q_OS_WIN
struct WindowsTokenIdentity
{
    QString userIdentifier;
    QString logonIdentifier;
    DWORD sessionId = (std::numeric_limits<DWORD>::max)();
    bool interactive = false;
    bool network = false;
};

QString sidForToken(HANDLE token, QString *errorMessage)
{
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (size == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        setError(errorMessage, QStringLiteral("TokenUser size query failed"));
        return {};
    }

    QByteArray storage(static_cast<qsizetype>(size), Qt::Uninitialized);
    if (!GetTokenInformation(token, TokenUser, storage.data(), size, &size)) {
        setError(errorMessage, QStringLiteral("TokenUser query failed"));
        return {};
    }

    const auto *tokenUser = reinterpret_cast<const TOKEN_USER *>(storage.constData());
    LPWSTR sidString = nullptr;
    if (!ConvertSidToStringSidW(tokenUser->User.Sid, &sidString)) {
        setError(errorMessage, QStringLiteral("SID conversion failed"));
        return {};
    }

    const QString result = QString::fromWCharArray(sidString);
    LocalFree(sidString);
    return result;
}

bool tokenContainsWellKnownSid(HANDLE token, WELL_KNOWN_SID_TYPE type, bool &contains,
                               QString *errorMessage)
{
    contains = false;
    DWORD size = 0;
    GetTokenInformation(token, TokenGroups, nullptr, 0, &size);
    if (size == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        setError(errorMessage, QStringLiteral("TokenGroups size query failed"));
        return false;
    }
    QByteArray groupsStorage(static_cast<qsizetype>(size), Qt::Uninitialized);
    if (!GetTokenInformation(token, TokenGroups, groupsStorage.data(), size, &size)) {
        setError(errorMessage, QStringLiteral("TokenGroups query failed"));
        return false;
    }

    alignas(DWORD) BYTE expectedSid[SECURITY_MAX_SID_SIZE] {};
    DWORD expectedSize = sizeof(expectedSid);
    if (!CreateWellKnownSid(type, nullptr, expectedSid, &expectedSize)) {
        setError(errorMessage, QStringLiteral("Well-known SID creation failed"));
        return false;
    }

    const auto *groups = reinterpret_cast<const TOKEN_GROUPS *>(groupsStorage.constData());
    for (DWORD index = 0; index < groups->GroupCount; ++index) {
        const SID_AND_ATTRIBUTES &group = groups->Groups[index];
        if ((group.Attributes & SE_GROUP_ENABLED) != 0 && EqualSid(group.Sid, expectedSid)) {
            contains = true;
            break;
        }
    }
    return true;
}

bool queryWindowsTokenIdentity(HANDLE token, WindowsTokenIdentity &identity,
                               QString *errorMessage)
{
    identity = {};
    identity.userIdentifier = sidForToken(token, errorMessage);
    if (identity.userIdentifier.isEmpty()) {
        return false;
    }

    DWORD size = sizeof(identity.sessionId);
    if (!GetTokenInformation(token, TokenSessionId, &identity.sessionId, size, &size)) {
        setError(errorMessage, QStringLiteral("TokenSessionId query failed"));
        return false;
    }

    TOKEN_STATISTICS statistics {};
    size = sizeof(statistics);
    if (!GetTokenInformation(token, TokenStatistics, &statistics, size, &size)) {
        setError(errorMessage, QStringLiteral("TokenStatistics query failed"));
        return false;
    }
    identity.logonIdentifier = QStringLiteral("%1:%2")
            .arg(statistics.AuthenticationId.HighPart)
            .arg(statistics.AuthenticationId.LowPart);

    return tokenContainsWellKnownSid(token, WinInteractiveSid, identity.interactive, errorMessage)
            && tokenContainsWellKnownSid(token, WinNetworkSid, identity.network, errorMessage);
}

bool queryProcessIdentity(DWORD processId, LocalPeerIdentity &identity, QString *errorMessage)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process) {
        setError(errorMessage, QStringLiteral("Unable to open local peer process"));
        return false;
    }

    std::wstring path(32768, L'\0');
    DWORD pathLength = static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(process, 0, path.data(), &pathLength) || pathLength == 0) {
        CloseHandle(process);
        setError(errorMessage, QStringLiteral("Unable to resolve local peer executable"));
        return false;
    }
    path.resize(pathLength);

    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &token)) {
        CloseHandle(process);
        setError(errorMessage, QStringLiteral("Unable to query local peer token"));
        return false;
    }

    WindowsTokenIdentity tokenIdentity;
    QString tokenError;
    const bool tokenResolved = queryWindowsTokenIdentity(token, tokenIdentity, &tokenError);
    CloseHandle(token);
    CloseHandle(process);
    if (!tokenResolved) {
        setError(errorMessage, tokenError);
        return false;
    }

    identity.processId = static_cast<qint64>(processId);
    identity.userIdentifier = tokenIdentity.userIdentifier;
    identity.logonIdentifier = tokenIdentity.logonIdentifier;
    identity.sessionId = tokenIdentity.sessionId;
    identity.executablePath = QString::fromStdWString(path);
    return true;
}

bool tokenCanModifyPath(HANDLE token, const QString &path, bool directory, QString *errorMessage)
{
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL dacl = nullptr;
    const DWORD status = GetNamedSecurityInfoW(
        reinterpret_cast<LPWSTR>(const_cast<ushort *>(path.utf16())), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &dacl, nullptr, &descriptor);
    if (status != ERROR_SUCCESS || descriptor == nullptr) {
        setError(errorMessage, QStringLiteral("Unable to read installed client ACL"));
        if (descriptor) {
            LocalFree(descriptor);
        }
        return true;
    }
    Q_UNUSED(dacl)

    HANDLE impersonationToken = nullptr;
    if (!DuplicateToken(token, SecurityImpersonation, &impersonationToken)) {
        LocalFree(descriptor);
        setError(errorMessage, QStringLiteral("Unable to duplicate local peer token"));
        return true;
    }

    GENERIC_MAPPING mapping {
        FILE_GENERIC_READ,
        FILE_GENERIC_WRITE,
        FILE_GENERIC_EXECUTE,
        FILE_ALL_ACCESS,
    };
    QByteArray privilegeStorage(4096, Qt::Uninitialized);
    auto *privileges = reinterpret_cast<PRIVILEGE_SET *>(privilegeStorage.data());
    DWORD privilegesSize = static_cast<DWORD>(privilegeStorage.size());
    DWORD grantedAccess = 0;
    BOOL accessStatus = FALSE;
    const BOOL checked = AccessCheck(descriptor, impersonationToken, MAXIMUM_ALLOWED, &mapping,
                                     privileges, &privilegesSize, &grantedAccess, &accessStatus);

    CloseHandle(impersonationToken);
    LocalFree(descriptor);
    if (!checked || !accessStatus) {
        setError(errorMessage, QStringLiteral("Unable to evaluate installed client ACL"));
        return true;
    }

    DWORD dangerous = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES
        | DELETE | WRITE_DAC | WRITE_OWNER;
    if (directory) {
        dangerous |= FILE_DELETE_CHILD | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY;
    }
    return (grantedAccess & dangerous) != 0;
}

bool installProtectedFromWindowsPeer(const LocalPeerIdentity &identity, const QString &expectedPath,
                                     QString *errorMessage)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                 static_cast<DWORD>(identity.processId));
    if (!process) {
        setError(errorMessage, QStringLiteral("Local peer exited before authorization"));
        return false;
    }

    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &token)) {
        CloseHandle(process);
        setError(errorMessage, QStringLiteral("Unable to query local peer token permissions"));
        return false;
    }

    const QFileInfo executable(expectedPath);
    const bool executableWritable = tokenCanModifyPath(token, executable.absoluteFilePath(), false,
                                                       errorMessage);
    const bool directoryWritable = !executableWritable
        && tokenCanModifyPath(token, executable.absolutePath(), true, errorMessage);
    CloseHandle(token);
    CloseHandle(process);

    if (executableWritable || directoryWritable) {
        if (errorMessage && errorMessage->isEmpty()) {
            *errorMessage = QStringLiteral("Installed client is replaceable by the local peer");
        }
        return false;
    }
    return true;
}

bool serviceExecutablePathFromCommandLine(const QString &commandLine,
                                          const QString &expectedPath, QString &path,
                                          QString *errorMessage)
{
    path.clear();
    const QString trimmed = commandLine.trimmed();
    if (trimmed.isEmpty()) {
        setError(errorMessage, QStringLiteral("Privileged VPN service has no binary path"));
        return false;
    }

    if (trimmed.startsWith(QLatin1Char('"'))) {
        const qsizetype closingQuote = trimmed.indexOf(QLatin1Char('"'), 1);
        if (closingQuote <= 1 || closingQuote != trimmed.size() - 1) {
            setError(errorMessage, QStringLiteral("Privileged VPN service must have exactly one binary path"));
            return false;
        }
        path = trimmed.mid(1, closingQuote - 1);
    } else {
        // Older packages registered the full path without quotation marks.
        // Treat the entire command line as that path; do not parse a prefix
        // before whitespace, because doing so would silently accept arguments.
        path = trimmed;
    }

    if (path.isEmpty() || !QFileInfo(path).isAbsolute()) {
        setError(errorMessage, QStringLiteral("Privileged VPN service binary path is not absolute"));
        return false;
    }
    if (!executablePathsMatch(path, expectedPath)) {
        setError(errorMessage, QStringLiteral("Privileged VPN service binary path is not the expected executable"));
        return false;
    }
    return true;
}

bool windowsServiceMatchesExpectedServer(const QString &serviceName, qint64 processId,
                                         const QString &expectedExecutablePath,
                                         QString *errorMessage)
{
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) {
        setError(errorMessage, QStringLiteral("Unable to open Windows service manager"));
        return false;
    }
    SC_HANDLE service = OpenServiceW(manager,
                                     reinterpret_cast<LPCWSTR>(serviceName.utf16()),
                                     SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!service) {
        CloseServiceHandle(manager);
        setError(errorMessage, QStringLiteral("Unable to query privileged VPN service"));
        return false;
    }

    SERVICE_STATUS_PROCESS statusBefore {};
    DWORD statusBytesNeeded = 0;
    const BOOL statusBeforeQueried = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                                           reinterpret_cast<LPBYTE>(&statusBefore),
                                                           sizeof(statusBefore), &statusBytesNeeded);
    if (!statusBeforeQueried || statusBefore.dwServiceType != SERVICE_WIN32_OWN_PROCESS
        || statusBefore.dwCurrentState != SERVICE_RUNNING
        || statusBefore.dwProcessId != static_cast<DWORD>(processId)) {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        setError(errorMessage, QStringLiteral("Named-pipe server is not the running VPN service"));
        return false;
    }

    DWORD configBytesNeeded = 0;
    QueryServiceConfigW(service, nullptr, 0, &configBytesNeeded);
    if (configBytesNeeded < sizeof(QUERY_SERVICE_CONFIGW)
        || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        setError(errorMessage, QStringLiteral("Unable to query privileged VPN service configuration"));
        return false;
    }
    std::vector<BYTE> configStorage(configBytesNeeded);
    auto *config = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(configStorage.data());
    if (!QueryServiceConfigW(service, config, configBytesNeeded, &configBytesNeeded)
        || config->lpBinaryPathName == nullptr || config->lpServiceStartName == nullptr) {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        setError(errorMessage, QStringLiteral("Unable to read privileged VPN service configuration"));
        return false;
    }

    const QString configuredCommandLine = QString::fromWCharArray(config->lpBinaryPathName);
    QString configuredExecutablePath;
    const bool configuredPathResolved = serviceExecutablePathFromCommandLine(
        configuredCommandLine, expectedExecutablePath, configuredExecutablePath, errorMessage);
    const bool ownProcess = config->dwServiceType == SERVICE_WIN32_OWN_PROCESS;
    const bool localSystem = QString::fromWCharArray(config->lpServiceStartName)
                                 .compare(QStringLiteral("LocalSystem"), Qt::CaseInsensitive) == 0;

    SERVICE_STATUS_PROCESS statusAfter {};
    statusBytesNeeded = 0;
    const BOOL statusAfterQueried = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                                          reinterpret_cast<LPBYTE>(&statusAfter),
                                                          sizeof(statusAfter), &statusBytesNeeded);
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (!configuredPathResolved || !ownProcess || !localSystem || !statusAfterQueried
        || statusAfter.dwServiceType != SERVICE_WIN32_OWN_PROCESS
        || statusAfter.dwCurrentState != SERVICE_RUNNING
        || statusAfter.dwProcessId != static_cast<DWORD>(processId)
        || statusBefore.dwProcessId != statusAfter.dwProcessId
        || !executablePathsMatch(configuredExecutablePath, expectedExecutablePath)) {
        if (errorMessage && errorMessage->isEmpty()) {
            *errorMessage = QStringLiteral("Named-pipe server is not the expected LocalSystem VPN service");
        }
        return false;
    }
    return true;
}

bool namedPipeServerProcessId(QLocalSocket *socket, qint64 &processId, QString *errorMessage)
{
    processId = -1;
    if (!socket || socket->socketDescriptor() == -1) {
        setError(errorMessage, QStringLiteral("Invalid local socket descriptor"));
        return false;
    }

    ULONG serverProcessId = 0;
    const HANDLE pipe = reinterpret_cast<HANDLE>(socket->socketDescriptor());
    if (!GetNamedPipeServerProcessId(pipe, &serverProcessId) || serverProcessId == 0) {
        setError(errorMessage, QStringLiteral("Unable to query named-pipe server PID"));
        return false;
    }
    processId = static_cast<qint64>(serverProcessId);
    return true;
}
#endif

#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS) || defined(Q_OS_MAC)
bool rootOwnedAndNotWritable(const QString &path, QString *errorMessage)
{
    const QByteArray nativePath = QFile::encodeName(path);
    struct stat info {};
    if (lstat(nativePath.constData(), &info) != 0 || !S_ISREG(info.st_mode)) {
        setError(errorMessage, QStringLiteral("Installed client is not a regular file"));
        return false;
    }
    if (info.st_uid != 0 || (info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        setError(errorMessage, QStringLiteral("Installed client is not protected from replacement"));
        return false;
    }

    QDir directory = QFileInfo(path).absoluteDir();
    while (true) {
        const QString directoryPath = directory.absolutePath();
        const QByteArray nativeDirectory = QFile::encodeName(directoryPath);
        struct stat directoryInfo {};
        if (lstat(nativeDirectory.constData(), &directoryInfo) != 0 || !S_ISDIR(directoryInfo.st_mode)
            || directoryInfo.st_uid != 0 || (directoryInfo.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            setError(errorMessage, QStringLiteral("Installed client directory is replaceable"));
            return false;
        }
        if (!directory.cdUp() || directory.absolutePath() == directoryPath) {
            break;
        }
    }
    return true;
}
#endif

#if defined(Q_OS_MACOS) || defined(Q_OS_MAC)
bool peerMatchesExpectedCodeRequirement(qint64 processId, const QString &expectedPath,
                                        QString *errorMessage)
{
    const QByteArray path = QFile::encodeName(expectedPath);
    CFURLRef expectedUrl = CFURLCreateFromFileSystemRepresentation(
        kCFAllocatorDefault, reinterpret_cast<const UInt8 *>(path.constData()),
        static_cast<CFIndex>(path.size()), false);
    if (!expectedUrl) {
        setError(errorMessage, QStringLiteral("Unable to create expected client code URL"));
        return false;
    }

    SecStaticCodeRef expectedCode = nullptr;
    OSStatus status = SecStaticCodeCreateWithPath(expectedUrl, kSecCSDefaultFlags, &expectedCode);
    CFRelease(expectedUrl);
    if (status != errSecSuccess || !expectedCode) {
        setError(errorMessage, QStringLiteral("Unable to load expected client code signature"));
        return false;
    }

    SecRequirementRef requirement = nullptr;
    status = SecCodeCopyDesignatedRequirement(expectedCode, kSecCSDefaultFlags, &requirement);
    CFRelease(expectedCode);
    if (status != errSecSuccess || !requirement) {
        setError(errorMessage, QStringLiteral("Expected client is not signed"));
        return false;
    }

    pid_t pid = static_cast<pid_t>(processId);
    CFNumberRef pidNumber = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &pid);
    const void *keys[] = { kSecGuestAttributePid };
    const void *values[] = { pidNumber };
    CFDictionaryRef attributes = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1,
                                                     &kCFTypeDictionaryKeyCallBacks,
                                                     &kCFTypeDictionaryValueCallBacks);
    SecCodeRef guestCode = nullptr;
    status = SecCodeCopyGuestWithAttributes(nullptr, attributes, kSecCSDefaultFlags, &guestCode);
    CFRelease(attributes);
    CFRelease(pidNumber);
    if (status == errSecSuccess && guestCode) {
        status = SecCodeCheckValidity(guestCode, kSecCSStrictValidate, requirement);
        CFRelease(guestCode);
    }
    CFRelease(requirement);

    if (status != errSecSuccess) {
        setError(errorMessage, QStringLiteral("Local peer code signature is not trusted"));
        return false;
    }
    return true;
}
#endif

} // namespace

QString canonicalExecutablePath(const QString &path)
{
    QFileInfo info(path);
    QString result = info.canonicalFilePath();
    if (result.isEmpty()) {
        result = QDir::cleanPath(info.absoluteFilePath());
    }
#ifdef Q_OS_WIN
    if (result.startsWith(QStringLiteral("\\\\?\\"))) {
        result.remove(0, 4);
    }
#endif
    return QDir::cleanPath(result);
}

bool executablePathsMatch(const QString &actualPath, const QString &expectedPath)
{
    const QString actual = canonicalExecutablePath(actualPath);
    const QString expected = canonicalExecutablePath(expectedPath);
    if (actual.isEmpty() || expected.isEmpty()) {
        return false;
    }
#ifdef Q_OS_WIN
    return actual.compare(expected, Qt::CaseInsensitive) == 0;
#else
    return actual == expected;
#endif
}

QString currentProcessUserIdentifier(QString *errorMessage)
{
#ifdef Q_OS_WIN
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        setError(errorMessage, QStringLiteral("Unable to query current process token"));
        return {};
    }
    const QString result = sidForToken(token, errorMessage);
    CloseHandle(token);
    return result;
#elif defined(Q_OS_LINUX) || defined(Q_OS_MACOS) || defined(Q_OS_MAC)
    Q_UNUSED(errorMessage)
    return QString::number(static_cast<qulonglong>(geteuid()));
#else
    setError(errorMessage, QStringLiteral("Local peer identity is unsupported on this platform"));
    return {};
#endif
}

bool queryLocalPeerIdentity(QLocalSocket *socket, LocalPeerIdentity &identity, QString *errorMessage)
{
    identity = {};
    if (!socket || socket->socketDescriptor() == -1) {
        setError(errorMessage, QStringLiteral("Invalid local socket descriptor"));
        return false;
    }

#ifdef Q_OS_WIN
    if (!isWindowsPrivilegedPipeSocket(socket)) {
        setError(errorMessage, QStringLiteral("Socket did not use the hardened local pipe transport"));
        return false;
    }
    const HANDLE pipe = reinterpret_cast<HANDLE>(socket->socketDescriptor());
    if (!ImpersonateNamedPipeClient(pipe)) {
        setError(errorMessage, QStringLiteral("Unable to impersonate named-pipe client"));
        return false;
    }

    HANDLE pipeToken = nullptr;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &pipeToken)) {
        if (!RevertToSelf()) {
            qFatal("Unable to revert named-pipe client impersonation");
        }
        setError(errorMessage, QStringLiteral("Unable to query named-pipe client token"));
        return false;
    }
    WindowsTokenIdentity pipeIdentity;
    QString pipeIdentityError;
    const bool pipeIdentityResolved =
            queryWindowsTokenIdentity(pipeToken, pipeIdentity, &pipeIdentityError);
    CloseHandle(pipeToken);
    const bool reverted = RevertToSelf();
    if (!reverted) {
        qFatal("Unable to revert named-pipe client impersonation");
    }
    if (!pipeIdentityResolved) {
        setError(errorMessage, pipeIdentityError);
        return false;
    }
    if (pipeIdentity.network || !pipeIdentity.interactive || pipeIdentity.sessionId == 0
        || pipeIdentity.logonIdentifier.isEmpty()) {
        setError(errorMessage, QStringLiteral("Named-pipe client is not a local interactive logon"));
        return false;
    }

    ULONG pipeSessionId = 0;
    if (!GetNamedPipeClientSessionId(pipe, &pipeSessionId)
        || pipeSessionId != pipeIdentity.sessionId) {
        setError(errorMessage, QStringLiteral("Named-pipe client session mismatch"));
        return false;
    }

    ULONG processId = 0;
    if (!GetNamedPipeClientProcessId(pipe, &processId) || processId == 0) {
        setError(errorMessage, QStringLiteral("Unable to query named-pipe client PID"));
        return false;
    }
    LocalPeerIdentity processIdentity;
    if (!queryProcessIdentity(processId, processIdentity, errorMessage)) {
        return false;
    }
    if (processIdentity.userIdentifier.compare(pipeIdentity.userIdentifier,
                                                Qt::CaseInsensitive) != 0
        || processIdentity.logonIdentifier != pipeIdentity.logonIdentifier
        || processIdentity.sessionId != pipeIdentity.sessionId) {
        setError(errorMessage, QStringLiteral("Named-pipe token does not match its client process"));
        return false;
    }
    identity = processIdentity;
    return true;
#elif defined(Q_OS_LINUX)
    struct PeerCredentials {
        pid_t pid;
        uid_t uid;
        gid_t gid;
    } credentials {};
    socklen_t length = sizeof(credentials);
    if (getsockopt(static_cast<int>(socket->socketDescriptor()), SOL_SOCKET, SO_PEERCRED,
                   &credentials, &length) != 0
        || length != sizeof(credentials) || credentials.pid <= 0) {
        setError(errorMessage, QStringLiteral("Unable to query Unix peer credentials"));
        return false;
    }

    const QString linkPath = QStringLiteral("/proc/%1/exe").arg(credentials.pid);
    const QString executable = QFileInfo(linkPath).symLinkTarget();
    if (executable.isEmpty()) {
        setError(errorMessage, QStringLiteral("Unable to resolve Unix peer executable"));
        return false;
    }
    identity.processId = static_cast<qint64>(credentials.pid);
    identity.userIdentifier = QString::number(static_cast<qulonglong>(credentials.uid));
    identity.executablePath = executable;
    return true;
#elif defined(Q_OS_MACOS) || defined(Q_OS_MAC)
    const int descriptor = static_cast<int>(socket->socketDescriptor());
    uid_t uid = 0;
    gid_t gid = 0;
    if (getpeereid(descriptor, &uid, &gid) != 0) {
        setError(errorMessage, QStringLiteral("Unable to query Unix peer user"));
        return false;
    }

    pid_t processId = 0;
    socklen_t length = sizeof(processId);
    if (getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERPID, &processId, &length) != 0
        || length != sizeof(processId) || processId <= 0) {
        setError(errorMessage, QStringLiteral("Unable to query Unix peer PID"));
        return false;
    }

    QByteArray path(PROC_PIDPATHINFO_MAXSIZE, Qt::Uninitialized);
    const int pathLength = proc_pidpath(processId, path.data(), static_cast<uint32_t>(path.size()));
    if (pathLength <= 0) {
        setError(errorMessage, QStringLiteral("Unable to resolve Unix peer executable"));
        return false;
    }
    identity.processId = static_cast<qint64>(processId);
    identity.userIdentifier = QString::number(static_cast<qulonglong>(uid));
    identity.executablePath = QString::fromUtf8(path.constData(), pathLength);
    return true;
#else
    setError(errorMessage, QStringLiteral("Local peer identity is unsupported on this platform"));
    return false;
#endif
}

bool queryLocalServerIdentity(QLocalSocket *socket, LocalPeerIdentity &identity, QString *errorMessage)
{
#ifdef Q_OS_WIN
    identity = {};
    if (!socket || socket->socketDescriptor() == -1) {
        setError(errorMessage, QStringLiteral("Invalid local socket descriptor"));
        return false;
    }
    ULONG processId = 0;
    const HANDLE pipe = reinterpret_cast<HANDLE>(socket->socketDescriptor());
    if (!GetNamedPipeServerProcessId(pipe, &processId) || processId == 0) {
        setError(errorMessage, QStringLiteral("Unable to query named-pipe server PID"));
        return false;
    }
    ULONG pipeSessionId = (std::numeric_limits<ULONG>::max)();
    if (!GetNamedPipeServerSessionId(pipe, &pipeSessionId)
        || !queryProcessIdentity(processId, identity, errorMessage)
        || identity.sessionId != pipeSessionId) {
        setError(errorMessage, QStringLiteral("Named-pipe server session mismatch"));
        identity = {};
        return false;
    }
    return true;
#else
    // SO_PEERCRED/getpeereid are symmetric for connected Unix-domain sockets.
    return queryLocalPeerIdentity(socket, identity, errorMessage);
#endif
}

bool authorizePrivilegedClient(QLocalSocket *socket, const QString &expectedExecutablePath,
                               LocalPeerIdentity *identity, QString *errorMessage)
{
#ifdef Q_OS_WIN
    if (!isWindowsPrivilegedPipeSocket(socket)) {
        setError(errorMessage, QStringLiteral("Client did not use the hardened local pipe transport"));
        return false;
    }
#endif
    LocalPeerIdentity resolved;
    if (!queryLocalPeerIdentity(socket, resolved, errorMessage)) {
        return false;
    }

    const QString expected = canonicalExecutablePath(expectedExecutablePath);
    if (!QFileInfo(expected).isFile() || !executablePathsMatch(resolved.executablePath, expected)) {
        setError(errorMessage, QStringLiteral("Local peer executable is not the installed VPN client"));
        return false;
    }

#ifdef Q_OS_WIN
    if (!installProtectedFromWindowsPeer(resolved, expected, errorMessage)) {
        return false;
    }
#elif defined(Q_OS_LINUX)
    if (!rootOwnedAndNotWritable(expected, errorMessage)) {
        return false;
    }
#elif defined(Q_OS_MACOS) || defined(Q_OS_MAC)
    if (!rootOwnedAndNotWritable(expected, errorMessage)
        || !peerMatchesExpectedCodeRequirement(resolved.processId, expected, errorMessage)) {
        return false;
    }
#else
    setError(errorMessage, QStringLiteral("Privileged peer authorization is unsupported"));
    return false;
#endif

    if (identity) {
        *identity = resolved;
    }
    return true;
}

bool authorizePrivilegedServer(QLocalSocket *socket, const QString &expectedExecutablePath,
                               const QString &windowsServiceName, LocalPeerIdentity *identity,
                               QString *errorMessage)
{
#ifndef Q_OS_WIN
    Q_UNUSED(windowsServiceName)
#endif
#ifdef Q_OS_WIN
    if (!isWindowsPrivilegedPipeSocket(socket)) {
        setError(errorMessage, QStringLiteral("Server did not use the hardened local pipe transport"));
        return false;
    }
#endif

    const QString expected = canonicalExecutablePath(expectedExecutablePath);
    if (!QFileInfo(expected).isFile()) {
        setError(errorMessage, QStringLiteral("Expected VPN service executable is missing"));
        return false;
    }

    LocalPeerIdentity resolved;

#ifndef Q_OS_WIN
    if (!queryLocalServerIdentity(socket, resolved, errorMessage)) {
        return false;
    }
    if (!executablePathsMatch(resolved.executablePath, expected)) {
        setError(errorMessage, QStringLiteral("Local socket server is not the installed VPN service"));
        return false;
    }
#endif

#ifdef Q_OS_WIN
    qint64 serverProcessId = -1;
    if (!namedPipeServerProcessId(socket, serverProcessId, errorMessage)
        || !windowsServiceMatchesExpectedServer(windowsServiceName, serverProcessId, expected,
                                                errorMessage)) {
        return false;
    }

    // A standard user cannot inspect the LocalSystem process token.  The SCM
    // is the authority for its account, process type, configured binary and
    // running PID, while GetNamedPipeServerProcessId binds those facts to this
    // connected pipe endpoint.
    resolved.processId = serverProcessId;
    resolved.userIdentifier = QStringLiteral("S-1-5-18");
    resolved.sessionId = 0;
    resolved.executablePath = expected;

    LocalPeerIdentity currentProcess;
    QString currentError;
    if (!queryProcessIdentity(GetCurrentProcessId(), currentProcess, &currentError)
        || !installProtectedFromWindowsPeer(currentProcess, expected, errorMessage)) {
        if (errorMessage && errorMessage->isEmpty()) {
            *errorMessage = currentError;
        }
        return false;
    }
#elif defined(Q_OS_LINUX)
    if (resolved.userIdentifier != QStringLiteral("0")
        || !rootOwnedAndNotWritable(expected, errorMessage)) {
        if (errorMessage && errorMessage->isEmpty()) {
            *errorMessage = QStringLiteral("Local socket server is not root-owned");
        }
        return false;
    }
#elif defined(Q_OS_MACOS) || defined(Q_OS_MAC)
    if (resolved.userIdentifier != QStringLiteral("0")
        || !rootOwnedAndNotWritable(expected, errorMessage)
        || !peerMatchesExpectedCodeRequirement(resolved.processId, expected, errorMessage)) {
        if (errorMessage && errorMessage->isEmpty()) {
            *errorMessage = QStringLiteral("Local socket server is not trusted");
        }
        return false;
    }
#else
    setError(errorMessage, QStringLiteral("Privileged server authorization is unsupported"));
    return false;
#endif

    if (identity) {
        *identity = resolved;
    }
    return true;
}

QString installedClientExecutablePath()
{
    QString executableName = QStringLiteral("AmneziaVPN");
#ifdef Q_OS_WIN
    executableName += QStringLiteral(".exe");
#endif
    return QDir(QCoreApplication::applicationDirPath()).filePath(executableName);
}

QString installedServiceExecutablePath()
{
    QString executableName = QStringLiteral("AmneziaVPN-service");
#ifdef Q_OS_WIN
    executableName += QStringLiteral(".exe");
#endif
    return QDir(QCoreApplication::applicationDirPath()).filePath(executableName);
}

bool preparePrivilegedIpcRuntime(QString *errorMessage)
{
#ifdef Q_OS_WIN
    Q_UNUSED(errorMessage)
    return true;
#elif defined(Q_OS_LINUX) || defined(Q_OS_MACOS) || defined(Q_OS_MAC)
    const QString runtimePath = QStringLiteral("/var/run/amneziavpn");
    const QByteArray nativePath = QFile::encodeName(runtimePath);
    struct stat info {};
    if (lstat(nativePath.constData(), &info) != 0) {
        if (::mkdir(nativePath.constData(), S_IRWXU | S_IXGRP | S_IXOTH) != 0) {
            setError(errorMessage, QStringLiteral("Unable to create privileged IPC runtime directory"));
            return false;
        }
        if (lstat(nativePath.constData(), &info) != 0) {
            setError(errorMessage, QStringLiteral("Unable to inspect privileged IPC runtime directory"));
            return false;
        }
    }

    if (!S_ISDIR(info.st_mode) || info.st_uid != 0) {
        setError(errorMessage, QStringLiteral("Privileged IPC runtime path is not a root-owned directory"));
        return false;
    }
    // Known control sockets remain traversable, while random capability names
    // cannot be discovered by listing the directory.
    if (::chmod(nativePath.constData(), S_IRWXU | S_IXGRP | S_IXOTH) != 0) {
        setError(errorMessage, QStringLiteral("Unable to secure privileged IPC runtime directory"));
        return false;
    }
    return true;
#else
    setError(errorMessage, QStringLiteral("Privileged IPC runtime is unsupported"));
    return false;
#endif
}

bool removeStalePrivilegedSocket(const QString &path, QString *errorMessage)
{
#ifdef Q_OS_WIN
    Q_UNUSED(path)
    Q_UNUSED(errorMessage)
    return true;
#elif defined(Q_OS_LINUX) || defined(Q_OS_MACOS) || defined(Q_OS_MAC)
    const QByteArray nativePath = QFile::encodeName(path);
    struct stat info {};
    if (lstat(nativePath.constData(), &info) != 0) {
        return true;
    }
    if (!S_ISSOCK(info.st_mode) || info.st_uid != 0) {
        setError(errorMessage, QStringLiteral("Refusing to remove an untrusted IPC path"));
        return false;
    }

    QLocalSocket probe;
    probe.connectToServer(path, QIODevice::ReadWrite);
    if (probe.waitForConnected(100)) {
        probe.disconnectFromServer();
        setError(errorMessage, QStringLiteral("A privileged IPC server is already listening"));
        return false;
    }
    if (!QLocalServer::removeServer(path)) {
        setError(errorMessage, QStringLiteral("Unable to remove stale privileged IPC socket"));
        return false;
    }
    return true;
#else
    Q_UNUSED(path)
    setError(errorMessage, QStringLiteral("Privileged IPC runtime is unsupported"));
    return false;
#endif
}

} // namespace amnezia::ipc
