#include "updateController.h"

#include <QCryptographicHash>
#include <QDate>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QNetworkReply>
#include <QProcess>
#include <QProcessEnvironment>
#include <QSaveFile>
#include <QSet>
#include <QStandardPaths>
#include <QVersionNumber>
#include <QUrl>
#include <QUrlQuery>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTimer>
#include <QUuid>
#include <QVector>

#if defined(Q_OS_WINDOWS)
    #include <aclapi.h>
    #include <sddl.h>
    #include <qt_windows.h>
    #pragma comment(lib, "Advapi32.lib")
#elif defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    #include <cerrno>
    #include <fcntl.h>
    #include <linux/memfd.h>
    #include <signal.h>
    #include <sys/stat.h>
    #include <sys/syscall.h>
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <unistd.h>
    extern char **environ;
#endif

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "amneziaApplication.h"
#include "logger.h"
#include "version.h"
#include "core/controllers/gatewayController.h"
#include "core/utils/api/gatewayPayloadBuilder.h"
#include "core/utils/constants/apiKeys.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/selfhostedUpdatePolicy.h"
#include "core/utils/selfhosted/scriptsRegistry.h"
#if defined(Q_OS_ANDROID)
    #include "platforms/android/android_controller.h"
#endif

namespace
{
    Logger logger("UpdateController");

    using amnezia::selfhostedUpdatePolicy::GenerationBindingDisposition;
    using amnezia::selfhostedUpdatePolicy::PlatformFamily;
    using amnezia::selfhostedUpdatePolicy::ReleasePolicyDisposition;
    using amnezia::selfhostedUpdatePolicy::CohortBucketCount;
    using amnezia::selfhostedUpdatePolicy::cohortBucket;
    using amnezia::selfhostedUpdatePolicy::evaluateGenerationBinding;
    using amnezia::selfhostedUpdatePolicy::automaticRollbackRunningVersionAllowed;
    using amnezia::selfhostedUpdatePolicy::boundedAuthorizationExpiry;
    using amnezia::selfhostedUpdatePolicy::evaluateRollbackLease;
    using amnezia::selfhostedUpdatePolicy::isCanonicalCohortSaltId;
    using amnezia::selfhostedUpdatePolicy::isCanonicalReleaseChannel;
    using amnezia::selfhostedUpdatePolicy::isCanonicalSha256;
    using amnezia::selfhostedUpdatePolicy::normalizeSha256;
    using amnezia::selfhostedUpdatePolicy::normalizedPrivateInstallerStagingPath;
    using amnezia::selfhostedUpdatePolicy::parseCanonicalUtcTimestamp;
    using amnezia::selfhostedUpdatePolicy::parseExactVersion;
    using amnezia::selfhostedUpdatePolicy::releasePolicyDispositionName;
    using amnezia::selfhostedUpdatePolicy::rollbackPolicyBindingMatches;
    using amnezia::selfhostedUpdatePolicy::RollbackLeaseDisposition;
    using amnezia::selfhostedUpdatePolicy::shouldTryNextManifest;

#if defined(Q_OS_WINDOWS)
    const QLatin1String kInstallerRemoteFileNamePattern("AmneziaVPN_%1_windows_x64.exe");
#elif defined(Q_OS_MACOS) && !defined(MACOS_NE)
    const QLatin1String kInstallerRemoteFileNamePattern("AmneziaVPN_%1_macos_x64.pkg");
#elif defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    const QLatin1String kInstallerRemoteFileNamePattern("AmneziaVPN_%1_linux_x64.run");
#endif

#ifndef SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64
#define SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64 ""
#endif

    constexpr qsizetype kManifestMaxPayloadBytes = 1024 * 1024;
    constexpr int kManifestTransferTimeoutMs = 7000;
    constexpr int kInstallerTransferTimeoutMs = 2 * 60 * 1000;
    constexpr int kInstallerTotalDeadlineMs = 25 * 60 * 1000;
    constexpr int kInitialBackgroundUpdateCheckMs = 60 * 1000;
    constexpr int kBackgroundUpdateCheckIntervalMs = 6 * 60 * 60 * 1000;
    constexpr int kDesktopQuitAfterInstallerStartMs = 1500;
    constexpr int kAndroidApkInstallPermissionWaitMs = 10 * 60 * 1000;
    constexpr int kAndroidInstallerAuthorizationSchema = 2;
    constexpr int kAndroidApkInstallFailed = 0;
    constexpr int kAndroidApkInstallStarted = 1;
    constexpr int kAndroidApkInstallPermissionSettingsOpened = 2;
    // Core waits up to 30 seconds for the privileged service before acknowledging
    // a healthy start. Keep a strict buffer so an accepted policy cannot expire
    // at the readiness timer boundary.
    constexpr int kMinimumHealthDeadlineSeconds = 60;
    constexpr int kMaximumHealthDeadlineSeconds = 24 * 60 * 60;
    constexpr int kRollbackConfirmationTimeoutSeconds = 30 * 60;
    constexpr qint64 kMaximumSafeJsonInteger = 9007199254740991LL;
    constexpr qint64 kMaximumAndroidVersionCode = 2100000000LL;
    constexpr int kHealthReceiptSchema = 2;
    constexpr int kRollbackIntentLeaseSeconds = kInstallerTotalDeadlineMs / 1000 + 60;
    constexpr int kMaximumAutomaticRollbackRecoveries = 1;
    constexpr int kMaximumAutomaticRollbackConfirmationFailures = 1;
    constexpr int kMaximumAutomaticRollbackPreHandoffFailures = 3;
    constexpr int kAutomaticRollbackInitialRetrySeconds = 15;

    int automaticRollbackRetryDelaySeconds(int failureCount)
    {
        const int boundedFailureCount = qBound(
                1, failureCount, kMaximumAutomaticRollbackPreHandoffFailures);
        return kAutomaticRollbackInitialRetrySeconds << (boundedFailureCount - 1);
    }

#if defined(Q_OS_WINDOWS)
    bool currentWindowsUserSid(QByteArray &tokenBuffer, PSID &sid)
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            return false;
        }
        DWORD requiredBytes = 0;
        (void) GetTokenInformation(token, TokenUser, nullptr, 0, &requiredBytes);
        tokenBuffer.resize(static_cast<qsizetype>(requiredBytes));
        const bool ok = requiredBytes > 0
                && GetTokenInformation(token, TokenUser, tokenBuffer.data(), requiredBytes,
                                       &requiredBytes);
        CloseHandle(token);
        if (!ok) {
            sid = nullptr;
            return false;
        }
        sid = reinterpret_cast<TOKEN_USER *>(tokenBuffer.data())->User.Sid;
        return IsValidSid(sid);
    }

    bool createPrivateWindowsInstallerDirectory(const QString &tempRoot,
                                                QString &directoryOut)
    {
        QByteArray tokenBuffer;
        PSID userSid = nullptr;
        if (!currentWindowsUserSid(tokenBuffer, userSid)) {
            return false;
        }
        LPWSTR sidText = nullptr;
        if (!ConvertSidToStringSidW(userSid, &sidText)) {
            return false;
        }
        const QString securityDescriptorText = QStringLiteral(
                "D:P(A;OICI;FA;;;%1)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
                                                       .arg(QString::fromWCharArray(sidText));
        LocalFree(sidText);

        PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    reinterpret_cast<LPCWSTR>(securityDescriptorText.utf16()),
                    SDDL_REVISION_1, &securityDescriptor, nullptr)) {
            return false;
        }
        SECURITY_ATTRIBUTES securityAttributes {};
        securityAttributes.nLength = sizeof(securityAttributes);
        securityAttributes.lpSecurityDescriptor = securityDescriptor;
        securityAttributes.bInheritHandle = FALSE;

        bool created = false;
        for (int attempt = 0; attempt < 8 && !created; ++attempt) {
            const QString candidate = QDir::cleanPath(
                    tempRoot + QStringLiteral("/amnezia-update-")
                    + QUuid::createUuid().toString(QUuid::WithoutBraces).toLower());
            const QString nativeCandidate = QDir::toNativeSeparators(candidate);
            if (CreateDirectoryW(reinterpret_cast<LPCWSTR>(nativeCandidate.utf16()),
                                 &securityAttributes)) {
                const DWORD attributes = GetFileAttributesW(
                        reinterpret_cast<LPCWSTR>(nativeCandidate.utf16()));
                if (attributes != INVALID_FILE_ATTRIBUTES
                    && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
                    && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
                    directoryOut = candidate;
                    created = true;
                } else {
                    (void) RemoveDirectoryW(
                            reinterpret_cast<LPCWSTR>(nativeCandidate.utf16()));
                }
            } else if (GetLastError() != ERROR_ALREADY_EXISTS) {
                break;
            }
        }
        LocalFree(securityDescriptor);
        return created;
    }

    bool windowsInstallerDirectoryIsPrivate(HANDLE directoryHandle)
    {
        PSID ownerSid = nullptr;
        PACL dacl = nullptr;
        PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
        const DWORD securityResult = GetSecurityInfo(
                directoryHandle, SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &ownerSid, nullptr, &dacl, nullptr, &securityDescriptor);
        if (securityResult != ERROR_SUCCESS || !ownerSid || !dacl || !securityDescriptor) {
            if (securityDescriptor) {
                LocalFree(securityDescriptor);
            }
            return false;
        }

        QByteArray tokenBuffer;
        PSID userSid = nullptr;
        BYTE systemSidBuffer[SECURITY_MAX_SID_SIZE] {};
        BYTE administratorsSidBuffer[SECURITY_MAX_SID_SIZE] {};
        DWORD systemSidSize = sizeof(systemSidBuffer);
        DWORD administratorsSidSize = sizeof(administratorsSidBuffer);
        const bool identitiesValid = currentWindowsUserSid(tokenBuffer, userSid)
                && CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSidBuffer,
                                      &systemSidSize)
                && CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr,
                                      administratorsSidBuffer, &administratorsSidSize)
                && EqualSid(ownerSid, userSid);
        SECURITY_DESCRIPTOR_CONTROL descriptorControl = 0;
        DWORD descriptorRevision = 0;
        const bool protectedDacl = GetSecurityDescriptorControl(
                securityDescriptor, &descriptorControl, &descriptorRevision)
                && (descriptorControl & SE_DACL_PROTECTED) != 0;

        bool exactAcl = identitiesValid && protectedDacl && dacl->AceCount == 3;
        bool userAcePresent = false;
        for (DWORD index = 0; exactAcl && index < dacl->AceCount; ++index) {
            void *rawAce = nullptr;
            if (!GetAce(dacl, index, &rawAce)) {
                exactAcl = false;
                break;
            }
            const auto *header = static_cast<ACE_HEADER *>(rawAce);
            if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
                exactAcl = false;
                break;
            }
            const auto *allowedAce = static_cast<ACCESS_ALLOWED_ACE *>(rawAce);
            PSID aceSid = const_cast<DWORD *>(&allowedAce->SidStart);
            const bool isUser = EqualSid(aceSid, userSid);
            const bool allowedIdentity = isUser
                    || EqualSid(aceSid, systemSidBuffer)
                    || EqualSid(aceSid, administratorsSidBuffer);
            if (!allowedIdentity || allowedAce->Mask != FILE_ALL_ACCESS) {
                exactAcl = false;
                break;
            }
            userAcePresent = userAcePresent || isUser;
        }
        LocalFree(securityDescriptor);
        return exactAcl && userAcePresent;
    }

    QString finalWindowsPathForHandle(HANDLE handle)
    {
        const DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
        const DWORD requiredCharacters = GetFinalPathNameByHandleW(handle, nullptr, 0, flags);
        if (requiredCharacters == 0) {
            return {};
        }
        QVector<wchar_t> buffer(static_cast<qsizetype>(requiredCharacters) + 1, L'\0');
        const DWORD writtenCharacters = GetFinalPathNameByHandleW(
                handle, buffer.data(), static_cast<DWORD>(buffer.size()), flags);
        if (writtenCharacters == 0 || writtenCharacters >= buffer.size()) {
            return {};
        }
        return QString::fromWCharArray(buffer.constData(),
                                      static_cast<qsizetype>(writtenCharacters));
    }

    bool windowsDirectoryContainsOnlyInstaller(const QString &resolvedDirectory,
                                               const QString &installerFileName)
    {
        const QString searchPath = QDir::toNativeSeparators(
                resolvedDirectory + QStringLiteral("/*"));
        WIN32_FIND_DATAW findData {};
        HANDLE findHandle = FindFirstFileW(
                reinterpret_cast<LPCWSTR>(searchPath.utf16()), &findData);
        if (findHandle == INVALID_HANDLE_VALUE) {
            return false;
        }
        bool foundInstaller = false;
        bool exactContents = true;
        do {
            const QString name = QString::fromWCharArray(findData.cFileName);
            if (name == QStringLiteral(".") || name == QStringLiteral("..")) {
                continue;
            }
            if (name.compare(installerFileName, Qt::CaseInsensitive) != 0
                || foundInstaller
                || (findData.dwFileAttributes
                    & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
                exactContents = false;
                break;
            }
            foundInstaller = true;
        } while (FindNextFileW(findHandle, &findData));
        const DWORD findError = GetLastError();
        FindClose(findHandle);
        return exactContents && foundInstaller && findError == ERROR_NO_MORE_FILES;
    }
#endif

#if defined(Q_OS_ANDROID)
    bool isCanonicalAndroidInstallerStagingPath(const QString &storedPath,
                                                QString *normalizedPath = nullptr,
                                                bool requireLivePath = false)
    {
        QString cleanPath;
        const QString tempRoot = QDir::cleanPath(QFileInfo(
                QStandardPaths::writableLocation(QStandardPaths::TempLocation))
                                                         .absoluteFilePath());
        if (!normalizedPrivateInstallerStagingPath(
                    storedPath, tempRoot, QStringLiteral("amnezia-update-"),
                    QStringLiteral("AmneziaVPN.apk"), &cleanPath)) {
            return false;
        }
        if (!requireLivePath) {
            if (normalizedPath) {
                *normalizedPath = cleanPath;
            }
            return true;
        }
        const QFileInfo installerInfo(cleanPath);
        const QFileInfo stagingDirectory(installerInfo.absolutePath());
        const QString canonicalTempRoot = QFileInfo(tempRoot).canonicalFilePath();
        const QString canonicalStagingDirectory = stagingDirectory.canonicalFilePath();
        if (!stagingDirectory.exists() || !stagingDirectory.isDir()
            || stagingDirectory.isSymLink() || canonicalTempRoot.isEmpty()
            || canonicalStagingDirectory.isEmpty()
            || canonicalStagingDirectory
                    != QDir(canonicalTempRoot).filePath(stagingDirectory.fileName())
            || stagingDirectory.canonicalPath() != canonicalTempRoot
            || (installerInfo.exists()
                && (!installerInfo.isFile() || installerInfo.isSymLink()))) {
            return false;
        }

        if (normalizedPath) {
            *normalizedPath = cleanPath;
        }
        return true;
    }
#endif

    bool jsonIntegerInRange(const QJsonValue &value, qint64 minimum, qint64 maximum, qint64 &result)
    {
        if (!value.isDouble()) {
            return false;
        }
        const double rawValue = value.toDouble();
        if (rawValue < static_cast<double>(minimum) || rawValue > static_cast<double>(maximum)) {
            return false;
        }
        const qint64 integerValue = static_cast<qint64>(rawValue);
        if (static_cast<double>(integerValue) != rawValue) {
            return false;
        }
        result = integerValue;
        return true;
    }

    bool jsonIntegerInRange(const QJsonValue &value, int minimum, int maximum, int &result)
    {
        qint64 integerValue = 0;
        if (!jsonIntegerInRange(value, static_cast<qint64>(minimum), static_cast<qint64>(maximum), integerValue)) {
            return false;
        }
        result = static_cast<int>(integerValue);
        return true;
    }

    QString utcTimestamp(const QDateTime &dateTime)
    {
        return dateTime.toUTC().toString(Qt::ISODateWithMs);
    }

    QDateTime storedUtcTimestamp(const QVariant &value)
    {
        QDateTime dateTime = value.toDateTime();
        if (!dateTime.isValid()) {
            dateTime = QDateTime::fromString(value.toString(), Qt::ISODateWithMs);
        }
        if (!dateTime.isValid()) {
            dateTime = QDateTime::fromString(value.toString(), Qt::ISODate);
        }
        return dateTime.isValid() ? dateTime.toUTC() : QDateTime();
    }

    QString boundedReceiptReason(const QString &reason)
    {
        const QString normalized = reason.simplified().left(160);
        return normalized.isEmpty() ? QStringLiteral("unspecified") : normalized;
    }

    QString selfHostedUpdateUrl(const QString &host, const QString &path)
    {
        const QString trimmedHost = host.trimmed().isEmpty()
                ? QString::fromLatin1(amnezia::protocols::selfHostedUpdates::syncHost)
                : host.trimmed();
        const QString normalizedPath = path.startsWith('/') ? path : QStringLiteral("/%1").arg(path);

        QString endpoint = trimmedHost;
        if (!endpoint.contains(QStringLiteral("://"))) {
            const bool looksLikeUnbracketedIpv6 = endpoint.count(QLatin1Char(':')) > 1
                    && !endpoint.startsWith(QLatin1Char('['));
            endpoint = looksLikeUnbracketedIpv6
                    ? QStringLiteral("http://[%1]").arg(endpoint)
                    : QStringLiteral("http://%1").arg(endpoint);
        }

        QUrl url(endpoint);
        if (url.port() < 0) {
            url.setPort(amnezia::protocols::selfHostedUpdates::syncPort);
        }
        url.setPath(normalizedPath);
        url.setQuery(QString());
        url.setFragment(QString());
        return url.toString();
    }

    bool isHttpOrHttpsUrl(const QUrl &url)
    {
        const QString scheme = url.scheme().toLower();
        return (scheme == QStringLiteral("http") || scheme == QStringLiteral("https")) && !url.host().isEmpty();
    }

    bool isAllowedExternalUpdateUrl(const QUrl &url)
    {
        if (!url.isValid() || url.isEmpty()) {
            return false;
        }

        const QString scheme = url.scheme().toLower();
#if defined(Q_OS_IOS)
        if (scheme == QStringLiteral("http")) {
            return false;
        }
#endif
        // External handoff cannot verify the bytes that the browser or store
        // eventually downloads. Require transport authentication everywhere;
        // locally downloaded http(s) artifacts remain protected by sha256/size.
        if (scheme == QStringLiteral("https")) {
            return !url.host().isEmpty();
        }
#if defined(Q_OS_IOS)
        if (scheme == QStringLiteral("itms-services")) {
            const QUrlQuery query(url);
            const QUrl manifestUrl(query.queryItemValue(QStringLiteral("url")));
            return manifestUrl.scheme().toLower() == QStringLiteral("https") && !manifestUrl.host().isEmpty();
        }
        if (scheme == QStringLiteral("itms-apps")) {
            return !url.host().isEmpty();
        }
        return false;
#else
        return false;
#endif
    }

    bool decodeStrictBase64(const QByteArray &encoded, QByteArray::Base64Options options, QByteArray &decoded)
    {
        const QByteArray::FromBase64Result result = QByteArray::fromBase64Encoding(
                encoded, options | QByteArray::AbortOnBase64DecodingErrors);
        if (!result) {
            decoded.clear();
            return false;
        }

        decoded = result.decoded;
        return true;
    }
}

UpdateController::UpdateController(SecureAppSettingsRepository* appSettingsRepository,
                                   SecureServersRepository* serversRepository,
                                   QObject *parent)
    : QObject(parent), m_appSettingsRepository(appSettingsRepository), m_serversRepository(serversRepository)
{
#if defined(Q_OS_ANDROID)
    connect(AndroidController::instance(), &AndroidController::apkInstallerLaunchAuthorizationRequested,
            this, [this](const QString &fileName, const QString &packageName,
                         const QString &versionName, qint64 versionCode, bool *authorized) {
        if (authorized) {
            *authorized = authorizeAndroidApkInstallerLaunch(
                    fileName, packageName, versionName, versionCode);
        }
    }, Qt::DirectConnection);
    connect(AndroidController::instance(), &AndroidController::apkInstallerStarted,
            this, &UpdateController::onAndroidApkInstallerStarted);
    connect(AndroidController::instance(), &AndroidController::apkInstallerStartFailed,
            this, &UpdateController::onAndroidApkInstallerStartFailed);
#endif
    if (m_appSettingsRepository) {
        m_highestObservedPolicyGeneration =
                m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyGeneration();
#if defined(Q_OS_ANDROID)
        recoverAndroidApkInstallerAuthorization();
#endif
        refreshPendingUpdateHealth();
    }
    startBackgroundUpdateChecks();
}

QString UpdateController::getRawChangelogText() const
{
    return m_changelogText;
}

QString UpdateController::getReleaseDate() const
{
    return m_releaseDate;
}

QString UpdateController::getVersion() const
{
    return m_version;
}

bool UpdateController::isUpdateCheckRunning() const
{
    return m_updateCheckRunning;
}

QString UpdateController::getReleaseChannel() const
{
    return m_observedReleasePolicy.generation > 0
            ? m_observedReleasePolicy.channel
            : QString();
}

qint64 UpdateController::getReleasePolicyGeneration() const
{
    return m_observedReleasePolicy.generation;
}

QString UpdateController::getReleasePolicyDisposition() const
{
    return releasePolicyDispositionName(m_observedReleasePolicy.disposition);
}

int UpdateController::getReleaseHealthDeadlineSeconds() const
{
    return m_selectedReleasePolicy.healthDeadlineSeconds;
}

QDateTime UpdateController::getReleasePolicyGeneratedAt() const
{
    return m_selectedReleasePolicy.generatedAt;
}

QDateTime UpdateController::getReleasePolicyExpiresAt() const
{
    return m_selectedReleasePolicy.expiresAt;
}

QString UpdateController::getPreviousVersion() const
{
    return m_selectedReleasePolicy.previousVersion;
}

bool UpdateController::hasRollbackArtifact() const
{
    return m_selectedReleasePolicy.hasRollbackArtifact;
}

QString UpdateController::getRollbackVersion() const
{
    return m_selectedReleasePolicy.rollbackVersion;
}

QUrl UpdateController::getRollbackArtifactUrl() const
{
    return m_selectedReleasePolicy.rollbackArtifact.url;
}

QString UpdateController::getRollbackArtifactSha256() const
{
    return m_selectedReleasePolicy.rollbackArtifact.sha256;
}

qint64 UpdateController::getRollbackArtifactSize() const
{
    return m_selectedReleasePolicy.rollbackArtifact.size;
}

QVariantMap UpdateController::getPendingUpdateHealthReceipt() const
{
    return m_appSettingsRepository
            ? m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt()
            : QVariantMap();
}

QVariantMap UpdateController::getLastUpdateHealthReceipt() const
{
    return m_appSettingsRepository
            ? m_appSettingsRepository->selfHostedUpdateLastHealthReceipt()
            : QVariantMap();
}

bool UpdateController::isUpdateHealthConfirmationPending() const
{
    const QVariantMap receipt = getPendingUpdateHealthReceipt();
    if (!isPendingHealthReceiptValid(receipt)) {
        return false;
    }
    // A failed target remains terminal, but a launched rollback still needs the
    // next process to prove that the rollback version is actually running.
    if (!receipt.value(QStringLiteral("rollbackRequestedAt")).toString().isEmpty()) {
        return true;
    }
    return receipt.value(QStringLiteral("healthState"), QStringLiteral("pending")).toString()
            != QStringLiteral("failed");
}

bool UpdateController::isRollbackAvailable() const
{
    return getRollbackActionMetadata().value(QStringLiteral("available")).toBool();
}

QVariantMap UpdateController::getRollbackActionMetadata() const
{
    QVariantMap result;
    result.insert(QStringLiteral("available"), false);

    const QVariantMap receipt = getPendingUpdateHealthReceipt();
    if (receipt.isEmpty()) {
        result.insert(QStringLiteral("reason"), QStringLiteral("no_pending_receipt"));
        return result;
    }
    if (receipt.value(QStringLiteral("rollbackState")).toString()
            == QStringLiteral("leased")) {
        result.insert(QStringLiteral("reason"), QStringLiteral("rollback_handoff_in_progress"));
        return result;
    }

#if defined(Q_OS_ANDROID)
    // Android's regular Package Installer refuses a lower versionCode. The
    // signed rollback artifacts currently represent older builds, so exposing
    // this action would claim a downgrade that the platform cannot perform.
    result.insert(QStringLiteral("reason"), QStringLiteral("platform_rollback_unsupported"));
    return result;
#endif

    if (!receiptMatchesAcceptedPolicy(receipt)) {
        result.insert(QStringLiteral("reason"), QStringLiteral("policy_binding_changed"));
        return result;
    }
    if (!isPendingHealthReceiptValid(receipt)) {
        result.insert(QStringLiteral("reason"), QStringLiteral("invalid_pending_receipt"));
        return result;
    }

    result.insert(QStringLiteral("targetVersion"), receipt.value(QStringLiteral("targetVersion")));
    result.insert(QStringLiteral("policyGeneration"), receipt.value(QStringLiteral("policyGeneration")));
    result.insert(QStringLiteral("deadlineAt"), receipt.value(QStringLiteral("deadlineAt")));
    result.insert(QStringLiteral("rollbackVersion"), receipt.value(QStringLiteral("rollbackVersion")));
    result.insert(QStringLiteral("rollbackPlatform"), receipt.value(QStringLiteral("rollbackPlatform")));
    result.insert(QStringLiteral("rollbackUrl"), receipt.value(QStringLiteral("rollbackUrl")));
    result.insert(QStringLiteral("rollbackSha256"), receipt.value(QStringLiteral("rollbackSha256")));
    result.insert(QStringLiteral("rollbackSize"), receipt.value(QStringLiteral("rollbackSize")));
    result.insert(QStringLiteral("rollbackOpenExternally"),
                  receipt.value(QStringLiteral("rollbackOpenExternally"), false));
    result.insert(QStringLiteral("rollbackLastErrorAt"),
                  receipt.value(QStringLiteral("rollbackLastErrorAt")));
    result.insert(QStringLiteral("rollbackLastErrorReason"),
                  receipt.value(QStringLiteral("rollbackLastErrorReason")));

    UpdateArtifact rollbackArtifact;
    if (!rollbackArtifactFromReceipt(receipt, rollbackArtifact)) {
        result.insert(QStringLiteral("reason"), QStringLiteral("no_verified_rollback_artifact"));
        return result;
    }

    const QString runningVersion = QString(APP_VERSION).trimmed();
    if (runningVersion == receipt.value(QStringLiteral("rollbackVersion")).toString()) {
        result.insert(QStringLiteral("reason"), QStringLiteral("already_running_rollback_version"));
        return result;
    }
    if (runningVersion != receipt.value(QStringLiteral("targetVersion")).toString()) {
        result.insert(QStringLiteral("reason"), QStringLiteral("unexpected_running_version"));
        return result;
    }
    if (!receipt.value(QStringLiteral("rollbackRequestedAt")).toString().isEmpty()) {
        result.insert(QStringLiteral("reason"), QStringLiteral("rollback_confirmation_pending"));
        return result;
    }
    if (m_selfHostedInstallInProgress || m_androidApkInstallPermissionPending) {
        result.insert(QStringLiteral("reason"), QStringLiteral("installer_busy"));
        return result;
    }

    const QDateTime deadline = storedUtcTimestamp(receipt.value(QStringLiteral("deadlineAt")));
    const bool deadlineExpired = deadline.isValid() && QDateTime::currentDateTimeUtc() >= deadline;
    const bool explicitlyFailed = receipt.value(QStringLiteral("healthState")).toString()
            == QStringLiteral("failed");
    if (!deadlineExpired && !explicitlyFailed) {
        result.insert(QStringLiteral("reason"), QStringLiteral("health_confirmation_pending"));
        return result;
    }

    result.insert(QStringLiteral("available"), true);
    result.insert(QStringLiteral("reason"), QStringLiteral("health_check_failed"));
    result.insert(QStringLiteral("action"), rollbackArtifact.openExternally
                  ? QStringLiteral("open_external_artifact")
                  : QStringLiteral("download_verify_and_launch"));
    return result;
}

void UpdateController::clearSelectedReleasePolicy()
{
    m_selectedReleasePolicy = {};
    m_observedReleasePolicy = {};
    emit releasePolicyChanged();
}

GenerationBindingDisposition UpdateController::acceptPolicyGeneration(qint64 generation,
                                                                      const QString &payloadSha256)
{
    const QString normalizedPayloadSha256 = normalizeSha256(payloadSha256);
    if (!m_appSettingsRepository) {
        return GenerationBindingDisposition::InvalidCandidate;
    }

    const qint64 persistedGeneration =
            m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyGeneration();
    const QString persistedPayloadSha256 =
            m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyPayloadSha256();
    const GenerationBindingDisposition disposition = evaluateGenerationBinding(
            generation, normalizedPayloadSha256, m_highestObservedPolicyGeneration,
            persistedGeneration, persistedPayloadSha256);
    const qint64 generationFloor = qMax(m_highestObservedPolicyGeneration, persistedGeneration);
    if (disposition == GenerationBindingDisposition::InvalidCandidate) {
        return disposition;
    }
    if (disposition == GenerationBindingDisposition::Stale) {
        logger.warning() << "Rejecting stale self-hosted release policy generation"
                         << generation << "accepted floor" << generationFloor;
        return disposition;
    }
    if (disposition == GenerationBindingDisposition::MissingPayloadBinding) {
        logger.warning() << "Rejecting same-generation policy without a persisted payload binding"
                         << generation;
        return disposition;
    }
    if (disposition == GenerationBindingDisposition::ConflictingPayload) {
        logger.warning() << "Rejecting conflicting payload for self-hosted policy generation"
                         << generation;
        return disposition;
    }
    if (disposition == GenerationBindingDisposition::AcceptExisting) {
        m_highestObservedPolicyGeneration = generationFloor;
        return disposition;
    }

    m_appSettingsRepository->setSelfHostedUpdateLastAcceptedPolicy(generation,
                                                                    normalizedPayloadSha256);
    const bool persisted =
            m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyGeneration() == generation
            && m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyPayloadSha256()
                    == normalizedPayloadSha256;
    if (!persisted) {
        logger.error() << "Failed to persist self-hosted release policy generation binding";
        return GenerationBindingDisposition::InvalidCandidate;
    }
    m_highestObservedPolicyGeneration = generation;
    return GenerationBindingDisposition::AcceptAdvance;
}

bool UpdateController::isPendingHealthReceiptValid(const QVariantMap &receipt) const
{
    bool schemaOk = false;
    const int schema = receipt.value(QStringLiteral("schema")).toInt(&schemaOk);
    bool generationOk = false;
    const qint64 generation = receipt.value(QStringLiteral("policyGeneration")).toLongLong(&generationOk);
    bool deadlineSecondsOk = false;
    const int deadlineSeconds = receipt.value(QStringLiteral("healthDeadlineSeconds")).toInt(&deadlineSecondsOk);
    if (!schemaOk || schema != kHealthReceiptSchema || !generationOk || generation <= 0
        || !deadlineSecondsOk || deadlineSeconds < kMinimumHealthDeadlineSeconds
        || deadlineSeconds > kMaximumHealthDeadlineSeconds) {
        return false;
    }

    const QString receiptId = receipt.value(QStringLiteral("receiptId")).toString().trimmed().toLower();
    const QUuid parsedReceiptId(receiptId);
    const QString policyPayloadSha256 = normalizeSha256(
            receipt.value(QStringLiteral("policyPayloadSha256")).toString());
    if (parsedReceiptId.isNull()
        || parsedReceiptId.toString(QUuid::WithoutBraces).toLower() != receiptId
        || !isCanonicalSha256(policyPayloadSha256)) {
        return false;
    }

    QVersionNumber targetVersion;
    QVersionNumber sourceVersion;
    if (!parseExactVersion(receipt.value(QStringLiteral("targetVersion")).toString(), targetVersion)
        || !parseExactVersion(receipt.value(QStringLiteral("sourceVersion")).toString(), sourceVersion)) {
        return false;
    }

    const QDateTime installerStartedAt = storedUtcTimestamp(receipt.value(QStringLiteral("installerStartedAt")));
    const QDateTime deadlineAt = storedUtcTimestamp(receipt.value(QStringLiteral("deadlineAt")));
    if (!installerStartedAt.isValid() || !deadlineAt.isValid() || deadlineAt <= installerStartedAt
        || deadlineAt > installerStartedAt.addSecs(deadlineSeconds + 1)) {
        return false;
    }

    const QDateTime policyExpiresAt = storedUtcTimestamp(
            receipt.value(QStringLiteral("policyExpiresAt")));
    if (!policyExpiresAt.isValid()) {
        return false;
    }

    const QString healthState = receipt.value(QStringLiteral("healthState"), QStringLiteral("pending")).toString();
    if (healthState != QStringLiteral("pending") && healthState != QStringLiteral("failed")) {
        return false;
    }
    const QDateTime failedAt = storedUtcTimestamp(receipt.value(QStringLiteral("failedAt")));
    if (healthState == QStringLiteral("failed") && !failedAt.isValid()) {
        return false;
    }
    bool preHandoffFailureCountOk = true;
    const bool hasPreHandoffFailureCount = receipt.contains(
            QStringLiteral("automaticRollbackPreHandoffFailureCount"));
    const int preHandoffFailureCount = hasPreHandoffFailureCount
            ? receipt.value(QStringLiteral("automaticRollbackPreHandoffFailureCount"))
                      .toInt(&preHandoffFailureCountOk)
            : 0;
    const bool hasAutomaticRetryAt = receipt.contains(
            QStringLiteral("automaticRollbackNextAttemptAt"));
    const QDateTime automaticRetryAt = storedUtcTimestamp(
            receipt.value(QStringLiteral("automaticRollbackNextAttemptAt")));
    const QDateTime automaticLastErrorAt = storedUtcTimestamp(
            receipt.value(QStringLiteral("automaticRollbackLastErrorAt")));
    const bool hasAutomaticTerminalAt = receipt.contains(
            QStringLiteral("automaticRollbackTerminalAt"));
    const QDateTime automaticTerminalAt = storedUtcTimestamp(
            receipt.value(QStringLiteral("automaticRollbackTerminalAt")));
    if (!preHandoffFailureCountOk || preHandoffFailureCount < 0
        || preHandoffFailureCount > kMaximumAutomaticRollbackPreHandoffFailures
        || (hasPreHandoffFailureCount && preHandoffFailureCount == 0)
        || (hasAutomaticRetryAt
            && (!automaticRetryAt.isValid() || preHandoffFailureCount <= 0
                || preHandoffFailureCount >= kMaximumAutomaticRollbackPreHandoffFailures
                || hasAutomaticTerminalAt || !automaticLastErrorAt.isValid()
                || automaticRetryAt <= automaticLastErrorAt
                || automaticRetryAt
                        > automaticLastErrorAt.addSecs(
                                automaticRollbackRetryDelaySeconds(
                                        preHandoffFailureCount) + 1)))
        || (hasAutomaticTerminalAt && !automaticTerminalAt.isValid())) {
        return false;
    }
    const QString rollbackState = receipt.value(QStringLiteral("rollbackState")).toString();
    const bool hasIntent = receipt.contains(QStringLiteral("rollbackIntentId"));
    const bool hasLease = receipt.contains(QStringLiteral("rollbackLeaseId"))
            || receipt.contains(QStringLiteral("rollbackLeaseAcquiredAt"))
            || receipt.contains(QStringLiteral("rollbackLeaseExpiresAt"));
    const bool hasHandoffLease = receipt.contains(
            QStringLiteral("rollbackHandoffLeaseId"));
    if (healthState == QStringLiteral("pending")
        && (receipt.contains(QStringLiteral("failedAt"))
            || receipt.contains(QStringLiteral("rollbackRequestedAt"))
            || !rollbackState.isEmpty() || hasIntent || hasLease || hasHandoffLease
            || hasPreHandoffFailureCount || hasAutomaticRetryAt
            || hasAutomaticTerminalAt)) {
        return false;
    }

    if (healthState == QStringLiteral("failed") && rollbackState.isEmpty()) {
        return !receipt.contains(QStringLiteral("rollbackRequestedAt"))
                && !hasIntent && !hasLease && !hasHandoffLease;
    }
    if (healthState != QStringLiteral("failed")
        || (rollbackState != QStringLiteral("leased")
            && rollbackState != QStringLiteral("confirmation_pending"))) {
        return healthState == QStringLiteral("pending");
    }

    const QString intentId = receipt.value(QStringLiteral("rollbackIntentId")).toString().trimmed().toLower();
    const QUuid parsedIntentId(intentId);
    const QString origin = receipt.value(QStringLiteral("rollbackOrigin")).toString();
    if (parsedIntentId.isNull()
        || parsedIntentId.toString(QUuid::WithoutBraces).toLower() != intentId
        || (origin != QStringLiteral("manual") && origin != QStringLiteral("automatic"))) {
        return false;
    }

    if (rollbackState == QStringLiteral("leased")) {
        if (receipt.contains(QStringLiteral("rollbackRequestedAt")) || hasHandoffLease
            || (origin == QStringLiteral("automatic") && hasAutomaticRetryAt)) {
            return false;
        }
        const QString leaseId = receipt.value(QStringLiteral("rollbackLeaseId")).toString().trimmed().toLower();
        const QUuid parsedLeaseId(leaseId);
        const QDateTime acquiredAt = storedUtcTimestamp(
                receipt.value(QStringLiteral("rollbackLeaseAcquiredAt")));
        const QDateTime expiresAt = storedUtcTimestamp(
                receipt.value(QStringLiteral("rollbackLeaseExpiresAt")));
        bool recoveryOk = false;
        const int recoveryCount = receipt.value(QStringLiteral("rollbackRecoveryCount"), 0)
                .toInt(&recoveryOk);
        return !parsedLeaseId.isNull()
                && parsedLeaseId.toString(QUuid::WithoutBraces).toLower() == leaseId
                && acquiredAt.isValid() && expiresAt > acquiredAt
                && expiresAt <= acquiredAt.addSecs(kRollbackIntentLeaseSeconds + 1)
                && recoveryOk && recoveryCount >= 0
                && recoveryCount <= kMaximumAutomaticRollbackRecoveries;
    }

    const QString handoffLeaseId = receipt.value(
            QStringLiteral("rollbackHandoffLeaseId")).toString().trimmed().toLower();
    const QUuid parsedHandoffLeaseId(handoffLeaseId);
    if (hasLease || !hasHandoffLease || parsedHandoffLeaseId.isNull()
        || parsedHandoffLeaseId.toString(QUuid::WithoutBraces).toLower()
                != handoffLeaseId
        || !receipt.contains(QStringLiteral("rollbackRequestedAt"))
        || hasAutomaticRetryAt) {
        return false;
    }
    const QDateTime rollbackRequestedAt =
            storedUtcTimestamp(receipt.value(QStringLiteral("rollbackRequestedAt")));
    return rollbackRequestedAt.isValid() && rollbackRequestedAt >= failedAt
            && installerStartedAt == rollbackRequestedAt;
}

bool UpdateController::receiptMatchesAcceptedPolicy(const QVariantMap &receipt) const
{
    return m_appSettingsRepository
            && rollbackPolicyBindingMatches(
                    receipt.value(QStringLiteral("policyGeneration")).toLongLong(),
                    receipt.value(QStringLiteral("policyPayloadSha256")).toString(),
                    m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyGeneration(),
                    m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyPayloadSha256());
}

void UpdateController::armUpdateInstallIntent()
{
    InstallIntent intent;
    intent.kind = InstallIntentKind::Update;
    intent.id = QUuid::createUuid().toString(QUuid::WithoutBraces).toLower();
    intent.targetVersion = m_version;
    intent.platform = m_selectedArtifact.platform;
    intent.url = m_selectedArtifact.url;
    intent.sha256 = normalizeSha256(m_selectedArtifact.sha256);
    intent.size = m_selectedArtifact.size;
    intent.policyGeneration = m_selectedReleasePolicy.generation;
    if (m_appSettingsRepository && intent.policyGeneration > 0) {
        intent.policyPayloadSha256 = normalizeSha256(
                m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyPayloadSha256());
    }
    m_installIntent = intent;
}

void UpdateController::armRollbackInstallIntent(const QVariantMap &receipt,
                                                const UpdateArtifact &artifact,
                                                const RollbackAttemptContext &expectedAttempt)
{
    InstallIntent intent;
    intent.kind = InstallIntentKind::Rollback;
    intent.id = expectedAttempt.intentId;
    intent.receiptId = expectedAttempt.receiptId;
    intent.leaseId = expectedAttempt.leaseId;
    intent.targetVersion = receipt.value(QStringLiteral("rollbackVersion")).toString();
    intent.platform = artifact.platform;
    intent.url = artifact.url;
    intent.sha256 = artifact.sha256;
    intent.size = artifact.size;
    intent.policyGeneration = receipt.value(QStringLiteral("policyGeneration")).toLongLong();
    intent.policyPayloadSha256 = normalizeSha256(
            receipt.value(QStringLiteral("policyPayloadSha256")).toString());
    m_installIntent = intent;
}

bool UpdateController::installIntentMatchesSelection() const
{
    if (!m_useSelfHostedArtifact || m_installIntent.kind == InstallIntentKind::None
        || m_installIntent.id.isEmpty() || m_installIntent.targetVersion != m_version
        || m_installIntent.platform != m_selectedArtifact.platform
        || m_installIntent.url != m_selectedArtifact.url
        || m_installIntent.sha256 != normalizeSha256(m_selectedArtifact.sha256)
        || m_installIntent.size != m_selectedArtifact.size) {
        return false;
    }

    if (m_installIntent.kind == InstallIntentKind::Update) {
        if (m_rollbackInstallAttempt
            || m_installIntent.policyGeneration != m_selectedReleasePolicy.generation) {
            return false;
        }
        return m_installIntent.policyGeneration == 0
                || (m_appSettingsRepository
                    && rollbackPolicyBindingMatches(
                            m_installIntent.policyGeneration,
                            m_installIntent.policyPayloadSha256,
                            m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyGeneration(),
                            m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyPayloadSha256()));
    }

    if (!m_rollbackInstallAttempt || !m_appSettingsRepository) {
        return false;
    }
    const QVariantMap receipt =
            m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
    return isPendingHealthReceiptValid(receipt) && receiptMatchesAcceptedPolicy(receipt)
            && receipt.value(QStringLiteral("rollbackState")).toString()
                    == QStringLiteral("leased")
            && receipt.value(QStringLiteral("rollbackIntentId")).toString()
                    == m_installIntent.id
            && receipt.value(QStringLiteral("receiptId")).toString()
                    == m_installIntent.receiptId
            && receipt.value(QStringLiteral("rollbackLeaseId")).toString()
                    == m_installIntent.leaseId
            && QString(APP_VERSION).trimmed()
                    == receipt.value(QStringLiteral("targetVersion")).toString();
}

void UpdateController::clearInstallSelection()
{
    m_installIntent = {};
    m_selectedArtifact = {};
    m_selectedReleasePolicy = {};
    m_useSelfHostedArtifact = false;
    m_downloadUrl.clear();
    m_version.clear();
    m_rollbackInstallAttempt = false;
}

bool UpdateController::rollbackArtifactFromReceipt(const QVariantMap &receipt, UpdateArtifact &artifactOut) const
{
#if defined(MACOS_NE) || defined(Q_OS_ANDROID)
    Q_UNUSED(receipt);
    Q_UNUSED(artifactOut);
    // MACOS_NE cannot launch a verified local rollback package through the
    // supported installer path. Do not silently downgrade it to openExternal,
    // which would discard the signed sha256/size contract.
    return false;
#else
    QVersionNumber rollbackVersion;
    if (!parseExactVersion(receipt.value(QStringLiteral("rollbackVersion")).toString(), rollbackVersion)) {
        return false;
    }

    UpdateArtifact artifact;
    artifact.platform = receipt.value(QStringLiteral("rollbackPlatform")).toString().trimmed();
    artifact.url = QUrl(receipt.value(QStringLiteral("rollbackUrl")).toString());
    artifact.sha256 = normalizeSha256(receipt.value(QStringLiteral("rollbackSha256")).toString());
    bool sizeOk = false;
    artifact.size = receipt.value(QStringLiteral("rollbackSize")).toLongLong(&sizeOk);
    artifact.openExternally = receipt.value(QStringLiteral("rollbackOpenExternally"), false).toBool();
    artifact.autoInstall = false;

    if (artifact.platform.isEmpty() || !platformCandidates().contains(artifact.platform)
        || !artifact.url.isValid() || artifact.url.isEmpty()) {
        return false;
    }
    if (artifact.openExternally) {
        if (!isAllowedExternalUpdateUrl(artifact.url)) {
            return false;
        }
    } else if (!isHttpOrHttpsUrl(artifact.url) || !isCanonicalSha256(artifact.sha256)
               || !sizeOk || artifact.size <= 0) {
        return false;
    }

    artifactOut = artifact;
    return true;
#endif
}

bool UpdateController::recordInstallerHandoffReceipt()
{
    if (!m_appSettingsRepository || m_selectedReleasePolicy.generation <= 0
        || m_selectedReleasePolicy.healthDeadlineSeconds <= 0
        || !m_selectedReleasePolicy.expiresAt.isValid()
        || QDateTime::currentDateTimeUtc() >= m_selectedReleasePolicy.expiresAt) {
        return false;
    }

    const QVariantMap existingReceipt = m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
    if (isPendingHealthReceiptValid(existingReceipt)
        && existingReceipt.value(QStringLiteral("targetVersion")).toString() != m_version) {
        finishPendingHealthReceipt(existingReceipt, QStringLiteral("failed"),
                                   QStringLiteral("superseded_by_new_update"), true);
    }

    const QDateTime now = QDateTime::currentDateTimeUtc();
    const qint64 acceptedGeneration =
            m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyGeneration();
    const QString acceptedPayloadSha256 = normalizeSha256(
            m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyPayloadSha256());
    if (acceptedGeneration != m_selectedReleasePolicy.generation
        || !isCanonicalSha256(acceptedPayloadSha256)) {
        logger.error() << "Cannot bind update health receipt to accepted release policy";
        return false;
    }
    QVariantMap receipt;
    receipt.insert(QStringLiteral("schema"), kHealthReceiptSchema);
    receipt.insert(QStringLiteral("receiptId"),
                   QUuid::createUuid().toString(QUuid::WithoutBraces).toLower());
    receipt.insert(QStringLiteral("targetVersion"), m_version);
    receipt.insert(QStringLiteral("sourceVersion"), QString(APP_VERSION).trimmed());
    receipt.insert(QStringLiteral("channel"), m_selectedReleasePolicy.channel);
    receipt.insert(QStringLiteral("policyGeneration"), m_selectedReleasePolicy.generation);
    receipt.insert(QStringLiteral("policyPayloadSha256"), acceptedPayloadSha256);
    receipt.insert(QStringLiteral("policyExpiresAt"),
                   utcTimestamp(m_selectedReleasePolicy.expiresAt));
    receipt.insert(QStringLiteral("installerStartedAt"), utcTimestamp(now));
    receipt.insert(QStringLiteral("healthDeadlineSeconds"), m_selectedReleasePolicy.healthDeadlineSeconds);
    receipt.insert(QStringLiteral("deadlineAt"),
                   utcTimestamp(now.addSecs(m_selectedReleasePolicy.healthDeadlineSeconds)));
    receipt.insert(QStringLiteral("healthState"), QStringLiteral("pending"));

    if (m_selectedReleasePolicy.hasRollbackArtifact) {
        receipt.insert(QStringLiteral("rollbackVersion"), m_selectedReleasePolicy.rollbackVersion);
        receipt.insert(QStringLiteral("rollbackPlatform"), m_selectedReleasePolicy.rollbackArtifact.platform);
        receipt.insert(QStringLiteral("rollbackUrl"), m_selectedReleasePolicy.rollbackArtifact.url.toString());
        receipt.insert(QStringLiteral("rollbackSha256"), m_selectedReleasePolicy.rollbackArtifact.sha256);
        receipt.insert(QStringLiteral("rollbackSize"), m_selectedReleasePolicy.rollbackArtifact.size);
        receipt.insert(QStringLiteral("rollbackOpenExternally"),
                       m_selectedReleasePolicy.rollbackArtifact.openExternally);
    }

    m_appSettingsRepository->setSelfHostedUpdatePendingHealthReceipt(receipt);
    const QVariantMap persistedReceipt =
            m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
    const bool persisted = isPendingHealthReceiptValid(persistedReceipt)
            && persistedReceipt.value(QStringLiteral("targetVersion")).toString() == m_version
            && persistedReceipt.value(QStringLiteral("receiptId")).toString()
                    == receipt.value(QStringLiteral("receiptId")).toString()
            && persistedReceipt.value(QStringLiteral("policyGeneration")).toLongLong()
                    == m_selectedReleasePolicy.generation
            && persistedReceipt.value(QStringLiteral("policyPayloadSha256")).toString()
                    == acceptedPayloadSha256
            && persistedReceipt.value(QStringLiteral("installerStartedAt")).toString()
                    == receipt.value(QStringLiteral("installerStartedAt")).toString();
    emit updateHealthReceiptChanged();
    emit rollbackAvailabilityChanged();
    if (!persisted) {
        logger.error() << "Failed to durably persist self-hosted update health receipt";
    }
    return persisted;
}

bool UpdateController::recordRollbackHandoff(
        const RollbackAttemptContext &expectedAttempt)
{
    if (!m_appSettingsRepository || !expectedAttempt.isComplete()
        || m_installIntent.kind != InstallIntentKind::Rollback
        || m_installIntent.id != expectedAttempt.intentId
        || m_installIntent.receiptId != expectedAttempt.receiptId
        || m_installIntent.leaseId != expectedAttempt.leaseId
        || !m_installIntent.consumed) {
        return false;
    }
    QVariantMap receipt = m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
    UpdateArtifact rollbackArtifact;
    if (!isPendingHealthReceiptValid(receipt) || !receiptMatchesAcceptedPolicy(receipt)
        || receipt.value(QStringLiteral("rollbackState")).toString() != QStringLiteral("leased")
        || receipt.value(QStringLiteral("rollbackIntentId")).toString()
                != expectedAttempt.intentId
        || receipt.value(QStringLiteral("receiptId")).toString()
                != expectedAttempt.receiptId
        || receipt.value(QStringLiteral("rollbackLeaseId")).toString()
                != expectedAttempt.leaseId
        || QString(APP_VERSION).trimmed() != receipt.value(QStringLiteral("targetVersion")).toString()
        || !rollbackArtifactFromReceipt(receipt, rollbackArtifact)
        || rollbackArtifact.platform != m_installIntent.platform
        || rollbackArtifact.url != m_installIntent.url
        || rollbackArtifact.sha256 != m_installIntent.sha256
        || rollbackArtifact.size != m_installIntent.size
        || QDateTime::currentDateTimeUtc() >= storedUtcTimestamp(
                   receipt.value(QStringLiteral("rollbackLeaseExpiresAt")))) {
        logger.warning() << "Refusing rollback handoff with stale or mismatched install intent";
        return false;
    }
    const QDateTime now = QDateTime::currentDateTimeUtc();
    const QString requestedAt = utcTimestamp(now);
    if (!receipt.contains(QStringLiteral("rollbackSourceInstallerStartedAt"))) {
        receipt.insert(QStringLiteral("rollbackSourceInstallerStartedAt"),
                       receipt.value(QStringLiteral("installerStartedAt")));
        receipt.insert(QStringLiteral("rollbackSourceHealthDeadlineSeconds"),
                       receipt.value(QStringLiteral("healthDeadlineSeconds")));
        receipt.insert(QStringLiteral("rollbackSourceDeadlineAt"),
                       receipt.value(QStringLiteral("deadlineAt")));
    }
    receipt.insert(QStringLiteral("rollbackRequestedAt"), requestedAt);
    receipt.insert(QStringLiteral("rollbackState"), QStringLiteral("confirmation_pending"));
    receipt.insert(QStringLiteral("rollbackHandoffLeaseId"), expectedAttempt.leaseId);
    // Core's readiness retry uses deadlineAt. Start a fresh bounded window for
    // the rollback process instead of reusing the already-expired target window.
    receipt.insert(QStringLiteral("installerStartedAt"), requestedAt);
    receipt.insert(QStringLiteral("healthDeadlineSeconds"), kRollbackConfirmationTimeoutSeconds);
    receipt.insert(QStringLiteral("deadlineAt"),
                   utcTimestamp(now.addSecs(kRollbackConfirmationTimeoutSeconds)));
    receipt.remove(QStringLiteral("rollbackLeaseId"));
    receipt.remove(QStringLiteral("rollbackLeaseAcquiredAt"));
    receipt.remove(QStringLiteral("rollbackLeaseExpiresAt"));
    receipt.remove(QStringLiteral("automaticRollbackNextAttemptAt"));
    receipt.remove(QStringLiteral("rollbackLastErrorAt"));
    receipt.remove(QStringLiteral("rollbackLastErrorReason"));
    m_appSettingsRepository->setSelfHostedUpdatePendingHealthReceipt(receipt);
    const QVariantMap persistedReceipt =
            m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
    const bool persisted = isPendingHealthReceiptValid(persistedReceipt)
            && persistedReceipt.value(QStringLiteral("rollbackRequestedAt")).toString()
                    == requestedAt
            && persistedReceipt.value(QStringLiteral("rollbackIntentId")).toString()
                    == expectedAttempt.intentId
            && persistedReceipt.value(QStringLiteral("receiptId")).toString()
                    == expectedAttempt.receiptId
            && persistedReceipt.value(QStringLiteral("rollbackHandoffLeaseId")).toString()
                    == expectedAttempt.leaseId;
    emit updateHealthReceiptChanged();
    emit rollbackAvailabilityChanged();
    if (persisted) {
        refreshPendingUpdateHealth();
    } else {
        logger.error() << "Failed to durably persist rollback handoff receipt";
    }
    return persisted;
}

void UpdateController::recordRollbackHandoffFailure(
        const RollbackAttemptContext &expectedAttempt,
        bool permanentValidationFailure)
{
    if (!m_appSettingsRepository || !expectedAttempt.isComplete()) {
        return;
    }
    QVariantMap receipt = m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
    const QString rollbackState = receipt.value(QStringLiteral("rollbackState")).toString();
    const QString activeLeaseId = rollbackState == QStringLiteral("confirmation_pending")
            ? receipt.value(QStringLiteral("rollbackHandoffLeaseId")).toString()
            : receipt.value(QStringLiteral("rollbackLeaseId")).toString();
    if (!isPendingHealthReceiptValid(receipt)
        || (rollbackState != QStringLiteral("leased")
            && rollbackState != QStringLiteral("confirmation_pending"))
        || receipt.value(QStringLiteral("receiptId")).toString()
                != expectedAttempt.receiptId
        || receipt.value(QStringLiteral("rollbackIntentId")).toString()
                != expectedAttempt.intentId
        || activeLeaseId != expectedAttempt.leaseId) {
        logger.info() << "Ignoring stale rollback failure callback for a superseded lease";
        return;
    }
    const QString origin = receipt.value(QStringLiteral("rollbackOrigin")).toString();
    // Every direct failure callback reaches this function before the platform
    // launcher has acknowledged a successful handoff. A prepared receipt may
    // already be confirmation_pending, but a false CreateProcess/QProcess/JNI
    // result is still a definite pre-handoff failure. Post-handoff ambiguity is
    // handled separately by the confirmation deadline state machine.
    const bool automaticPreHandoff = origin == QStringLiteral("automatic");
    const QDateTime now = QDateTime::currentDateTimeUtc();
    const int previousPreHandoffFailures = receipt.value(
            QStringLiteral("automaticRollbackPreHandoffFailureCount"), 0).toInt();
    const int preHandoffFailures = automaticPreHandoff
            ? qMin(kMaximumAutomaticRollbackPreHandoffFailures,
                   previousPreHandoffFailures + 1)
            : previousPreHandoffFailures;
    const bool retryAutomatic = automaticPreHandoff
            && !permanentValidationFailure
            && preHandoffFailures < kMaximumAutomaticRollbackPreHandoffFailures;
    receipt.remove(QStringLiteral("rollbackRequestedAt"));
    if (receipt.contains(QStringLiteral("rollbackSourceInstallerStartedAt"))) {
        receipt.insert(QStringLiteral("installerStartedAt"),
                       receipt.take(QStringLiteral("rollbackSourceInstallerStartedAt")));
        receipt.insert(QStringLiteral("healthDeadlineSeconds"),
                       receipt.take(QStringLiteral("rollbackSourceHealthDeadlineSeconds")));
        receipt.insert(QStringLiteral("deadlineAt"),
                       receipt.take(QStringLiteral("rollbackSourceDeadlineAt")));
    }
    receipt.insert(QStringLiteral("rollbackLastErrorAt"), utcTimestamp(now));
    receipt.insert(QStringLiteral("rollbackLastErrorReason"),
                   permanentValidationFailure
                           ? QStringLiteral("rollback_validation_failed")
                           : QStringLiteral("installer_handoff_failed"));
    if (origin == QStringLiteral("automatic")) {
        receipt.insert(QStringLiteral("automaticRollbackLastErrorAt"), utcTimestamp(now));
        receipt.insert(QStringLiteral("automaticRollbackLastErrorReason"),
                       permanentValidationFailure
                               ? QStringLiteral("permanent_validation_failure")
                               : QStringLiteral("pre_handoff_failure"));
        if (automaticPreHandoff) {
            receipt.insert(QStringLiteral("automaticRollbackPreHandoffFailureCount"),
                           preHandoffFailures);
        }
        if (retryAutomatic) {
            receipt.remove(QStringLiteral("automaticRollbackTerminalAt"));
            receipt.insert(QStringLiteral("automaticRollbackNextAttemptAt"),
                           utcTimestamp(now.addSecs(
                                   automaticRollbackRetryDelaySeconds(preHandoffFailures))));
        } else {
            receipt.remove(QStringLiteral("automaticRollbackNextAttemptAt"));
            receipt.insert(QStringLiteral("automaticRollbackTerminalAt"), utcTimestamp(now));
        }
    }
    receipt.remove(QStringLiteral("rollbackState"));
    receipt.remove(QStringLiteral("rollbackIntentId"));
    receipt.remove(QStringLiteral("rollbackOrigin"));
    receipt.remove(QStringLiteral("rollbackLeaseId"));
    receipt.remove(QStringLiteral("rollbackLeaseAcquiredAt"));
    receipt.remove(QStringLiteral("rollbackLeaseExpiresAt"));
    receipt.remove(QStringLiteral("rollbackRecoveryCount"));
    receipt.remove(QStringLiteral("rollbackHandoffLeaseId"));
    m_appSettingsRepository->setSelfHostedUpdatePendingHealthReceipt(receipt);
    const QVariantMap persistedReceipt =
            m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
    const bool persisted = isPendingHealthReceiptValid(persistedReceipt)
            && persistedReceipt.value(QStringLiteral("receiptId")).toString()
                    == expectedAttempt.receiptId
            && persistedReceipt.value(QStringLiteral("rollbackState")).toString().isEmpty()
            && !persistedReceipt.contains(QStringLiteral("rollbackIntentId"))
            && !persistedReceipt.contains(QStringLiteral("rollbackLeaseId"))
            && (!retryAutomatic
                || (persistedReceipt.value(
                            QStringLiteral("automaticRollbackPreHandoffFailureCount")).toInt()
                                == preHandoffFailures
                    && persistedReceipt.value(
                               QStringLiteral("automaticRollbackNextAttemptAt")).toString()
                            == receipt.value(
                               QStringLiteral("automaticRollbackNextAttemptAt")).toString()));
    if (!persisted) {
        logger.error() << "Failed to durably persist rollback failure transition";
    }
    emit updateHealthReceiptChanged();
    emit rollbackAvailabilityChanged();
    if (persisted && retryAutomatic) {
        scheduleAutomaticRollbackRetry(persistedReceipt);
    } else if (persisted && origin == QStringLiteral("manual")
               && persistedReceipt.contains(
                       QStringLiteral("automaticRollbackNextAttemptAt"))) {
        scheduleAutomaticRollbackRetry(persistedReceipt);
    }
}

bool UpdateController::prepareSelfHostedInstallerHandoff()
{
    if (m_handoffReceiptPrepared) {
        return true;
    }
#if defined(Q_OS_ANDROID)
    if (m_useSelfHostedArtifact && !m_selectedArtifact.openExternally) {
        const bool persisted = prepareAndroidApkInstallerAuthorization();
        m_handoffReceiptPrepared = persisted;
        return persisted;
    }
#endif
    if (!m_rollbackInstallAttempt && m_selectedReleasePolicy.generation <= 0) {
        // Schema-1 compatibility has no policy health contract to persist.
        m_handoffReceiptPrepared = true;
        return true;
    }
    const bool persisted = m_rollbackInstallAttempt
            ? recordRollbackHandoff(RollbackAttemptContext {
                    m_installIntent.receiptId, m_installIntent.id, m_installIntent.leaseId })
            : recordInstallerHandoffReceipt();
    m_handoffReceiptPrepared = persisted;
    return persisted;
}

void UpdateController::cancelPreparedSelfHostedInstallerHandoff()
{
    if (!m_handoffReceiptPrepared || !m_appSettingsRepository) {
        m_handoffReceiptPrepared = false;
        return;
    }
#if defined(Q_OS_ANDROID)
    const QVariantMap androidAuthorization =
            m_appSettingsRepository->selfHostedUpdateAndroidInstallerAuthorization();
    if (!androidAuthorization.isEmpty()) {
        m_appSettingsRepository->clearSelfHostedUpdateAndroidInstallerAuthorization();
        if (androidAuthorization.value(QStringLiteral("mode")).toString()
            == QStringLiteral("rollback")) {
            recordRollbackHandoffFailure(RollbackAttemptContext {
                    m_installIntent.receiptId, m_installIntent.id, m_installIntent.leaseId });
        }
        m_handoffReceiptPrepared = false;
        return;
    }
#endif
    if (!m_rollbackInstallAttempt && m_selectedReleasePolicy.generation <= 0) {
        m_handoffReceiptPrepared = false;
        return;
    }

    if (m_rollbackInstallAttempt) {
        recordRollbackHandoffFailure(RollbackAttemptContext {
                m_installIntent.receiptId, m_installIntent.id, m_installIntent.leaseId });
    } else {
        const QVariantMap receipt = m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
        if (receipt.value(QStringLiteral("targetVersion")).toString() == m_version) {
            m_appSettingsRepository->clearSelfHostedUpdatePendingHealthReceipt();
            emit updateHealthReceiptChanged();
            emit rollbackAvailabilityChanged();
        }
    }
    m_handoffReceiptPrepared = false;
}

#if defined(Q_OS_ANDROID)
bool UpdateController::prepareAndroidApkInstallerAuthorization()
{
    if (!m_appSettingsRepository || m_rollbackInstallAttempt
        || m_selectedArtifact.openExternally
        || m_selectedArtifact.platform.isEmpty()
        || !platformCandidates().contains(m_selectedArtifact.platform)
        || !isCanonicalSha256(normalizeSha256(m_selectedArtifact.sha256))
        || m_selectedArtifact.size <= 0 || m_selectedArtifact.androidVersionCode <= 0) {
        return false;
    }

    const QVariantMap existingAuthorization =
            m_appSettingsRepository->selfHostedUpdateAndroidInstallerAuthorization();
    if (!existingAuthorization.isEmpty()) {
        if (isAndroidApkInstallerAuthorizationValid(existingAuthorization)) {
            logger.warning() << "Android APK installer authorization is already pending";
            return false;
        }
        m_appSettingsRepository->clearSelfHostedUpdateAndroidInstallerAuthorization();
    }

    const QDateTime now = QDateTime::currentDateTimeUtc();
    const QDateTime authorizationExpiresAt = boundedAuthorizationExpiry(
            now, kAndroidApkInstallPermissionWaitMs,
            m_selectedReleasePolicy.generation > 0
                    ? m_selectedReleasePolicy.expiresAt : QDateTime());
    if (!authorizationExpiresAt.isValid()) {
        logger.warning() << "Refusing Android APK handoff after signed policy expiry";
        return false;
    }
    QVariantMap authorization;
    authorization.insert(QStringLiteral("schema"), kAndroidInstallerAuthorizationSchema);
    authorization.insert(QStringLiteral("state"), QStringLiteral("prepared"));
    authorization.insert(QStringLiteral("sourceVersion"), QString(APP_VERSION).trimmed());
    authorization.insert(QStringLiteral("installVersion"), m_version);
    authorization.insert(QStringLiteral("installVersionCode"),
                         m_selectedArtifact.androidVersionCode);
    authorization.insert(QStringLiteral("platform"), m_selectedArtifact.platform);
    authorization.insert(QStringLiteral("sha256"), normalizeSha256(m_selectedArtifact.sha256));
    authorization.insert(QStringLiteral("size"), m_selectedArtifact.size);
    authorization.insert(QStringLiteral("localPath"),
                         QDir::cleanPath(QFileInfo(localInstallerPath()).absoluteFilePath()));
    authorization.insert(QStringLiteral("preparedAt"), utcTimestamp(now));
    authorization.insert(QStringLiteral("expiresAt"), utcTimestamp(authorizationExpiresAt));
    if (!m_pendingAutoInstallAttemptId.isEmpty()) {
        authorization.insert(QStringLiteral("autoInstallAttemptMarker"),
                             m_pendingAutoInstallAttemptId.left(1024));
    }

    if (m_rollbackInstallAttempt) {
        const QVariantMap pendingReceipt =
                m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
        UpdateArtifact rollbackArtifact;
        if (!isPendingHealthReceiptValid(pendingReceipt)
            || pendingReceipt.value(QStringLiteral("healthState")).toString()
                    != QStringLiteral("failed")
            || !rollbackArtifactFromReceipt(pendingReceipt, rollbackArtifact)
            || rollbackArtifact.openExternally
            || rollbackArtifact.platform != m_selectedArtifact.platform
            || rollbackArtifact.sha256 != normalizeSha256(m_selectedArtifact.sha256)
            || rollbackArtifact.size != m_selectedArtifact.size
            || pendingReceipt.value(QStringLiteral("rollbackVersion")).toString() != m_version) {
            return false;
        }
        authorization.insert(QStringLiteral("mode"), QStringLiteral("rollback"));
        authorization.insert(QStringLiteral("policyGeneration"),
                             pendingReceipt.value(QStringLiteral("policyGeneration")));
        authorization.insert(QStringLiteral("policyPayloadSha256"),
                             pendingReceipt.value(QStringLiteral("policyPayloadSha256")));
    } else {
        authorization.insert(QStringLiteral("mode"), QStringLiteral("update"));
        authorization.insert(QStringLiteral("policyGeneration"), m_selectedReleasePolicy.generation);

        if (m_selectedReleasePolicy.generation > 0) {
            const qint64 acceptedGeneration =
                    m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyGeneration();
            const QString acceptedPayloadSha256 = normalizeSha256(
                    m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyPayloadSha256());
            if (acceptedGeneration != m_selectedReleasePolicy.generation
                || !isCanonicalSha256(acceptedPayloadSha256)) {
                return false;
            }

            const QVariantMap existingReceipt =
                    m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
            if (isPendingHealthReceiptValid(existingReceipt)
                && existingReceipt.value(QStringLiteral("targetVersion")).toString() != m_version) {
                finishPendingHealthReceipt(existingReceipt, QStringLiteral("failed"),
                                           QStringLiteral("superseded_by_new_update"), true);
            }

            QVariantMap healthReceipt;
            healthReceipt.insert(QStringLiteral("schema"), kHealthReceiptSchema);
            healthReceipt.insert(QStringLiteral("receiptId"),
                                 QUuid::createUuid().toString(QUuid::WithoutBraces).toLower());
            healthReceipt.insert(QStringLiteral("targetVersion"), m_version);
            healthReceipt.insert(QStringLiteral("sourceVersion"), QString(APP_VERSION).trimmed());
            healthReceipt.insert(QStringLiteral("channel"), m_selectedReleasePolicy.channel);
            healthReceipt.insert(QStringLiteral("policyGeneration"), m_selectedReleasePolicy.generation);
            healthReceipt.insert(QStringLiteral("policyPayloadSha256"), acceptedPayloadSha256);
            healthReceipt.insert(QStringLiteral("policyExpiresAt"),
                                 utcTimestamp(m_selectedReleasePolicy.expiresAt));
            healthReceipt.insert(QStringLiteral("installerStartedAt"), utcTimestamp(now));
            healthReceipt.insert(QStringLiteral("healthDeadlineSeconds"),
                                 m_selectedReleasePolicy.healthDeadlineSeconds);
            healthReceipt.insert(QStringLiteral("deadlineAt"),
                                 utcTimestamp(now.addSecs(
                                         m_selectedReleasePolicy.healthDeadlineSeconds)));
            healthReceipt.insert(QStringLiteral("healthState"), QStringLiteral("pending"));
            if (m_selectedReleasePolicy.hasRollbackArtifact) {
                healthReceipt.insert(QStringLiteral("rollbackVersion"),
                                     m_selectedReleasePolicy.rollbackVersion);
                healthReceipt.insert(QStringLiteral("rollbackPlatform"),
                                     m_selectedReleasePolicy.rollbackArtifact.platform);
                healthReceipt.insert(QStringLiteral("rollbackUrl"),
                                     m_selectedReleasePolicy.rollbackArtifact.url.toString());
                healthReceipt.insert(QStringLiteral("rollbackSha256"),
                                     m_selectedReleasePolicy.rollbackArtifact.sha256);
                healthReceipt.insert(QStringLiteral("rollbackSize"),
                                     m_selectedReleasePolicy.rollbackArtifact.size);
                healthReceipt.insert(QStringLiteral("rollbackOpenExternally"),
                                     m_selectedReleasePolicy.rollbackArtifact.openExternally);
            }
            if (!isPendingHealthReceiptValid(healthReceipt)) {
                return false;
            }
            authorization.insert(QStringLiteral("policyPayloadSha256"), acceptedPayloadSha256);
            authorization.insert(QStringLiteral("policyExpiresAt"),
                                 utcTimestamp(m_selectedReleasePolicy.expiresAt));
            authorization.insert(QStringLiteral("healthReceipt"), healthReceipt);
        }
    }

    m_appSettingsRepository->setSelfHostedUpdateAndroidInstallerAuthorization(authorization);
    const QVariantMap persisted =
            m_appSettingsRepository->selfHostedUpdateAndroidInstallerAuthorization();
    const bool persistedExactly = isAndroidApkInstallerAuthorizationValid(persisted)
            && persisted.value(QStringLiteral("preparedAt")).toString()
                    == authorization.value(QStringLiteral("preparedAt")).toString()
            && persisted.value(QStringLiteral("sha256")).toString()
                    == authorization.value(QStringLiteral("sha256")).toString();
    if (!persistedExactly) {
        logger.error() << "Failed to durably persist Android APK installer authorization";
    } else {
        const QString preparedAt = authorization.value(QStringLiteral("preparedAt")).toString();
        const qint64 remainingMs = now.msecsTo(authorizationExpiresAt);
        QTimer::singleShot(static_cast<int>(qMax<qint64>(1, remainingMs)), this,
                           [this, preparedAt]() {
            expireAndroidApkInstallerAuthorization(preparedAt);
        });
    }
    return persistedExactly;
}

bool UpdateController::isAndroidApkInstallerAuthorizationValid(
        const QVariantMap &authorization) const
{
    bool schemaOk = false;
    const int schema = authorization.value(QStringLiteral("schema")).toInt(&schemaOk);
    const QString state = authorization.value(QStringLiteral("state")).toString();
    const QString mode = authorization.value(QStringLiteral("mode")).toString();
    if (!schemaOk || schema != kAndroidInstallerAuthorizationSchema
        || (state != QStringLiteral("prepared") && state != QStringLiteral("authorized"))
        || mode != QStringLiteral("update")) {
        return false;
    }

    QVersionNumber sourceVersion;
    QVersionNumber installVersion;
    if (!parseExactVersion(authorization.value(QStringLiteral("sourceVersion")).toString(),
                           sourceVersion)
        || !parseExactVersion(authorization.value(QStringLiteral("installVersion")).toString(),
                              installVersion)) {
        return false;
    }

    bool sizeOk = false;
    const qint64 size = authorization.value(QStringLiteral("size")).toLongLong(&sizeOk);
    const QString platform = authorization.value(QStringLiteral("platform")).toString();
    const QString sha256 = normalizeSha256(
            authorization.value(QStringLiteral("sha256")).toString());
    const bool localPathValid = isCanonicalAndroidInstallerStagingPath(
            authorization.value(QStringLiteral("localPath")).toString());
    bool versionCodeOk = false;
    const qint64 installVersionCode = authorization.value(QStringLiteral("installVersionCode"))
            .toLongLong(&versionCodeOk);
    if (!sizeOk || size <= 0 || !versionCodeOk || installVersionCode <= 0
        || !platformCandidates().contains(platform)
        || !isCanonicalSha256(sha256)
        || !localPathValid) {
        return false;
    }

    const QDateTime preparedAt = storedUtcTimestamp(
            authorization.value(QStringLiteral("preparedAt")));
    const QDateTime expiresAt = storedUtcTimestamp(
            authorization.value(QStringLiteral("expiresAt")));
    if (!preparedAt.isValid() || !expiresAt.isValid() || expiresAt <= preparedAt
        || expiresAt > preparedAt.addMSecs(kAndroidApkInstallPermissionWaitMs + 1000)) {
        return false;
    }
    if (state == QStringLiteral("authorized")) {
        const QDateTime authorizedAt = storedUtcTimestamp(
                authorization.value(QStringLiteral("authorizedAt")));
        if (!authorizedAt.isValid() || authorizedAt < preparedAt || authorizedAt > expiresAt) {
            return false;
        }
    }

    bool generationOk = false;
    const qint64 generation =
            authorization.value(QStringLiteral("policyGeneration")).toLongLong(&generationOk);
    if (!generationOk || generation < 0) {
        return false;
    }
    if (generation > 0) {
        const QString payloadSha256 = normalizeSha256(
                authorization.value(QStringLiteral("policyPayloadSha256")).toString());
        const QDateTime policyExpiresAt = storedUtcTimestamp(
                authorization.value(QStringLiteral("policyExpiresAt")));
        if (!isCanonicalSha256(payloadSha256) || !policyExpiresAt.isValid()
            || expiresAt > policyExpiresAt || !m_appSettingsRepository
            || generation != m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyGeneration()
            || payloadSha256 != normalizeSha256(
                       m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyPayloadSha256())) {
            return false;
        }
    }

    if (mode == QStringLiteral("update")) {
        const QVariantMap healthReceipt =
                authorization.value(QStringLiteral("healthReceipt")).toMap();
        if (generation == 0) {
            return healthReceipt.isEmpty();
        }
        return isPendingHealthReceiptValid(healthReceipt)
                && healthReceipt.value(QStringLiteral("targetVersion")).toString()
                        == authorization.value(QStringLiteral("installVersion")).toString()
                && healthReceipt.value(QStringLiteral("sourceVersion")).toString()
                        == authorization.value(QStringLiteral("sourceVersion")).toString()
                && healthReceipt.value(QStringLiteral("policyGeneration")).toLongLong()
                        == generation
                && healthReceipt.value(QStringLiteral("policyPayloadSha256")).toString()
                        == authorization.value(QStringLiteral("policyPayloadSha256")).toString()
                && healthReceipt.value(QStringLiteral("policyExpiresAt")).toString()
                        == authorization.value(QStringLiteral("policyExpiresAt")).toString();
    }

    return false;
}

bool UpdateController::verifiedAndroidApkMatchesAuthorization(
        const QString &fileName, const QVariantMap &authorization) const
{
    if (!isAndroidApkInstallerAuthorizationValid(authorization)) {
        return false;
    }
    QString normalizedExpectedPath;
    if (!isCanonicalAndroidInstallerStagingPath(
                authorization.value(QStringLiteral("localPath")).toString(),
                &normalizedExpectedPath, true)) {
        return false;
    }
    const QFileInfo suppliedInfo(fileName);
    const QFileInfo expectedInfo(normalizedExpectedPath);
    if (!suppliedInfo.exists() || !suppliedInfo.isFile() || suppliedInfo.isSymLink()
        || QDir::cleanPath(suppliedInfo.absoluteFilePath())
                != QDir::cleanPath(expectedInfo.absoluteFilePath())
        || suppliedInfo.canonicalFilePath().isEmpty()
        || suppliedInfo.canonicalFilePath() != expectedInfo.canonicalFilePath()) {
        return false;
    }

    bool sizeOk = false;
    const qint64 expectedSize =
            authorization.value(QStringLiteral("size")).toLongLong(&sizeOk);
    if (!sizeOk || expectedSize <= 0 || suppliedInfo.size() != expectedSize) {
        return false;
    }

    QFile file(suppliedInfo.absoluteFilePath());
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }
    QCryptographicHash hash(QCryptographicHash::Sha256);
    qint64 bytesRead = 0;
    while (!file.atEnd()) {
        const QByteArray chunk = file.read(1024 * 1024);
        if (chunk.isEmpty() && file.error() != QFileDevice::NoError) {
            return false;
        }
        hash.addData(chunk);
        bytesRead += chunk.size();
        if (bytesRead > expectedSize) {
            return false;
        }
    }
    return bytesRead == expectedSize
            && QString::fromLatin1(hash.result().toHex())
                    == normalizeSha256(authorization.value(QStringLiteral("sha256")).toString());
}

bool UpdateController::authorizeAndroidApkInstallerLaunch(const QString &fileName,
                                                          const QString &packageName,
                                                          const QString &versionName,
                                                          qint64 versionCode)
{
    if (!m_appSettingsRepository) {
        return false;
    }
    QVariantMap authorization =
            m_appSettingsRepository->selfHostedUpdateAndroidInstallerAuthorization();
    if (!isAndroidApkInstallerAuthorizationValid(authorization)
        || authorization.value(QStringLiteral("state")).toString()
                != QStringLiteral("prepared")
        || QDateTime::currentDateTimeUtc()
                >= storedUtcTimestamp(authorization.value(QStringLiteral("expiresAt")))
        || (authorization.value(QStringLiteral("policyGeneration")).toLongLong() > 0
            && QDateTime::currentDateTimeUtc() >= storedUtcTimestamp(
                       authorization.value(QStringLiteral("policyExpiresAt"))))
        || QString(APP_VERSION).trimmed()
                != authorization.value(QStringLiteral("sourceVersion")).toString()
        || packageName != QStringLiteral("org.amnezia.vpn")
        || versionName != authorization.value(QStringLiteral("installVersion")).toString()
        || versionCode != authorization.value(QStringLiteral("installVersionCode")).toLongLong()
        || !verifiedAndroidApkMatchesAuthorization(fileName, authorization)) {
        logger.warning() << "Rejecting Android APK installer launch without a valid durable authorization";
        return false;
    }

    const QString authorizedAt = utcTimestamp(QDateTime::currentDateTimeUtc());
    authorization.insert(QStringLiteral("state"), QStringLiteral("authorized"));
    authorization.insert(QStringLiteral("authorizedAt"), authorizedAt);
    m_appSettingsRepository->setSelfHostedUpdateAndroidInstallerAuthorization(authorization);
    const QVariantMap persisted =
            m_appSettingsRepository->selfHostedUpdateAndroidInstallerAuthorization();
    const bool persistedExactly = isAndroidApkInstallerAuthorizationValid(persisted)
            && persisted.value(QStringLiteral("state")).toString()
                    == QStringLiteral("authorized")
            && persisted.value(QStringLiteral("authorizedAt")).toString() == authorizedAt;
    if (!persistedExactly) {
        logger.error() << "Failed to durably authorize Android APK installer launch";
    }
    return persistedExactly;
}

bool UpdateController::finalizeAndroidApkInstallerLaunch(const QString &fileName,
                                                         bool inferredFromRunningVersion)
{
    if (!m_appSettingsRepository) {
        return false;
    }
    const QVariantMap authorization =
            m_appSettingsRepository->selfHostedUpdateAndroidInstallerAuthorization();
    if (!isAndroidApkInstallerAuthorizationValid(authorization)
        || authorization.value(QStringLiteral("state")).toString()
                != QStringLiteral("authorized")) {
        return false;
    }
    const QString installVersion = authorization.value(QStringLiteral("installVersion")).toString();
    if (inferredFromRunningVersion) {
        if (QString(APP_VERSION).trimmed() != installVersion) {
            return false;
        }
    } else if (!verifiedAndroidApkMatchesAuthorization(fileName, authorization)) {
        return false;
    }

    const QString mode = authorization.value(QStringLiteral("mode")).toString();
    const qint64 generation = authorization.value(QStringLiteral("policyGeneration")).toLongLong();
    bool receiptPersisted = generation == 0 && mode == QStringLiteral("update");
    if (mode == QStringLiteral("update") && generation > 0) {
        QVariantMap receipt = authorization.value(QStringLiteral("healthReceipt")).toMap();
        const QDateTime now = QDateTime::currentDateTimeUtc();
        const int deadlineSeconds = receipt.value(QStringLiteral("healthDeadlineSeconds")).toInt();
        receipt.insert(QStringLiteral("installerStartedAt"), utcTimestamp(now));
        receipt.insert(QStringLiteral("deadlineAt"), utcTimestamp(now.addSecs(deadlineSeconds)));
        m_appSettingsRepository->setSelfHostedUpdatePendingHealthReceipt(receipt);
        const QVariantMap persistedReceipt =
                m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
        receiptPersisted = isPendingHealthReceiptValid(persistedReceipt)
                && persistedReceipt.value(QStringLiteral("targetVersion")).toString()
                        == installVersion
                && persistedReceipt.value(QStringLiteral("installerStartedAt")).toString()
                        == receipt.value(QStringLiteral("installerStartedAt")).toString();
        if (receiptPersisted) {
            emit updateHealthReceiptChanged();
            emit rollbackAvailabilityChanged();
        }
    } else if (mode == QStringLiteral("rollback")) {
        // Android Package Installer cannot apply the older signed rollback
        // build. This mode is rejected during authorization and remains here
        // only so stale schema-1 state fails closed.
        receiptPersisted = false;
    }
    if (!receiptPersisted) {
        logger.error() << "Android APK installer started without a durable health handoff receipt";
        return false;
    }

    const QString autoInstallAttemptMarker =
            authorization.value(QStringLiteral("autoInstallAttemptMarker")).toString();
    if (!autoInstallAttemptMarker.isEmpty() && autoInstallAttemptMarker.size() <= 1024) {
        m_appSettingsRepository->setSelfHostedUpdateLastAutoInstallAttempt(
                autoInstallAttemptMarker);
    }
    m_appSettingsRepository->clearSelfHostedUpdateAndroidInstallerAuthorization();
    return m_appSettingsRepository->selfHostedUpdateAndroidInstallerAuthorization().isEmpty();
}

void UpdateController::failAndroidApkInstallerLaunch(const QString &fileName,
                                                     const QString &reason)
{
    if (!m_appSettingsRepository) {
        return;
    }
    const QVariantMap authorization =
            m_appSettingsRepository->selfHostedUpdateAndroidInstallerAuthorization();
    if (!isAndroidApkInstallerAuthorizationValid(authorization)
        || QDir::cleanPath(QFileInfo(fileName).absoluteFilePath())
                != QDir::cleanPath(QFileInfo(
                       authorization.value(QStringLiteral("localPath")).toString())
                                           .absoluteFilePath())) {
        return;
    }

    m_appSettingsRepository->clearSelfHostedUpdateAndroidInstallerAuthorization();
    if (authorization.value(QStringLiteral("mode")).toString()
        == QStringLiteral("rollback")) {
        QVariantMap receipt = m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
        if (isPendingHealthReceiptValid(receipt)) {
            receipt.insert(QStringLiteral("rollbackLastErrorAt"),
                           utcTimestamp(QDateTime::currentDateTimeUtc()));
            receipt.insert(QStringLiteral("rollbackLastErrorReason"), boundedReceiptReason(reason));
            m_appSettingsRepository->setSelfHostedUpdatePendingHealthReceipt(receipt);
            emit updateHealthReceiptChanged();
            emit rollbackAvailabilityChanged();
        }
    }
    m_handoffReceiptPrepared = false;
    m_androidApkInstallPermissionPending = false;
    m_selfHostedInstallInProgress = false;
    clearPendingAutoInstallAttempt();
    clearInstallSelection();
}

void UpdateController::recoverAndroidApkInstallerAuthorization()
{
    if (!m_appSettingsRepository) {
        return;
    }
    const QVariantMap authorization =
            m_appSettingsRepository->selfHostedUpdateAndroidInstallerAuthorization();
    if (authorization.isEmpty()) {
        return;
    }
    if (!isAndroidApkInstallerAuthorizationValid(authorization)) {
        logger.warning() << "Discarding invalid Android APK installer authorization";
        m_appSettingsRepository->clearSelfHostedUpdateAndroidInstallerAuthorization();
        return;
    }

    const QString state = authorization.value(QStringLiteral("state")).toString();
    const QString runningVersion = QString(APP_VERSION).trimmed();
    const QString sourceVersion = authorization.value(QStringLiteral("sourceVersion")).toString();
    const QString installVersion = authorization.value(QStringLiteral("installVersion")).toString();
    QString persistedLocalPath;
    if (!isCanonicalAndroidInstallerStagingPath(
                authorization.value(QStringLiteral("localPath")).toString(),
                &persistedLocalPath)) {
        m_appSettingsRepository->clearSelfHostedUpdateAndroidInstallerAuthorization();
        return;
    }
    if (state == QStringLiteral("authorized") && runningVersion == installVersion) {
        m_localInstallerPath = persistedLocalPath;
        if (!finalizeAndroidApkInstallerLaunch(
                    persistedLocalPath, true)) {
            logger.error() << "Failed to recover Android APK installer health receipt";
        }
        return;
    }
    if (runningVersion != sourceVersion) {
        failAndroidApkInstallerLaunch(
                authorization.value(QStringLiteral("localPath")).toString(),
                QStringLiteral("unexpected_running_version"));
        return;
    }
    if (!isCanonicalAndroidInstallerStagingPath(
                persistedLocalPath, nullptr, true)
        || !verifiedAndroidApkMatchesAuthorization(persistedLocalPath, authorization)) {
        failAndroidApkInstallerLaunch(
                persistedLocalPath, QStringLiteral("apk_authorization_rejected"));
        return;
    }

    m_localInstallerPath = persistedLocalPath;
    m_selfHostedInstallInProgress = true;
    m_androidApkInstallPermissionPending = true;
    m_rollbackInstallAttempt = authorization.value(QStringLiteral("mode")).toString()
            == QStringLiteral("rollback");
    const QDateTime expiresAt = storedUtcTimestamp(
            authorization.value(QStringLiteral("expiresAt")));
    const qint64 remainingMs = QDateTime::currentDateTimeUtc().msecsTo(expiresAt);
    if (remainingMs <= 0) {
        expireAndroidApkInstallerAuthorization(
                authorization.value(QStringLiteral("preparedAt")).toString());
        return;
    }
    QTimer::singleShot(static_cast<int>(remainingMs), this,
                       [this, preparedAt = authorization.value(
                                QStringLiteral("preparedAt")).toString()]() {
        expireAndroidApkInstallerAuthorization(preparedAt);
    });
}

void UpdateController::expireAndroidApkInstallerAuthorization(const QString &preparedAt)
{
    if (!m_appSettingsRepository) {
        return;
    }
    const QVariantMap authorization =
            m_appSettingsRepository->selfHostedUpdateAndroidInstallerAuthorization();
    if (!isAndroidApkInstallerAuthorizationValid(authorization)
        || authorization.value(QStringLiteral("preparedAt")).toString() != preparedAt) {
        return;
    }
    const QDateTime expiresAt = storedUtcTimestamp(
            authorization.value(QStringLiteral("expiresAt")));
    const qint64 remainingMs = QDateTime::currentDateTimeUtc().msecsTo(expiresAt);
    if (remainingMs > 0) {
        QTimer::singleShot(static_cast<int>(remainingMs), this,
                           [this, preparedAt]() {
            expireAndroidApkInstallerAuthorization(preparedAt);
        });
        return;
    }
    logger.info() << "Android APK installer authorization expired before handoff";
    failAndroidApkInstallerLaunch(
            authorization.value(QStringLiteral("localPath")).toString(),
            QStringLiteral("android_installer_authorization_expired"));
}
#endif

bool UpdateController::scheduleAutomaticRollbackRetry(const QVariantMap &receipt)
{
    if (!m_appSettingsRepository || !isPendingHealthReceiptValid(receipt)
        || receipt.value(QStringLiteral("healthState")).toString()
                != QStringLiteral("failed")
        || !receipt.value(QStringLiteral("rollbackState")).toString().isEmpty()
        || !receipt.value(QStringLiteral("automaticRollbackTerminalAt")).toString().isEmpty()) {
        return false;
    }
    bool failureCountOk = false;
    const int failureCount = receipt.value(
            QStringLiteral("automaticRollbackPreHandoffFailureCount"))
                                     .toInt(&failureCountOk);
    const QDateTime retryAt = storedUtcTimestamp(
            receipt.value(QStringLiteral("automaticRollbackNextAttemptAt")));
    if (!failureCountOk || failureCount <= 0
        || failureCount >= kMaximumAutomaticRollbackPreHandoffFailures
        || !retryAt.isValid()) {
        return false;
    }

    const QString receiptId = receipt.value(QStringLiteral("receiptId")).toString();
    const QString expectedRetryAt = utcTimestamp(retryAt);
    const qint64 remainingMs = qMax<qint64>(
            0, QDateTime::currentDateTimeUtc().msecsTo(retryAt));
    QTimer::singleShot(static_cast<int>(remainingMs), this,
                       [this, receiptId, failureCount, expectedRetryAt]() {
        if (!m_appSettingsRepository) {
            return;
        }
        const QVariantMap current =
                m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
        if (!isPendingHealthReceiptValid(current)
            || current.value(QStringLiteral("receiptId")).toString() != receiptId
            || !current.value(QStringLiteral("rollbackState")).toString().isEmpty()
            || !current.value(QStringLiteral("automaticRollbackTerminalAt")).toString().isEmpty()
            || current.value(
                       QStringLiteral("automaticRollbackPreHandoffFailureCount")).toInt()
                    != failureCount
            || current.value(QStringLiteral("automaticRollbackNextAttemptAt")).toString()
                    != expectedRetryAt) {
            return;
        }
        const QDateTime currentRetryAt = storedUtcTimestamp(
                current.value(QStringLiteral("automaticRollbackNextAttemptAt")));
        if (QDateTime::currentDateTimeUtc() < currentRetryAt) {
            scheduleAutomaticRollbackRetry(current);
            return;
        }
        scheduleAutomaticRollbackIfEligible();
    });
    return true;
}

bool UpdateController::scheduleAutomaticRollbackIfEligible()
{
    if (!m_appSettingsRepository || m_selfHostedInstallInProgress
        || m_androidApkInstallPermissionPending || m_rollbackInstallAttempt) {
        return false;
    }

    const QVariantMap receipt = m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
    if (!isPendingHealthReceiptValid(receipt)
        || receipt.value(QStringLiteral("healthState")).toString() != QStringLiteral("failed")
        || !receipt.value(QStringLiteral("rollbackRequestedAt")).toString().isEmpty()) {
        return false;
    }

    if (receipt.value(QStringLiteral("rollbackState")).toString()
            == QStringLiteral("leased")) {
        return receipt.value(QStringLiteral("rollbackOrigin")).toString()
                        == QStringLiteral("automatic")
                && recoverAutomaticRollbackLease(receipt);
    }
    if (!receipt.value(QStringLiteral("rollbackState")).toString().isEmpty()
        || !receipt.value(QStringLiteral("automaticRollbackTerminalAt")).toString().isEmpty()) {
        return false;
    }
    const QDateTime retryAt = storedUtcTimestamp(
            receipt.value(QStringLiteral("automaticRollbackNextAttemptAt")));
    if (retryAt.isValid() && QDateTime::currentDateTimeUtc() < retryAt) {
        return scheduleAutomaticRollbackRetry(receipt);
    }

    UpdateArtifact rollbackArtifact;
    if (!rollbackArtifactFromReceipt(receipt, rollbackArtifact)
        || rollbackArtifact.openExternally
        || receipt.value(QStringLiteral("rollbackVersion")).toString()
                != receipt.value(QStringLiteral("sourceVersion")).toString()
        || !automaticRollbackRunningVersionAllowed(
                QString(APP_VERSION).trimmed(),
                receipt.value(QStringLiteral("targetVersion")).toString(),
                receipt.value(QStringLiteral("rollbackVersion")).toString())) {
        return false;
    }
    if (!receiptMatchesAcceptedPolicy(receipt)) {
        logger.warning() << "Automatic rollback skipped because receipt policy binding is unavailable";
        return false;
    }

    RollbackAttemptContext attempt;
    if (!claimRollbackIntent(QStringLiteral("automatic"), attempt)) {
        return false;
    }
    QTimer::singleShot(0, this, [this, attempt]() {
        runPendingRollbackWithIntent(attempt);
    });
    return true;
}

bool UpdateController::claimRollbackIntent(const QString &origin,
                                           RollbackAttemptContext &attemptOut)
{
    if (!m_appSettingsRepository
        || (origin != QStringLiteral("manual") && origin != QStringLiteral("automatic"))) {
        return false;
    }
    QVariantMap receipt = m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
    UpdateArtifact artifact;
    if (!isPendingHealthReceiptValid(receipt) || !receiptMatchesAcceptedPolicy(receipt)
        || receipt.value(QStringLiteral("healthState")).toString() != QStringLiteral("failed")
        || !receipt.value(QStringLiteral("rollbackState")).toString().isEmpty()
        || !automaticRollbackRunningVersionAllowed(
                QString(APP_VERSION).trimmed(),
                receipt.value(QStringLiteral("targetVersion")).toString(),
                receipt.value(QStringLiteral("rollbackVersion")).toString())
        || !rollbackArtifactFromReceipt(receipt, artifact) || artifact.openExternally) {
        return false;
    }

    const QDateTime now = QDateTime::currentDateTimeUtc();
    if (origin == QStringLiteral("automatic")) {
        bool failureCountOk = true;
        const int failureCount = receipt.contains(
                QStringLiteral("automaticRollbackPreHandoffFailureCount"))
                ? receipt.value(QStringLiteral(
                          "automaticRollbackPreHandoffFailureCount")).toInt(&failureCountOk)
                : 0;
        const QDateTime retryAt = storedUtcTimestamp(
                receipt.value(QStringLiteral("automaticRollbackNextAttemptAt")));
        if (!failureCountOk
            || failureCount >= kMaximumAutomaticRollbackPreHandoffFailures
            || !receipt.value(QStringLiteral("automaticRollbackTerminalAt")).toString().isEmpty()
            || (retryAt.isValid() && now < retryAt)) {
            return false;
        }
    }
    const QString intentId = QUuid::createUuid().toString(QUuid::WithoutBraces).toLower();
    const QString leaseId = QUuid::createUuid().toString(QUuid::WithoutBraces).toLower();
    receipt.insert(QStringLiteral("rollbackState"), QStringLiteral("leased"));
    receipt.insert(QStringLiteral("rollbackIntentId"), intentId);
    receipt.insert(QStringLiteral("rollbackOrigin"), origin);
    receipt.insert(QStringLiteral("rollbackLeaseId"), leaseId);
    receipt.insert(QStringLiteral("rollbackLeaseAcquiredAt"), utcTimestamp(now));
    receipt.insert(QStringLiteral("rollbackLeaseExpiresAt"),
                   utcTimestamp(now.addSecs(kRollbackIntentLeaseSeconds)));
    receipt.insert(QStringLiteral("rollbackRecoveryCount"), 0);
    if (origin == QStringLiteral("automatic")) {
        receipt.remove(QStringLiteral("automaticRollbackNextAttemptAt"));
    }
    m_appSettingsRepository->setSelfHostedUpdatePendingHealthReceipt(receipt);
    const QVariantMap persisted = m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
    if (!isPendingHealthReceiptValid(persisted)
        || persisted.value(QStringLiteral("receiptId")).toString()
                != receipt.value(QStringLiteral("receiptId")).toString()
        || persisted.value(QStringLiteral("rollbackIntentId")).toString() != intentId
        || persisted.value(QStringLiteral("rollbackLeaseId")).toString() != leaseId) {
        logger.error() << "Rollback intent lease could not be durably persisted";
        return false;
    }
    attemptOut = RollbackAttemptContext {
        receipt.value(QStringLiteral("receiptId")).toString(), intentId, leaseId
    };
    emit updateHealthReceiptChanged();
    emit rollbackAvailabilityChanged();
    return true;
}

bool UpdateController::recoverAutomaticRollbackLease(QVariantMap receipt)
{
    if (!m_appSettingsRepository || !isPendingHealthReceiptValid(receipt)
        || receipt.value(QStringLiteral("rollbackState")).toString() != QStringLiteral("leased")
        || receipt.value(QStringLiteral("rollbackOrigin")).toString() != QStringLiteral("automatic")) {
        return false;
    }
    if (m_selfHostedInstallInProgress && m_rollbackInstallAttempt
        && m_installIntent.kind == InstallIntentKind::Rollback
        && m_installIntent.consumed
        && m_installIntent.receiptId
                == receipt.value(QStringLiteral("receiptId")).toString()
        && m_installIntent.id
                == receipt.value(QStringLiteral("rollbackIntentId")).toString()
        && m_installIntent.leaseId
                == receipt.value(QStringLiteral("rollbackLeaseId")).toString()) {
        QTimer::singleShot(1000, this, &UpdateController::refreshPendingUpdateHealth);
        return true;
    }
    const QDateTime now = QDateTime::currentDateTimeUtc();
    const QDateTime expiresAt = storedUtcTimestamp(
            receipt.value(QStringLiteral("rollbackLeaseExpiresAt")));
    const int recoveryCount = receipt.value(QStringLiteral("rollbackRecoveryCount")).toInt();
    const RollbackLeaseDisposition disposition = evaluateRollbackLease(
            now, expiresAt, recoveryCount, kMaximumAutomaticRollbackRecoveries);
    if (disposition == RollbackLeaseDisposition::Wait) {
        QTimer::singleShot(static_cast<int>(qMax<qint64>(1, now.msecsTo(expiresAt))),
                           this, &UpdateController::refreshPendingUpdateHealth);
        return true;
    }
    if (disposition == RollbackLeaseDisposition::Exhausted) {
        receipt.insert(QStringLiteral("automaticRollbackTerminalAt"), utcTimestamp(now));
        receipt.insert(QStringLiteral("automaticRollbackLastErrorAt"), utcTimestamp(now));
        receipt.insert(QStringLiteral("automaticRollbackLastErrorReason"),
                       QStringLiteral("lease_recovery_exhausted"));
        receipt.remove(QStringLiteral("rollbackState"));
        receipt.remove(QStringLiteral("rollbackIntentId"));
        receipt.remove(QStringLiteral("rollbackOrigin"));
        receipt.remove(QStringLiteral("rollbackLeaseId"));
        receipt.remove(QStringLiteral("rollbackLeaseAcquiredAt"));
        receipt.remove(QStringLiteral("rollbackLeaseExpiresAt"));
        receipt.remove(QStringLiteral("rollbackRecoveryCount"));
        m_appSettingsRepository->setSelfHostedUpdatePendingHealthReceipt(receipt);
        emit updateHealthReceiptChanged();
        emit rollbackAvailabilityChanged();
        return false;
    }
    if (disposition != RollbackLeaseDisposition::Recover) {
        return false;
    }

    const QString intentId = receipt.value(QStringLiteral("rollbackIntentId")).toString();
    const QString leaseId = QUuid::createUuid().toString(QUuid::WithoutBraces).toLower();
    receipt.insert(QStringLiteral("rollbackLeaseId"), leaseId);
    receipt.insert(QStringLiteral("rollbackLeaseAcquiredAt"), utcTimestamp(now));
    receipt.insert(QStringLiteral("rollbackLeaseExpiresAt"),
                   utcTimestamp(now.addSecs(kRollbackIntentLeaseSeconds)));
    receipt.insert(QStringLiteral("rollbackRecoveryCount"), recoveryCount + 1);
    m_appSettingsRepository->setSelfHostedUpdatePendingHealthReceipt(receipt);
    const QVariantMap persisted = m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
    if (!isPendingHealthReceiptValid(persisted)
        || persisted.value(QStringLiteral("rollbackIntentId")).toString() != intentId
        || persisted.value(QStringLiteral("rollbackLeaseId")).toString() != leaseId) {
        return false;
    }
    emit updateHealthReceiptChanged();
    emit rollbackAvailabilityChanged();
    const RollbackAttemptContext attempt {
        persisted.value(QStringLiteral("receiptId")).toString(), intentId, leaseId
    };
    QTimer::singleShot(0, this, [this, attempt]() {
        runPendingRollbackWithIntent(attempt);
    });
    return true;
}

void UpdateController::finishPendingHealthReceipt(const QVariantMap &pendingReceipt,
                                                  const QString &status,
                                                  const QString &reason,
                                                  bool clearPendingReceipt)
{
    if (!m_appSettingsRepository) {
        return;
    }

    QVariantMap lastReceipt;
    lastReceipt.insert(QStringLiteral("schema"), kHealthReceiptSchema);
    lastReceipt.insert(QStringLiteral("receiptId"), pendingReceipt.value(QStringLiteral("receiptId")));
    lastReceipt.insert(QStringLiteral("targetVersion"), pendingReceipt.value(QStringLiteral("targetVersion")));
    lastReceipt.insert(QStringLiteral("policyGeneration"), pendingReceipt.value(QStringLiteral("policyGeneration")));
    lastReceipt.insert(QStringLiteral("policyPayloadSha256"),
                       pendingReceipt.value(QStringLiteral("policyPayloadSha256")));
    lastReceipt.insert(QStringLiteral("rollbackIntentId"),
                       pendingReceipt.value(QStringLiteral("rollbackIntentId")));
    lastReceipt.insert(QStringLiteral("rollbackOrigin"),
                       pendingReceipt.value(QStringLiteral("rollbackOrigin")));
    lastReceipt.insert(QStringLiteral("rollbackSha256"),
                       pendingReceipt.value(QStringLiteral("rollbackSha256")));
    lastReceipt.insert(QStringLiteral("status"), status);
    lastReceipt.insert(QStringLiteral("observedAt"), utcTimestamp(QDateTime::currentDateTimeUtc()));
    lastReceipt.insert(QStringLiteral("reason"), boundedReceiptReason(reason));
    lastReceipt.insert(QStringLiteral("runningVersion"), QString(APP_VERSION).trimmed());
    lastReceipt.insert(QStringLiteral("channel"), pendingReceipt.value(QStringLiteral("channel")));
    m_appSettingsRepository->setSelfHostedUpdateLastHealthReceipt(lastReceipt);

    if (clearPendingReceipt) {
        m_appSettingsRepository->clearSelfHostedUpdatePendingHealthReceipt();
    } else {
        QVariantMap updatedPending = pendingReceipt;
        updatedPending.insert(QStringLiteral("healthState"), QStringLiteral("failed"));
        updatedPending.insert(QStringLiteral("failedAt"), utcTimestamp(QDateTime::currentDateTimeUtc()));
        updatedPending.insert(QStringLiteral("failureReason"), boundedReceiptReason(reason));
        m_appSettingsRepository->setSelfHostedUpdatePendingHealthReceipt(updatedPending);
    }

    emit updateHealthReceiptChanged();
    emit rollbackAvailabilityChanged();
}

void UpdateController::refreshPendingUpdateHealth()
{
    if (!m_appSettingsRepository) {
        return;
    }
    QVariantMap receipt = m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
    if (receipt.isEmpty()) {
        return;
    }
    if (!isPendingHealthReceiptValid(receipt)) {
        QVariantMap invalidReceipt;
        invalidReceipt.insert(QStringLiteral("schema"), kHealthReceiptSchema);
        invalidReceipt.insert(QStringLiteral("targetVersion"), receipt.value(QStringLiteral("targetVersion")));
        invalidReceipt.insert(QStringLiteral("policyGeneration"), receipt.value(QStringLiteral("policyGeneration")));
        invalidReceipt.insert(QStringLiteral("status"), QStringLiteral("failed"));
        invalidReceipt.insert(QStringLiteral("observedAt"), utcTimestamp(QDateTime::currentDateTimeUtc()));
        invalidReceipt.insert(QStringLiteral("reason"), QStringLiteral("invalid_pending_receipt"));
        invalidReceipt.insert(QStringLiteral("runningVersion"), QString(APP_VERSION).trimmed());
        m_appSettingsRepository->setSelfHostedUpdateLastHealthReceipt(invalidReceipt);
        m_appSettingsRepository->clearSelfHostedUpdatePendingHealthReceipt();
        emit updateHealthReceiptChanged();
        emit rollbackAvailabilityChanged();
        return;
    }

    const QDateTime now = QDateTime::currentDateTimeUtc();
    const QString runningVersion = QString(APP_VERSION).trimmed();
    const QString rollbackVersion = receipt.value(QStringLiteral("rollbackVersion")).toString();
    const bool failed = receipt.value(QStringLiteral("healthState")).toString() == QStringLiteral("failed");
    if (failed) {
        const QString rollbackState = receipt.value(QStringLiteral("rollbackState")).toString();
        if (rollbackState == QStringLiteral("confirmation_pending")) {
            const QDateTime confirmationExpiresAt = storedUtcTimestamp(
                    receipt.value(QStringLiteral("deadlineAt")));
            const qint64 remainingMs = now.msecsTo(confirmationExpiresAt);
            if (remainingMs > 0) {
                QTimer::singleShot(static_cast<int>(remainingMs), this,
                                   &UpdateController::refreshPendingUpdateHealth);
                return;
            }
            // A rollback binary that is running but never proves service
            // readiness is still a failed rollback. Do not let version equality
            // bypass or cancel this persisted deadline.
            if (!rollbackVersion.isEmpty() && runningVersion == rollbackVersion) {
                finishPendingHealthReceipt(receipt, QStringLiteral("failed"),
                                           QStringLiteral("rollback_readiness_timeout"), true);
                return;
            }

            // The installer may have been cancelled at UAC/PackageKit after a
            // successful process handoff. If the rollback version never became
            // active, retain the original failed receipt and signed artifact so
            // the operator can retry. Automatic attempts are bounded: a
            // confirmation miss is terminal for automation and never loops.
            const int confirmationFailures = qMin(
                    kMaximumAutomaticRollbackConfirmationFailures,
                    receipt.value(QStringLiteral("rollbackConfirmationFailureCount"), 0)
                                    .toInt() + 1);
            if (receipt.contains(QStringLiteral("rollbackSourceInstallerStartedAt"))) {
                receipt.insert(QStringLiteral("installerStartedAt"),
                               receipt.take(QStringLiteral("rollbackSourceInstallerStartedAt")));
                receipt.insert(QStringLiteral("healthDeadlineSeconds"),
                               receipt.take(QStringLiteral("rollbackSourceHealthDeadlineSeconds")));
                receipt.insert(QStringLiteral("deadlineAt"),
                               receipt.take(QStringLiteral("rollbackSourceDeadlineAt")));
            }
            receipt.insert(QStringLiteral("rollbackConfirmationFailureCount"),
                           confirmationFailures);
            receipt.insert(QStringLiteral("rollbackLastErrorAt"), utcTimestamp(now));
            receipt.insert(QStringLiteral("rollbackLastErrorReason"),
                           QStringLiteral("rollback_version_not_observed"));
            if (confirmationFailures >= kMaximumAutomaticRollbackConfirmationFailures) {
                receipt.insert(QStringLiteral("automaticRollbackTerminalAt"), utcTimestamp(now));
                receipt.insert(QStringLiteral("automaticRollbackLastErrorAt"), utcTimestamp(now));
                receipt.insert(QStringLiteral("automaticRollbackLastErrorReason"),
                               QStringLiteral("confirmation_not_observed"));
            }
            receipt.remove(QStringLiteral("rollbackRequestedAt"));
            receipt.remove(QStringLiteral("rollbackState"));
            receipt.remove(QStringLiteral("rollbackIntentId"));
            receipt.remove(QStringLiteral("rollbackOrigin"));
            receipt.remove(QStringLiteral("rollbackLeaseId"));
            receipt.remove(QStringLiteral("rollbackLeaseAcquiredAt"));
            receipt.remove(QStringLiteral("rollbackLeaseExpiresAt"));
            receipt.remove(QStringLiteral("rollbackRecoveryCount"));
            receipt.remove(QStringLiteral("rollbackHandoffLeaseId"));
            m_appSettingsRepository->setSelfHostedUpdatePendingHealthReceipt(receipt);
            const QVariantMap restoredReceipt =
                    m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
            if (!isPendingHealthReceiptValid(restoredReceipt)
                || restoredReceipt.value(QStringLiteral("receiptId")).toString()
                        != receipt.value(QStringLiteral("receiptId")).toString()
                || restoredReceipt.value(QStringLiteral("rollbackSha256")).toString()
                        != receipt.value(QStringLiteral("rollbackSha256")).toString()) {
                logger.error() << "Failed to restore retryable rollback receipt after confirmation timeout";
            }
            emit updateHealthReceiptChanged();
            emit rollbackAvailabilityChanged();
            return;
        }

        if (rollbackState == QStringLiteral("leased")) {
            if (receipt.value(QStringLiteral("rollbackOrigin")).toString()
                    == QStringLiteral("automatic")) {
                recoverAutomaticRollbackLease(receipt);
                return;
            }
            const QDateTime leaseExpiresAt = storedUtcTimestamp(
                    receipt.value(QStringLiteral("rollbackLeaseExpiresAt")));
            const qint64 remainingMs = now.msecsTo(leaseExpiresAt);
            if (remainingMs > 0) {
                QTimer::singleShot(static_cast<int>(remainingMs), this,
                                   &UpdateController::refreshPendingUpdateHealth);
                return;
            }
            receipt.insert(QStringLiteral("rollbackLastErrorAt"), utcTimestamp(now));
            receipt.insert(QStringLiteral("rollbackLastErrorReason"),
                           QStringLiteral("manual_handoff_interrupted"));
            receipt.remove(QStringLiteral("rollbackState"));
            receipt.remove(QStringLiteral("rollbackIntentId"));
            receipt.remove(QStringLiteral("rollbackOrigin"));
            receipt.remove(QStringLiteral("rollbackLeaseId"));
            receipt.remove(QStringLiteral("rollbackLeaseAcquiredAt"));
            receipt.remove(QStringLiteral("rollbackLeaseExpiresAt"));
            receipt.remove(QStringLiteral("rollbackRecoveryCount"));
            m_appSettingsRepository->setSelfHostedUpdatePendingHealthReceipt(receipt);
            const QVariantMap restoredReceipt =
                    m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
            emit updateHealthReceiptChanged();
            emit rollbackAvailabilityChanged();
            if (isPendingHealthReceiptValid(restoredReceipt)
                && restoredReceipt.value(QStringLiteral("receiptId")).toString()
                        == receipt.value(QStringLiteral("receiptId")).toString()
                && restoredReceipt.contains(
                        QStringLiteral("automaticRollbackNextAttemptAt"))) {
                scheduleAutomaticRollbackRetry(restoredReceipt);
            }
            return;
        }

        if (!rollbackVersion.isEmpty() && runningVersion == rollbackVersion) {
            finishPendingHealthReceipt(receipt, QStringLiteral("failed"),
                                       QStringLiteral("rollback_without_intent"), true);
            return;
        }
        scheduleAutomaticRollbackIfEligible();
        return;
    }

    const QDateTime deadlineAt = storedUtcTimestamp(receipt.value(QStringLiteral("deadlineAt")));
    if (now < deadlineAt) {
        return;
    }

    UpdateArtifact rollbackArtifact;
    const bool keepForRollback = rollbackArtifactFromReceipt(receipt, rollbackArtifact)
            && runningVersion != rollbackVersion;
    finishPendingHealthReceipt(receipt, QStringLiteral("failed"),
                               QStringLiteral("health_deadline_expired"), !keepForRollback);
    if (keepForRollback) {
        scheduleAutomaticRollbackIfEligible();
    }
}

bool UpdateController::confirmRunningVersionHealthy()
{
    if (!m_appSettingsRepository) {
        return false;
    }
    QVariantMap receipt = m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
    if (!isPendingHealthReceiptValid(receipt)) {
        refreshPendingUpdateHealth();
        return false;
    }

    const QString runningVersion = QString(APP_VERSION).trimmed();
    const QString rollbackVersion = receipt.value(QStringLiteral("rollbackVersion")).toString();
    const QDateTime deadlineAt = storedUtcTimestamp(receipt.value(QStringLiteral("deadlineAt")));
    if (QDateTime::currentDateTimeUtc() >= deadlineAt) {
        refreshPendingUpdateHealth();
        return false;
    }
    if (receipt.value(QStringLiteral("rollbackState")).toString()
                == QStringLiteral("confirmation_pending")
        && !receipt.value(QStringLiteral("rollbackRequestedAt")).toString().isEmpty()
        && !rollbackVersion.isEmpty() && runningVersion == rollbackVersion) {
        finishPendingHealthReceipt(receipt, QStringLiteral("rolled_back"),
                                   QStringLiteral("rollback_version_running"), true);
        return true;
    }

    if (receipt.value(QStringLiteral("healthState")).toString() == QStringLiteral("failed")) {
        return false;
    }
    if (runningVersion == receipt.value(QStringLiteral("targetVersion")).toString()) {
        finishPendingHealthReceipt(receipt, QStringLiteral("healthy"),
                                   QStringLiteral("running_version_ready"), true);
        return true;
    }
    if (runningVersion == receipt.value(QStringLiteral("sourceVersion")).toString()) {
        return false;
    }
    return markRunningVersionUnhealthy(QStringLiteral("unexpected_running_version"));
}

bool UpdateController::markRunningVersionUnhealthy(const QString &reason)
{
    if (!m_appSettingsRepository) {
        return false;
    }
    const QVariantMap receipt = m_appSettingsRepository->selfHostedUpdatePendingHealthReceipt();
    if (!isPendingHealthReceiptValid(receipt)
        || receipt.value(QStringLiteral("healthState")).toString() == QStringLiteral("failed")
        || QString(APP_VERSION).trimmed() != receipt.value(QStringLiteral("targetVersion")).toString()) {
        return false;
    }

    UpdateArtifact rollbackArtifact;
    const bool keepForRollback = rollbackArtifactFromReceipt(receipt, rollbackArtifact)
            && QString(APP_VERSION).trimmed() != receipt.value(QStringLiteral("rollbackVersion")).toString();
    finishPendingHealthReceipt(receipt, QStringLiteral("failed"), reason, !keepForRollback);
    if (keepForRollback) {
        scheduleAutomaticRollbackIfEligible();
    }
    return true;
}

bool UpdateController::runPendingRollback()
{
    const QVariantMap action = getRollbackActionMetadata();
    if (!action.value(QStringLiteral("available")).toBool()) {
        logger.warning() << "Rollback action is unavailable:" << action.value(QStringLiteral("reason")).toString();
        return false;
    }

    RollbackAttemptContext attempt;
    if (!claimRollbackIntent(QStringLiteral("manual"), attempt)) {
        return false;
    }
    return runPendingRollbackWithIntent(attempt);
}

bool UpdateController::runPendingRollbackWithIntent(
        const RollbackAttemptContext &expectedAttempt)
{
    if (!m_appSettingsRepository || !expectedAttempt.isComplete()) {
        return false;
    }
    const QVariantMap receipt = getPendingUpdateHealthReceipt();
    UpdateArtifact rollbackArtifact;
    const bool exactLeaseOwned = receipt.value(QStringLiteral("rollbackState")).toString()
                    == QStringLiteral("leased")
        && receipt.value(QStringLiteral("receiptId")).toString()
                == expectedAttempt.receiptId
        && receipt.value(QStringLiteral("rollbackIntentId")).toString()
                == expectedAttempt.intentId
        && receipt.value(QStringLiteral("rollbackLeaseId")).toString()
                == expectedAttempt.leaseId;
    if (!exactLeaseOwned) {
        return false;
    }
    if (!isPendingHealthReceiptValid(receipt)) {
        refreshPendingUpdateHealth();
        return false;
    }
    if (QDateTime::currentDateTimeUtc() >= storedUtcTimestamp(
                receipt.value(QStringLiteral("rollbackLeaseExpiresAt")))) {
        // A queued attempt may resume after suspend with an already-expired
        // lease. Progress recovery now instead of starting a download that can
        // no longer produce an authorized handoff.
        refreshPendingUpdateHealth();
        return false;
    }
    if (!receiptMatchesAcceptedPolicy(receipt)
        || QString(APP_VERSION).trimmed()
                != receipt.value(QStringLiteral("targetVersion")).toString()
        || !rollbackArtifactFromReceipt(receipt, rollbackArtifact)
        || rollbackArtifact.openExternally) {
        recordRollbackHandoffFailure(expectedAttempt, true);
        return false;
    }
    m_selectedArtifact = rollbackArtifact;
    m_version = receipt.value(QStringLiteral("rollbackVersion")).toString();
    m_downloadUrl = rollbackArtifact.url.toString();
    m_useSelfHostedArtifact = true;
    m_pendingAutoInstallAttemptId.clear();
    m_rollbackInstallAttempt = true;
    armRollbackInstallIntent(receipt, rollbackArtifact, expectedAttempt);
    const bool started = runInstaller();
    if (!started) {
        recordRollbackHandoffFailure(expectedAttempt);
    }
    if (!started && m_rollbackInstallAttempt) {
        clearInstallSelection();
    }
    return started;
}

bool UpdateController::checkForUpdates()
{
    if (m_updateCheckRunning || m_selfHostedInstallInProgress || m_androidApkInstallPermissionPending || !m_appSettingsRepository) {
        return false;
    }
    m_updateCheckRunning = true;
    m_updateFoundDuringCheck = false;
    clearInstallSelection();
    clearSelectedReleasePolicy();
    m_pendingAutoInstallAttemptId.clear();

    if (isSelfHostedUpdateChannelConfigured()) {
        fetchSelfHostedManifest();
    } else {
        fetchGatewayUrl();
    }
    return true;
}

void UpdateController::finishUpdateCheck()
{
    const bool updateAvailable = m_updateFoundDuringCheck;
    m_updateCheckRunning = false;
    emit updateCheckFinished(updateAvailable);
}

void UpdateController::startBackgroundUpdateChecks()
{
    m_backgroundUpdateTimer = new QTimer(this);
    m_backgroundUpdateTimer->setInterval(kBackgroundUpdateCheckIntervalMs);
    m_backgroundUpdateTimer->setSingleShot(false);
    connect(m_backgroundUpdateTimer, &QTimer::timeout, this, &UpdateController::checkForUpdates);
    m_backgroundUpdateTimer->start();

    QTimer::singleShot(kInitialBackgroundUpdateCheckMs, this, &UpdateController::checkForUpdates);
}

void UpdateController::fetchSelfHostedManifest()
{
    const QList<QUrl> manifestUrls = selfHostedManifestUrls();
    if (manifestUrls.isEmpty()) {
        finishUpdateCheck();
        return;
    }

    fetchSelfHostedManifestFromUrls(manifestUrls, 0);
}

void UpdateController::fetchSelfHostedManifestFromUrls(const QList<QUrl> &manifestUrls, int urlIndex)
{
    if (urlIndex < 0 || urlIndex >= manifestUrls.size()) {
        finishUpdateCheck();
        return;
    }

    const QUrl manifestUrl = manifestUrls.at(urlIndex);
    QNetworkRequest request(manifestUrl);
    request.setTransferTimeout(kManifestTransferTimeoutMs);

    QNetworkReply *reply = amnApp->networkManager()->get(request);
    auto *manifestData = new QByteArray();
    auto *manifestTooLarge = new bool(false);
    QObject::connect(reply, &QIODevice::readyRead, this, [reply, manifestData, manifestTooLarge]() {
        if (manifestData->size() > kManifestMaxPayloadBytes) {
            return;
        }
        manifestData->append(reply->readAll());
        if (manifestData->size() > kManifestMaxPayloadBytes) {
            *manifestTooLarge = true;
            reply->abort();
        }
    });
    QObject::connect(reply, &QNetworkReply::metaDataChanged, this, [reply, manifestTooLarge]() {
        const QVariant contentLength = reply->header(QNetworkRequest::ContentLengthHeader);
        if (contentLength.isValid() && contentLength.toLongLong() > kManifestMaxPayloadBytes) {
            *manifestTooLarge = true;
            reply->abort();
        }
    });
    QObject::connect(reply, &QNetworkReply::finished, this,
                     [this, reply, manifestData, manifestTooLarge, manifestUrls, urlIndex, manifestUrl]() {
        const bool ok = (reply->error() == QNetworkReply::NoError);
        const int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QString errorString = ok ? QString() : reply->errorString();
        const QByteArray data = ok ? *manifestData : QByteArray();
        reply->deleteLater();

        const bool responseValid = ok && statusCode >= 200 && statusCode < 300
                && !*manifestTooLarge && data.size() <= kManifestMaxPayloadBytes;
        const ManifestProcessResult processResult = responseValid
                ? processSelfHostedManifest(manifestUrl, data)
                : ManifestProcessResult::Invalid;
        if (!responseValid || shouldTryNextManifest(processResult)) {
            if (!ok) {
                logger.info() << "Self-hosted update manifest unavailable at" << manifestUrl.toString() << errorString;
            }
            delete manifestData;
            delete manifestTooLarge;
            fetchSelfHostedManifestFromUrls(manifestUrls, urlIndex + 1);
            return;
        }

        delete manifestData;
        delete manifestTooLarge;
        if (processResult == ManifestProcessResult::NoUpdate) {
            finishUpdateCheck();
            return;
        }
        m_updateFoundDuringCheck = true;
        emit updateFound();
        scheduleSelfHostedAutoInstall();
        finishUpdateCheck();
    });
}

void UpdateController::doGetAsync(const QString &endpoint, std::function<void(bool, QByteArray)> onDone)
{
    QString fullUrl = m_baseUrl + endpoint;

    QNetworkRequest req;
    req.setTransferTimeout(7000);
    req.setUrl(QUrl(fullUrl));

    QNetworkReply *reply = amnApp->networkManager()->get(req);
    setupNetworkErrorHandling(reply, endpoint);

    QObject::connect(reply, &QNetworkReply::finished, this, [this, reply, endpoint, onDone]() {
        const bool ok = (reply->error() == QNetworkReply::NoError);
        QByteArray data;
        if (ok) {
            data = reply->readAll();
        } else {
            handleNetworkError(reply, endpoint);
        }
        reply->deleteLater();
        onDone(ok, data);
    });
}

void UpdateController::fetchGatewayUrl()
{
    auto gatewayController = QSharedPointer<GatewayController>::create(m_appSettingsRepository->getGatewayEndpoint(),
                                                                       m_appSettingsRepository->isDevGatewayEnv(),
                                                                       7000,
                                                                       m_appSettingsRepository->isStrictKillSwitchEnabled(),
                                                                       m_appSettingsRepository);

    QJsonObject apiPayload = GatewayPayloadBuilder(m_appSettingsRepository)
                                     .addField(apiDefs::key::cliVersion, QString(APP_VERSION))
                                     .build();

    // Workaround: wait before contacting gateway to avoid rate limit triggered by other requests (news etc.)
    QTimer::singleShot(1000, this, [this, gatewayController, apiPayload]() {
        gatewayController->postAsync(QStringLiteral("%1v1/updater_endpoint"), apiPayload)
            .then(this, [this, gatewayController](QPair<ErrorCode, QByteArray> result) {
                auto [err, gatewayResponse] = result;
                if (err != ErrorCode::NoError) {
                    logger.error() << "Gateway request failed, error code:" << static_cast<int>(err);
                    finishUpdateCheck();
                    return;
                }

                QJsonObject gatewayData = QJsonDocument::fromJson(gatewayResponse).object();

                QString baseUrl = gatewayData.value("url").toString();
                if (baseUrl.endsWith('/')) {
                    baseUrl.chop(1);
                }
                m_baseUrl = baseUrl;

                fetchVersionInfo();
            });
    });
}

void UpdateController::fetchVersionInfo()
{
    doGetAsync("/VERSION", [this](bool ok, QByteArray data) {
        if (!ok) {
            finishUpdateCheck();
            return;
        }
        m_version = QString::fromUtf8(data).trimmed();

        if (!isNewVersionAvailable()) {
            finishUpdateCheck();
            return;
        }
        fetchChangelog();
    });
}

void UpdateController::fetchChangelog()
{
    doGetAsync("/CHANGELOG", [this](bool ok, QByteArray data) {
        if (!ok) {
            m_changelogText.clear();
        } else {
            m_changelogText = QString::fromUtf8(data);
        }
        fetchReleaseDate();
    });
}

void UpdateController::fetchReleaseDate()
{
    doGetAsync("/RELEASE_DATE", [this](bool ok, QByteArray data) {
        if (ok) {
            m_releaseDate = QString::fromUtf8(data).trimmed();
        } else {
            m_releaseDate = QString();
        }

        m_downloadUrl = composeDownloadUrl();
        if (m_downloadUrl.isEmpty()) {
            logger.info() << "Update is available on gateway, but this platform has no installer URL";
            finishUpdateCheck();
            return;
        }
        m_updateFoundDuringCheck = true;
        emit updateFound();
        finishUpdateCheck();
    });
}

bool UpdateController::isNewVersionAvailable() const
{
    return isNewVersionAvailable(m_version);
}

bool UpdateController::isSelfHostedUpdateChannelConfigured() const
{
    return !QByteArray(SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64).trimmed().isEmpty();
}

bool UpdateController::isNewVersionAvailable(const QString &version) const
{
    const auto currentVersion = QVersionNumber::fromString(QString(APP_VERSION));
    const auto newVersion = QVersionNumber::fromString(version);
    return newVersion > currentVersion;
}

QList<QUrl> UpdateController::selfHostedManifestUrls() const
{
    QList<QUrl> urls;
    const auto addHost = [this, &urls](const QString &host) {
        const QUrl url = normalizedSelfHostedManifestUrl(host);
        if (!url.isValid() || url.isEmpty()) {
            return;
        }
        const QString normalized = url.toString(QUrl::FullyEncoded);
        for (const QUrl &existing : urls) {
            if (existing.toString(QUrl::FullyEncoded) == normalized) {
                return;
            }
        }
        urls.append(url);
    };

    QStringList serverCredentialHosts;
    if (m_serversRepository) {
        const QString defaultServerId = m_serversRepository->defaultServerId();
        const QVector<QString> orderedServerIds = m_serversRepository->orderedServerIds();
        QStringList serverIds;
        if (!defaultServerId.isEmpty()) {
            serverIds.append(defaultServerId);
        }
        for (const QString &serverId : orderedServerIds) {
            if (!serverIds.contains(serverId)) {
                serverIds.append(serverId);
            }
        }
        for (const QString &serverId : serverIds) {
            const int serverIndex = m_serversRepository->indexOfServerId(serverId);
            if (serverIndex < 0) {
                continue;
            }
            const QJsonObject serverJson = m_serversRepository->serverJson(serverIndex);
            addHost(serverJson.value(configKey::serverRoutingRulesSyncHost).toString());
            const ServerCredentials credentials = m_serversRepository->serverCredentials(serverIndex);
            serverCredentialHosts.append(credentials.hostName);
        }
    }
    addHost(QString::fromLatin1(amnezia::protocols::selfHostedUpdates::syncHost));
    for (const QString &host : serverCredentialHosts) {
        addHost(host);
    }

    return urls;
}

QUrl UpdateController::normalizedSelfHostedManifestUrl(const QString &host) const
{
    const QString trimmedHost = host.trimmed();
    if (trimmedHost.isEmpty()) {
        return {};
    }

    const QUrl explicitUrl(trimmedHost);
    if (explicitUrl.isValid() && !explicitUrl.scheme().isEmpty()) {
        if (explicitUrl.scheme() != QStringLiteral("http") && explicitUrl.scheme() != QStringLiteral("https")) {
            return {};
        }
        QUrl url = explicitUrl;
        const QString manifestPath = QString::fromLatin1(amnezia::protocols::selfHostedUpdates::manifestPath);
        if (url.path().isEmpty() || url.path() == QStringLiteral("/")) {
            url.setPath(manifestPath);
        } else if (!url.path().endsWith(manifestPath)) {
            QString path = url.path().trimmed();
            while (path.endsWith(QLatin1Char('/'))) {
                path.chop(1);
            }
            url.setPath(path + manifestPath);
        }
        return url;
    }

    return QUrl(selfHostedUpdateUrl(trimmedHost, QString::fromLatin1(amnezia::protocols::selfHostedUpdates::manifestPath)));
}

QList<QString> UpdateController::platformCandidates() const
{
#if defined(Q_OS_WINDOWS)
    constexpr PlatformFamily platform = PlatformFamily::Windows;
#elif defined(Q_OS_ANDROID)
    constexpr PlatformFamily platform = PlatformFamily::Android;
#elif defined(Q_OS_IOS)
    constexpr PlatformFamily platform = PlatformFamily::IOS;
#elif defined(Q_OS_MACOS)
    constexpr PlatformFamily platform = PlatformFamily::MacOS;
#elif defined(Q_OS_LINUX)
    constexpr PlatformFamily platform = PlatformFamily::Linux;
#else
    constexpr PlatformFamily platform = PlatformFamily::Unsupported;
#endif
    return amnezia::selfhostedUpdatePolicy::platformCandidates(
            platform, QSysInfo::currentCpuArchitecture());
}

UpdateController::ManifestProcessResult UpdateController::processSelfHostedManifest(const QUrl &manifestUrl,
                                                                                     const QByteArray &manifestData)
{
    QByteArray payloadData;
    if (!verifySignedManifestEnvelope(manifestData, payloadData)) {
        return ManifestProcessResult::Invalid;
    }

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(payloadData, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        logger.error() << "Invalid self-hosted update payload:" << parseError.errorString();
        return ManifestProcessResult::Invalid;
    }

    const QJsonObject payload = document.object();
    int payloadSchema = 0;
    if (!jsonIntegerInRange(payload.value(QStringLiteral("schema")), 1, 2, payloadSchema)) {
        logger.error() << "Unexpected self-hosted update payload schema";
        return ManifestProcessResult::Invalid;
    }

    const qint64 persistedGeneration = m_appSettingsRepository
            ? m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyGeneration()
            : 0;
    const qint64 generationFloor = qMax(m_highestObservedPolicyGeneration, persistedGeneration);
    if (payloadSchema == 1 && generationFloor > 0) {
        logger.warning() << "Rejecting legacy self-hosted update payload after accepting policy generation"
                         << generationFloor;
        return ManifestProcessResult::Invalid;
    }
    if (payloadSchema == 1 && payload.contains(QStringLiteral("releasePolicy"))) {
        logger.error() << "Legacy self-hosted update payload must not contain releasePolicy";
        return ManifestProcessResult::Invalid;
    }

    if (!payload.value(QStringLiteral("version")).isString()) {
        logger.error() << "Self-hosted update payload is missing a release version";
        return ManifestProcessResult::Invalid;
    }
    const QString version = payload.value(QStringLiteral("version")).toString();
    QVersionNumber parsedReleaseVersion;
    if (!parseExactVersion(version, parsedReleaseVersion)) {
        logger.error() << "Self-hosted update payload has an invalid release version";
        return ManifestProcessResult::Invalid;
    }

    ReleasePolicy releasePolicy;
    if (payloadSchema == 2) {
        const QJsonValue policyValue = payload.value(QStringLiteral("releasePolicy"));
        if (!policyValue.isObject()) {
            logger.error() << "Self-hosted update payload schema 2 is missing releasePolicy";
            return ManifestProcessResult::Invalid;
        }
        const ReleasePolicyResult policyResult = evaluateReleasePolicy(
                manifestUrl, policyValue.toObject(), version, releasePolicy);
        if (policyResult == ReleasePolicyResult::Invalid) {
            return ManifestProcessResult::Invalid;
        }
        if (policyResult == ReleasePolicyResult::Stale) {
            return ManifestProcessResult::Stale;
        }
        const QString payloadSha256 = QString::fromLatin1(
                QCryptographicHash::hash(payloadData, QCryptographicHash::Sha256).toHex());
        const GenerationBindingDisposition generationDisposition =
                acceptPolicyGeneration(releasePolicy.generation, payloadSha256);
        if (generationDisposition == GenerationBindingDisposition::Stale
            || generationDisposition == GenerationBindingDisposition::MissingPayloadBinding
            || generationDisposition == GenerationBindingDisposition::ConflictingPayload) {
            return ManifestProcessResult::Stale;
        }
        if (generationDisposition != GenerationBindingDisposition::AcceptExisting
            && generationDisposition != GenerationBindingDisposition::AcceptAdvance) {
            return ManifestProcessResult::Invalid;
        }
        m_observedReleasePolicy = releasePolicy;
        emit releasePolicyChanged();
        if (policyResult == ReleasePolicyResult::Ineligible) {
            return ManifestProcessResult::NoUpdate;
        }
    }

    if (!isNewVersionAvailable(version)) {
        return ManifestProcessResult::NoUpdate;
    }

    if (!payloadHasPlatformCandidate(payload)) {
        logger.info() << "Self-hosted update has no artifact for this platform";
        return ManifestProcessResult::NoUpdate;
    }
    UpdateArtifact artifact;
    if (!selectSelfHostedArtifact(manifestUrl, payload, artifact)) {
        return ManifestProcessResult::Invalid;
    }

    m_version = version;
    m_releaseDate = payload.value(QStringLiteral("releaseDate")).toString(
            payload.value(QStringLiteral("release_date")).toString());
    m_changelogText = payload.value(QStringLiteral("changelog")).toString(
            payload.value(QStringLiteral("body")).toString());
    m_selectedArtifact = artifact;
    m_downloadUrl = artifact.url.toString();
    m_baseUrl = manifestUrl.adjusted(QUrl::RemoveFilename | QUrl::StripTrailingSlash).toString();
    m_useSelfHostedArtifact = true;
    m_selectedReleasePolicy = releasePolicy;
    armUpdateInstallIntent();
    if (payloadSchema == 1) {
        // Legacy signed manifests have no rollout policy. Keep the observed
        // policy empty so the operator UI can fall back to durable receipts
        // instead of fabricating a stable channel/generation.
        m_observedReleasePolicy = {};
        emit releasePolicyChanged();
    }
    logger.info() << "Self-hosted update available:" << m_version << "for" << artifact.platform
                  << artifact.url.toString() << "channel" << m_selectedReleasePolicy.channel;
    return ManifestProcessResult::UpdateAvailable;
}

UpdateController::ReleasePolicyResult UpdateController::evaluateReleasePolicy(const QUrl &manifestUrl,
                                                                               const QJsonObject &policyObject,
                                                                               const QString &releaseVersion,
                                                                               ReleasePolicy &policyOut) const
{
    const QStringList requiredPolicyKeys {
        QStringLiteral("schema"), QStringLiteral("generation"), QStringLiteral("generatedAt"),
        QStringLiteral("expiresAt"), QStringLiteral("channel"), QStringLiteral("rollout"),
        QStringLiteral("eligibility"), QStringLiteral("healthDeadlineSeconds")
    };
    const QStringList optionalPolicyKeys {
        QStringLiteral("previousVersion"), QStringLiteral("rollback")
    };
    for (const QString &requiredKey : requiredPolicyKeys) {
        if (!policyObject.contains(requiredKey)) {
            logger.error() << "Self-hosted release policy is missing required field" << requiredKey;
            return ReleasePolicyResult::Invalid;
        }
    }
    for (auto iterator = policyObject.constBegin(); iterator != policyObject.constEnd(); ++iterator) {
        if (!requiredPolicyKeys.contains(iterator.key()) && !optionalPolicyKeys.contains(iterator.key())) {
            logger.error() << "Self-hosted release policy has unknown field" << iterator.key();
            return ReleasePolicyResult::Invalid;
        }
    }

    int policySchema = 0;
    if (!jsonIntegerInRange(policyObject.value(QStringLiteral("schema")), 2, 2, policySchema)) {
        logger.error() << "Self-hosted release policy has an unsupported schema";
        return ReleasePolicyResult::Invalid;
    }

    ReleasePolicy policy;
    if (!policyObject.value(QStringLiteral("channel")).isString()) {
        logger.error() << "Self-hosted release policy is missing channel";
        return ReleasePolicyResult::Invalid;
    }
    policy.channel = policyObject.value(QStringLiteral("channel")).toString();
    if (!isCanonicalReleaseChannel(policy.channel)) {
        logger.error() << "Self-hosted release policy has an invalid channel";
        return ReleasePolicyResult::Invalid;
    }
    if (!jsonIntegerInRange(policyObject.value(QStringLiteral("generation")),
                            1, kMaximumSafeJsonInteger, policy.generation)) {
        logger.error() << "Self-hosted release policy has an invalid generation";
        return ReleasePolicyResult::Invalid;
    }

    const QJsonValue rolloutValue = policyObject.value(QStringLiteral("rollout"));
    if (!rolloutValue.isObject()) {
        logger.error() << "Self-hosted release policy is missing rollout";
        return ReleasePolicyResult::Invalid;
    }
    const QJsonObject rollout = rolloutValue.toObject();
    if (rollout.size() != 2 || !rollout.contains(QStringLiteral("percentage"))
        || !rollout.contains(QStringLiteral("cohortSaltId"))) {
        logger.error() << "Self-hosted release policy rollout has unexpected fields";
        return ReleasePolicyResult::Invalid;
    }
    if (!jsonIntegerInRange(rollout.value(QStringLiteral("percentage")),
                            0, 100, policy.rolloutPercentage)) {
        logger.error() << "Self-hosted release policy has an invalid rollout percentage";
        return ReleasePolicyResult::Invalid;
    }
    if (!rollout.value(QStringLiteral("cohortSaltId")).isString()) {
        logger.error() << "Self-hosted release policy is missing cohortSaltId";
        return ReleasePolicyResult::Invalid;
    }
    policy.cohortSaltId = rollout.value(QStringLiteral("cohortSaltId")).toString();
    if (!isCanonicalCohortSaltId(policy.cohortSaltId)) {
        logger.error() << "Self-hosted release policy has an invalid cohortSaltId";
        return ReleasePolicyResult::Invalid;
    }

    const QJsonValue eligibilityValue = policyObject.value(QStringLiteral("eligibility"));
    if (!eligibilityValue.isObject()) {
        logger.error() << "Self-hosted release policy is missing eligibility";
        return ReleasePolicyResult::Invalid;
    }
    const QJsonObject eligibility = eligibilityValue.toObject();
    for (auto iterator = eligibility.constBegin(); iterator != eligibility.constEnd(); ++iterator) {
        if (iterator.key() != QStringLiteral("minimumVersion")
            && iterator.key() != QStringLiteral("maximumVersion")) {
            logger.error() << "Self-hosted release policy eligibility has unknown field" << iterator.key();
            return ReleasePolicyResult::Invalid;
        }
    }
    QVersionNumber minimumVersion;
    QVersionNumber maximumVersion;
    if (eligibility.contains(QStringLiteral("minimumVersion"))) {
        if (!eligibility.value(QStringLiteral("minimumVersion")).isString()) {
            logger.error() << "Self-hosted release policy minimumVersion must be a string";
            return ReleasePolicyResult::Invalid;
        }
        policy.minimumVersion = eligibility.value(QStringLiteral("minimumVersion")).toString();
        if (!parseExactVersion(policy.minimumVersion, minimumVersion)) {
            logger.error() << "Self-hosted release policy has an invalid minimumVersion";
            return ReleasePolicyResult::Invalid;
        }
    }
    if (eligibility.contains(QStringLiteral("maximumVersion"))) {
        if (!eligibility.value(QStringLiteral("maximumVersion")).isString()) {
            logger.error() << "Self-hosted release policy maximumVersion must be a string";
            return ReleasePolicyResult::Invalid;
        }
        policy.maximumVersion = eligibility.value(QStringLiteral("maximumVersion")).toString();
        if (!parseExactVersion(policy.maximumVersion, maximumVersion)) {
            logger.error() << "Self-hosted release policy has an invalid maximumVersion";
            return ReleasePolicyResult::Invalid;
        }
    }
    if (!minimumVersion.isNull() && !maximumVersion.isNull() && minimumVersion > maximumVersion) {
        logger.error() << "Self-hosted release policy has an inverted eligibility range";
        return ReleasePolicyResult::Invalid;
    }

    if (!jsonIntegerInRange(policyObject.value(QStringLiteral("healthDeadlineSeconds")),
                            kMinimumHealthDeadlineSeconds, kMaximumHealthDeadlineSeconds,
                            policy.healthDeadlineSeconds)) {
        logger.error() << "Self-hosted release policy has an invalid health deadline";
        return ReleasePolicyResult::Invalid;
    }
    const QJsonValue generatedAtValue = policyObject.value(QStringLiteral("generatedAt"));
    const QJsonValue expiresAtValue = policyObject.value(QStringLiteral("expiresAt"));
    if (!generatedAtValue.isString() || !expiresAtValue.isString()
        || !parseCanonicalUtcTimestamp(generatedAtValue.toString(), policy.generatedAt)
        || !parseCanonicalUtcTimestamp(expiresAtValue.toString(), policy.expiresAt)
        || policy.expiresAt <= policy.generatedAt) {
        logger.error() << "Self-hosted release policy has invalid generation or expiry timestamps";
        return ReleasePolicyResult::Invalid;
    }

    QVersionNumber parsedReleaseVersion;
    if (!parseExactVersion(releaseVersion, parsedReleaseVersion)) {
        return ReleasePolicyResult::Invalid;
    }

    if (policyObject.contains(QStringLiteral("previousVersion"))) {
        if (!policyObject.value(QStringLiteral("previousVersion")).isString()) {
            logger.error() << "Self-hosted release policy previousVersion must be a string";
            return ReleasePolicyResult::Invalid;
        }
        policy.previousVersion = policyObject.value(QStringLiteral("previousVersion")).toString();
        QVersionNumber previousVersion;
        if (!parseExactVersion(policy.previousVersion, previousVersion)
            || previousVersion >= parsedReleaseVersion) {
            logger.error() << "Self-hosted release policy has an invalid previousVersion";
            return ReleasePolicyResult::Invalid;
        }
    }

    if (policyObject.contains(QStringLiteral("rollback"))) {
        const QJsonValue rollbackValue = policyObject.value(QStringLiteral("rollback"));
        if (!rollbackValue.isObject() || policy.previousVersion.isEmpty()) {
            logger.error() << "Self-hosted release policy rollback requires previousVersion";
            return ReleasePolicyResult::Invalid;
        }
        const QJsonObject rollback = rollbackValue.toObject();
        if (rollback.size() != 2 || !rollback.value(QStringLiteral("version")).isString()
            || !rollback.value(QStringLiteral("platforms")).isObject()) {
            logger.error() << "Self-hosted release policy has invalid rollback metadata";
            return ReleasePolicyResult::Invalid;
        }
        policy.rollbackVersion = rollback.value(QStringLiteral("version")).toString();
        QVersionNumber rollbackVersion;
        const QJsonObject rollbackPlatforms = rollback.value(QStringLiteral("platforms")).toObject();
        if (!parseExactVersion(policy.rollbackVersion, rollbackVersion)
            || policy.rollbackVersion != policy.previousVersion
            || rollbackPlatforms.isEmpty()) {
            logger.error() << "Self-hosted release policy has invalid rollback version or platforms";
            return ReleasePolicyResult::Invalid;
        }

        QJsonObject rollbackPayload;
        rollbackPayload.insert(QStringLiteral("platforms"), rollbackPlatforms);
        if (payloadHasPlatformCandidate(rollbackPayload)) {
            UpdateArtifact rollbackArtifact;
            if (!selectSelfHostedArtifact(manifestUrl, rollbackPayload, rollbackArtifact, true)) {
                logger.error() << "Self-hosted release policy has an invalid rollback artifact for this platform";
                return ReleasePolicyResult::Invalid;
            }
            policy.rollbackArtifact = rollbackArtifact;
            policy.hasRollbackArtifact = true;
        }
    }

    const qint64 persistedGeneration = m_appSettingsRepository
            ? m_appSettingsRepository->selfHostedUpdateLastAcceptedPolicyGeneration()
            : 0;
    const qint64 generationFloor = qMax(m_highestObservedPolicyGeneration, persistedGeneration);
    if (policy.generation < generationFloor) {
        policy.disposition = ReleasePolicyDisposition::None;
        policyOut = policy;
        logger.warning() << "Rejecting stale self-hosted release policy generation"
                         << policy.generation << "accepted floor" << generationFloor;
        return ReleasePolicyResult::Stale;
    }

    if (QDateTime::currentDateTimeUtc() >= policy.expiresAt) {
        policy.disposition = ReleasePolicyDisposition::Expired;
        policyOut = policy;
        logger.info() << "Self-hosted release policy has expired; update is not eligible";
        return ReleasePolicyResult::Ineligible;
    }

    QVersionNumber currentVersion;
    if (!parseExactVersion(QString(APP_VERSION), currentVersion)) {
        logger.error() << "Current application version cannot be evaluated against release policy";
        return ReleasePolicyResult::Invalid;
    }
    if ((!minimumVersion.isNull() && currentVersion < minimumVersion)
        || (!maximumVersion.isNull() && currentVersion > maximumVersion)) {
        policy.disposition = ReleasePolicyDisposition::VersionIneligible;
        policyOut = policy;
        logger.info() << "Current application version is outside self-hosted release eligibility";
        return ReleasePolicyResult::Ineligible;
    }

    if (policy.rolloutPercentage == 0) {
        policy.disposition = ReleasePolicyDisposition::Paused;
        policyOut = policy;
        logger.info() << "Self-hosted release rollout is paused";
        return ReleasePolicyResult::Ineligible;
    }
    if (policy.rolloutPercentage < 100) {
        if (!m_appSettingsRepository) {
            logger.error() << "Installation identity is unavailable for self-hosted release rollout";
            return ReleasePolicyResult::Invalid;
        }
        const QString installationUuid = m_appSettingsRepository->getInstallationUuid(true).trimmed();
        if (installationUuid.isEmpty()) {
            logger.error() << "Installation identity is empty for self-hosted release rollout";
            return ReleasePolicyResult::Invalid;
        }
        const int cohortBucketValue = cohortBucket(installationUuid, policy.cohortSaltId);
        if (cohortBucketValue < 0
            || cohortBucketValue >= policy.rolloutPercentage * (CohortBucketCount / 100)) {
            policy.disposition = ReleasePolicyDisposition::CohortIneligible;
            policyOut = policy;
            logger.info() << "Installation is outside self-hosted release rollout percentage"
                          << policy.rolloutPercentage;
            return ReleasePolicyResult::Ineligible;
        }
    }

    policy.disposition = ReleasePolicyDisposition::Eligible;
    policyOut = policy;
    return ReleasePolicyResult::Eligible;
}

bool UpdateController::verifySignedManifestEnvelope(const QByteArray &manifestData, QByteArray &payloadData) const
{
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(manifestData, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        logger.error() << "Invalid self-hosted update manifest:" << parseError.errorString();
        return false;
    }

    const QJsonObject envelope = document.object();
    const QString schema = envelope.value(QStringLiteral("schema")).toString();
    if (schema != QStringLiteral("amnezia-selfhosted-update-v1")) {
        logger.error() << "Unexpected self-hosted update manifest schema:" << schema;
        return false;
    }
    const QString signatureAlgorithm = envelope.value(QStringLiteral("signatureAlgorithm")).toString();
    if (signatureAlgorithm != QStringLiteral("Ed25519")) {
        logger.error() << "Unexpected self-hosted update manifest signature algorithm:" << signatureAlgorithm;
        return false;
    }

    QByteArray payload;
    QByteArray signature;
    const bool decodedPayload = decodeStrictBase64(envelope.value(QStringLiteral("payload")).toString().toUtf8(),
                                                   QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals,
                                                   payload);
    const bool decodedSignature = decodeStrictBase64(envelope.value(QStringLiteral("signature")).toString().toUtf8(),
                                                     QByteArray::Base64Encoding,
                                                     signature);
    if (!decodedPayload || !decodedSignature || payload.isEmpty() || signature.isEmpty()) {
        logger.error() << "Self-hosted update manifest is missing payload or signature";
        return false;
    }
    if (payload.size() > kManifestMaxPayloadBytes) {
        logger.error() << "Self-hosted update manifest payload is too large";
        return false;
    }
    if (signature.size() != 64) {
        logger.error() << "Self-hosted update manifest signature has invalid Ed25519 size";
        return false;
    }
    if (!verifyManifestSignature(payload, signature)) {
        logger.error() << "Self-hosted update manifest signature verification failed";
        return false;
    }

    payloadData = payload;
    return true;
}

bool UpdateController::verifyManifestSignature(const QByteArray &payloadData, const QByteArray &signature) const
{
    QByteArray publicKeyPem;
    if (!decodeStrictBase64(QByteArray(SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64),
                            QByteArray::Base64Encoding,
                            publicKeyPem) || publicKeyPem.isEmpty()) {
        logger.warning() << "Self-hosted update public key is not configured; ignoring private update manifest";
        return false;
    }

    BIO *bio = BIO_new_mem_buf(publicKeyPem.constData(), publicKeyPem.size());
    if (!bio) {
        return false;
    }

    EVP_PKEY *publicKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!publicKey) {
        return false;
    }

    bool ok = false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx) {
        if (EVP_PKEY_base_id(publicKey) == EVP_PKEY_ED25519
            && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, publicKey) == 1
            && EVP_DigestVerify(ctx,
                                reinterpret_cast<const unsigned char *>(signature.constData()),
                                static_cast<size_t>(signature.size()),
                                reinterpret_cast<const unsigned char *>(payloadData.constData()),
                                static_cast<size_t>(payloadData.size())) == 1) {
            ok = true;
        }
        EVP_MD_CTX_free(ctx);
    }
    EVP_PKEY_free(publicKey);
    return ok;
}

bool UpdateController::payloadHasPlatformCandidate(const QJsonObject &payload) const
{
    const QJsonValue platformsValue = payload.value(QStringLiteral("platforms"));
    if (!platformsValue.isObject()) {
        return false;
    }
    const QJsonObject platforms = platformsValue.toObject();
    for (const QString &platform : platformCandidates()) {
        if (platforms.contains(platform)) {
            return true;
        }
    }
    return false;
}

bool UpdateController::selectSelfHostedArtifact(const QUrl &manifestUrl,
                                                const QJsonObject &payload,
                                                UpdateArtifact &artifactOut,
                                                bool rollbackArtifact) const
{
    const QJsonObject platforms = payload.value(QStringLiteral("platforms")).toObject();
    if (platforms.isEmpty()) {
        logger.error() << "Self-hosted update payload has no platforms";
        return false;
    }

    for (const QString &platform : platformCandidates()) {
        const QJsonValue artifactValue = platforms.value(platform);
        if (!artifactValue.isObject()) {
            continue;
        }

        const QJsonObject artifactObject = artifactValue.toObject();
        const QString urlOrPath = artifactObject.value(QStringLiteral("url")).toString(
                artifactObject.value(QStringLiteral("path")).toString());
        const QUrl url = resolvedArtifactUrl(manifestUrl, urlOrPath);
        if (!url.isValid() || url.isEmpty()) {
            continue;
        }

        UpdateArtifact artifact;
        artifact.platform = platform;
        artifact.url = url;
        artifact.sha256 = normalizeSha256(artifactObject.value(QStringLiteral("sha256")).toString());
        const QJsonValue sizeValue = artifactObject.value(QStringLiteral("size"));
        artifact.size = -1;
        jsonIntegerInRange(sizeValue, 1, kMaximumSafeJsonInteger, artifact.size);
        artifact.openExternally = artifactObject.value(QStringLiteral("openExternal")).toBool(false);
        artifact.autoInstall = artifactObject.value(QStringLiteral("autoInstall")).toBool(
                payload.value(QStringLiteral("autoInstall")).toBool(false));
#if defined(Q_OS_ANDROID)
        if (rollbackArtifact) {
            logger.error() << "Android Package Installer rollback is unsupported";
            continue;
        }
        if (!artifact.openExternally
            && !jsonIntegerInRange(artifactObject.value(QStringLiteral("versionCode")),
                                   1, kMaximumAndroidVersionCode,
                                   artifact.androidVersionCode)) {
            logger.error() << "Self-hosted Android artifact is missing a signed versionCode";
            continue;
        }
#endif

#if defined(MACOS_NE)
        if (rollbackArtifact) {
            logger.error() << "Local rollback artifacts are unsupported by the macOS Network Extension build";
            continue;
        }
        artifact.openExternally = true;
#elif defined(Q_OS_IOS)
        artifact.openExternally = true;
#endif

        if (!artifact.openExternally && !isCanonicalSha256(artifact.sha256)) {
            logger.error() << "Self-hosted update artifact is missing or has invalid sha256 for" << platform;
            continue;
        }
        if (!artifact.openExternally && !isHttpOrHttpsUrl(artifact.url)) {
            logger.error() << "Self-hosted update artifact URL must use http(s) for" << platform;
            continue;
        }
        if (!artifact.openExternally && artifact.size <= 0) {
            logger.error() << "Self-hosted update artifact is missing or has invalid size for" << platform;
            continue;
        }
        if (artifact.openExternally && !isAllowedExternalUpdateUrl(artifact.url)) {
            logger.error() << "Self-hosted external update URL has unsupported scheme for" << platform;
            continue;
        }

        artifactOut = artifact;
        return true;
    }

    logger.info() << "No matching self-hosted update artifact for platform candidates" << platformCandidates();
    return false;
}

QUrl UpdateController::resolvedArtifactUrl(const QUrl &manifestUrl, const QString &urlOrPath) const
{
    if (urlOrPath.trimmed().isEmpty()) {
        return {};
    }

    const QUrl candidate(urlOrPath);
    if (candidate.isValid() && !candidate.isRelative()) {
        return candidate;
    }
    return manifestUrl.resolved(QUrl(urlOrPath));
}

void UpdateController::setupNetworkErrorHandling(QNetworkReply* reply, const QString& operation)
{
    QObject::connect(reply, &QNetworkReply::errorOccurred, [reply, operation](QNetworkReply::NetworkError error) {
        logger.error() << QString("Network error occurred while fetching %1: %2 %3")
                          .arg(operation, reply->errorString(), QString::number(error));
    });

    QObject::connect(reply, &QNetworkReply::sslErrors, [operation](const QList<QSslError> &errors) {
        QStringList errorStrings;
        for (const QSslError &err : errors) {
            errorStrings << err.errorString();
        }
        logger.error() << QString("SSL errors while fetching %1: %2").arg(operation, errorStrings.join("; "));
    });
}

void UpdateController::handleNetworkError(QNetworkReply* reply, const QString& operation)
{
    logger.error() << "Network error code:" << QString::number(static_cast<int>(reply->error()));
    logger.error() << "HTTP status:" << reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
}

QString UpdateController::composeDownloadUrl() const
{
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    const QString fileName = QString(kInstallerRemoteFileNamePattern).arg(m_version);
    return m_baseUrl + "/" + fileName;
#else
    return QString();
#endif
}

QString UpdateController::localInstallerPath() const
{
    if (!m_localInstallerPath.isEmpty()) {
        return m_localInstallerPath;
    }
    QString privateDir;
#if defined(Q_OS_WINDOWS)
    const QString stagingRoot = QStandardPaths::writableLocation(
            QStandardPaths::AppLocalDataLocation);
    if (stagingRoot.isEmpty() || !QDir().mkpath(stagingRoot)
        || !createPrivateWindowsInstallerDirectory(stagingRoot, privateDir)) {
        logger.error() << "Failed to atomically create protected installer staging directory";
        return {};
    }
#else
    const QString tempDir = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    privateDir = tempDir + QStringLiteral("/amnezia-update-")
            + QUuid::createUuid().toString(QUuid::WithoutBraces).toLower();
    if (!QDir().mkpath(privateDir)
        || !QFile::setPermissions(privateDir,
                                  QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                          | QFileDevice::ExeOwner)) {
        logger.error() << "Failed to create private installer staging directory";
        return {};
    }
#endif
#if defined(Q_OS_WINDOWS)
    m_localInstallerPath = privateDir + QStringLiteral("/AmneziaVPN_installer.exe");
#elif defined(Q_OS_MACOS) && !defined(MACOS_NE)
    m_localInstallerPath = privateDir + QStringLiteral("/AmneziaVPN.pkg");
#elif defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    m_localInstallerPath = privateDir + QStringLiteral("/AmneziaVPN.run");
#elif defined(Q_OS_ANDROID)
    m_localInstallerPath = privateDir + QStringLiteral("/AmneziaVPN.apk");
#else
    m_localInstallerPath = privateDir + QStringLiteral("/AmneziaVPN_update");
#endif
    return m_localInstallerPath;
}

bool UpdateController::runInstaller()
{
    if (m_useSelfHostedArtifact) {
        if (m_selfHostedInstallInProgress) {
            logger.info() << "Self-hosted update installer handoff is already in progress";
            return false;
        }
        if (m_installIntent.consumed || !installIntentMatchesSelection()) {
            logger.warning() << "Refusing self-hosted installer without a current one-shot install intent";
            clearPendingAutoInstallAttempt();
            clearInstallSelection();
            return false;
        }
        if (!m_rollbackInstallAttempt && m_selectedReleasePolicy.generation > 0
            && (!m_selectedReleasePolicy.expiresAt.isValid()
                || QDateTime::currentDateTimeUtc() >= m_selectedReleasePolicy.expiresAt)) {
            logger.warning() << "Refusing to install an expired self-hosted release policy generation"
                             << m_selectedReleasePolicy.generation;
            clearPendingAutoInstallAttempt();
            clearInstallSelection();
            return false;
        }
        m_installIntent.consumed = true;
        m_selfHostedInstallInProgress = true;
    }

    if (m_useSelfHostedArtifact && m_selectedArtifact.openExternally) {
        if (!prepareSelfHostedInstallerHandoff()) {
            finishSelfHostedInstallerAttempt(InstallerHandoffResult::Failed);
            return false;
        }
        const bool opened = openArtifactExternally();
        finishSelfHostedInstallerAttempt(opened
                                         ? InstallerHandoffResult::Started
                                         : InstallerHandoffResult::Failed);
        return opened;
    }

#if defined(Q_OS_ANDROID)
    if (m_useSelfHostedArtifact) {
        return startArtifactDownload();
    }
    return openArtifactExternally();
#elif !defined(Q_OS_IOS) && !defined(MACOS_NE)
    if (m_useSelfHostedArtifact) {
        return startArtifactDownload();
    }

    if (m_downloadUrl.isEmpty()) {
        logger.error() << "Download URL is empty";
        return false;
    }

    QNetworkRequest request;
    request.setTransferTimeout(30000);
    request.setUrl(m_downloadUrl);

    QNetworkReply *reply = amnApp->networkManager()->get(request);

    QObject::connect(reply, &QNetworkReply::finished, [this, reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            const QString installerPath = localInstallerPath();
            const QByteArray installerData = reply->readAll();
            const QString installerSha256 = QString::fromLatin1(
                    QCryptographicHash::hash(installerData, QCryptographicHash::Sha256).toHex());
            const qint64 installerSize = installerData.size();
            QSaveFile file(installerPath);
            file.setDirectWriteFallback(false);
            if (!file.open(QIODevice::WriteOnly)) {
                logger.error() << "Failed to open installer file for writing:" << installerPath << "Error:" << file.errorString();
                reply->deleteLater();
                return;
            }

            if (file.write(installerData) != installerData.size()) {
                logger.error() << "Failed to write installer data to file:" << installerPath << "Error:" << file.errorString();
                file.cancelWriting();
                reply->deleteLater();
                return;
            }

            if (!file.commit()) {
                logger.error() << "Failed to atomically commit installer file:" << installerPath << "Error:" << file.errorString();
                reply->deleteLater();
                return;
            }

    #if defined(Q_OS_WINDOWS)
            if (runWindowsInstaller(installerPath, installerSha256, installerSize) == 0) {
                scheduleDesktopQuitAfterInstallerStart();
            }
    #elif defined(Q_OS_MACOS) && !defined(MACOS_NE)
            if (runMacInstaller(installerPath, installerSha256, installerSize) == 0) {
                scheduleDesktopQuitAfterInstallerStart();
            }
    #elif defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
            if (runLinuxInstaller(installerPath, installerSha256, installerSize) == 0) {
                scheduleDesktopQuitAfterInstallerStart();
            }
    #endif
        } else {
            logger.error() << "Installer download failed, network error:" << static_cast<int>(reply->error())
                           << reply->errorString();
            logger.error() << "HTTP status:" << reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        }
        reply->deleteLater();
    });
    return true;
#else
    if (m_useSelfHostedArtifact) {
        if (!prepareSelfHostedInstallerHandoff()) {
            finishSelfHostedInstallerAttempt(InstallerHandoffResult::Failed);
            return false;
        }
        const bool opened = openArtifactExternally();
        finishSelfHostedInstallerAttempt(opened
                                         ? InstallerHandoffResult::Started
                                         : InstallerHandoffResult::Failed);
        return opened;
    }
    return openArtifactExternally();
#endif
}

bool UpdateController::startArtifactDownload()
{
    if (m_selectedArtifact.url.isEmpty()) {
        logger.error() << "Self-hosted update artifact URL is empty";
        finishSelfHostedInstallerAttempt(InstallerHandoffResult::Failed);
        return false;
    }

    const QString installerPath = localInstallerPath();
    if (installerPath.isEmpty()
        || !QDir().mkpath(QFileInfo(installerPath).absolutePath())) {
        logger.error() << "Failed to create self-hosted installer directory:" << installerPath;
        finishSelfHostedInstallerAttempt(InstallerHandoffResult::Failed);
        return false;
    }

    auto *file = new QSaveFile(installerPath);
    file->setDirectWriteFallback(false);
    if (!file->open(QIODevice::WriteOnly)) {
        logger.error() << "Failed to open exclusive self-hosted installer staging file:"
                       << installerPath << file->errorString();
        delete file;
        finishSelfHostedInstallerAttempt(InstallerHandoffResult::Failed);
        return false;
    }

    auto *hash = new QCryptographicHash(QCryptographicHash::Sha256);
    auto *bytesWritten = new qint64(0);
    auto *writeFailed = new bool(false);
    auto *downloadTooLarge = new bool(false);
    auto *totalDeadlineExceeded = new bool(false);

    QNetworkRequest request;
    request.setTransferTimeout(kInstallerTransferTimeoutMs);
    request.setUrl(m_selectedArtifact.url);

    QNetworkReply *reply = amnApp->networkManager()->get(request);
    auto *totalDeadlineTimer = new QTimer(reply);
    totalDeadlineTimer->setSingleShot(true);
    totalDeadlineTimer->setInterval(kInstallerTotalDeadlineMs);
    QObject::connect(totalDeadlineTimer, &QTimer::timeout, reply,
                     [reply, totalDeadlineExceeded]() {
        *totalDeadlineExceeded = true;
        reply->abort();
    });
    totalDeadlineTimer->start();
    QObject::connect(reply, &QNetworkReply::metaDataChanged, this, [this, reply, downloadTooLarge]() {
        const QVariant contentLength = reply->header(QNetworkRequest::ContentLengthHeader);
        if (m_selectedArtifact.size >= 0 && contentLength.isValid()
            && contentLength.toLongLong() > m_selectedArtifact.size) {
            *downloadTooLarge = true;
            reply->abort();
        }
    });
    QObject::connect(reply, &QIODevice::readyRead, this, [this, reply, file, hash, bytesWritten, writeFailed, downloadTooLarge]() {
        const QByteArray chunk = reply->readAll();
        if (chunk.isEmpty() || *writeFailed || *downloadTooLarge) {
            return;
        }
        if (m_selectedArtifact.size >= 0 && *bytesWritten + chunk.size() > m_selectedArtifact.size) {
            *downloadTooLarge = true;
            reply->abort();
            return;
        }
        if (file->write(chunk) != chunk.size()) {
            *writeFailed = true;
            return;
        }
        hash->addData(chunk);
        *bytesWritten += chunk.size();
    });
    QObject::connect(reply, &QNetworkReply::finished, this,
                     [this, reply, file, hash, bytesWritten, writeFailed, downloadTooLarge,
                      totalDeadlineExceeded, totalDeadlineTimer, installerPath]() {
        totalDeadlineTimer->stop();
        const auto cleanup = [file, hash, bytesWritten, writeFailed, downloadTooLarge,
                              totalDeadlineExceeded]() {
            delete file;
            delete hash;
            delete bytesWritten;
            delete writeFailed;
            delete downloadTooLarge;
            delete totalDeadlineExceeded;
        };

        if (reply->bytesAvailable() > 0 && !*writeFailed && !*downloadTooLarge) {
            const QByteArray chunk = reply->readAll();
            if (!chunk.isEmpty()) {
                if (m_selectedArtifact.size >= 0 && *bytesWritten + chunk.size() > m_selectedArtifact.size) {
                    *downloadTooLarge = true;
                } else if (file->write(chunk) != chunk.size()) {
                    *writeFailed = true;
                } else {
                    hash->addData(chunk);
                    *bytesWritten += chunk.size();
                }
            }
        }
        const int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (reply->error() != QNetworkReply::NoError || statusCode < 200 || statusCode >= 300) {
            logger.error() << (*totalDeadlineExceeded
                                       ? "Self-hosted installer hard total deadline exceeded:"
                                       : "Self-hosted installer download failed:")
                           << static_cast<int>(reply->error()) << reply->errorString()
                           << "HTTP status:" << statusCode;
            reply->deleteLater();
            file->cancelWriting();
            cleanup();
            finishSelfHostedInstallerAttempt(InstallerHandoffResult::Failed);
            return;
        }

        reply->deleteLater();

        if (*downloadTooLarge) {
            logger.error() << "Self-hosted installer download exceeded manifest size for" << m_selectedArtifact.url.toString();
            file->cancelWriting();
            cleanup();
            finishSelfHostedInstallerAttempt(InstallerHandoffResult::Failed);
            return;
        }

        if (*writeFailed) {
            logger.error() << "Failed to write full self-hosted installer:" << installerPath << file->errorString();
            file->cancelWriting();
            cleanup();
            finishSelfHostedInstallerAttempt(InstallerHandoffResult::Failed);
            return;
        }

        const QString actualSha256 = QString::fromLatin1(hash->result().toHex());
        if (actualSha256 != normalizeSha256(m_selectedArtifact.sha256)) {
            logger.error() << "Self-hosted installer sha256 verification failed for" << m_selectedArtifact.url.toString();
            file->cancelWriting();
            cleanup();
            finishSelfHostedInstallerAttempt(InstallerHandoffResult::Failed);
            return;
        }
        if (m_selectedArtifact.size >= 0 && *bytesWritten != m_selectedArtifact.size) {
            logger.error() << "Self-hosted installer size differs from manifest:"
                             << *bytesWritten << "expected" << m_selectedArtifact.size;
            file->cancelWriting();
            cleanup();
            finishSelfHostedInstallerAttempt(InstallerHandoffResult::Failed);
            return;
        }

        if (!file->commit()) {
            logger.error() << "Failed to atomically commit verified self-hosted installer:"
                           << installerPath << file->errorString();
            cleanup();
            finishSelfHostedInstallerAttempt(InstallerHandoffResult::Failed);
            return;
        }

        cleanup();
        finishSelfHostedInstallerAttempt(launchDownloadedArtifact(installerPath));
    });
    return true;
}

UpdateController::InstallerHandoffResult UpdateController::launchDownloadedArtifact(const QString &localPath)
{
    if (!m_rollbackInstallAttempt && m_selectedReleasePolicy.generation > 0
        && (!m_selectedReleasePolicy.expiresAt.isValid()
            || QDateTime::currentDateTimeUtc() >= m_selectedReleasePolicy.expiresAt)) {
        logger.warning() << "Refusing to launch an installer from an expired self-hosted release policy generation"
                         << m_selectedReleasePolicy.generation;
        return InstallerHandoffResult::Failed;
    }

    // Persist the anti-replay/health handoff before a desktop installer gets a
    // chance to terminate this process. Failed launches restore retryable state.
    if (!prepareSelfHostedInstallerHandoff()) {
        return InstallerHandoffResult::Failed;
    }
#if defined(Q_OS_WINDOWS)
    const bool launched = runWindowsInstaller(
            localPath, m_selectedArtifact.sha256, m_selectedArtifact.size) == 0;
    if (launched) {
        scheduleDesktopQuitAfterInstallerStart();
    }
    return launched ? InstallerHandoffResult::Started : InstallerHandoffResult::Failed;
#elif defined(Q_OS_MACOS) && !defined(MACOS_NE)
    const bool launched = runMacInstaller(
            localPath, m_selectedArtifact.sha256, m_selectedArtifact.size) == 0;
    if (launched) {
        scheduleDesktopQuitAfterInstallerStart();
    }
    return launched ? InstallerHandoffResult::Started : InstallerHandoffResult::Failed;
#elif defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    const bool launched = runLinuxInstaller(
            localPath, m_selectedArtifact.sha256, m_selectedArtifact.size) == 0;
    if (launched) {
        scheduleDesktopQuitAfterInstallerStart();
    }
    return launched ? InstallerHandoffResult::Started : InstallerHandoffResult::Failed;
#elif defined(Q_OS_ANDROID)
    const int result = AndroidController::instance()->installApk(localPath);
    if (result == kAndroidApkInstallStarted) {
        return InstallerHandoffResult::Started;
    }
    if (result == kAndroidApkInstallPermissionSettingsOpened) {
        return InstallerHandoffResult::PendingPermission;
    }
    return InstallerHandoffResult::Failed;
#else
    return QDesktopServices::openUrl(QUrl::fromLocalFile(localPath))
            ? InstallerHandoffResult::Started
            : InstallerHandoffResult::Failed;
#endif
}

bool UpdateController::openArtifactExternally()
{
    const QUrl url = m_selectedArtifact.url.isEmpty() ? QUrl(m_downloadUrl) : m_selectedArtifact.url;
    if (!url.isValid() || url.isEmpty()) {
        logger.error() << "Update URL is empty or invalid";
        return false;
    }
    if (!isAllowedExternalUpdateUrl(url)) {
        logger.error() << "Update URL has unsupported external scheme:" << url.toString();
        return false;
    }
    if (!QDesktopServices::openUrl(url)) {
        logger.error() << "Failed to open update URL externally:" << url.toString();
        return false;
    }
    return true;
}

bool UpdateController::shouldAutoInstallSelfHostedArtifact() const
{
    if (!m_useSelfHostedArtifact || !m_selectedArtifact.autoInstall || !m_appSettingsRepository) {
        return false;
    }
    const QString attemptMarker = selfHostedAutoInstallAttemptMarker();
    return !attemptMarker.isEmpty() && m_appSettingsRepository->selfHostedUpdateLastAutoInstallAttempt() != attemptMarker;
}

QString UpdateController::selfHostedAutoInstallAttemptId() const
{
    if (m_version.trimmed().isEmpty() || m_selectedArtifact.platform.trimmed().isEmpty()) {
        return {};
    }
    const QString artifactIdentity = m_selectedArtifact.sha256.isEmpty()
            ? m_selectedArtifact.url.toString()
            : m_selectedArtifact.sha256;
    return QStringLiteral("%1|%2|%3").arg(m_version, m_selectedArtifact.platform, artifactIdentity);
}

QString UpdateController::selfHostedAutoInstallAttemptMarker() const
{
    const QString attemptId = selfHostedAutoInstallAttemptId();
    if (attemptId.isEmpty()) {
        return {};
    }
    return QStringLiteral("%1|%2").arg(attemptId, QDate::currentDate().toString(Qt::ISODate));
}

void UpdateController::scheduleSelfHostedAutoInstall()
{
    if (!shouldAutoInstallSelfHostedArtifact()) {
        return;
    }

    m_pendingAutoInstallAttemptId = selfHostedAutoInstallAttemptMarker();
    QTimer::singleShot(0, this, [this]() {
        runInstaller();
    });
}

void UpdateController::commitPendingAutoInstallAttempt()
{
    if (!m_appSettingsRepository || m_pendingAutoInstallAttemptId.isEmpty()) {
        return;
    }
    m_appSettingsRepository->setSelfHostedUpdateLastAutoInstallAttempt(m_pendingAutoInstallAttemptId);
    m_pendingAutoInstallAttemptId.clear();
}

void UpdateController::clearPendingAutoInstallAttempt()
{
    m_pendingAutoInstallAttemptId.clear();
}

void UpdateController::finishSelfHostedInstallerAttempt(InstallerHandoffResult result)
{
    if (result == InstallerHandoffResult::Started) {
        if (!m_handoffReceiptPrepared) {
                m_handoffReceiptPrepared = m_rollbackInstallAttempt
                    ? recordRollbackHandoff(RollbackAttemptContext {
                            m_installIntent.receiptId, m_installIntent.id,
                            m_installIntent.leaseId })
                    : recordInstallerHandoffReceipt();
        }
        if (!m_handoffReceiptPrepared) {
            logger.error() << "Installer started without a durable update health receipt";
        }
        commitPendingAutoInstallAttempt();
        m_handoffReceiptPrepared = false;
        m_androidApkInstallPermissionPending = false;
        m_selfHostedInstallInProgress = false;
        clearInstallSelection();
        return;
    }

    if (result == InstallerHandoffResult::PendingPermission) {
        // Keep the verified APK authorization durable while Android's
        // unknown-sources settings Activity is in front. The authorization
        // itself owns the expiry timer and survives process recreation.
        m_handoffReceiptPrepared = false;
        m_androidApkInstallPermissionPending = true;
        return;
    }

    if (m_handoffReceiptPrepared) {
        cancelPreparedSelfHostedInstallerHandoff();
    } else if (m_rollbackInstallAttempt) {
        recordRollbackHandoffFailure(RollbackAttemptContext {
                m_installIntent.receiptId, m_installIntent.id, m_installIntent.leaseId });
    }
    m_handoffReceiptPrepared = false;
    m_androidApkInstallPermissionPending = false;
    m_selfHostedInstallInProgress = false;
    clearPendingAutoInstallAttempt();
    clearInstallSelection();
}

void UpdateController::onAndroidApkInstallerStarted(const QString &fileName)
{
#if defined(Q_OS_ANDROID)
    const bool callbackDuringActiveHandoff = m_handoffReceiptPrepared;
    if (!finalizeAndroidApkInstallerLaunch(fileName)) {
        logger.error() << "Failed to finalize durable Android APK installer handoff:" << fileName;
        return;
    }

    m_androidApkInstallPermissionPending = false;
    if (callbackDuringActiveHandoff) {
        // The synchronous installApk() caller will complete the remaining
        // in-memory bookkeeping without writing a second receipt.
        return;
    }

    m_selfHostedInstallInProgress = false;
    clearPendingAutoInstallAttempt();
    m_handoffReceiptPrepared = false;
    clearInstallSelection();
#else
    Q_UNUSED(fileName);
#endif
}

void UpdateController::onAndroidApkInstallerStartFailed(const QString &fileName,
                                                        const QString &reason)
{
#if defined(Q_OS_ANDROID)
    static const QSet<QString> allowedReasons {
        QStringLiteral("apk_missing"),
        QStringLiteral("apk_archive_invalid"),
        QStringLiteral("apk_package_mismatch"),
        QStringLiteral("apk_version_name_invalid"),
        QStringLiteral("apk_version_code_invalid"),
        QStringLiteral("apk_version_not_newer"),
        QStringLiteral("apk_signer_invalid"),
        QStringLiteral("apk_signer_mismatch"),
        QStringLiteral("apk_install_permission_missing"),
        QStringLiteral("apk_authorization_rejected"),
        QStringLiteral("apk_installer_unavailable"),
        QStringLiteral("apk_installer_start_failed")
    };
    failAndroidApkInstallerLaunch(
            fileName, allowedReasons.contains(reason)
                    ? reason : QStringLiteral("android_installer_start_failed"));
#else
    Q_UNUSED(fileName);
    Q_UNUSED(reason);
#endif
}

void UpdateController::scheduleDesktopQuitAfterInstallerStart()
{
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    QTimer::singleShot(kDesktopQuitAfterInstallerStartMs, this, []() {
        if (amnApp) {
            logger.info() << "Quitting application after update installer handoff";
            amnApp->forceQuit();
        }
    });
#endif
}

#if defined(Q_OS_WINDOWS)
int UpdateController::runWindowsInstaller(const QString &installerPath,
                                          const QString &expectedSha256,
                                          qint64 expectedSize)
{
    const QString normalizedExpectedSha256 = normalizeSha256(expectedSha256);
    if (!isCanonicalSha256(normalizedExpectedSha256) || expectedSize < 0) {
        logger.error() << "Refusing to launch Windows installer without an exact verified identity";
        return -1;
    }

    HANDLE installerHandle = CreateFileW(
            reinterpret_cast<LPCWSTR>(installerPath.utf16()),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
    if (installerHandle == INVALID_HANDLE_VALUE) {
        logger.error() << "Failed to pin verified Windows installer:" << GetLastError();
        return -1;
    }

    const QString installerDirectoryPath = QDir::toNativeSeparators(
            QFileInfo(installerPath).absolutePath());
    HANDLE directoryHandle = CreateFileW(
            reinterpret_cast<LPCWSTR>(installerDirectoryPath.utf16()),
            FILE_LIST_DIRECTORY | READ_CONTROL,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
    if (directoryHandle == INVALID_HANDLE_VALUE) {
        logger.error() << "Failed to pin protected Windows installer directory:" << GetLastError();
        CloseHandle(installerHandle);
        return -1;
    }

    FILE_ATTRIBUTE_TAG_INFO attributeInfo {};
    FILE_ATTRIBUTE_TAG_INFO directoryAttributeInfo {};
    LARGE_INTEGER fileSize {};
    if (!GetFileInformationByHandleEx(installerHandle, FileAttributeTagInfo,
                                      &attributeInfo, sizeof(attributeInfo))
        || (attributeInfo.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0
        || GetFileType(installerHandle) != FILE_TYPE_DISK
        || !GetFileSizeEx(installerHandle, &fileSize)
        || fileSize.QuadPart != expectedSize
        || !GetFileInformationByHandleEx(directoryHandle, FileAttributeTagInfo,
                                         &directoryAttributeInfo,
                                         sizeof(directoryAttributeInfo))
        || (directoryAttributeInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
        || (directoryAttributeInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || !windowsInstallerDirectoryIsPrivate(directoryHandle)) {
        logger.error() << "Windows installer identity or file type changed before launch";
        CloseHandle(directoryHandle);
        CloseHandle(installerHandle);
        return -1;
    }

    const QString resolvedInstallerPath = finalWindowsPathForHandle(installerHandle);
    const QString resolvedDirectoryPath = finalWindowsPathForHandle(directoryHandle);
    QString expectedResolvedInstallerPath = resolvedDirectoryPath;
    if (!expectedResolvedInstallerPath.endsWith(QLatin1Char('\\'))) {
        expectedResolvedInstallerPath.append(QLatin1Char('\\'));
    }
    expectedResolvedInstallerPath.append(QFileInfo(installerPath).fileName());
    if (resolvedInstallerPath.isEmpty() || resolvedDirectoryPath.isEmpty()
        || resolvedInstallerPath.compare(expectedResolvedInstallerPath,
                                         Qt::CaseInsensitive) != 0
        || !windowsDirectoryContainsOnlyInstaller(
                resolvedDirectoryPath, QFileInfo(installerPath).fileName())) {
        logger.error() << "Windows installer resolved namespace or staging contents are unsafe";
        CloseHandle(directoryHandle);
        CloseHandle(installerHandle);
        return -1;
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);
    QByteArray buffer(64 * 1024, '\0');
    DWORD bytesRead = 0;
    BOOL readSucceeded = TRUE;
    while ((readSucceeded = ReadFile(installerHandle, buffer.data(),
                                     static_cast<DWORD>(buffer.size()),
                                     &bytesRead, nullptr))
           && bytesRead > 0) {
        hash.addData(buffer.constData(), bytesRead);
    }
    if (!readSucceeded) {
        logger.error() << "Failed to read pinned Windows installer:" << GetLastError();
        CloseHandle(directoryHandle);
        CloseHandle(installerHandle);
        return -1;
    }
    if (QString::fromLatin1(hash.result().toHex()) != normalizedExpectedSha256) {
        logger.error() << "Windows installer changed after download verification";
        CloseHandle(directoryHandle);
        CloseHandle(installerHandle);
        return -1;
    }

    const QString commandLine = QStringLiteral("\"") + resolvedInstallerPath
            + QStringLiteral("\"");
    QVector<wchar_t> commandLineBuffer(commandLine.size() + 1, L'\0');
    commandLine.toWCharArray(commandLineBuffer.data());
    if (!SetHandleInformation(directoryHandle, HANDLE_FLAG_INHERIT,
                              HANDLE_FLAG_INHERIT)) {
        logger.error() << "Failed to make the Windows staging-directory pin inheritable:"
                       << GetLastError();
        CloseHandle(directoryHandle);
        CloseHandle(installerHandle);
        return -1;
    }
    SIZE_T attributeListSize = 0;
    (void) InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeListSize);
    QVector<BYTE> attributeStorage(static_cast<qsizetype>(attributeListSize));
    auto *attributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
            attributeStorage.data());
    if (attributeListSize == 0
        || !InitializeProcThreadAttributeList(attributeList, 1, 0,
                                              &attributeListSize)
        || !UpdateProcThreadAttribute(
                attributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                &directoryHandle, sizeof(directoryHandle), nullptr, nullptr)) {
        logger.error() << "Failed to restrict Windows installer handle inheritance:"
                       << GetLastError();
        SetHandleInformation(directoryHandle, HANDLE_FLAG_INHERIT, 0);
        CloseHandle(directoryHandle);
        CloseHandle(installerHandle);
        return -1;
    }

    STARTUPINFOEXW startupInfo {};
    startupInfo.StartupInfo.cb = sizeof(startupInfo);
    startupInfo.lpAttributeList = attributeList;
    PROCESS_INFORMATION processInfo {};
    const bool success = CreateProcessW(
            reinterpret_cast<LPCWSTR>(resolvedInstallerPath.utf16()),
            commandLineBuffer.data(), nullptr, nullptr, TRUE,
            CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | EXTENDED_STARTUPINFO_PRESENT,
            nullptr, nullptr, &startupInfo.StartupInfo, &processInfo);
    const DWORD launchError = success ? ERROR_SUCCESS : GetLastError();
    DeleteProcThreadAttributeList(attributeList);
    SetHandleInformation(directoryHandle, HANDLE_FLAG_INHERIT, 0);
    qint64 pid = 0;
    if (success) {
        pid = static_cast<qint64>(processInfo.dwProcessId);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
    }
    CloseHandle(directoryHandle);
    CloseHandle(installerHandle);

    if (success) {
        logger.info() << "Installation process started with PID:" << pid;
    } else {
        logger.error() << "Failed to start installation process:" << launchError;
        return -1;
    }

    return 0;
}
#endif

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
int UpdateController::runMacInstaller(const QString &installerPath,
                                      const QString &expectedSha256,
                                      qint64 expectedSize)
{
    const QString normalizedExpectedSha256 = normalizeSha256(expectedSha256);
    if (!QFileInfo(installerPath).isAbsolute()
        || !isCanonicalSha256(normalizedExpectedSha256)
        || expectedSize < 0) {
        logger.error() << "Refusing to launch macOS installer without an exact verified identity";
        return -1;
    }

    const QString scriptContent = amnezia::scriptData(amnezia::ClientScriptType::mac_installer);
    if (scriptContent.isEmpty()) {
        logger.error() << "macOS installer script content is empty";
        return -1;
    }

    QProcess process;
    QProcessEnvironment cleanEnvironment;
    cleanEnvironment.insert(QStringLiteral("PATH"),
                            QStringLiteral("/usr/bin:/bin:/usr/sbin:/sbin"));
    cleanEnvironment.insert(QStringLiteral("LANG"), QStringLiteral("C"));
    process.setProcessEnvironment(cleanEnvironment);
    process.setProgram(QStringLiteral("/bin/bash"));
    process.setArguments(
            QStringList { QStringLiteral("--noprofile"), QStringLiteral("--norc"),
                          QStringLiteral("-c"), scriptContent,
                          QStringLiteral("amnezia-macos-installer"), installerPath,
                          normalizedExpectedSha256, QString::number(expectedSize) });
    qint64 pid;
    const bool success = process.startDetached(&pid);

    if (success) {
        logger.info() << "Installation process started with PID:" << pid;
    } else {
        logger.error() << "Failed to start installation process";
        return -1;
    }

    return 0;
}
#endif

#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
int UpdateController::runLinuxInstaller(const QString &installerPath,
                                        const QString &expectedSha256,
                                        qint64 expectedSize)
{
    const QString normalizedExpectedSha256 = normalizeSha256(expectedSha256);
    if (!isCanonicalSha256(normalizedExpectedSha256) || expectedSize < 0) {
        logger.error() << "Refusing to launch Linux installer without an exact verified identity";
        return -1;
    }

    const QByteArray nativePath = QFile::encodeName(installerPath);
    const int sourceFd = ::open(nativePath.constData(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (sourceFd < 0) {
        logger.error() << "Failed to pin verified Linux installer:" << errno;
        return -1;
    }

    struct stat installerStat {};
    if (::fstat(sourceFd, &installerStat) != 0
        || !S_ISREG(installerStat.st_mode)
        || installerStat.st_uid != ::getuid()
        || installerStat.st_nlink != 1
        || installerStat.st_size != expectedSize) {
        logger.error() << "Linux installer identity or ownership changed before launch";
        ::close(sourceFd);
        return -1;
    }

#if !defined(SYS_memfd_create)
    logger.error() << "Sealed Linux installer execution is unsupported by this platform";
    ::close(sourceFd);
    return -1;
#else
    const int installerFd = static_cast<int>(::syscall(
            SYS_memfd_create, "amnezia-verified-installer", MFD_ALLOW_SEALING));
    if (installerFd < 0) {
        logger.error() << "Failed to create sealed Linux installer image:" << errno;
        ::close(sourceFd);
        return -1;
    }

    QByteArray buffer(64 * 1024, '\0');
    ssize_t bytesRead = 0;
    qint64 copiedBytes = 0;
    while ((bytesRead = ::read(sourceFd, buffer.data(), static_cast<size_t>(buffer.size()))) > 0) {
        ssize_t writtenBytes = 0;
        while (writtenBytes < bytesRead) {
            const ssize_t writeResult = ::write(
                    installerFd, buffer.constData() + writtenBytes,
                    static_cast<size_t>(bytesRead - writtenBytes));
            if (writeResult < 0 && errno == EINTR) {
                continue;
            }
            if (writeResult <= 0) {
                logger.error() << "Failed to copy Linux installer into sealed image:" << errno;
                ::close(sourceFd);
                ::close(installerFd);
                return -1;
            }
            writtenBytes += writeResult;
        }
        copiedBytes += bytesRead;
    }
    ::close(sourceFd);
    const int requiredSeals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    struct stat sealedStat {};
    if (bytesRead < 0 || copiedBytes != expectedSize
        || ::fchmod(installerFd, S_IRUSR | S_IXUSR) != 0
        || ::fcntl(installerFd, F_ADD_SEALS, requiredSeals) != 0
        || ::fcntl(installerFd, F_GET_SEALS) != requiredSeals
        || ::fstat(installerFd, &sealedStat) != 0
        || !S_ISREG(sealedStat.st_mode) || sealedStat.st_size != expectedSize
        || ::lseek(installerFd, 0, SEEK_SET) < 0) {
        logger.error() << "Linux installer changed or could not be sealed for exact-fd execution:" << errno;
        ::close(installerFd);
        return -1;
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);
    qint64 verifiedBytes = 0;
    while ((bytesRead = ::read(installerFd, buffer.data(), static_cast<size_t>(buffer.size()))) > 0) {
        hash.addData(buffer.constData(), bytesRead);
        verifiedBytes += bytesRead;
    }
    if (bytesRead < 0 || verifiedBytes != expectedSize
        || QString::fromLatin1(hash.result().toHex()) != normalizedExpectedSha256
        || ::lseek(installerFd, 0, SEEK_SET) < 0) {
        logger.error() << "Sealed Linux installer identity does not match the signed artifact";
        ::close(installerFd);
        return -1;
    }

    int execStatusPipe[2] { -1, -1 };
    if (::pipe2(execStatusPipe, O_CLOEXEC) != 0) {
        logger.error() << "Failed to create Linux installer handoff pipe:" << errno;
        ::close(installerFd);
        return -1;
    }

    const pid_t firstChild = ::fork();
    if (firstChild == 0) {
        ::close(execStatusPipe[0]);
        if (::setsid() < 0) {
            const int launchError = errno;
            (void) ::write(execStatusPipe[1], &launchError, sizeof(launchError));
            _exit(127);
        }
        const pid_t detachedChild = ::fork();
        if (detachedChild < 0) {
            const int launchError = errno;
            (void) ::write(execStatusPipe[1], &launchError, sizeof(launchError));
            _exit(127);
        }
        if (detachedChild > 0) {
            _exit(0);
        }

        char processName[] = "AmneziaVPN-installer";
        char *const arguments[] { processName, nullptr };
        ::fexecve(installerFd, arguments, environ);
        const int launchError = errno;
        (void) ::write(execStatusPipe[1], &launchError, sizeof(launchError));
        _exit(127);
    }

    ::close(execStatusPipe[1]);
    ::close(installerFd);
    if (firstChild < 0) {
        logger.error() << "Failed to fork Linux installer process:" << errno;
        ::close(execStatusPipe[0]);
        return -1;
    }

    int childStatus = 0;
    (void) ::waitpid(firstChild, &childStatus, 0);
    int launchError = 0;
    const ssize_t statusBytes = ::read(execStatusPipe[0], &launchError, sizeof(launchError));
    ::close(execStatusPipe[0]);
    if (!WIFEXITED(childStatus) || WEXITSTATUS(childStatus) != 0 || statusBytes != 0) {
        logger.error() << "Failed to execute pinned Linux installer:" << launchError;
        return -1;
    }

    logger.info() << "Pinned Linux installer process started";
    return 0;
#endif
}
#endif
