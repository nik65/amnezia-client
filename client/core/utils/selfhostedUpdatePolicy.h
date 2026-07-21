#ifndef SELFHOSTEDUPDATEPOLICY_H
#define SELFHOSTEDUPDATEPOLICY_H

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QString>
#include <QStringList>
#include <QUuid>
#include <QVersionNumber>

namespace amnezia::selfhostedUpdatePolicy
{
    inline constexpr int CohortBucketCount = 10000;
    inline constexpr qsizetype MaximumCohortIdentityLength = 512;

    enum class ManifestResult
    {
        Invalid,
        Stale,
        NoUpdate,
        UpdateAvailable
    };

    inline bool shouldTryNextManifest(ManifestResult result)
    {
        return result == ManifestResult::Invalid || result == ManifestResult::Stale;
    }

    enum class GenerationBindingDisposition
    {
        InvalidCandidate,
        Stale,
        MissingPayloadBinding,
        ConflictingPayload,
        AcceptExisting,
        AcceptAdvance
    };

    enum class PlatformFamily
    {
        Windows,
        MacOS,
        IOS,
        Android,
        Linux,
        Unsupported
    };

    enum class ReleasePolicyDisposition
    {
        None,
        Eligible,
        Paused,
        Expired,
        VersionIneligible,
        CohortIneligible
    };

    enum class RollbackLeaseDisposition
    {
        Invalid,
        Acquire,
        Wait,
        Recover,
        Exhausted
    };

    inline QString releasePolicyDispositionName(ReleasePolicyDisposition disposition)
    {
        switch (disposition) {
        case ReleasePolicyDisposition::Eligible:
            return QStringLiteral("eligible");
        case ReleasePolicyDisposition::Paused:
            return QStringLiteral("paused");
        case ReleasePolicyDisposition::Expired:
            return QStringLiteral("expired");
        case ReleasePolicyDisposition::VersionIneligible:
            return QStringLiteral("version_ineligible");
        case ReleasePolicyDisposition::CohortIneligible:
            return QStringLiteral("cohort_ineligible");
        case ReleasePolicyDisposition::None:
            break;
        }
        return QStringLiteral("none");
    }

    inline bool parseExactVersion(const QString &value, QVersionNumber &versionOut)
    {
        if (value.isEmpty() || value != value.trimmed()) {
            return false;
        }

        const QStringList parts = value.split(QLatin1Char('.'));
        if (parts.size() != 4) {
            return false;
        }
        for (const QString &part : parts) {
            if (part.isEmpty()) {
                return false;
            }
            // Keep the serialized value canonical because update receipts are
            // persisted across process boundaries and compared with APP_VERSION.
            // QVersionNumber deliberately treats 04.09.0.11 as 4.9.0.11, but
            // accepting both spellings would make a successfully installed
            // binary impossible to acknowledge by its canonical build version.
            if (part.size() > 1 && part.startsWith(QLatin1Char('0'))) {
                return false;
            }
            for (const QChar character : part) {
                const ushort codePoint = character.unicode();
                if (codePoint < '0' || codePoint > '9') {
                    return false;
                }
            }
        }

        qsizetype suffixIndex = 0;
        const QVersionNumber version = QVersionNumber::fromString(value, &suffixIndex);
        if (version.isNull() || suffixIndex != value.size() || version.segmentCount() != 4) {
            return false;
        }
        versionOut = version;
        return true;
    }

    inline bool parseCanonicalUtcTimestamp(const QString &timestamp, QDateTime &dateTimeOut)
    {
        if (timestamp.size() != 20
            || timestamp.at(4) != QLatin1Char('-') || timestamp.at(7) != QLatin1Char('-')
            || timestamp.at(10) != QLatin1Char('T') || timestamp.at(13) != QLatin1Char(':')
            || timestamp.at(16) != QLatin1Char(':') || timestamp.at(19) != QLatin1Char('Z')) {
            return false;
        }
        for (int index = 0; index < timestamp.size(); ++index) {
            if (index == 4 || index == 7 || index == 10 || index == 13
                || index == 16 || index == 19) {
                continue;
            }
            const ushort codePoint = timestamp.at(index).unicode();
            if (codePoint < '0' || codePoint > '9') {
                return false;
            }
        }

        const QDateTime dateTime = QDateTime::fromString(timestamp, Qt::ISODate);
        if (!dateTime.isValid() || dateTime.timeSpec() != Qt::UTC
            || dateTime.toString(QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")) != timestamp) {
            return false;
        }
        dateTimeOut = dateTime;
        return true;
    }

    inline bool isCanonicalReleaseChannel(const QString &value)
    {
        return value == QStringLiteral("stable")
                || value == QStringLiteral("canary")
                || value == QStringLiteral("emergency");
    }

    inline bool isCanonicalCohortSaltId(const QString &value)
    {
        if (value.isEmpty() || value.size() > 64) {
            return false;
        }
        for (int index = 0; index < value.size(); ++index) {
            const ushort character = value.at(index).unicode();
            const bool alphaNumeric = (character >= 'A' && character <= 'Z')
                    || (character >= 'a' && character <= 'z')
                    || (character >= '0' && character <= '9');
            const bool separator = character == '.' || character == '_' || character == '-';
            if (!alphaNumeric && (index == 0 || !separator)) {
                return false;
            }
        }
        return true;
    }

    inline int cohortBucket(const QString &installationIdentity, const QString &cohortSaltId)
    {
        if (!isCanonicalCohortSaltId(cohortSaltId)
            || installationIdentity.size() > MaximumCohortIdentityLength) {
            return -1;
        }
        const QString normalizedIdentity = installationIdentity.trimmed().toLower();
        if (normalizedIdentity.isEmpty()) {
            return -1;
        }

        QByteArray input = QByteArrayLiteral("amnezia-update-cohort-v1");
        input.append('\0');
        input.append(cohortSaltId.toUtf8());
        input.append('\0');
        input.append(normalizedIdentity.toUtf8());
        const QByteArray digest = QCryptographicHash::hash(input, QCryptographicHash::Sha256);

        int bucket = 0;
        for (int index = 0; index < 8; ++index) {
            bucket = (bucket * 256 + static_cast<unsigned char>(digest.at(index))) % CohortBucketCount;
        }
        return bucket;
    }

    inline QString normalizeSha256(const QString &value)
    {
        QString normalized = value.trimmed().toLower();
        normalized.remove(QLatin1Char(':'));
        return normalized;
    }

    inline bool isCanonicalSha256(const QString &value)
    {
        if (value.size() != 64) {
            return false;
        }
        for (const QChar character : value) {
            const ushort codePoint = character.unicode();
            const bool decimal = codePoint >= '0' && codePoint <= '9';
            const bool lowerHex = codePoint >= 'a' && codePoint <= 'f';
            if (!decimal && !lowerHex) {
                return false;
            }
        }
        return true;
    }

    inline bool normalizedPrivateInstallerStagingPath(
            const QString &storedPath,
            const QString &tempRoot,
            const QString &directoryPrefix,
            const QString &installerFileName,
            QString *normalizedPath = nullptr)
    {
        const QString nativeNormalized = QDir::fromNativeSeparators(storedPath);
        for (const QChar character : nativeNormalized) {
            const ushort codePoint = character.unicode();
            if (codePoint <= 0x1f || codePoint == 0x7f) {
                return false;
            }
        }

        const QFileInfo installerInfo(nativeNormalized);
        const QString cleanPath = QDir::cleanPath(installerInfo.absoluteFilePath());
        const QString cleanTempRoot = QDir::cleanPath(QFileInfo(tempRoot).absoluteFilePath());
        if (nativeNormalized.isEmpty() || !installerInfo.isAbsolute()
            || nativeNormalized != cleanPath || cleanTempRoot.isEmpty()
            || installerInfo.fileName() != installerFileName) {
            return false;
        }

        const QString relativePath = QDir(cleanTempRoot).relativeFilePath(cleanPath);
        const QStringList relativeParts = relativePath.split(QLatin1Char('/'), Qt::KeepEmptyParts);
        if (relativeParts.size() != 2 || relativeParts.at(1) != installerFileName) {
            return false;
        }
        const QString directoryName = relativeParts.at(0);
        if (!directoryName.startsWith(directoryPrefix)) {
            return false;
        }
        const QString directoryId = directoryName.mid(directoryPrefix.size()).toLower();
        const QUuid parsedDirectoryId(directoryId);
        if (parsedDirectoryId.isNull()
            || parsedDirectoryId.toString(QUuid::WithoutBraces).toLower() != directoryId) {
            return false;
        }

        if (normalizedPath) {
            *normalizedPath = cleanPath;
        }
        return true;
    }

    inline bool rollbackPolicyBindingMatches(qint64 receiptGeneration,
                                             const QString &receiptPayloadSha256,
                                             qint64 acceptedGeneration,
                                             const QString &acceptedPayloadSha256)
    {
        const QString receiptDigest = normalizeSha256(receiptPayloadSha256);
        const QString acceptedDigest = normalizeSha256(acceptedPayloadSha256);
        return receiptGeneration > 0 && receiptGeneration == acceptedGeneration
                && isCanonicalSha256(receiptDigest) && receiptDigest == acceptedDigest;
    }

    inline bool automaticRollbackRunningVersionAllowed(const QString &runningVersion,
                                                       const QString &targetVersion,
                                                       const QString &rollbackVersion)
    {
        return !runningVersion.isEmpty() && runningVersion == targetVersion
                && runningVersion != rollbackVersion;
    }

    inline QDateTime boundedAuthorizationExpiry(const QDateTime &now,
                                                qint64 handoffTtlMs,
                                                const QDateTime &policyExpiresAt = {})
    {
        if (!now.isValid() || handoffTtlMs <= 0) {
            return {};
        }
        const QDateTime ttlExpiry = now.toUTC().addMSecs(handoffTtlMs);
        if (!policyExpiresAt.isValid()) {
            return ttlExpiry;
        }
        const QDateTime policyExpiry = policyExpiresAt.toUTC();
        if (policyExpiry <= now.toUTC()) {
            return {};
        }
        return policyExpiry < ttlExpiry ? policyExpiry : ttlExpiry;
    }

    inline RollbackLeaseDisposition evaluateRollbackLease(const QDateTime &now,
                                                           const QDateTime &leaseExpiresAt,
                                                           int recoveryCount,
                                                           int maximumRecoveries)
    {
        if (!now.isValid() || recoveryCount < 0 || maximumRecoveries < 0
            || recoveryCount > maximumRecoveries) {
            return RollbackLeaseDisposition::Invalid;
        }
        if (!leaseExpiresAt.isValid()) {
            return recoveryCount == 0 ? RollbackLeaseDisposition::Acquire
                                      : RollbackLeaseDisposition::Invalid;
        }
        if (now.toUTC() < leaseExpiresAt.toUTC()) {
            return RollbackLeaseDisposition::Wait;
        }
        return recoveryCount < maximumRecoveries ? RollbackLeaseDisposition::Recover
                                                  : RollbackLeaseDisposition::Exhausted;
    }

    inline GenerationBindingDisposition evaluateGenerationBinding(
            qint64 candidateGeneration,
            const QString &candidatePayloadSha256,
            qint64 highestObservedGeneration,
            qint64 persistedGeneration,
            const QString &persistedPayloadSha256)
    {
        const QString normalizedCandidateSha256 = normalizeSha256(candidatePayloadSha256);
        if (candidateGeneration <= 0 || !isCanonicalSha256(normalizedCandidateSha256)) {
            return GenerationBindingDisposition::InvalidCandidate;
        }

        const qint64 generationFloor = qMax(highestObservedGeneration, persistedGeneration);
        if (candidateGeneration < generationFloor) {
            return GenerationBindingDisposition::Stale;
        }
        if (candidateGeneration > generationFloor) {
            return GenerationBindingDisposition::AcceptAdvance;
        }
        if (persistedGeneration != candidateGeneration || persistedPayloadSha256.isEmpty()) {
            return GenerationBindingDisposition::MissingPayloadBinding;
        }
        if (persistedPayloadSha256 != normalizedCandidateSha256) {
            return GenerationBindingDisposition::ConflictingPayload;
        }
        return GenerationBindingDisposition::AcceptExisting;
    }

    inline QStringList platformCandidates(PlatformFamily platform, const QString &cpuArchitecture)
    {
        const QString arch = cpuArchitecture.trimmed().toLower();
        const bool isArm64 = arch.contains(QStringLiteral("arm64"))
                || arch.contains(QStringLiteral("aarch64"));
        const bool isArm = isArm64 || arch.contains(QStringLiteral("arm"));
        QStringList candidates;

        switch (platform) {
        case PlatformFamily::Windows:
            candidates << (isArm ? QStringLiteral("windows-arm64") : QStringLiteral("windows-x64"))
                       << QStringLiteral("windows-x64")
                       << QStringLiteral("windows");
            break;
        case PlatformFamily::MacOS:
            candidates << (isArm64 ? QStringLiteral("macos-arm64") : QStringLiteral("macos-x64"))
                       << QStringLiteral("macos-x64")
                       << QStringLiteral("macos");
            break;
        case PlatformFamily::IOS:
            candidates << QStringLiteral("ios");
            break;
        case PlatformFamily::Android:
            if (isArm64) {
                candidates << QStringLiteral("android-arm64-v8a");
            } else if (isArm) {
                candidates << QStringLiteral("android-armeabi-v7a");
            } else if (arch.contains(QStringLiteral("x86_64")) || arch.contains(QStringLiteral("amd64"))) {
                candidates << QStringLiteral("android-x86_64");
            } else if (arch.contains(QStringLiteral("x86"))) {
                candidates << QStringLiteral("android-x86");
            }
            candidates << QStringLiteral("android");
            break;
        case PlatformFamily::Linux:
            if (isArm64) {
                candidates << QStringLiteral("linux-arm64");
            } else if (!isArm) {
                candidates << QStringLiteral("linux-x64");
            }
            // The architecture-neutral key remains a deliberate publisher
            // opt-in. Never silently hand an x64 installer to an ARM client.
            candidates << QStringLiteral("linux");
            break;
        case PlatformFamily::Unsupported:
            break;
        }

        candidates.removeDuplicates();
        return candidates;
    }
}

#endif // SELFHOSTEDUPDATEPOLICY_H
