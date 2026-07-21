#include <QCoreApplication>
#include <QDateTime>
#include <QList>
#include <QStringList>
#include <QTemporaryDir>
#include <QTextStream>
#include <QUuid>
#include <QVersionNumber>

#include "core/utils/selfhostedUpdatePolicy.h"
#include "secureQSettings.h"

using namespace amnezia::selfhostedUpdatePolicy;

namespace
{
    class TestRunner
    {
    public:
        void check(bool condition, const char *expression, int line)
        {
            ++m_assertions;
            if (condition) {
                return;
            }
            ++m_failures;
            QTextStream(stderr) << "FAIL line " << line << ": " << expression << Qt::endl;
        }

        int finish() const
        {
            QTextStream stream(m_failures == 0 ? stdout : stderr);
            stream << (m_failures == 0 ? "PASS" : "FAIL")
                   << ": " << m_assertions << " assertions, " << m_failures << " failures"
                   << Qt::endl;
            return m_failures == 0 ? 0 : 1;
        }

    private:
        int m_assertions = 0;
        int m_failures = 0;
    };
}

#define CHECK(expression) runner.check((expression), #expression, __LINE__)

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    TestRunner runner;

    QVersionNumber version;
    CHECK(parseExactVersion(QStringLiteral("0.0.0.0"), version));
    CHECK(version.segments() == QList<int>({ 0, 0, 0, 0 }));
    CHECK(parseExactVersion(QStringLiteral("4.9.0.11"), version));
    CHECK(version.segments() == QList<int>({ 4, 9, 0, 11 }));
    CHECK(parseExactVersion(QStringLiteral("2147483647.0.0.0"), version));
    CHECK(version.segmentAt(0) == 2147483647);

    const QStringList invalidVersions {
        QString(),
        QStringLiteral("1.2.3"),
        QStringLiteral("1.2.3.4.5"),
        QStringLiteral("1..3.4"),
        QStringLiteral(".1.2.3"),
        QStringLiteral("1.2.3."),
        QStringLiteral(" 1.2.3.4"),
        QStringLiteral("1.2.3.4 "),
        QStringLiteral("1.2.3.4-beta"),
        QStringLiteral("+1.2.3.4"),
        QStringLiteral("-1.2.3.4"),
        QStringLiteral("1.2.3.a"),
        QStringLiteral("01.2.3.4"),
        QStringLiteral("1.02.3.4"),
        QStringLiteral("1.2.03.4"),
        QStringLiteral("1.2.3.04"),
        QString::fromUtf8("١.٢.٣.٤"),
        QStringLiteral("2147483648.0.0.0")
    };
    for (const QString &value : invalidVersions) {
        CHECK(!parseExactVersion(value, version));
    }

    QDateTime dateTime;
    CHECK(parseCanonicalUtcTimestamp(QStringLiteral("0001-01-01T00:00:00Z"), dateTime));
    CHECK(dateTime.isValid());
    CHECK(dateTime.timeSpec() == Qt::UTC);
    CHECK(parseCanonicalUtcTimestamp(QStringLiteral("2026-07-20T23:59:59Z"), dateTime));
    CHECK(dateTime.toString(Qt::ISODate) == QStringLiteral("2026-07-20T23:59:59Z"));
    CHECK(parseCanonicalUtcTimestamp(QStringLiteral("9999-12-31T23:59:59Z"), dateTime));
    CHECK(dateTime.timeSpec() == Qt::UTC);

    const QStringList invalidTimestamps {
        QString(),
        QStringLiteral("2026-07-20T10:00:00"),
        QStringLiteral("2026-07-20T10:00:00+00:00"),
        QStringLiteral("2026-07-20T13:00:00+03:00"),
        QStringLiteral("2026-07-20T10:00:00.000Z"),
        QStringLiteral("2026-07-20 10:00:00Z"),
        QStringLiteral("2026-07-20t10:00:00Z"),
        QStringLiteral("2026-07-20T10:00:00z"),
        QStringLiteral("2026-02-29T10:00:00Z"),
        QStringLiteral("2024-02-30T10:00:00Z"),
        QStringLiteral("2026-07-20T24:00:00Z"),
        QStringLiteral("2026-07-20T23:59:60Z"),
        QStringLiteral(" 2026-07-20T10:00:00Z")
    };
    for (const QString &value : invalidTimestamps) {
        CHECK(!parseCanonicalUtcTimestamp(value, dateTime));
    }

    CHECK(isCanonicalReleaseChannel(QStringLiteral("stable")));
    CHECK(isCanonicalReleaseChannel(QStringLiteral("canary")));
    CHECK(isCanonicalReleaseChannel(QStringLiteral("emergency")));
    CHECK(!isCanonicalReleaseChannel(QStringLiteral("Stable")));
    CHECK(!isCanonicalReleaseChannel(QStringLiteral("preview")));
    CHECK(!isCanonicalReleaseChannel(QStringLiteral(" stable")));

    CHECK(releasePolicyDispositionName(ReleasePolicyDisposition::None) == QStringLiteral("none"));
    CHECK(releasePolicyDispositionName(ReleasePolicyDisposition::Eligible) == QStringLiteral("eligible"));
    CHECK(releasePolicyDispositionName(ReleasePolicyDisposition::Paused) == QStringLiteral("paused"));
    CHECK(releasePolicyDispositionName(ReleasePolicyDisposition::Expired) == QStringLiteral("expired"));
    CHECK(releasePolicyDispositionName(ReleasePolicyDisposition::VersionIneligible)
          == QStringLiteral("version_ineligible"));
    CHECK(releasePolicyDispositionName(ReleasePolicyDisposition::CohortIneligible)
          == QStringLiteral("cohort_ineligible"));

    CHECK(isCanonicalCohortSaltId(QStringLiteral("fleet-v1")));
    CHECK(isCanonicalCohortSaltId(QStringLiteral("A.b_C-9")));
    CHECK(isCanonicalCohortSaltId(QString(64, QLatin1Char('x'))));
    CHECK(!isCanonicalCohortSaltId(QString()));
    CHECK(!isCanonicalCohortSaltId(QStringLiteral("-fleet")));
    CHECK(!isCanonicalCohortSaltId(QStringLiteral("fleet secret")));
    CHECK(!isCanonicalCohortSaltId(QStringLiteral("fleet/secret")));
    CHECK(!isCanonicalCohortSaltId(QString::fromUtf8("fléet")));
    CHECK(!isCanonicalCohortSaltId(QString(65, QLatin1Char('x'))));

    CHECK(cohortBucket(QStringLiteral("00000000-0000-0000-0000-000000000000"),
                       QStringLiteral("fleet-v1")) == 8765);
    CHECK(cohortBucket(QStringLiteral("123e4567-e89b-12d3-a456-426614174000"),
                       QStringLiteral("fleet-v1")) == 4110);
    CHECK(cohortBucket(QStringLiteral("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"),
                       QStringLiteral("fleet-v1")) == 5782);
    CHECK(cohortBucket(QStringLiteral(" 123E4567-E89B-12D3-A456-426614174000 "),
                       QStringLiteral("fleet-v1")) == 4110);
    const int bucket = cohortBucket(QStringLiteral("123e4567-e89b-12d3-a456-426614174000"),
                                    QStringLiteral("fleet-v1"));
    CHECK(bucket >= 0);
    CHECK(bucket < CohortBucketCount);
    CHECK(!(bucket < 0 * (CohortBucketCount / 100)));
    CHECK(bucket < 100 * (CohortBucketCount / 100));
    CHECK(cohortBucket(QString(), QStringLiteral("fleet-v1")) == -1);
    CHECK(cohortBucket(QStringLiteral("   "), QStringLiteral("fleet-v1")) == -1);
    CHECK(cohortBucket(QStringLiteral("device"), QStringLiteral("-invalid")) == -1);
    CHECK(cohortBucket(QString(MaximumCohortIdentityLength + 1, QLatin1Char('x')),
                       QStringLiteral("fleet-v1")) == -1);
    const int maximumLengthBucket = cohortBucket(
            QString(MaximumCohortIdentityLength, QLatin1Char('x')), QStringLiteral("fleet-v1"));
    CHECK(maximumLengthBucket >= 0);
    CHECK(maximumLengthBucket < CohortBucketCount);

    CHECK(shouldTryNextManifest(ManifestResult::Invalid));
    CHECK(shouldTryNextManifest(ManifestResult::Stale));
    CHECK(!shouldTryNextManifest(ManifestResult::NoUpdate));
    CHECK(!shouldTryNextManifest(ManifestResult::UpdateAvailable));

    const QString digestA(64, QLatin1Char('a'));
    const QString digestB(64, QLatin1Char('b'));
    CHECK(evaluateGenerationBinding(7, digestA, 0, 7, digestA)
          == GenerationBindingDisposition::AcceptExisting);
    CHECK(evaluateGenerationBinding(8, digestA, 0, 7, digestA)
          == GenerationBindingDisposition::AcceptAdvance);
    CHECK(evaluateGenerationBinding(8, digestA, 8, 7, digestA)
          == GenerationBindingDisposition::MissingPayloadBinding);

    QString decoratedDigest = digestA.toUpper();
    decoratedDigest.insert(2, QLatin1Char(':'));
    decoratedDigest.prepend(QLatin1Char(' '));
    decoratedDigest.append(QLatin1Char(' '));
    CHECK(evaluateGenerationBinding(8, decoratedDigest, 7, 7, digestA)
          == GenerationBindingDisposition::AcceptAdvance);
    CHECK(evaluateGenerationBinding(0, digestA, 0, 0, QString())
          == GenerationBindingDisposition::InvalidCandidate);
    CHECK(evaluateGenerationBinding(1, QStringLiteral("not-a-sha256"), 0, 0, QString())
          == GenerationBindingDisposition::InvalidCandidate);
    CHECK(evaluateGenerationBinding(6, digestA, 0, 7, digestA)
          == GenerationBindingDisposition::Stale);
    CHECK(evaluateGenerationBinding(7, digestA, 0, 7, QString())
          == GenerationBindingDisposition::MissingPayloadBinding);
    CHECK(evaluateGenerationBinding(7, digestB, 0, 7, digestA)
          == GenerationBindingDisposition::ConflictingPayload);
    CHECK(evaluateGenerationBinding(7, digestA, 9, 7, digestA)
          == GenerationBindingDisposition::Stale);
    // A crash after the generation floor is written but before its payload
    // digest must fail closed for the same generation.
    CHECK(evaluateGenerationBinding(8, digestA, 0, 8, QString())
          == GenerationBindingDisposition::MissingPayloadBinding);
    CHECK(evaluateGenerationBinding(8, digestA, 0, 8, digestB)
          == GenerationBindingDisposition::ConflictingPayload);

    CHECK(rollbackPolicyBindingMatches(7, digestA, 7, digestA));
    CHECK(rollbackPolicyBindingMatches(7, digestA.toUpper(), 7, digestA));
    CHECK(!rollbackPolicyBindingMatches(6, digestA, 7, digestA));
    CHECK(!rollbackPolicyBindingMatches(7, digestB, 7, digestA));
    CHECK(!rollbackPolicyBindingMatches(7, QString(), 7, digestA));
    CHECK(automaticRollbackRunningVersionAllowed(QStringLiteral("4.9.0.11"),
                                                  QStringLiteral("4.9.0.11"),
                                                  QStringLiteral("4.9.0.10")));
    CHECK(!automaticRollbackRunningVersionAllowed(QStringLiteral("4.9.0.12"),
                                                   QStringLiteral("4.9.0.11"),
                                                   QStringLiteral("4.9.0.10")));
    CHECK(!automaticRollbackRunningVersionAllowed(QStringLiteral("4.9.0.10"),
                                                   QStringLiteral("4.9.0.11"),
                                                   QStringLiteral("4.9.0.10")));

    const QDateTime authNow = QDateTime::fromString(
            QStringLiteral("2026-07-21T10:00:00Z"), Qt::ISODate);
    CHECK(boundedAuthorizationExpiry(authNow, 600000)
          == authNow.addSecs(600));
    CHECK(boundedAuthorizationExpiry(authNow, 600000, authNow.addSecs(120))
          == authNow.addSecs(120));
    CHECK(boundedAuthorizationExpiry(authNow, 600000, authNow.addSecs(1200))
          == authNow.addSecs(600));
    CHECK(!boundedAuthorizationExpiry(authNow, 600000, authNow).isValid());
    CHECK(!boundedAuthorizationExpiry(authNow, 0).isValid());

    QTemporaryDir installerTempRoot;
    CHECK(installerTempRoot.isValid());
    const QString installerDirectoryName = QStringLiteral("amnezia-update-%1").arg(
            QUuid::createUuid().toString(QUuid::WithoutBraces).toLower());
    const QString installerDirectory = QDir(installerTempRoot.path()).filePath(
            installerDirectoryName);
    CHECK(QDir().mkpath(installerDirectory));
    const QString installerPath = QDir(installerDirectory).filePath(
            QStringLiteral("AmneziaVPN.apk"));
    QString normalizedInstallerPath;
    CHECK(normalizedPrivateInstallerStagingPath(
            installerPath, installerTempRoot.path(), QStringLiteral("amnezia-update-"),
            QStringLiteral("AmneziaVPN.apk"), &normalizedInstallerPath));
    CHECK(normalizedInstallerPath == QDir::cleanPath(installerPath));
    CHECK(!normalizedPrivateInstallerStagingPath(
            QDir(installerTempRoot.path()).filePath(QStringLiteral("AmneziaVPN.apk")),
            installerTempRoot.path(), QStringLiteral("amnezia-update-"),
            QStringLiteral("AmneziaVPN.apk")));
    CHECK(!normalizedPrivateInstallerStagingPath(
            QDir(installerDirectory).filePath(QStringLiteral("../AmneziaVPN.apk")),
            installerTempRoot.path(), QStringLiteral("amnezia-update-"),
            QStringLiteral("AmneziaVPN.apk")));
    CHECK(!normalizedPrivateInstallerStagingPath(
            QDir(installerDirectory).filePath(QStringLiteral("other.apk")),
            installerTempRoot.path(), QStringLiteral("amnezia-update-"),
            QStringLiteral("AmneziaVPN.apk")));

    CHECK(evaluateRollbackLease(authNow, {}, 0, 1)
          == RollbackLeaseDisposition::Acquire);
    CHECK(evaluateRollbackLease(authNow, authNow.addSecs(10), 0, 1)
          == RollbackLeaseDisposition::Wait);
    CHECK(evaluateRollbackLease(authNow, authNow.addSecs(-1), 0, 1)
          == RollbackLeaseDisposition::Recover);
    CHECK(evaluateRollbackLease(authNow, authNow.addSecs(-1), 1, 1)
          == RollbackLeaseDisposition::Exhausted);
    CHECK(evaluateRollbackLease(authNow, {}, 1, 1)
          == RollbackLeaseDisposition::Invalid);

    CHECK(platformCandidates(PlatformFamily::MacOS, QStringLiteral("x86_64")).first()
          == QStringLiteral("macos-x64"));
    const QStringList armMac = platformCandidates(PlatformFamily::MacOS, QStringLiteral("arm64"));
    CHECK(armMac.first() == QStringLiteral("macos-arm64"));
    CHECK(armMac.contains(QStringLiteral("macos-x64")));
    CHECK(platformCandidates(PlatformFamily::IOS, QStringLiteral("arm64"))
          == QStringList({ QStringLiteral("ios") }));
    CHECK(platformCandidates(PlatformFamily::Windows, QStringLiteral("amd64"))
                  .contains(QStringLiteral("windows-x64")));
    CHECK(platformCandidates(PlatformFamily::Linux, QStringLiteral("x86_64"))
                  .contains(QStringLiteral("linux-x64")));
    const QStringList armLinux = platformCandidates(PlatformFamily::Linux, QStringLiteral("aarch64"));
    CHECK(armLinux.first() == QStringLiteral("linux-arm64"));
    CHECK(!armLinux.contains(QStringLiteral("linux-x64")));
    CHECK(armLinux.contains(QStringLiteral("linux")));
    CHECK(platformCandidates(PlatformFamily::Android, QStringLiteral("aarch64"))
                  .contains(QStringLiteral("android-arm64-v8a")));

    using amnezia::secureSettingsPolicy::canonicalKey;
    using amnezia::secureSettingsPolicy::isLocalOnlySetting;
    using amnezia::secureSettingsPolicy::isRetainedAcrossSettingsClear;
    using amnezia::secureSettingsPolicy::isEncryptedSetting;
    using amnezia::secureSettingsPolicy::isValidSettingsKey;
    using amnezia::secureSettingsPolicy::keyListContains;
    using amnezia::secureSettingsPolicy::requiresDurableWrite;
    CHECK(canonicalKey(QStringLiteral("Conf//selfHostedUpdate//pendingHealthReceipt"))
          == QStringLiteral("Conf/selfHostedUpdate/pendingHealthReceipt"));
    CHECK(canonicalKey(QStringLiteral("/Conf\\selfHostedUpdate\\pendingHealthReceipt/"))
          == QStringLiteral("Conf/selfHostedUpdate/pendingHealthReceipt"));
    QString nulAlias = QStringLiteral("Conf/selfHostedUpdate");
    nulAlias.append(QChar::Null);
    nulAlias.append(QStringLiteral("/lastAcceptedPolicyGeneration"));
    CHECK(!isValidSettingsKey(nulAlias));
    CHECK(canonicalKey(nulAlias).isEmpty());
    CHECK(!isValidSettingsKey(QStringLiteral("Conf/selfHostedUpdate\nreceipt")));
    CHECK(!isValidSettingsKey(QStringLiteral("Conf/selfHostedUpdate\treceipt")));
    CHECK(!isValidSettingsKey(QStringLiteral("Conf/selfHostedUpdate\u007freceipt")));
    CHECK(!isValidSettingsKey(QStringLiteral("Conf/selfHostedUpdate\u0085receipt")));
    CHECK(isValidSettingsKey(QStringLiteral("Conf/selfHostedUpdate/pendingHealthReceipt")));
    CHECK(isLocalOnlySetting(nulAlias));
    CHECK(isRetainedAcrossSettingsClear(nulAlias));
    CHECK(isEncryptedSetting(QStringLiteral("Servers/SERVERSLIST")));
    CHECK(isEncryptedSetting(QStringLiteral("conf/REMOTELOGTOKENS/device")));
    CHECK(!isEncryptedSetting(nulAlias));
    CHECK(isLocalOnlySetting(QStringLiteral("Conf//selfHostedUpdate//pendingHealthReceipt")));
    CHECK(isLocalOnlySetting(QStringLiteral("Conf/selfHostedUpdate/futureSecurityState")));
    CHECK(isLocalOnlySetting(QStringLiteral("Conf/selfHostedUpdateLastAutoInstallAttempt")));
    CHECK(isLocalOnlySetting(QStringLiteral("Conf\\installationUuid")));
    CHECK(requiresDurableWrite(QStringLiteral("Conf/selfHostedUpdate/lastAcceptedPolicyGeneration")));
    CHECK(requiresDurableWrite(QStringLiteral("Conf/selfHostedUpdateLastAutoInstallAttempt")));
    CHECK(!requiresDurableWrite(QStringLiteral("Conf/appLanguage")));
    CHECK(isRetainedAcrossSettingsClear(QStringLiteral("Conf/installationUuid")));
    CHECK(isRetainedAcrossSettingsClear(
            QStringLiteral("Conf//selfHostedUpdate//pendingHealthReceipt")));
    CHECK(!isRetainedAcrossSettingsClear(QStringLiteral("Conf/remoteLogTokens")));
    CHECK(!isRetainedAcrossSettingsClear(QStringLiteral("Conf/appLanguage")));
#if defined(Q_OS_WINDOWS)
    CHECK(keyListContains(QStringList({ QStringLiteral("Servers/serversList") }),
                          QStringLiteral("servers/SERVERSLIST")));

    // Qt's Windows NativeFormat reaches NUL-terminated Registry APIs: an
    // unguarded embedded-NUL value name aliases the protected prefix. Exercise
    // the real backend, then prove the policy guard prevents that overwrite.
    const QString nativeTestOrganization = QStringLiteral("AmneziaSecurityTest-%1").arg(
            QUuid::createUuid().toString(QUuid::WithoutBraces));
    QSettings nativeSettings(QSettings::NativeFormat, QSettings::UserScope,
                             nativeTestOrganization, QStringLiteral("nul-alias"));
    nativeSettings.setFallbacksEnabled(false);
    nativeSettings.clear();
    const QString protectedNativeKey = QStringLiteral("Conf/installationUuid");
    QString maliciousNativeAlias = protectedNativeKey;
    maliciousNativeAlias.append(QChar::Null);
    maliciousNativeAlias.append(QStringLiteral("ignored-suffix"));
    nativeSettings.setValue(protectedNativeKey, QStringLiteral("sentinel"));
    nativeSettings.setValue(maliciousNativeAlias, QStringLiteral("unguarded-overwrite"));
    nativeSettings.sync();
    CHECK(nativeSettings.value(protectedNativeKey).toString()
          == QStringLiteral("unguarded-overwrite"));
    nativeSettings.setValue(protectedNativeKey, QStringLiteral("sentinel"));
    if (isValidSettingsKey(maliciousNativeAlias)) {
        nativeSettings.setValue(maliciousNativeAlias, QStringLiteral("guarded-overwrite"));
    }
    nativeSettings.sync();
    CHECK(nativeSettings.value(protectedNativeKey).toString() == QStringLiteral("sentinel"));
    nativeSettings.clear();
    nativeSettings.sync();
#else
    CHECK(!keyListContains(QStringList({ QStringLiteral("Servers/serversList") }),
                           QStringLiteral("servers/SERVERSLIST")));
#endif

    return runner.finish();
}
