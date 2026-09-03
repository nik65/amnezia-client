#ifndef UPDATECONTROLLER_H
#define UPDATECONTROLLER_H

#include <functional>
#include <QDateTime>
#include <QObject>
#include <QJsonObject>
#include <QNetworkReply>
#include <QUrl>
#include <QVariantMap>

#include "core/repositories/secureAppSettingsRepository.h"
#include "core/repositories/secureServersRepository.h"
#include "core/utils/selfhostedUpdatePolicy.h"

class QTimer;

class UpdateController : public QObject
{
    Q_OBJECT
public:
    explicit UpdateController(SecureAppSettingsRepository* appSettingsRepository,
                              SecureServersRepository* serversRepository,
                              QObject *parent = nullptr);

    QString getRawChangelogText() const;
    QString getReleaseDate() const;
    QString getVersion() const;
    bool isUpdateCheckRunning() const;
    QString getReleaseChannel() const;
    qint64 getReleasePolicyGeneration() const;
    QString getReleasePolicyDisposition() const;
    int getReleaseHealthDeadlineSeconds() const;
    QDateTime getReleasePolicyGeneratedAt() const;
    QDateTime getReleasePolicyExpiresAt() const;
    QString getPreviousVersion() const;
    bool hasRollbackArtifact() const;
    QString getRollbackVersion() const;
    QUrl getRollbackArtifactUrl() const;
    QString getRollbackArtifactSha256() const;
    qint64 getRollbackArtifactSize() const;
    QVariantMap getPendingUpdateHealthReceipt() const;
    QVariantMap getLastUpdateHealthReceipt() const;
    bool isUpdateHealthConfirmationPending() const;
    bool isRollbackAvailable() const;
    QVariantMap getRollbackActionMetadata() const;

public slots:
    bool checkForUpdates();
    bool runInstaller();
    void refreshPendingUpdateHealth();
    bool confirmRunningVersionHealthy();
    bool markRunningVersionUnhealthy(const QString &reason);
    bool runPendingRollback();

signals:
    void updateFound();
    void updateCheckFinished(bool updateAvailable);
    void releasePolicyChanged();
    void updateHealthReceiptChanged();
    void rollbackAvailabilityChanged();

private:
    struct UpdateArtifact
    {
        QString platform;
        QUrl url;
        QString sha256;
        qint64 size = -1;
        bool openExternally = false;
        bool autoInstall = false;
        qint64 androidVersionCode = -1;
    };

    enum class InstallIntentKind
    {
        None,
        Update,
        Rollback
    };

    struct RollbackAttemptContext
    {
        QString receiptId;
        QString intentId;
        QString leaseId;

        bool isComplete() const
        {
            return !receiptId.isEmpty() && !intentId.isEmpty() && !leaseId.isEmpty();
        }
    };

    struct InstallIntent
    {
        InstallIntentKind kind = InstallIntentKind::None;
        QString id;
        QString receiptId;
        QString leaseId;
        QString targetVersion;
        QString platform;
        QUrl url;
        QString sha256;
        qint64 size = -1;
        qint64 policyGeneration = 0;
        QString policyPayloadSha256;
        bool consumed = false;
    };

    struct ReleasePolicy
    {
        QString channel = QStringLiteral("stable");
        qint64 generation = 0;
        int rolloutPercentage = 100;
        QString cohortSaltId;
        QString minimumVersion;
        QString maximumVersion;
        int healthDeadlineSeconds = 0;
        QDateTime generatedAt;
        QDateTime expiresAt;
        QString previousVersion;
        QString rollbackVersion;
        UpdateArtifact rollbackArtifact;
        bool hasRollbackArtifact = false;
        amnezia::selfhostedUpdatePolicy::ReleasePolicyDisposition disposition =
                amnezia::selfhostedUpdatePolicy::ReleasePolicyDisposition::None;
    };

    using ManifestProcessResult = amnezia::selfhostedUpdatePolicy::ManifestResult;

    enum class ReleasePolicyResult
    {
        Invalid,
        Stale,
        Ineligible,
        Eligible
    };

    enum class InstallerHandoffResult
    {
        Failed,
        Started,
        PendingPermission
    };

    void finishUpdateCheck();
    void fetchSelfHostedManifest();
    void fetchSelfHostedManifestFromUrls(const QList<QUrl> &manifestUrls, int urlIndex);
    void fetchGatewayUrl();
    void fetchVersionInfo();
    void fetchChangelog();
    void fetchReleaseDate();
    void doGetAsync(const QString &endpoint, std::function<void(bool, QByteArray)> onDone);
    bool isSelfHostedUpdateChannelConfigured() const;
    bool isNewVersionAvailable() const;
    bool isNewVersionAvailable(const QString &version) const;
    QList<QUrl> selfHostedManifestUrls() const;
    QUrl normalizedSelfHostedManifestUrl(const QString &host) const;
    QList<QString> platformCandidates() const;
    ManifestProcessResult processSelfHostedManifest(const QUrl &manifestUrl, const QByteArray &manifestData);
    ReleasePolicyResult evaluateReleasePolicy(const QUrl &manifestUrl,
                                              const QJsonObject &policyObject,
                                              const QString &releaseVersion,
                                              ReleasePolicy &policyOut) const;
    bool verifySignedManifestEnvelope(const QByteArray &manifestData, QByteArray &payloadData) const;
    bool verifyManifestSignature(const QByteArray &payloadData, const QByteArray &signature) const;
    bool selectSelfHostedArtifact(const QUrl &manifestUrl,
                                  const QJsonObject &payload,
                                  UpdateArtifact &artifactOut,
                                  bool rollbackArtifact = false) const;
    QUrl resolvedArtifactUrl(const QUrl &manifestUrl, const QString &urlOrPath) const;
    bool payloadHasPlatformCandidate(const QJsonObject &payload) const;
    void clearSelectedReleasePolicy();
    amnezia::selfhostedUpdatePolicy::GenerationBindingDisposition acceptPolicyGeneration(
            qint64 generation, const QString &payloadSha256);
    bool isPendingHealthReceiptValid(const QVariantMap &receipt) const;
    bool receiptMatchesAcceptedPolicy(const QVariantMap &receipt) const;
    bool rollbackArtifactFromReceipt(const QVariantMap &receipt, UpdateArtifact &artifactOut) const;
    bool recordInstallerHandoffReceipt();
    bool recordRollbackHandoff(const RollbackAttemptContext &expectedAttempt);
    void recordRollbackHandoffFailure(const RollbackAttemptContext &expectedAttempt,
                                      bool permanentValidationFailure = false);
    bool prepareSelfHostedInstallerHandoff();
    void cancelPreparedSelfHostedInstallerHandoff();
#if defined(Q_OS_ANDROID)
    bool prepareAndroidApkInstallerAuthorization();
    bool isAndroidApkInstallerAuthorizationValid(const QVariantMap &authorization) const;
    bool authorizeAndroidApkInstallerLaunch(const QString &fileName,
                                            const QString &packageName,
                                            const QString &versionName,
                                            qint64 versionCode);
    bool finalizeAndroidApkInstallerLaunch(const QString &fileName, bool inferredFromRunningVersion = false);
    void failAndroidApkInstallerLaunch(const QString &fileName, const QString &reason);
    void recoverAndroidApkInstallerAuthorization();
    void expireAndroidApkInstallerAuthorization(const QString &preparedAt);
    bool verifiedAndroidApkMatchesAuthorization(const QString &fileName,
                                                const QVariantMap &authorization) const;
#endif
    bool scheduleAutomaticRollbackIfEligible();
    bool scheduleAutomaticRollbackRetry(const QVariantMap &receipt);
    bool claimRollbackIntent(const QString &origin, RollbackAttemptContext &attemptOut);
    bool recoverAutomaticRollbackLease(QVariantMap receipt);
    bool runPendingRollbackWithIntent(const RollbackAttemptContext &expectedAttempt);
    bool installIntentMatchesSelection() const;
    void armUpdateInstallIntent();
    void armRollbackInstallIntent(const QVariantMap &receipt,
                                  const UpdateArtifact &artifact,
                                  const RollbackAttemptContext &expectedAttempt);
    void clearInstallSelection();
    void finishPendingHealthReceipt(const QVariantMap &pendingReceipt,
                                    const QString &status,
                                    const QString &reason,
                                    bool clearPendingReceipt);
    bool startArtifactDownload();
    InstallerHandoffResult launchDownloadedArtifact(const QString &localPath);
    bool openArtifactExternally();
    bool shouldAutoInstallSelfHostedArtifact() const;
    QString selfHostedAutoInstallAttemptId() const;
    QString selfHostedAutoInstallAttemptMarker() const;
    void scheduleSelfHostedAutoInstall();
    void commitPendingAutoInstallAttempt();
    void clearPendingAutoInstallAttempt();
    void finishSelfHostedInstallerAttempt(InstallerHandoffResult result);
    void onAndroidApkInstallerStarted(const QString &fileName);
    void onAndroidApkInstallerStartFailed(const QString &fileName, const QString &reason);
    void scheduleDesktopQuitAfterInstallerStart();
    void setupNetworkErrorHandling(QNetworkReply* reply, const QString& operation);
    void handleNetworkError(QNetworkReply* reply, const QString& operation);
    QString composeDownloadUrl() const;
    QString localInstallerPath() const;
    void startBackgroundUpdateChecks();

    SecureAppSettingsRepository* m_appSettingsRepository;
    SecureServersRepository* m_serversRepository;
    QTimer* m_backgroundUpdateTimer = nullptr;

    QString m_baseUrl;
    QString m_changelogText;
    QString m_version;
    QString m_releaseDate;
    QString m_downloadUrl;
    UpdateArtifact m_selectedArtifact;
    ReleasePolicy m_selectedReleasePolicy;
    ReleasePolicy m_observedReleasePolicy;
    qint64 m_highestObservedPolicyGeneration = 0;
    QString m_pendingAutoInstallAttemptId;
    InstallIntent m_installIntent;
    mutable QString m_localInstallerPath;
    bool m_useSelfHostedArtifact = false;
    bool m_updateCheckRunning = false;
    bool m_updateFoundDuringCheck = false;
    bool m_selfHostedInstallInProgress = false;
    bool m_androidApkInstallPermissionPending = false;
    bool m_rollbackInstallAttempt = false;
    bool m_handoffReceiptPrepared = false;
    bool m_desktopQuitScheduled = false;

#if defined(Q_OS_WINDOWS)
    int runWindowsInstaller(const QString &installerPath,
                            const QString &expectedSha256 = {},
                            qint64 expectedSize = -1);
#elif defined(Q_OS_MACOS) && !defined(MACOS_NE)
    int runMacInstaller(const QString &installerPath,
                        const QString &expectedSha256 = {},
                        qint64 expectedSize = -1);
#elif defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    int runLinuxInstaller(const QString &installerPath,
                          const QString &expectedSha256 = {},
                          qint64 expectedSize = -1);
#endif
};

#endif // UPDATECONTROLLER_H
