#ifndef REMOTELOGUPLOADER_H
#define REMOTELOGUPLOADER_H

#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QList>
#include <QNetworkAccessManager>
#include <QObject>
#include <QSet>
#include <QString>
#include <QTimer>

#include "core/protocols/vpnProtocol.h"
#include "core/utils/containerEnum.h"
#include "core/utils/remoteLogBatchHealth.h"
#include "core/utils/remoteLogSanitizer.h"

class SecureAppSettingsRepository;
class SecureServersRepository;
class VpnConnection;
class QFile;

class RemoteLogUploader : public QObject
{
    Q_OBJECT

    Q_PROPERTY(State state READ state NOTIFY stateChanged)
    Q_PROPERTY(QDateTime lastSuccess READ lastSuccess NOTIFY lastSuccessChanged)
    Q_PROPERTY(qint64 pendingBytes READ pendingBytes NOTIFY pendingBytesChanged)
    Q_PROPERTY(ErrorCategory lastErrorCategory READ lastErrorCategory NOTIFY lastErrorCategoryChanged)
    Q_PROPERTY(QDateTime nextRetryAt READ nextRetryAt NOTIFY nextRetryAtChanged)

public:
    enum class State {
        WaitingForVpn,
        TargetMissing,
        Uploading,
        Healthy,
        Stale,
        Error
    };
    Q_ENUM(State)

    enum class ErrorCategory {
        None,
        Configuration,
        Bootstrap,
        Authentication,
        Network,
        Timeout,
        Server,
        Source
    };
    Q_ENUM(ErrorCategory)

    explicit RemoteLogUploader(SecureServersRepository *serversRepository,
                               SecureAppSettingsRepository *appSettingsRepository,
                               VpnConnection *vpnConnection,
                               QObject *parent = nullptr);

    State state() const;
    QDateTime lastSuccess() const;
    qint64 pendingBytes() const;
    ErrorCategory lastErrorCategory() const;
    QDateTime nextRetryAt() const;

public slots:
    void start();
    void retryNow();

signals:
    void stateChanged();
    void lastSuccessChanged();
    void pendingBytesChanged();
    void lastErrorCategoryChanged();
    void nextRetryAtChanged();

private:
    struct UploadTarget
    {
        QString endpoint;
        QString clientId;
        QString token;
        QString serverId;
        QString tokenCacheKey;
        bool bootstrap = false;
    };

    struct LogPayload
    {
        QString kind;
        QByteArray data;
        QString offsetKey;
        QString fingerprint;
        qint64 fingerprintBytes = 0;
        QString offsetAnchor;
        QString nextAnchor;
        QString sourceRangeSha256;
        QString sanitizerSecretSetSha256;
        QString currentSecretSetSha256;
        qint64 offset = 0;
        qint64 nextOffset = 0;
        qint64 sourceSize = 0;
        qint64 remainingBytes = 0;
        bool hasMore = false;
        bool advancesCursor = true;
        bool wholeRedacted = false;
        amnezia::remoteLogSanitizer::StreamState streamState;
        qint64 sourceBytes = 0;
    };

    struct ConnectionSnapshot
    {
        Vpn::ConnectionState state = Vpn::ConnectionState::Unknown;
        QString serverId;
        amnezia::DockerContainer container = amnezia::DockerContainer::None;
    };

    struct LogCursor
    {
        qint64 offset = -1;
        QString fingerprint;
        qint64 fingerprintBytes = 0;
        QString anchor;
        QString sanitizerSecretSetSha256;
        amnezia::remoteLogSanitizer::StreamState streamState;
        bool streamStateKnown = false;
        bool persistenceReadable = true;
    };

    struct StateScanProgress
    {
        QString fingerprint;
        qint64 targetOffset = 0;
        qint64 position = 0;
        QString anchor;
        QByteArray lookbehind;
        amnezia::remoteLogSanitizer::StreamState state;
    };

    struct RetrySanitizerMarker
    {
        bool present = false;
        bool valid = false;
        QString binding;
        QString fingerprint;
        qint64 offset = -1;
        qint64 nextOffset = -1;
        qint64 highWaterOffset = -1;
        QString offsetAnchor;
        QString nextAnchor;
        QString sourceRangeSha256;
        QString secretSetSha256;
        bool requiresInheritedSecrets = true;
        bool awaitingStableSource = false;
        qint64 confirmationCursorOffset = -1;
        QString confirmationCursorAnchor;
    };

    void uploadNow();
    void uploadWithSnapshot(const ConnectionSnapshot &snapshot);
    UploadTarget findUploadTarget(const ConnectionSnapshot &snapshot) const;
    QList<LogPayload> collectPayloads();
    void bootstrapCurrentTarget();
    void postNext();
    QString payloadDedupeKey(const QString &kind) const;
    LogCursor cursorForKey(const QString &key);
    bool persistCursor(const QString &key, const LogCursor &cursor) const;
    LogPayload payloadFromFile(const QString &kind, const QString &filePath,
                               bool *sourceReadable = nullptr);
    LogPayload payloadFromBytes(const QString &kind, const QByteArray &data);
    bool advanceFileStateScan(QFile &file,
                              const QString &key,
                              const QString &fingerprint,
                              qint64 targetOffset,
                              amnezia::remoteLogSanitizer::StreamState &state);
    bool advanceBytesStateScan(const QByteArray &data,
                               const QString &key,
                               const QString &fingerprint,
                               qint64 targetOffset,
                               amnezia::remoteLogSanitizer::StreamState &state);
    QByteArray sanitizePayload(const QByteArray &data,
                               bool startsInsideRecord,
                               bool endsInsideRecord,
                               const amnezia::remoteLogSanitizer::StreamState &streamState,
                               const amnezia::remoteLogSanitizer::StreamBoundary &boundary,
                               const amnezia::RemoteLogSanitizerSecretSet &sanitizerSecrets,
                               amnezia::remoteLogSanitizer::StreamState &nextStreamState) const;
    amnezia::RemoteLogSanitizerSecretSet sanitizerSecretsForPayload(
            const QString &key, const QString &fingerprint, qint64 offset,
            const QString &offsetAnchor, const QString &sourceRangeSha256,
            qint64 nextOffset, const QString &nextAnchor, qint64 sourceSize,
            const LogCursor &cursor, bool cursorMatchesSource,
            QString *currentSecretSetSha256 = nullptr);
    amnezia::RemoteLogSanitizerSecretSet currentSanitizerSecrets() const;
    QString sanitizerSecretSetSha256(
            const amnezia::RemoteLogSanitizerSecretSet &secrets) const;
    RetrySanitizerMarker retrySanitizerMarker(const QString &key) const;
    bool persistRetrySanitizerMarker(const QString &key,
                                     const RetrySanitizerMarker &marker) const;
    bool reconcileRetrySanitizerTransition(
            const QString &key, const QString &fingerprint,
            qint64 capturedSize, qint64 sourceOffset,
            const QString &offsetAnchor, qint64 nextOffset,
            const QString &nextAnchor, const QString &sourceRangeSha256,
            const LogCursor &cursor,
            bool cursorMatchesSource, const QString &currentSecretSetSha256);
    bool retainRetrySanitizerSecrets(const LogPayload &payload);
    bool armRetrySanitizerStableSource(const LogPayload &payload,
                                       const LogCursor &cursor);
    bool discardRetrySanitizerSecrets(const QString &key);
    void finishUpload();
    void recordFailure(ErrorCategory category);
    void markUploadSuccess();
    void scheduleRetry();
    void clearRetry();
    void refreshStaleness();
    void setState(State state);
    void setPendingBytes(qint64 pendingBytes);
    void setLastErrorCategory(ErrorCategory category);
    void setNextRetryAt(const QDateTime &nextRetryAt);
    void activateTargetHealth(const UploadTarget &target);
    QString batchIdForPayload(const LogPayload &payload) const;
    QString targetIdentity(const UploadTarget &target) const;
    static bool sameTarget(const UploadTarget &left, const UploadTarget &right);

    SecureServersRepository *m_serversRepository = nullptr;
    SecureAppSettingsRepository *m_appSettingsRepository = nullptr;
    VpnConnection *m_vpnConnection = nullptr;
    QTimer m_uploadTimer;
    QTimer m_retryTimer;
    QTimer m_healthTimer;
    QNetworkAccessManager m_networkAccessManager;
    UploadTarget m_currentTarget;
    ConnectionSnapshot m_currentConnectionSnapshot;
    QList<LogPayload> m_pendingPayloads;
    QHash<QString, LogCursor> m_logCursors;
    QHash<QString, StateScanProgress> m_stateScans;
    QSet<QString> m_retrySanitizerKeys;
    State m_state = State::WaitingForVpn;
    ErrorCategory m_lastErrorCategory = ErrorCategory::None;
    QDateTime m_lastSuccess;
    QDateTime m_nextRetryAt;
    QDateTime m_nextTokenRefreshAt;
    QString m_healthTargetId;
    qint64 m_pendingBytes = 0;
    int m_consecutiveFailures = 0;
    bool m_uploadInProgress = false;
    bool m_uploadRequested = false;
    bool m_snapshotPending = false;
    quint64 m_snapshotGeneration = 0;
    quint64 m_connectionContextGeneration = 0;
    quint64 m_currentConnectionContextGeneration = 0;
    bool m_bootstrapInProgress = false;
    bool m_batchHadFailure = false;
    bool m_started = false;
    bool m_collectionHasReadableSource = false;
    bool m_collectionAllExpectedSourcesReadable = false;
    bool m_collectionHasPendingStateScan = false;
    bool m_collectionPrivacyQuarantined = false;
    bool m_collectionWholeRedactionUsed = false;
    bool m_retryPersistenceFailClosed = false;
};

#endif // REMOTELOGUPLOADER_H
