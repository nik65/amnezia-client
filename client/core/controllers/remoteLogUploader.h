#ifndef REMOTELOGUPLOADER_H
#define REMOTELOGUPLOADER_H

#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QList>
#include <QNetworkAccessManager>
#include <QObject>
#include <QString>
#include <QTimer>

#include "core/protocols/vpnProtocol.h"
#include "core/utils/containerEnum.h"
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
        QString nextAnchor;
        qint64 offset = 0;
        qint64 nextOffset = 0;
        qint64 remainingBytes = 0;
        bool hasMore = false;
        bool advancesCursor = true;
        amnezia::remoteLogSanitizer::StreamState streamState;
        qint64 sourceBytes = 0;
    };

    struct ConnectionSnapshot
    {
        Vpn::ConnectionState state = Vpn::ConnectionState::Unknown;
        int serverIndex = -1;
        amnezia::DockerContainer container = amnezia::DockerContainer::None;
    };

    struct LogCursor
    {
        qint64 offset = -1;
        QString fingerprint;
        qint64 fingerprintBytes = 0;
        QString anchor;
        amnezia::remoteLogSanitizer::StreamState streamState;
        bool streamStateKnown = false;
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

    void uploadNow();
    UploadTarget findUploadTarget() const;
    ConnectionSnapshot currentConnectionSnapshot() const;
    QList<LogPayload> collectPayloads();
    void bootstrapCurrentTarget();
    void postNext();
    QString payloadDedupeKey(const QString &kind) const;
    LogCursor cursorForKey(const QString &key);
    void persistCursor(const QString &key, const LogCursor &cursor) const;
    LogPayload payloadFromFile(const QString &kind, const QString &filePath);
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
                               amnezia::remoteLogSanitizer::StreamState &nextStreamState) const;
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
    QList<LogPayload> m_pendingPayloads;
    QHash<QString, LogCursor> m_logCursors;
    QHash<QString, StateScanProgress> m_stateScans;
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
    bool m_bootstrapInProgress = false;
    bool m_batchHadFailure = false;
    bool m_started = false;
    bool m_collectionHasReadableSource = false;
    bool m_collectionHasPendingStateScan = false;
};

#endif // REMOTELOGUPLOADER_H
