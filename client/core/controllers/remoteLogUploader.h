#ifndef REMOTELOGUPLOADER_H
#define REMOTELOGUPLOADER_H

#include <QByteArray>
#include <QHash>
#include <QDateTime>
#include <QList>
#include <QNetworkAccessManager>
#include <QObject>
#include <QString>
#include <QTimer>

#include "core/protocols/vpnProtocol.h"
#include "core/repositories/secureAppSettingsRepository.h"
#include "core/repositories/secureServersRepository.h"
#include "core/utils/containerEnum.h"

class VpnConnection;

class RemoteLogUploader : public QObject
{
    Q_OBJECT

public:
    explicit RemoteLogUploader(SecureServersRepository *serversRepository,
                               SecureAppSettingsRepository *appSettingsRepository,
                               VpnConnection *vpnConnection,
                               QObject *parent = nullptr);

    void start();

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
        qint64 nextOffset = 0;
        bool hasMore = false;
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
    };

    void uploadNow();
    UploadTarget findUploadTarget() const;
    ConnectionSnapshot currentConnectionSnapshot() const;
    QList<LogPayload> collectPayloads();
    void bootstrapCurrentTarget();
    void postNext();
    QString payloadDedupeKey(const QString &kind) const;
    LogPayload payloadFromFile(const QString &kind, const QString &filePath);
    LogPayload payloadFromBytes(const QString &kind, const QByteArray &data);
    void finishUpload();
    static bool sameTarget(const UploadTarget &left, const UploadTarget &right);

    SecureServersRepository *m_serversRepository = nullptr;
    SecureAppSettingsRepository *m_appSettingsRepository = nullptr;
    VpnConnection *m_vpnConnection = nullptr;
    QTimer m_uploadTimer;
    QNetworkAccessManager m_networkAccessManager;
    UploadTarget m_currentTarget;
    QList<LogPayload> m_pendingPayloads;
    QHash<QString, LogCursor> m_logCursors;
    QDateTime m_nextTokenRefreshAt;
    bool m_uploadInProgress = false;
    bool m_uploadRequested = false;
    bool m_bootstrapInProgress = false;
};

#endif // REMOTELOGUPLOADER_H
