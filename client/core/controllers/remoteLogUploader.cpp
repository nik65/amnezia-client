#include "remoteLogUploader.h"

#include <QCryptographicHash>
#include <QFile>
#include <QFileDevice>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QThread>
#include <QUrl>

#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/selfhosted/clientLogsUtils.h"
#include "vpnConnection.h"
#include "logger.h"
#include "core/utils/containers/containerUtils.h"

#ifdef Q_OS_ANDROID
    #include "platforms/android/android_controller.h"
#endif

namespace
{
    Logger logger("RemoteLogUploader");
    constexpr int uploadIntervalMs = 60 * 1000;
    constexpr int initialUploadDelayMs = 15 * 1000;
    constexpr int uploadTimeoutMs = 30 * 1000;
    constexpr qint64 maxPayloadBytes = 15 * 1024 * 1024;
    constexpr qint64 maxBootstrapResponseBytes = 4096;

    qint64 initialOffset(qint64 size)
    {
        return size > maxPayloadBytes ? size - maxPayloadBytes : 0;
    }

    QString fileFingerprint(QFile &file)
    {
        const QFileDevice::FileTime birthTime = QFileDevice::FileBirthTime;
        const QDateTime created = file.fileTime(birthTime);
        const qint64 originalPosition = file.pos();
        file.seek(0);
        const QByteArray head = file.read(4096);
        file.seek(originalPosition);
        return QStringLiteral("%1:%2:%3")
                .arg(file.fileName(),
                     QString::number(created.isValid() ? created.toMSecsSinceEpoch() : 0),
                     QString::fromLatin1(QCryptographicHash::hash(head, QCryptographicHash::Sha256).toHex()));
    }

    bool isTrustedClientLogsEndpoint(const QString &endpoint)
    {
        const QUrl url(endpoint);
        return url.isValid()
               && url.scheme() == QStringLiteral("http")
               && url.host() == QString::fromLatin1(amnezia::protocols::clientLogs::syncHost)
               && url.port() == amnezia::protocols::clientLogs::syncPort
               && url.path() == QString::fromLatin1(amnezia::protocols::clientLogs::uploadPath);
    }

}

RemoteLogUploader::RemoteLogUploader(SecureServersRepository *serversRepository,
                                     SecureAppSettingsRepository *appSettingsRepository,
                                     VpnConnection *vpnConnection,
                                     QObject *parent)
    : QObject(parent),
      m_serversRepository(serversRepository),
      m_appSettingsRepository(appSettingsRepository),
      m_vpnConnection(vpnConnection)
{
    m_uploadTimer.setInterval(uploadIntervalMs);
    connect(&m_uploadTimer, &QTimer::timeout, this, &RemoteLogUploader::uploadNow);

    if (m_serversRepository) {
        connect(m_serversRepository, &SecureServersRepository::serverAdded, this, [this](const QString &) { uploadNow(); });
        connect(m_serversRepository, &SecureServersRepository::serverEdited, this, [this](const QString &) { uploadNow(); });
    }
    if (m_vpnConnection) {
        connect(m_vpnConnection, &VpnConnection::connectionStateChanged, this, [this](Vpn::ConnectionState) { uploadNow(); });
    }
}

bool RemoteLogUploader::sameTarget(const UploadTarget &left, const UploadTarget &right)
{
    return left.endpoint == right.endpoint
           && left.clientId == right.clientId
           && left.token == right.token
           && left.serverId == right.serverId
           && left.bootstrap == right.bootstrap;
}

void RemoteLogUploader::start()
{
    if (!m_uploadTimer.isActive()) {
        m_uploadTimer.start();
    }
    QTimer::singleShot(initialUploadDelayMs, this, &RemoteLogUploader::uploadNow);
}

void RemoteLogUploader::uploadNow()
{
    if (m_uploadInProgress) {
        m_uploadRequested = true;
        return;
    }

    m_currentTarget = findUploadTarget();
    if (m_currentTarget.endpoint.isEmpty() || m_currentTarget.clientId.isEmpty()) {
        return;
    }
    if (m_currentTarget.token.isEmpty()) {
        if (m_currentTarget.bootstrap) {
            bootstrapCurrentTarget();
        }
        return;
    }

    m_pendingPayloads = collectPayloads();
    if (m_pendingPayloads.isEmpty()) {
        return;
    }

    m_uploadInProgress = true;
    postNext();
}

QString RemoteLogUploader::payloadDedupeKey(const QString &kind) const
{
    return m_currentTarget.serverId + QLatin1Char(':') + m_currentTarget.endpoint + QLatin1Char(':')
           + m_currentTarget.clientId + QLatin1Char(':') + kind;
}

RemoteLogUploader::ConnectionSnapshot RemoteLogUploader::currentConnectionSnapshot() const
{
    ConnectionSnapshot snapshot;
    if (!m_vpnConnection) {
        return snapshot;
    }

    if (QThread::currentThread() == m_vpnConnection->thread()) {
        snapshot.state = m_vpnConnection->connectionState();
        snapshot.serverIndex = m_vpnConnection->serverIndex();
        snapshot.container = m_vpnConnection->container();
        return snapshot;
    }

    const bool invoked = QMetaObject::invokeMethod(m_vpnConnection, [this, &snapshot]() {
        snapshot.state = m_vpnConnection->connectionState();
        snapshot.serverIndex = m_vpnConnection->serverIndex();
        snapshot.container = m_vpnConnection->container();
    }, Qt::BlockingQueuedConnection);
    if (!invoked) {
        return {};
    }
    return snapshot;
}

RemoteLogUploader::UploadTarget RemoteLogUploader::findUploadTarget() const
{
    if (!m_serversRepository) {
        return {};
    }

    const ConnectionSnapshot snapshot = currentConnectionSnapshot();
    if (snapshot.state != Vpn::ConnectionState::Connected) {
        return {};
    }

    QString serverId;
    const int activeServerIndex = snapshot.serverIndex;
    if (activeServerIndex >= 0 && activeServerIndex < m_serversRepository->serversCount()) {
        serverId = m_serversRepository->serverIdAt(activeServerIndex);
    }
    if (serverId.isEmpty()) {
        return {};
    }

    const int serverIndex = m_serversRepository->indexOfServerId(serverId);
    if (serverIndex < 0) {
        return {};
    }

    const QJsonObject serverJson = m_serversRepository->serverJson(serverIndex);
    QJsonObject clientLogs = serverJson.value(amnezia::configKey::clientLogs).toObject();
    if (clientLogs.isEmpty()) {
        if (const auto config = m_serversRepository->selfHostedAdminConfig(serverId)) {
            const amnezia::DockerContainer container = snapshot.container != amnezia::DockerContainer::None
                    ? snapshot.container : config->defaultContainer;
            clientLogs = amnezia::clientLogsUtils::legacyBootstrapTarget(
                    container, config->containerConfig(container));
        } else if (const auto config = m_serversRepository->selfHostedUserConfig(serverId)) {
            const amnezia::DockerContainer container = snapshot.container != amnezia::DockerContainer::None
                    ? snapshot.container : config->defaultContainer;
            clientLogs = amnezia::clientLogsUtils::legacyBootstrapTarget(
                    container, config->containerConfig(container));
        }
    }

    UploadTarget target;
    target.endpoint = clientLogs.value(amnezia::configKey::clientLogsEndpoint).toString();
    target.clientId = clientLogs.value(amnezia::configKey::clientLogsClientId).toString();
    target.token = clientLogs.value(amnezia::configKey::clientLogsToken).toString();
    target.bootstrap = clientLogs.value(amnezia::configKey::clientLogsBootstrap).toBool(false);
    target.serverId = serverId;
    target.tokenCacheKey = serverId + QLatin1Char(':') + target.clientId;
    if (target.bootstrap && target.token.isEmpty() && m_appSettingsRepository) {
        target.token = m_appSettingsRepository->remoteLogToken(target.tokenCacheKey);
    }
    if (target.clientId.isEmpty() || (!target.bootstrap && target.token.isEmpty()) || !isTrustedClientLogsEndpoint(target.endpoint)) {
        return {};
    }
    return target;
}

RemoteLogUploader::LogPayload RemoteLogUploader::payloadFromFile(const QString &kind, const QString &filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }

    const qint64 size = file.size();
    const QString key = payloadDedupeKey(kind);
    const QString fingerprint = fileFingerprint(file);
    LogCursor cursor = m_logCursors.value(key);
    qint64 offset = cursor.offset;
    if (cursor.fingerprint != fingerprint || offset < 0 || offset > size) {
        offset = initialOffset(size);
    }
    if (offset >= size || !file.seek(offset)) {
        return {};
    }

    const QByteArray data = file.read(maxPayloadBytes);
    if (data.isEmpty()) {
        return {};
    }

    return { kind, data, key, fingerprint, offset + data.size(), offset + data.size() < size };
}

RemoteLogUploader::LogPayload RemoteLogUploader::payloadFromBytes(const QString &kind, const QByteArray &data)
{
    const qint64 size = data.size();
    const QString key = payloadDedupeKey(kind);
    LogCursor cursor = m_logCursors.value(key);
    qint64 offset = cursor.offset;
    if (offset < 0 || offset > size) {
        offset = initialOffset(size);
    }
    if (offset >= size) {
        return {};
    }

    const QByteArray payload = data.mid(offset, maxPayloadBytes);
    if (payload.isEmpty()) {
        return {};
    }

    return { kind, payload, key, QString(), offset + payload.size(), offset + payload.size() < size };
}

QList<RemoteLogUploader::LogPayload> RemoteLogUploader::collectPayloads()
{
    QList<LogPayload> payloads;

#ifdef Q_OS_ANDROID
    const LogPayload payload = payloadFromBytes(QStringLiteral("android"), AndroidController::instance()->getLogs().toUtf8());
    if (!payload.data.isEmpty()) {
        payloads.append(payload);
    }
#elif defined(Q_OS_IOS) || defined(MACOS_NE)
    const LogPayload payload = payloadFromBytes(QStringLiteral("client"), Logger::getLogFile().toUtf8());
    if (!payload.data.isEmpty()) {
        payloads.append(payload);
    }
#else
    const LogPayload clientLog = payloadFromFile(QStringLiteral("client"), Logger::userLogsFilePath());
    if (!clientLog.data.isEmpty()) {
        payloads.append(clientLog);
    }

    const LogPayload serviceLog = payloadFromFile(QStringLiteral("service"), Logger::serviceLogsFilePath());
    if (!serviceLog.data.isEmpty()) {
        payloads.append(serviceLog);
    }
#endif

    return payloads;
}

void RemoteLogUploader::bootstrapCurrentTarget()
{
    if (!m_currentTarget.bootstrap || m_currentTarget.clientId.isEmpty()) {
        return;
    }
    if (m_bootstrapInProgress) {
        m_uploadRequested = true;
        return;
    }

    m_bootstrapInProgress = true;
    QNetworkRequest request{QUrl(amnezia::clientLogsUtils::bootstrapEndpoint())};
    request.setTransferTimeout(uploadTimeoutMs);
    request.setRawHeader("X-Amnezia-Client-Id", m_currentTarget.clientId.toUtf8());
    if (m_appSettingsRepository) {
        request.setRawHeader("X-Amnezia-Installation-Id", m_appSettingsRepository->getInstallationUuid(true).toUtf8());
    }

    QNetworkReply *reply = m_networkAccessManager.post(request, QByteArray());
    connect(reply, &QNetworkReply::finished, this, [this, reply, target = m_currentTarget]() {
        const int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool networkOk = reply->error() == QNetworkReply::NoError && statusCode >= 200 && statusCode < 300;
        bool tokenStored = false;
        if (networkOk) {
            const QByteArray response = reply->read(maxBootstrapResponseBytes + 1);
            if (response.size() > maxBootstrapResponseBytes) {
                logger.warning() << "Bootstrap response is too large" << target.serverId << target.clientId;
            }
            const QJsonDocument document = response.size() > maxBootstrapResponseBytes
                    ? QJsonDocument() : QJsonDocument::fromJson(response);
            const QJsonObject clientLogs = document.object();
            const QString endpoint = clientLogs.value(amnezia::configKey::clientLogsEndpoint).toString();
            const QString clientId = clientLogs.value(amnezia::configKey::clientLogsClientId).toString();
            const QString token = clientLogs.value(amnezia::configKey::clientLogsToken).toString();
            if (endpoint == target.endpoint && clientId == target.clientId && !token.isEmpty() && m_appSettingsRepository) {
                m_appSettingsRepository->setRemoteLogToken(target.tokenCacheKey, token);
                tokenStored = true;
            }
        }
        if (!tokenStored) {
            logger.warning() << "Bootstrap failed"
                             << target.serverId
                             << amnezia::clientLogsUtils::bootstrapEndpoint()
                             << target.clientId
                             << static_cast<uint64_t>(reply->error())
                             << static_cast<uint64_t>(statusCode)
                             << reply->errorString();
        }
        reply->deleteLater();
        const bool runAgain = tokenStored || m_uploadRequested;
        m_uploadRequested = false;
        m_bootstrapInProgress = false;
        if (runAgain) {
            QTimer::singleShot(0, this, &RemoteLogUploader::uploadNow);
        }
    });
}

void RemoteLogUploader::postNext()
{
    if (m_pendingPayloads.isEmpty()) {
        finishUpload();
        return;
    }

    if (!sameTarget(findUploadTarget(), m_currentTarget)) {
        m_pendingPayloads.clear();
        finishUpload();
        return;
    }

    const LogPayload payload = m_pendingPayloads.takeFirst();
    QNetworkRequest request(QUrl(m_currentTarget.endpoint));
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("text/plain; charset=utf-8"));
    request.setTransferTimeout(uploadTimeoutMs);
    request.setRawHeader("X-Amnezia-Client-Id", m_currentTarget.clientId.toUtf8());
    request.setRawHeader("X-Amnezia-Log-Token", m_currentTarget.token.toUtf8());
    request.setRawHeader("X-Amnezia-Log-Kind", payload.kind.toUtf8());
    if (m_appSettingsRepository) {
        request.setRawHeader("X-Amnezia-Installation-Id", m_appSettingsRepository->getInstallationUuid(true).toUtf8());
    }

    QNetworkReply *reply = m_networkAccessManager.post(request, payload.data);
    connect(reply, &QNetworkReply::finished, this, [this, reply, payload]() {
        const int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool ok = reply->error() == QNetworkReply::NoError && statusCode >= 200 && statusCode < 300;
        if (ok) {
            m_logCursors.insert(payload.offsetKey, { payload.nextOffset, payload.fingerprint });
            if (payload.hasMore) {
                m_uploadRequested = true;
            }
        } else {
            if (statusCode == 403 && m_currentTarget.bootstrap && m_appSettingsRepository
                && (!m_nextTokenRefreshAt.isValid() || QDateTime::currentDateTimeUtc() >= m_nextTokenRefreshAt)) {
                m_appSettingsRepository->clearRemoteLogToken(m_currentTarget.tokenCacheKey);
                m_nextTokenRefreshAt = QDateTime::currentDateTimeUtc().addMSecs(uploadIntervalMs);
                m_uploadRequested = true;
            }
            logger.warning() << "Upload failed"
                             << m_currentTarget.serverId
                             << m_currentTarget.endpoint
                             << payload.kind
                             << m_currentTarget.clientId
                             << static_cast<uint64_t>(reply->error())
                             << static_cast<uint64_t>(statusCode)
                             << reply->errorString();
        }
        reply->deleteLater();
        postNext();
    });
}

void RemoteLogUploader::finishUpload()
{
    const bool runAgain = m_uploadRequested;
    m_uploadRequested = false;
    m_uploadInProgress = false;
    if (runAgain) {
        QTimer::singleShot(0, this, &RemoteLogUploader::uploadNow);
    }
}
