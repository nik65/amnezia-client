#include "remoteLogUploader.h"

#include <QCryptographicHash>
#include <QFile>
#include <QFileDevice>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRandomGenerator>
#include <QSettings>
#include <QUrl>

#include <optional>
#include <utility>

#include "core/repositories/secureAppSettingsRepository.h"
#include "core/repositories/secureServersRepository.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/boundedQueuedSnapshot.h"
#include "core/utils/remoteLogBatchHealth.h"
#include "core/utils/remoteLogSanitizer.h"
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
    constexpr int vpnSnapshotTimeoutMs = 750;
    constexpr int healthRefreshIntervalMs = 60 * 1000;
    constexpr int staleAfterMs = 5 * 60 * 1000;
    constexpr int initialRetryDelayMs = 5 * 1000;
    constexpr int maxRetryDelayMs = 5 * 60 * 1000;
    constexpr int retryJitterPercent = 20;
    constexpr int stateScanYieldMs = 25;
    constexpr qint64 maxPayloadBytes = 15 * 1024 * 1024;
    constexpr qint64 maxBootstrapResponseBytes = 4096;
    constexpr qint64 fingerprintSampleBytes = 64 * 1024;
    constexpr qint64 cursorAnchorBytes = 4096;
    constexpr qint64 stateScanBytesPerTick = 1024 * 1024;
    constexpr int streamStateVersion = 2;
    constexpr int retrySanitizerMarkerVersion = 3;
    constexpr int maximumRetrySanitizerMarkers = 16;
    constexpr auto cursorSettingsPrefix = "Runtime/remoteLogUploader/cursors/";
    constexpr auto targetSettingsPrefix = "Runtime/remoteLogUploader/targets/";
    constexpr auto retryMarkerSettingsPrefix = "Runtime/remoteLogUploader/retryMarkers/";
    constexpr auto retryMarkerIndexKey = "Runtime/remoteLogUploader/retryMarkerIndex";
    constexpr auto retryMarkerOverflowFailClosedKey =
            "Runtime/remoteLogUploader/retryMarkerOverflowFailClosed";

    QString errorCategoryName(RemoteLogUploader::ErrorCategory category)
    {
        switch (category) {
        case RemoteLogUploader::ErrorCategory::None:
            return QStringLiteral("none");
        case RemoteLogUploader::ErrorCategory::Configuration:
            return QStringLiteral("configuration");
        case RemoteLogUploader::ErrorCategory::Bootstrap:
            return QStringLiteral("bootstrap");
        case RemoteLogUploader::ErrorCategory::Authentication:
            return QStringLiteral("authentication");
        case RemoteLogUploader::ErrorCategory::Network:
            return QStringLiteral("network");
        case RemoteLogUploader::ErrorCategory::Timeout:
            return QStringLiteral("timeout");
        case RemoteLogUploader::ErrorCategory::Server:
            return QStringLiteral("server");
        case RemoteLogUploader::ErrorCategory::Source:
            return QStringLiteral("source");
        }
        return QStringLiteral("unknown");
    }

    qint64 initialOffset(qint64 size)
    {
        return size > maxPayloadBytes ? size - maxPayloadBytes : 0;
    }

    QString fileFingerprint(QFile &file, qint64 sampleBytes)
    {
        const QFileDevice::FileTime birthTime = QFileDevice::FileBirthTime;
        const QDateTime created = file.fileTime(birthTime);
        const qint64 originalPosition = file.pos();
        file.seek(0);
        const QByteArray head = file.read(sampleBytes);
        file.seek(originalPosition);
        QFileInfo fileInfo(file.fileName());
        QString stablePath = fileInfo.canonicalFilePath();
        if (stablePath.isEmpty()) {
            stablePath = fileInfo.absoluteFilePath();
        }
        QByteArray fingerprintMaterial = stablePath.toUtf8();
        fingerprintMaterial.append(':');
        fingerprintMaterial.append(QByteArray::number(created.isValid() ? created.toMSecsSinceEpoch() : 0));
        fingerprintMaterial.append(':');
        fingerprintMaterial.append(head);
        return QString::fromLatin1(QCryptographicHash::hash(fingerprintMaterial, QCryptographicHash::Sha256).toHex());
    }

    QString bytesFingerprint(const QByteArray &data, qint64 sampleBytes)
    {
        return QString::fromLatin1(
                QCryptographicHash::hash(data.left(sampleBytes), QCryptographicHash::Sha256).toHex());
    }

    QString bytesAnchor(const QByteArray &data, qint64 offset)
    {
        if (offset <= 0 || offset > data.size()) {
            return {};
        }
        const qint64 anchorOffset = qMax<qint64>(0, offset - cursorAnchorBytes);
        return QString::fromLatin1(QCryptographicHash::hash(
                data.mid(anchorOffset, offset - anchorOffset), QCryptographicHash::Sha256).toHex());
    }

    QString fileAnchor(QFile &file, qint64 offset)
    {
        if (offset <= 0 || offset > file.size()) {
            return {};
        }
        const qint64 originalPosition = file.pos();
        const qint64 anchorOffset = qMax<qint64>(0, offset - cursorAnchorBytes);
        if (!file.seek(anchorOffset)) {
            file.seek(originalPosition);
            return {};
        }
        const QByteArray anchorData = file.read(offset - anchorOffset);
        file.seek(originalPosition);
        if (anchorData.size() != offset - anchorOffset) {
            return {};
        }
        return QString::fromLatin1(QCryptographicHash::hash(anchorData, QCryptographicHash::Sha256).toHex());
    }

    QString persistentCursorId(const QString &key)
    {
        return QString::fromLatin1(QCryptographicHash::hash(key.toUtf8(), QCryptographicHash::Sha256).toHex());
    }

    QString persistentTargetId(const QString &key)
    {
        return QString::fromLatin1(QCryptographicHash::hash(key.toUtf8(), QCryptographicHash::Sha256).toHex());
    }

    bool isSha256Hex(const QString &value)
    {
        if (value.size() != 64) {
            return false;
        }
        for (const QChar character : value) {
            const ushort code = character.unicode();
            if (!((code >= '0' && code <= '9') || (code >= 'a' && code <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    bool readRetryMarkerIndex(QSettings &settings, QStringList &order,
                              bool &globalFailClosed)
    {
        settings.sync();
        if (settings.status() != QSettings::NoError) {
            return false;
        }
        const QVariant tombstone = settings.value(
                QLatin1String(retryMarkerOverflowFailClosedKey));
        if (tombstone.isValid() && !tombstone.canConvert<bool>()) {
            return false;
        }
        globalFailClosed = tombstone.toBool();

        const QVariant index = settings.value(QLatin1String(retryMarkerIndexKey));
        if (index.isValid() && !index.canConvert<QStringList>()) {
            return false;
        }
        const QStringList storedOrder = index.toStringList();
        for (const QString &entry : storedOrder) {
            if (!isSha256Hex(entry) || order.contains(entry)
                || order.size() >= maximumRetrySanitizerMarkers) {
                return false;
            }
            order.append(entry);
        }
        return true;
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

    void updatePrivateKeyLookbehind(QByteArray &lookbehind, const QByteArray &block)
    {
        if (block.size() >= amnezia::remoteLogSanitizer::MaximumPrivateKeyMarkerBytes) {
            lookbehind = block.right(amnezia::remoteLogSanitizer::MaximumPrivateKeyMarkerBytes);
        } else {
            lookbehind = (lookbehind + block).right(
                    amnezia::remoteLogSanitizer::MaximumPrivateKeyMarkerBytes);
        }
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

    m_retryTimer.setSingleShot(true);
    connect(&m_retryTimer, &QTimer::timeout, this, [this]() {
        setNextRetryAt({});
        uploadNow();
    });

    m_healthTimer.setInterval(healthRefreshIntervalMs);
    connect(&m_healthTimer, &QTimer::timeout, this, &RemoteLogUploader::refreshStaleness);

    if (m_serversRepository) {
        connect(m_serversRepository, &SecureServersRepository::serverAdded, this, [this](const QString &) { retryNow(); });
        connect(m_serversRepository, &SecureServersRepository::serverEdited, this, [this](const QString &) { retryNow(); });
    }

    if (m_vpnConnection) {
        connect(m_vpnConnection, &VpnConnection::connectionContextChanged, this,
                [this](const QString &, const QString &, quint64) {
                    ++m_connectionContextGeneration;
                    retryNow();
                },
                Qt::QueuedConnection);
    }
}

RemoteLogUploader::State RemoteLogUploader::state() const
{
    return m_state;
}

QDateTime RemoteLogUploader::lastSuccess() const
{
    return m_lastSuccess;
}

qint64 RemoteLogUploader::pendingBytes() const
{
    return m_pendingBytes;
}

RemoteLogUploader::ErrorCategory RemoteLogUploader::lastErrorCategory() const
{
    return m_lastErrorCategory;
}

QDateTime RemoteLogUploader::nextRetryAt() const
{
    return m_nextRetryAt;
}

bool RemoteLogUploader::sameTarget(const UploadTarget &left, const UploadTarget &right)
{
    return left.endpoint == right.endpoint
           && left.clientId == right.clientId
           && left.token == right.token
           && left.serverId == right.serverId
           && left.bootstrap == right.bootstrap;
}

QString RemoteLogUploader::targetIdentity(const UploadTarget &target) const
{
    QByteArray canonical = QByteArrayLiteral("amnezia-remote-log-target-v1");
    canonical.append('\0');
    canonical.append(target.serverId.toUtf8());
    canonical.append('\0');
    canonical.append(target.endpoint.toUtf8());
    canonical.append('\0');
    canonical.append(target.clientId.toUtf8());
    canonical.append('\0');
    if (m_appSettingsRepository) {
        canonical.append(m_appSettingsRepository->getInstallationUuid(true).trimmed().toLower().toUtf8());
    }
    return QString::fromLatin1(QCryptographicHash::hash(canonical, QCryptographicHash::Sha256).toHex());
}

void RemoteLogUploader::activateTargetHealth(const UploadTarget &target)
{
    const QString targetId = targetIdentity(target);
    if (targetId == m_healthTargetId) {
        return;
    }

    m_healthTargetId = targetId;
    m_nextTokenRefreshAt = {};
    QSettings settings;
    settings.sync();
    if (settings.status() != QSettings::NoError) {
        m_retryPersistenceFailClosed = true;
    }
    const QString settingsPrefix = QLatin1String(targetSettingsPrefix) + persistentTargetId(targetId) + QLatin1Char('/');
    const QDateTime lastSuccess = settings.value(settingsPrefix + QStringLiteral("lastSuccess")).toDateTime().toUTC();
    if (settings.contains(settingsPrefix + QStringLiteral("lastSuccess"))
        && !lastSuccess.isValid()) {
        m_retryPersistenceFailClosed = true;
    }
    if (m_lastSuccess != lastSuccess) {
        m_lastSuccess = lastSuccess;
        emit lastSuccessChanged();
    }
    setLastErrorCategory(ErrorCategory::None);
}

QString RemoteLogUploader::batchIdForPayload(const LogPayload &payload) const
{
    QByteArray canonical = targetIdentity(m_currentTarget).toUtf8();
    canonical.append('\0');
    canonical.append(payload.kind.toUtf8());
    canonical.append('\0');
    QByteArray payloadFingerprint = payload.fingerprint.toUtf8();
    payloadFingerprint.append(':');
    payloadFingerprint.append(QCryptographicHash::hash(payload.data, QCryptographicHash::Sha256).toHex());
    canonical.append(payloadFingerprint);
    canonical.append('\0');
    canonical.append(QByteArray::number(payload.offset));
    canonical.append('\0');
    canonical.append(QByteArray::number(payload.data.size()));
    canonical.append('\0');
    canonical.append(QByteArray::number(payload.sourceBytes));
    return QString::fromLatin1(QCryptographicHash::hash(canonical, QCryptographicHash::Sha256).toHex());
}

void RemoteLogUploader::start()
{
    if (m_started) {
        return;
    }
    m_started = true;
    if (!m_uploadTimer.isActive()) {
        m_uploadTimer.start();
    }
    m_healthTimer.start();
    QTimer::singleShot(initialUploadDelayMs, this, &RemoteLogUploader::uploadNow);
}

void RemoteLogUploader::retryNow()
{
    clearRetry();
    if (m_uploadInProgress || m_bootstrapInProgress || m_snapshotPending) {
        m_uploadRequested = true;
        return;
    }
    QTimer::singleShot(0, this, &RemoteLogUploader::uploadNow);
}

void RemoteLogUploader::uploadNow()
{
    if (m_retryTimer.isActive() && QDateTime::currentDateTimeUtc() < m_nextRetryAt) {
        return;
    }
    if (m_uploadInProgress || m_bootstrapInProgress || m_snapshotPending) {
        m_uploadRequested = true;
        return;
    }

    m_snapshotPending = true;
    ++m_snapshotGeneration;
    if (m_snapshotGeneration == 0) {
        ++m_snapshotGeneration;
    }
    const quint64 generation = m_snapshotGeneration;
    const quint64 connectionContextGeneration = m_connectionContextGeneration;
    requestBoundedQueuedSnapshot(
            m_vpnConnection, this, vpnSnapshotTimeoutMs,
            [](VpnConnection *vpnConnection) {
                ConnectionSnapshot snapshot;
                snapshot.state = vpnConnection->connectionState();
                snapshot.serverId = vpnConnection->serverId();
                snapshot.container = vpnConnection->container();
                return snapshot;
            },
            [this, generation, connectionContextGeneration](
                    BoundedQueuedSnapshotStatus status,
                    std::optional<ConnectionSnapshot> snapshot) {
                if (generation != m_snapshotGeneration) {
                    return;
                }
                m_snapshotPending = false;
                const bool rerunRequested = m_uploadRequested;
                m_uploadRequested = false;
                if (connectionContextGeneration != m_connectionContextGeneration) {
                    m_pendingPayloads.clear();
                    setPendingBytes(0);
                    QTimer::singleShot(0, this, &RemoteLogUploader::uploadNow);
                    return;
                }
                if (status != BoundedQueuedSnapshotStatus::Ready || !snapshot.has_value()) {
                    m_pendingPayloads.clear();
                    setPendingBytes(0);
                    recordFailure(ErrorCategory::Timeout);
                    if (rerunRequested) {
                        QTimer::singleShot(0, this, &RemoteLogUploader::retryNow);
                    }
                    return;
                }
                m_currentConnectionContextGeneration = connectionContextGeneration;
                uploadWithSnapshot(snapshot.value());
                if (rerunRequested) {
                    QTimer::singleShot(0, this, &RemoteLogUploader::uploadNow);
                }
            });
}

void RemoteLogUploader::uploadWithSnapshot(const ConnectionSnapshot &snapshot)
{
    if (snapshot.state != Vpn::ConnectionState::Connected) {
        m_pendingPayloads.clear();
        setPendingBytes(0);
        clearRetry();
        m_consecutiveFailures = 0;
        setState(State::WaitingForVpn);
        return;
    }

    m_currentConnectionSnapshot = snapshot;
    m_currentTarget = findUploadTarget(snapshot);
    if (m_currentTarget.endpoint.isEmpty() || m_currentTarget.clientId.isEmpty()) {
        m_pendingPayloads.clear();
        setPendingBytes(0);
        clearRetry();
        m_consecutiveFailures = 0;
        setLastErrorCategory(ErrorCategory::Configuration);
        setState(State::TargetMissing);
        return;
    }
    activateTargetHealth(m_currentTarget);
    if (m_currentTarget.token.isEmpty()) {
        if (m_currentTarget.bootstrap) {
            const QDateTime now = QDateTime::currentDateTimeUtc();
            if (m_nextTokenRefreshAt.isValid() && now < m_nextTokenRefreshAt) {
                const int delay = static_cast<int>(qBound<qint64>(
                        qint64 { 1000 }, now.msecsTo(m_nextTokenRefreshAt), qint64 { uploadIntervalMs }));
                setNextRetryAt(now.addMSecs(delay));
                m_retryTimer.start(delay);
                return;
            }
            m_nextTokenRefreshAt = {};
            bootstrapCurrentTarget();
        } else {
            setState(State::TargetMissing);
        }
        return;
    }

    m_batchHadFailure = false;
    m_pendingPayloads = collectPayloads();
    if (m_retryPersistenceFailClosed || m_collectionPrivacyQuarantined
        || m_collectionWholeRedactionUsed) {
        recordFailure(ErrorCategory::Source);
    }
    if (!m_collectionAllExpectedSourcesReadable
        && !m_collectionHasPendingStateScan) {
        recordFailure(ErrorCategory::Source);
        if (m_pendingPayloads.isEmpty()) {
            setPendingBytes(0);
            return;
        }
    }
    qint64 pendingBytes = 0;
    for (const LogPayload &payload : std::as_const(m_pendingPayloads)) {
        pendingBytes += payload.remainingBytes;
    }
    setPendingBytes(pendingBytes);
    if (m_collectionHasPendingStateScan) {
        if (m_pendingPayloads.isEmpty()) {
            setState(State::Uploading);
            QTimer::singleShot(stateScanYieldMs, this, &RemoteLogUploader::uploadNow);
            return;
        }
        m_uploadRequested = true;
    }
    if (m_pendingPayloads.isEmpty()) {
        if (!m_collectionHasReadableSource) {
            recordFailure(ErrorCategory::Source);
            return;
        }
        // An authenticated, idempotent heartbeat is an accepted empty
        // synchronization. It prevents a freshly configured target from being
        // labelled healthy before the collector has actually acknowledged it.
        const QByteArray heartbeat("\n", 1);
        LogPayload heartbeatPayload;
        heartbeatPayload.kind = QStringLiteral("client");
        heartbeatPayload.data = heartbeat;
        heartbeatPayload.fingerprint = bytesFingerprint(
                QByteArrayLiteral("amnezia-empty-sync-v1"), 21);
        heartbeatPayload.fingerprintBytes = 21;
        heartbeatPayload.advancesCursor = false;
        m_pendingPayloads.append(heartbeatPayload);
    }

    m_uploadInProgress = true;
    setState(State::Uploading);
    postNext();
}

QString RemoteLogUploader::payloadDedupeKey(const QString &kind) const
{
    return targetIdentity(m_currentTarget) + QLatin1Char(':') + kind;
}

RemoteLogUploader::LogCursor RemoteLogUploader::cursorForKey(const QString &key)
{
    const auto existing = m_logCursors.constFind(key);
    if (existing != m_logCursors.constEnd()) {
        return existing.value();
    }

    LogCursor cursor;
    QSettings settings;
    settings.sync();
    if (settings.status() != QSettings::NoError) {
        cursor.persistenceReadable = false;
        m_retryPersistenceFailClosed = true;
        m_logCursors.insert(key, cursor);
        return cursor;
    }
    const QString cursorPrefix = QLatin1String(cursorSettingsPrefix) + persistentCursorId(key) + QLatin1Char('/');
    const bool cursorMetadataPresent = settings.contains(cursorPrefix + QStringLiteral("offset"))
            || settings.contains(cursorPrefix + QStringLiteral("fingerprint"));
    cursor.offset = settings.value(cursorPrefix + QStringLiteral("offset"), -1).toLongLong();
    cursor.fingerprint = settings.value(cursorPrefix + QStringLiteral("fingerprint")).toString();
    cursor.fingerprintBytes = settings.value(cursorPrefix + QStringLiteral("fingerprintBytes"), 0).toLongLong();
    cursor.anchor = settings.value(cursorPrefix + QStringLiteral("anchor")).toString();
    cursor.sanitizerSecretSetSha256 = settings.value(
            cursorPrefix + QStringLiteral("sanitizerSecretSetSha256")).toString();
    if (!cursor.sanitizerSecretSetSha256.isEmpty()
        && !isSha256Hex(cursor.sanitizerSecretSetSha256)) {
        cursor.persistenceReadable = false;
        m_retryPersistenceFailClosed = true;
    }
    const bool cursorMetadataValid = cursor.offset >= 0
            && isSha256Hex(cursor.fingerprint)
            && cursor.fingerprintBytes > 0
            && cursor.fingerprintBytes <= fingerprintSampleBytes
            && ((cursor.offset == 0 && cursor.anchor.isEmpty())
                || (cursor.offset > 0 && isSha256Hex(cursor.anchor)));
    if (cursorMetadataPresent && !cursorMetadataValid) {
        cursor.persistenceReadable = false;
        m_retryPersistenceFailClosed = true;
    }
    const int blockKind = settings.value(
            cursorPrefix + QStringLiteral("streamStateBlockKind"), 0).toInt();
    const qint64 arrayDepth = settings.value(
            cursorPrefix + QStringLiteral("streamStateArrayDepth"), 0).toLongLong();
    const QString arrayQuote = settings.value(
            cursorPrefix + QStringLiteral("streamStateArrayQuote")).toString();
    const int pendingKind = settings.value(
            cursorPrefix + QStringLiteral("streamStatePendingKind"), 0).toInt();
    const int pendingPhase = settings.value(
            cursorPrefix + QStringLiteral("streamStatePendingPhase"), 0).toInt();
    const qint64 pendingWhitespaceBytes = settings.value(
            cursorPrefix + QStringLiteral("streamStatePendingWhitespaceBytes"), 0).toLongLong();
    const bool blockKindValid = blockKind >= static_cast<int>(
            amnezia::remoteLogSanitizer::SecretBlockKind::None)
            && blockKind <= static_cast<int>(
                    amnezia::remoteLogSanitizer::SecretBlockKind::TlsCrypt);
    const bool arrayStateValid = arrayDepth >= 0 && arrayDepth <= maxPayloadBytes
            && (arrayQuote.isEmpty() || arrayQuote == QStringLiteral("\"")
                || arrayQuote == QStringLiteral("'"));
    const bool pendingKindValid = pendingKind >= static_cast<int>(
            amnezia::remoteLogSanitizer::PendingSecretKind::None)
            && pendingKind <= static_cast<int>(
                    amnezia::remoteLogSanitizer::PendingSecretKind::Array);
    const bool pendingPhaseValid = pendingPhase >= static_cast<int>(
            amnezia::remoteLogSanitizer::PendingSecretPhase::None)
            && pendingPhase <= static_cast<int>(
                    amnezia::remoteLogSanitizer::PendingSecretPhase::RedactingValue);
    const bool pendingWhitespaceValid = pendingWhitespaceBytes >= 0
            && pendingWhitespaceBytes
                    <= amnezia::remoteLogSanitizer::MaximumPendingSecretWhitespaceBytes;
    cursor.streamStateKnown = settings.value(
            cursorPrefix + QStringLiteral("streamStateVersion"), 0).toInt() == streamStateVersion
            && settings.value(cursorPrefix + QStringLiteral("streamStateOffset"), -1).toLongLong()
                    == cursor.offset
            && blockKindValid && arrayStateValid && pendingKindValid
            && pendingPhaseValid && pendingWhitespaceValid;
    if (cursor.streamStateKnown) {
        cursor.streamState.blockKind = static_cast<
                amnezia::remoteLogSanitizer::SecretBlockKind>(blockKind);
        cursor.streamState.secretArrayOpen = settings.value(
                cursorPrefix + QStringLiteral("streamStateArrayOpen"), false).toBool();
        cursor.streamState.secretArrayDepth = arrayDepth;
        cursor.streamState.secretArrayQuote = arrayQuote.isEmpty()
                ? QChar() : arrayQuote.front();
        cursor.streamState.secretArrayEscaped = settings.value(
                cursorPrefix + QStringLiteral("streamStateArrayEscaped"), false).toBool();
        cursor.streamState.pendingSecretKind = static_cast<
                amnezia::remoteLogSanitizer::PendingSecretKind>(pendingKind);
        cursor.streamState.pendingSecretPhase = static_cast<
                amnezia::remoteLogSanitizer::PendingSecretPhase>(pendingPhase);
        cursor.streamState.pendingSecretWhitespaceBytes = pendingWhitespaceBytes;
        const bool pendingOverflow = cursor.streamState.pendingSecretPhase
                        == amnezia::remoteLogSanitizer::PendingSecretPhase::OverflowAwaitingSeparator
                || cursor.streamState.pendingSecretPhase
                        == amnezia::remoteLogSanitizer::PendingSecretPhase::OverflowAwaitingValue;
        const bool pendingStateInactive = cursor.streamState.pendingSecretKind
                        == amnezia::remoteLogSanitizer::PendingSecretKind::None
                && cursor.streamState.pendingSecretPhase
                        == amnezia::remoteLogSanitizer::PendingSecretPhase::None
                && pendingWhitespaceBytes == 0;
        const bool pendingStateActive = cursor.streamState.pendingSecretKind
                        != amnezia::remoteLogSanitizer::PendingSecretKind::None
                && cursor.streamState.pendingSecretPhase
                        != amnezia::remoteLogSanitizer::PendingSecretPhase::None
                && (!pendingOverflow
                    || pendingWhitespaceBytes
                            == amnezia::remoteLogSanitizer::MaximumPendingSecretWhitespaceBytes)
                && (cursor.streamState.pendingSecretPhase
                                != amnezia::remoteLogSanitizer::PendingSecretPhase::RedactingValue
                    || pendingWhitespaceBytes == 0);
        if (cursor.streamState.secretArrayOpen != (arrayDepth > 0)
            || (!cursor.streamState.secretArrayOpen
                && (!cursor.streamState.secretArrayQuote.isNull()
                    || cursor.streamState.secretArrayEscaped))
            || (cursor.streamState.secretArrayOpen && !pendingStateInactive)
            || (!pendingStateInactive && !pendingStateActive)) {
            cursor.streamState = {};
            cursor.streamStateKnown = false;
        }
    }
    const bool streamMetadataPresent = settings.contains(
            cursorPrefix + QStringLiteral("streamStateVersion"));
    if (streamMetadataPresent && !cursor.streamStateKnown) {
        cursor.persistenceReadable = false;
        m_retryPersistenceFailClosed = true;
    }
    m_logCursors.insert(key, cursor);
    return cursor;
}

bool RemoteLogUploader::persistCursor(const QString &key, const LogCursor &cursor) const
{
    QSettings settings;
    const QString cursorPrefix = QLatin1String(cursorSettingsPrefix) + persistentCursorId(key) + QLatin1Char('/');
    settings.setValue(cursorPrefix + QStringLiteral("fingerprint"), cursor.fingerprint);
    settings.setValue(cursorPrefix + QStringLiteral("fingerprintBytes"), cursor.fingerprintBytes);
    settings.setValue(cursorPrefix + QStringLiteral("anchor"), cursor.anchor);
    settings.setValue(cursorPrefix + QStringLiteral("sanitizerSecretSetSha256"),
                      cursor.sanitizerSecretSetSha256);
    settings.setValue(cursorPrefix + QStringLiteral("streamStateVersion"), streamStateVersion);
    settings.setValue(cursorPrefix + QStringLiteral("streamStateBlockKind"),
                      static_cast<int>(cursor.streamState.blockKind));
    settings.setValue(cursorPrefix + QStringLiteral("streamStateArrayOpen"),
                      cursor.streamState.secretArrayOpen);
    settings.setValue(cursorPrefix + QStringLiteral("streamStateArrayDepth"),
                      cursor.streamState.secretArrayDepth);
    settings.setValue(cursorPrefix + QStringLiteral("streamStateArrayQuote"),
                      cursor.streamState.secretArrayQuote.isNull()
                              ? QString() : QString(cursor.streamState.secretArrayQuote));
    settings.setValue(cursorPrefix + QStringLiteral("streamStateArrayEscaped"),
                      cursor.streamState.secretArrayEscaped);
    settings.setValue(cursorPrefix + QStringLiteral("streamStatePendingKind"),
                      static_cast<int>(cursor.streamState.pendingSecretKind));
    settings.setValue(cursorPrefix + QStringLiteral("streamStatePendingPhase"),
                      static_cast<int>(cursor.streamState.pendingSecretPhase));
    settings.setValue(cursorPrefix + QStringLiteral("streamStatePendingWhitespaceBytes"),
                      cursor.streamState.pendingSecretWhitespaceBytes);
    settings.setValue(cursorPrefix + QStringLiteral("streamStateOffset"), cursor.offset);
    settings.setValue(cursorPrefix + QStringLiteral("privateKeyBlockOpen"),
                      cursor.streamState.blockKind
                              == amnezia::remoteLogSanitizer::SecretBlockKind::PrivateKey);
    // Offset is written last and streamStateOffset binds the security state to
    // that exact raw source position after a crash or partial settings write.
    settings.setValue(cursorPrefix + QStringLiteral("offset"), cursor.offset);
    settings.sync();
    return settings.status() == QSettings::NoError;
}

QByteArray RemoteLogUploader::sanitizePayload(const QByteArray &data,
                                              bool startsInsideRecord,
                                              bool endsInsideRecord,
                                              const amnezia::remoteLogSanitizer::StreamState &streamState,
                                              const amnezia::remoteLogSanitizer::StreamBoundary &boundary,
                                              const amnezia::RemoteLogSanitizerSecretSet &sanitizerSecrets,
                                              amnezia::remoteLogSanitizer::StreamState &nextStreamState) const
{
    amnezia::remoteLogSanitizer::ChunkContext context;
    context.startsInsideRecord = startsInsideRecord;
    context.endsInsideRecord = endsInsideRecord;
    context.streamState = streamState;
    context.boundaryBlockKind = boundary.beginBlockKind;
    context.secretBlockEndMarkerCharacters =
            boundary.endBlockMarkerCharactersInInput;
    context.secretArrayStartCharacters =
            boundary.secretArrayStartCharactersInInput;
    context.boundaryPendingSecretKind = boundary.pendingSecretKind;
    context.boundaryPendingSecretPhase = boundary.pendingSecretPhase;
    context.boundaryPendingSecretCharacters =
            boundary.pendingSecretCharactersInInput;
    context.boundaryPendingSecretWhitespaceBytes =
            boundary.pendingSecretWhitespaceBytes;
    const amnezia::remoteLogSanitizer::SanitizedChunk sanitized =
            amnezia::remoteLogSanitizer::sanitize(data, context, sanitizerSecrets.values);
    nextStreamState = sanitized.streamState;
    return sanitizerSecrets.forceRedacted
            ? QByteArrayLiteral("[REDACTED LOG CHUNK]\n") : sanitized.data;
}

QString RemoteLogUploader::sanitizerSecretSetSha256(
        const amnezia::RemoteLogSanitizerSecretSet &secrets) const
{
    QStringList normalized = secrets.values;
    normalized.removeDuplicates();
    normalized.sort(Qt::CaseSensitive);
    QByteArray canonical = secrets.forceRedacted
            ? QByteArrayLiteral("force-redacted-v1")
            : QByteArrayLiteral("bounded-secrets-v1");
    for (const QString &value : std::as_const(normalized)) {
        const QByteArray encoded = value.toUtf8();
        canonical.append('\0');
        canonical.append(QByteArray::number(encoded.size()));
        canonical.append(':');
        canonical.append(encoded);
    }
    return QString::fromLatin1(
            QCryptographicHash::hash(canonical, QCryptographicHash::Sha256).toHex());
}

amnezia::RemoteLogSanitizerSecretSet RemoteLogUploader::currentSanitizerSecrets() const
{
    QStringList currentSecrets;
    if (!m_currentTarget.token.isEmpty()) {
        currentSecrets.append(m_currentTarget.token);
    }
    if (m_appSettingsRepository) {
        const QString installationUuid =
                m_appSettingsRepository->getInstallationUuid(true).trimmed();
        if (!installationUuid.isEmpty()) {
            currentSecrets.append(installationUuid);
            currentSecrets.append(installationUuid.toLower());
            currentSecrets.append(installationUuid.toUpper());
        }
    }
    return amnezia::remoteLogSanitizerSecretUnion({}, currentSecrets);
}

RemoteLogUploader::RetrySanitizerMarker RemoteLogUploader::retrySanitizerMarker(
        const QString &key) const
{
    RetrySanitizerMarker marker;
    const QString binding = persistentCursorId(key);
    const QString prefix = QLatin1String(retryMarkerSettingsPrefix)
            + binding + QLatin1Char('/');
    QSettings settings;
    QStringList order;
    bool globalFailClosed = false;
    if (!readRetryMarkerIndex(settings, order, globalFailClosed) || globalFailClosed) {
        marker.present = true;
        marker.valid = false;
        return marker;
    }
    marker.present = settings.contains(prefix + QStringLiteral("version"))
            || settings.contains(prefix + QStringLiteral("binding"));
    if (!marker.present) {
        if (order.contains(binding)) {
            marker.present = true;
            marker.valid = false;
        }
        return marker;
    }

    if (!order.contains(binding)) {
        marker.valid = false;
        return marker;
    }

    marker.binding = settings.value(prefix + QStringLiteral("binding")).toString();
    marker.fingerprint = settings.value(prefix + QStringLiteral("fingerprint")).toString();
    marker.offset = settings.value(prefix + QStringLiteral("offset"), -1).toLongLong();
    marker.nextOffset = settings.value(prefix + QStringLiteral("nextOffset"), -1).toLongLong();
    marker.highWaterOffset = settings.value(
            prefix + QStringLiteral("highWaterOffset"), -1).toLongLong();
    marker.offsetAnchor = settings.value(prefix + QStringLiteral("offsetAnchor")).toString();
    marker.nextAnchor = settings.value(prefix + QStringLiteral("nextAnchor")).toString();
    marker.sourceRangeSha256 = settings.value(
            prefix + QStringLiteral("sourceRangeSha256")).toString();
    marker.secretSetSha256 = settings.value(
            prefix + QStringLiteral("secretSetSha256")).toString();
    marker.requiresInheritedSecrets = settings.value(
            prefix + QStringLiteral("requiresInheritedSecrets"), true).toBool();
    marker.awaitingStableSource = settings.value(
            prefix + QStringLiteral("awaitingStableSource"), false).toBool();
    marker.confirmationCursorOffset = settings.value(
            prefix + QStringLiteral("confirmationCursorOffset"), -1).toLongLong();
    marker.confirmationCursorAnchor = settings.value(
            prefix + QStringLiteral("confirmationCursorAnchor")).toString();
    const QStringList requiredFields {
        QStringLiteral("version"), QStringLiteral("binding"),
        QStringLiteral("fingerprint"), QStringLiteral("offset"),
        QStringLiteral("nextOffset"), QStringLiteral("highWaterOffset"),
        QStringLiteral("offsetAnchor"), QStringLiteral("nextAnchor"),
        QStringLiteral("sourceRangeSha256"), QStringLiteral("secretSetSha256"),
        QStringLiteral("requiresInheritedSecrets"),
        QStringLiteral("awaitingStableSource"),
        QStringLiteral("confirmationCursorOffset"),
        QStringLiteral("confirmationCursorAnchor")
    };
    bool fieldsPresent = true;
    for (const QString &field : requiredFields) {
        fieldsPresent = fieldsPresent && settings.contains(prefix + field);
    }
    const bool offsetAnchorValid = (marker.offset == 0 && marker.offsetAnchor.isEmpty())
            || (marker.offset > 0 && isSha256Hex(marker.offsetAnchor));
    const bool nextAnchorValid = (marker.nextOffset == 0 && marker.nextAnchor.isEmpty())
            || (marker.nextOffset > 0 && isSha256Hex(marker.nextAnchor));
    const bool confirmationCursorValid = marker.awaitingStableSource
            ? marker.confirmationCursorOffset >= 0
                    && marker.confirmationCursorOffset <= marker.highWaterOffset
                    && ((marker.confirmationCursorOffset == 0
                         && marker.confirmationCursorAnchor.isEmpty())
                        || (marker.confirmationCursorOffset > 0
                            && isSha256Hex(marker.confirmationCursorAnchor)))
            : marker.confirmationCursorOffset == -1
                    && marker.confirmationCursorAnchor.isEmpty();
    marker.valid = fieldsPresent
            && settings.value(prefix + QStringLiteral("version"), 0).toInt()
            == retrySanitizerMarkerVersion
            && marker.binding == binding
            && isSha256Hex(marker.fingerprint)
            && marker.offset >= 0 && marker.nextOffset >= marker.offset
            && marker.highWaterOffset >= marker.nextOffset
            && offsetAnchorValid && nextAnchorValid
            && isSha256Hex(marker.sourceRangeSha256)
            && isSha256Hex(marker.secretSetSha256)
            && marker.requiresInheritedSecrets
            && confirmationCursorValid;
    return marker;
}

bool RemoteLogUploader::persistRetrySanitizerMarker(
        const QString &key, const RetrySanitizerMarker &marker) const
{
    const QString binding = persistentCursorId(key);
    const QString prefix = QLatin1String(retryMarkerSettingsPrefix)
            + binding + QLatin1Char('/');
    QSettings settings;
    QStringList order;
    bool globalFailClosed = false;
    if (!readRetryMarkerIndex(settings, order, globalFailClosed) || globalFailClosed) {
        return false;
    }
    const auto capacityDecision = amnezia::remoteLogRetryMarkerCapacityDecision(
            order.size(), maximumRetrySanitizerMarkers, order.contains(binding),
            globalFailClosed, amnezia::RemoteLogPersistenceStatus::Healthy);
    if (capacityDecision
        == amnezia::RemoteLogRetryMarkerCapacityDecision::GlobalFailClosed) {
        // Never evict unresolved privacy evidence. A single bounded global
        // tombstone makes every future range fail closed until operator repair.
        settings.setValue(QLatin1String(retryMarkerOverflowFailClosedKey), true);
        settings.sync();
        return false;
    }

    settings.setValue(prefix + QStringLiteral("version"), retrySanitizerMarkerVersion);
    settings.setValue(prefix + QStringLiteral("binding"), binding);
    settings.setValue(prefix + QStringLiteral("fingerprint"), marker.fingerprint);
    settings.setValue(prefix + QStringLiteral("offset"), marker.offset);
    settings.setValue(prefix + QStringLiteral("nextOffset"), marker.nextOffset);
    settings.setValue(prefix + QStringLiteral("highWaterOffset"), marker.highWaterOffset);
    settings.setValue(prefix + QStringLiteral("offsetAnchor"), marker.offsetAnchor);
    settings.setValue(prefix + QStringLiteral("nextAnchor"), marker.nextAnchor);
    settings.setValue(prefix + QStringLiteral("sourceRangeSha256"), marker.sourceRangeSha256);
    settings.setValue(prefix + QStringLiteral("secretSetSha256"), marker.secretSetSha256);
    settings.setValue(prefix + QStringLiteral("requiresInheritedSecrets"), true);
    settings.setValue(prefix + QStringLiteral("awaitingStableSource"),
                      marker.awaitingStableSource);
    settings.setValue(prefix + QStringLiteral("confirmationCursorOffset"),
                      marker.confirmationCursorOffset);
    settings.setValue(prefix + QStringLiteral("confirmationCursorAnchor"),
                      marker.confirmationCursorAnchor);
    order.removeAll(binding);
    order.append(binding);
    settings.setValue(QLatin1String(retryMarkerIndexKey), order);
    settings.sync();
    return settings.status() == QSettings::NoError;
}

bool RemoteLogUploader::reconcileRetrySanitizerTransition(
        const QString &key, const QString &fingerprint,
        qint64 capturedSize, qint64 sourceOffset,
        const QString &offsetAnchor, qint64 nextOffset,
        const QString &nextAnchor, const QString &sourceRangeSha256,
        const LogCursor &cursor, bool cursorMatchesSource,
        const QString &currentSecretSetSha256)
{
    RetrySanitizerMarker marker = retrySanitizerMarker(key);
    if (!marker.present
        && cursor.sanitizerSecretSetSha256 == currentSecretSetSha256) {
        return false;
    }

    const qint64 durableCursorOffset = marker.present ? cursor.offset : sourceOffset;
    const bool markerCursorMatches = !marker.present
            || !marker.awaitingStableSource
            || (marker.confirmationCursorOffset == cursor.offset
                && marker.confirmationCursorAnchor == cursor.anchor);
    const bool markerCursorIsAhead = marker.present
            && marker.awaitingStableSource
            && marker.confirmationCursorOffset > cursor.offset;
    const bool markerRangeStartsAtCursor = !marker.present
            || marker.awaitingStableSource
            || (marker.offset == cursor.offset && marker.offsetAnchor == cursor.anchor);
    const amnezia::RemoteLogSecretTransitionState transitionState {
        marker.present, marker.awaitingStableSource,
        marker.present ? marker.highWaterOffset : qint64 { 0 }
    };
    amnezia::RemoteLogSecretTransitionEvidence evidence;
    evidence.markerValid = !marker.present || marker.valid;
    evidence.sourceIdentityMatches = !marker.present
            || (marker.fingerprint == fingerprint && markerRangeStartsAtCursor);
    evidence.cursorMatchesSource = !marker.present || cursorMatchesSource;
    evidence.markerCursorMatches = markerCursorMatches;
    evidence.markerCursorIsAhead = markerCursorIsAhead;
    evidence.lastAcceptedSecretSetMatches =
            cursor.sanitizerSecretSetSha256 == currentSecretSetSha256;
    evidence.markerSecretSetMatches = !marker.present
            || marker.secretSetSha256 == currentSecretSetSha256;
    evidence.sourceSize = capturedSize;
    evidence.acceptedCursorOffset = durableCursorOffset;
    const amnezia::RemoteLogSecretTransitionResult transition =
            amnezia::remoteLogAdvanceSecretTransition(transitionState, evidence);
    if (transition.globalFailClosed) {
        m_retryPersistenceFailClosed = true;
        m_collectionPrivacyQuarantined = true;
        m_collectionWholeRedactionUsed = true;
        return true;
    }
    if (transition.clearMarker) {
        if (!discardRetrySanitizerSecrets(key)) {
            m_retryPersistenceFailClosed = true;
            m_collectionPrivacyQuarantined = true;
            m_collectionWholeRedactionUsed = true;
            return true;
        }
        return false;
    }

    if (transition.state.present) {
        const qint64 rangeEnd = nextOffset >= sourceOffset ? nextOffset : sourceOffset;
        const QString rangeEndAnchor = nextOffset >= sourceOffset
                ? nextAnchor : offsetAnchor;
        const QString rangeSha256 = sourceRangeSha256.isEmpty()
                ? QString::fromLatin1(QCryptographicHash::hash(
                          QByteArray(), QCryptographicHash::Sha256).toHex())
                : sourceRangeSha256;
        const bool markerChanged = !marker.present || transition.persistMarker
                || marker.fingerprint != fingerprint
                || marker.offset != sourceOffset
                || marker.nextOffset != rangeEnd
                || marker.offsetAnchor != offsetAnchor
                || marker.nextAnchor != rangeEndAnchor
                || marker.sourceRangeSha256 != rangeSha256;
        marker.present = true;
        marker.valid = true;
        marker.binding = persistentCursorId(key);
        marker.fingerprint = fingerprint;
        marker.offset = sourceOffset;
        marker.nextOffset = rangeEnd;
        marker.offsetAnchor = offsetAnchor;
        marker.nextAnchor = rangeEndAnchor;
        marker.sourceRangeSha256 = rangeSha256;
        marker.highWaterOffset = transition.state.highWaterOffset;
        marker.awaitingStableSource = transition.state.awaitingStableSource;
        marker.requiresInheritedSecrets = true;
        if (!marker.awaitingStableSource) {
            marker.confirmationCursorOffset = -1;
            marker.confirmationCursorAnchor.clear();
        }
        if (transition.updateMarkerSecretSet || marker.secretSetSha256.isEmpty()) {
            marker.secretSetSha256 = currentSecretSetSha256;
        }
        if (markerChanged && !persistRetrySanitizerMarker(key, marker)) {
            m_retryPersistenceFailClosed = true;
            m_collectionPrivacyQuarantined = true;
            m_collectionWholeRedactionUsed = true;
            return true;
        }
        m_retrySanitizerKeys.insert(persistentCursorId(key));
        m_collectionPrivacyQuarantined = true;
        m_collectionWholeRedactionUsed = true;
        return true;
    }
    return false;
}

amnezia::RemoteLogSanitizerSecretSet RemoteLogUploader::sanitizerSecretsForPayload(
        const QString &key, const QString &fingerprint, qint64 offset,
        const QString &offsetAnchor, const QString &sourceRangeSha256,
        qint64 nextOffset, const QString &nextAnchor, qint64 sourceSize,
        const LogCursor &cursor, bool cursorMatchesSource,
        QString *currentSecretSetSha256Out)
{
    const amnezia::RemoteLogSanitizerSecretSet current = currentSanitizerSecrets();
    const QString currentSecretSetSha256 = sanitizerSecretSetSha256(current);
    if (currentSecretSetSha256Out) {
        *currentSecretSetSha256Out = currentSecretSetSha256;
    }
    if (current.forceRedacted) {
        m_collectionWholeRedactionUsed = true;
    }
    if (m_retryPersistenceFailClosed || !cursor.persistenceReadable) {
        m_retryPersistenceFailClosed = true;
        m_collectionPrivacyQuarantined = true;
        m_collectionWholeRedactionUsed = true;
        return { {}, true };
    }
    if (reconcileRetrySanitizerTransition(
                key, fingerprint, sourceSize, offset, offsetAnchor,
                nextOffset, nextAnchor, sourceRangeSha256, cursor,
                cursorMatchesSource, currentSecretSetSha256)) {
        return { {}, true };
    }
    return current;
}

bool RemoteLogUploader::retainRetrySanitizerSecrets(const LogPayload &payload)
{
    if (!payload.advancesCursor || payload.offsetKey.isEmpty()) {
        return true;
    }
    if (!isSha256Hex(payload.currentSecretSetSha256)) {
        m_retryPersistenceFailClosed = true;
        m_collectionPrivacyQuarantined = true;
        m_collectionWholeRedactionUsed = true;
        return false;
    }
    RetrySanitizerMarker marker = retrySanitizerMarker(payload.offsetKey);
    if (marker.present && (!marker.valid || marker.fingerprint != payload.fingerprint)) {
        m_retryPersistenceFailClosed = true;
        m_collectionPrivacyQuarantined = true;
        m_collectionWholeRedactionUsed = true;
        return false;
    }
    marker.present = true;
    marker.valid = true;
    marker.binding = persistentCursorId(payload.offsetKey);
    marker.fingerprint = payload.fingerprint;
    marker.offset = payload.offset;
    marker.nextOffset = payload.nextOffset;
    marker.offsetAnchor = payload.offsetAnchor;
    marker.nextAnchor = payload.nextAnchor;
    marker.sourceRangeSha256 = payload.sourceRangeSha256;
    marker.highWaterOffset = qMax(marker.highWaterOffset, payload.sourceSize);
    marker.secretSetSha256 = payload.currentSecretSetSha256;
    marker.requiresInheritedSecrets = true;
    marker.awaitingStableSource = false;
    marker.confirmationCursorOffset = -1;
    marker.confirmationCursorAnchor.clear();
    if (!persistRetrySanitizerMarker(payload.offsetKey, marker)) {
        m_retryPersistenceFailClosed = true;
        m_collectionPrivacyQuarantined = true;
        m_collectionWholeRedactionUsed = true;
        return false;
    }
    const QString opaqueKey = persistentCursorId(payload.offsetKey);
    if (!m_retrySanitizerKeys.contains(opaqueKey)
        && m_retrySanitizerKeys.size() >= maximumRetrySanitizerMarkers) {
        QSettings settings;
        settings.setValue(QLatin1String(retryMarkerOverflowFailClosedKey), true);
        settings.sync();
        m_retryPersistenceFailClosed = true;
        m_collectionPrivacyQuarantined = true;
        m_collectionWholeRedactionUsed = true;
        return false;
    }
    // Keep only the opaque settings binding in memory. The payload-local raw
    // secrets are neither needed nor retained after the rejected request.
    m_retrySanitizerKeys.insert(opaqueKey);
    m_collectionPrivacyQuarantined = true;
    m_collectionWholeRedactionUsed = true;
    return true;
}

bool RemoteLogUploader::armRetrySanitizerStableSource(
        const LogPayload &payload, const LogCursor &cursor)
{
    RetrySanitizerMarker marker = retrySanitizerMarker(payload.offsetKey);
    if (!marker.present) {
        return true;
    }
    const bool sourceIdentityMatches = marker.valid
            && marker.fingerprint == payload.fingerprint
            && marker.fingerprint == cursor.fingerprint
            && payload.nextOffset == cursor.offset
            && payload.nextAnchor == cursor.anchor;
    const bool secretSetMatches = isSha256Hex(payload.currentSecretSetSha256)
            && payload.currentSecretSetSha256 == marker.secretSetSha256
            && cursor.sanitizerSecretSetSha256 == marker.secretSetSha256;
    const amnezia::RemoteLogSecretTransitionResult armed =
            amnezia::remoteLogArmStableSourceAfterAck(
                    { true, marker.awaitingStableSource, marker.highWaterOffset },
                    marker.valid, sourceIdentityMatches, secretSetMatches,
                    payload.sourceSize, cursor.offset);
    if (armed.globalFailClosed) {
        m_retryPersistenceFailClosed = true;
        m_collectionPrivacyQuarantined = true;
        m_collectionWholeRedactionUsed = true;
        return false;
    }
    marker.highWaterOffset = armed.state.highWaterOffset;
    marker.awaitingStableSource = armed.state.awaitingStableSource;
    marker.confirmationCursorOffset = cursor.offset;
    marker.confirmationCursorAnchor = cursor.anchor;
    if (!persistRetrySanitizerMarker(payload.offsetKey, marker)) {
        m_retryPersistenceFailClosed = true;
        m_collectionPrivacyQuarantined = true;
        m_collectionWholeRedactionUsed = true;
        return false;
    }
    m_retrySanitizerKeys.insert(persistentCursorId(payload.offsetKey));
    m_collectionPrivacyQuarantined = true;
    m_collectionWholeRedactionUsed = true;
    return true;
}

bool RemoteLogUploader::discardRetrySanitizerSecrets(const QString &key)
{
    if (key.isEmpty()) {
        return true;
    }
    const QString binding = persistentCursorId(key);
    QSettings settings;
    QStringList order;
    bool globalFailClosed = false;
    if (!readRetryMarkerIndex(settings, order, globalFailClosed)
        || globalFailClosed) {
        return false;
    }
    settings.remove(QLatin1String(retryMarkerSettingsPrefix) + binding);
    order.removeAll(binding);
    settings.setValue(QLatin1String(retryMarkerIndexKey), order);
    settings.sync();
    if (settings.status() != QSettings::NoError
        || settings.contains(QLatin1String(retryMarkerSettingsPrefix) + binding)
        || settings.value(QLatin1String(retryMarkerIndexKey)).toStringList().contains(binding)) {
        return false;
    }
    m_retrySanitizerKeys.remove(binding);
    return true;
}

bool RemoteLogUploader::advanceFileStateScan(
        QFile &file,
        const QString &key,
        const QString &fingerprint,
        qint64 targetOffset,
        amnezia::remoteLogSanitizer::StreamState &state)
{
    if (targetOffset <= 0) {
        m_stateScans.remove(key);
        state = {};
        return true;
    }

    auto scanIt = m_stateScans.find(key);
    const bool reset = scanIt == m_stateScans.end()
            || scanIt->fingerprint != fingerprint
            || scanIt->targetOffset != targetOffset
            || scanIt->position < 0 || scanIt->position > targetOffset
            || (scanIt->position > 0
                && (scanIt->anchor.isEmpty()
                    || fileAnchor(file, scanIt->position) != scanIt->anchor));
    if (reset) {
        StateScanProgress progress;
        progress.fingerprint = fingerprint;
        progress.targetOffset = targetOffset;
        m_stateScans.insert(key, progress);
        scanIt = m_stateScans.find(key);
    }

    const qint64 requested = qMin(stateScanBytesPerTick,
                                  targetOffset - scanIt->position);
    const qint64 originalPosition = file.pos();
    if (requested > 0) {
        if (!file.seek(scanIt->position)) {
            m_stateScans.remove(key);
            return false;
        }
        const QByteArray block = file.read(requested);
        if (block.size() != requested) {
            file.seek(originalPosition);
            m_stateScans.remove(key);
            return false;
        }
        scanIt->state = amnezia::remoteLogSanitizer::advanceStreamState(
                scanIt->lookbehind, block, scanIt->state);
        updatePrivateKeyLookbehind(scanIt->lookbehind, block);
        scanIt->position += requested;
        scanIt->anchor = fileAnchor(file, scanIt->position);
        if (scanIt->anchor.isEmpty()) {
            file.seek(originalPosition);
            m_stateScans.remove(key);
            return false;
        }
    }
    if (!file.seek(originalPosition)) {
        m_stateScans.remove(key);
        return false;
    }

    if (scanIt->position < targetOffset) {
        m_collectionHasReadableSource = true;
        m_collectionHasPendingStateScan = true;
        return false;
    }
    state = scanIt->state;
    return true;
}

bool RemoteLogUploader::advanceBytesStateScan(
        const QByteArray &data,
        const QString &key,
        const QString &fingerprint,
        qint64 targetOffset,
        amnezia::remoteLogSanitizer::StreamState &state)
{
    if (targetOffset <= 0) {
        m_stateScans.remove(key);
        state = {};
        return true;
    }

    auto scanIt = m_stateScans.find(key);
    const bool reset = scanIt == m_stateScans.end()
            || scanIt->fingerprint != fingerprint
            || scanIt->targetOffset != targetOffset
            || scanIt->position < 0 || scanIt->position > targetOffset
            || (scanIt->position > 0
                && (scanIt->anchor.isEmpty()
                    || bytesAnchor(data, scanIt->position) != scanIt->anchor));
    if (reset) {
        StateScanProgress progress;
        progress.fingerprint = fingerprint;
        progress.targetOffset = targetOffset;
        m_stateScans.insert(key, progress);
        scanIt = m_stateScans.find(key);
    }

    const qint64 bytes = qMin(stateScanBytesPerTick,
                              targetOffset - scanIt->position);
    if (bytes > 0) {
        const QByteArray block = data.mid(scanIt->position, bytes);
        if (block.size() != bytes) {
            m_stateScans.remove(key);
            return false;
        }
        scanIt->state = amnezia::remoteLogSanitizer::advanceStreamState(
                scanIt->lookbehind, block, scanIt->state);
        updatePrivateKeyLookbehind(scanIt->lookbehind, block);
        scanIt->position += bytes;
        scanIt->anchor = bytesAnchor(data, scanIt->position);
        if (scanIt->anchor.isEmpty()) {
            m_stateScans.remove(key);
            return false;
        }
    }

    if (scanIt->position < targetOffset) {
        m_collectionHasReadableSource = true;
        m_collectionHasPendingStateScan = true;
        return false;
    }
    state = scanIt->state;
    return true;
}

RemoteLogUploader::UploadTarget RemoteLogUploader::findUploadTarget(
        const ConnectionSnapshot &snapshot) const
{
    if (!m_serversRepository) {
        return {};
    }

    if (snapshot.state != Vpn::ConnectionState::Connected) {
        return {};
    }

    const QString serverId = snapshot.serverId;
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

RemoteLogUploader::LogPayload RemoteLogUploader::payloadFromFile(
        const QString &kind, const QString &filePath, bool *sourceReadable)
{
    if (sourceReadable) {
        *sourceReadable = false;
    }
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }

    const qint64 size = file.size();
    const QString key = payloadDedupeKey(kind);
    const LogCursor cursor = cursorForKey(key);
    qint64 fingerprintBytes = cursor.fingerprintBytes > 0
            ? qMin(cursor.fingerprintBytes, size) : qMin(fingerprintSampleBytes, size);
    QString fingerprint = fileFingerprint(file, fingerprintBytes);
    qint64 offset = cursor.offset;
    const bool offsetValid = offset >= 0 && offset <= size;
    const bool cursorMatches = offsetValid && cursor.fingerprint == fingerprint
            && (cursor.anchor.isEmpty() || fileAnchor(file, offset) == cursor.anchor);
    if (!cursorMatches) {
        fingerprintBytes = qMin(fingerprintSampleBytes, size);
        fingerprint = fileFingerprint(file, fingerprintBytes);
        const auto scan = m_stateScans.constFind(key);
        offset = scan != m_stateScans.constEnd()
                        && scan->fingerprint == fingerprint
                        && scan->targetOffset >= 0 && scan->targetOffset <= size
                ? scan->targetOffset : initialOffset(size);
    }
    if (offset >= size) {
        const amnezia::RemoteLogSanitizerSecretSet current = currentSanitizerSecrets();
        const QString currentSecretSetSha256 = sanitizerSecretSetSha256(current);
        if (current.forceRedacted) {
            m_collectionWholeRedactionUsed = true;
        }
        const RetrySanitizerMarker marker = retrySanitizerMarker(key);
        if (marker.present) {
            reconcileRetrySanitizerTransition(
                    key, fingerprint, size, offset, fileAnchor(file, offset),
                    -1, {}, {}, cursor, cursorMatches, currentSecretSetSha256);
        }
        m_collectionHasReadableSource = true;
        if (sourceReadable) {
            *sourceReadable = true;
        }
        return {};
    }
    amnezia::remoteLogSanitizer::StreamState streamState;
    if (cursorMatches && cursor.streamStateKnown) {
        streamState = cursor.streamState;
    } else if (!advanceFileStateScan(file, key, fingerprint, offset, streamState)) {
        return {};
    }

    QByteArray lookbehind;
    if (offset > 0) {
        const qint64 lookbehindBytes = qMin<qint64>(
                offset, amnezia::remoteLogSanitizer::MaximumPrivateKeyMarkerBytes);
        if (!file.seek(offset - lookbehindBytes)) {
            return {};
        }
        lookbehind = file.read(lookbehindBytes);
        if (lookbehind.size() != lookbehindBytes) {
            return {};
        }
    }
    if (!file.seek(offset)) {
        return {};
    }

    const qint64 requestedBytes = qMin(maxPayloadBytes, size - offset);
    const QByteArray sourceData = file.read(requestedBytes);
    if (!amnezia::remoteLogCapturedReadIsExact(
                requestedBytes, sourceData.size())) {
        return {};
    }

    const qint64 nextOffset = offset + sourceData.size();
    const QString offsetAnchor = fileAnchor(file, offset);
    if (offset > 0 && offsetAnchor.isEmpty()) {
        return {};
    }
    const QString sourceRangeSha256 = QString::fromLatin1(
            QCryptographicHash::hash(sourceData, QCryptographicHash::Sha256).toHex());
    const QString nextAnchor = fileAnchor(file, nextOffset);
    if (nextOffset > 0 && nextAnchor.isEmpty()) {
        return {};
    }
    const bool startsInsideRecord = offset > 0
            && (lookbehind.isEmpty()
                || !amnezia::remoteLogByteIsRecordDelimiter(lookbehind.back()));
    // The last record in the captured file extent is not stable until its
    // delimiter is present.  A writer may append after file.size() was sampled;
    // treating an unterminated captured tail as complete would expose the first
    // half of a concurrently written sensitive record.
    const bool endsInsideRecord = amnezia::remoteLogCapturedTailIsPartial(
            sourceData.size(),
            !sourceData.isEmpty()
                    && amnezia::remoteLogByteIsRecordDelimiter(sourceData.back()));
    const amnezia::remoteLogSanitizer::StreamBoundary boundary =
            amnezia::remoteLogSanitizer::inspectStreamBoundary(
                    lookbehind, sourceData, streamState);
    amnezia::remoteLogSanitizer::StreamState nextStreamState;
    QString currentSecretSetSha256;
    const amnezia::RemoteLogSanitizerSecretSet sanitizerSecrets =
            sanitizerSecretsForPayload(key, fingerprint, offset, offsetAnchor,
                                       sourceRangeSha256, nextOffset, nextAnchor,
                                       size, cursor, cursorMatches,
                                       &currentSecretSetSha256);
    const QByteArray sanitizedData = sanitizePayload(sourceData,
                                                     startsInsideRecord,
                                                     endsInsideRecord,
                                                     streamState,
                                                     boundary,
                                                     sanitizerSecrets,
                                                     nextStreamState);
    m_collectionHasReadableSource = true;
    if (sourceReadable) {
        *sourceReadable = true;
    }
    LogPayload payload;
    payload.kind = kind;
    payload.data = sanitizedData;
    payload.offsetKey = key;
    payload.fingerprint = fingerprint;
    payload.fingerprintBytes = fingerprintBytes;
    payload.offsetAnchor = offsetAnchor;
    payload.nextAnchor = nextAnchor;
    payload.sourceRangeSha256 = sourceRangeSha256;
    payload.sanitizerSecretSetSha256 = sanitizerSecretSetSha256(sanitizerSecrets);
    payload.currentSecretSetSha256 = currentSecretSetSha256;
    payload.offset = offset;
    payload.nextOffset = nextOffset;
    payload.sourceSize = size;
    payload.remainingBytes = size - offset;
    payload.hasMore = nextOffset < size;
    payload.wholeRedacted = sanitizerSecrets.forceRedacted;
    payload.streamState = nextStreamState;
    payload.sourceBytes = sourceData.size();
    return payload;
}

RemoteLogUploader::LogPayload RemoteLogUploader::payloadFromBytes(const QString &kind, const QByteArray &data)
{
    m_collectionHasReadableSource = true;
    const qint64 size = data.size();
    const QString key = payloadDedupeKey(kind);
    const LogCursor cursor = cursorForKey(key);
    qint64 fingerprintBytes = cursor.fingerprintBytes > 0
            ? qMin(cursor.fingerprintBytes, size) : qMin(fingerprintSampleBytes, size);
    QString fingerprint = bytesFingerprint(data, fingerprintBytes);
    qint64 offset = cursor.offset;
    const bool offsetValid = offset >= 0 && offset <= size;
    const bool cursorMatches = offsetValid && cursor.fingerprint == fingerprint
            && (cursor.anchor.isEmpty() || bytesAnchor(data, offset) == cursor.anchor);
    if (!cursorMatches) {
        fingerprintBytes = qMin(fingerprintSampleBytes, size);
        fingerprint = bytesFingerprint(data, fingerprintBytes);
        const auto scan = m_stateScans.constFind(key);
        offset = scan != m_stateScans.constEnd()
                        && scan->fingerprint == fingerprint
                        && scan->targetOffset >= 0 && scan->targetOffset <= size
                ? scan->targetOffset : initialOffset(size);
    }
    if (offset >= size) {
        const amnezia::RemoteLogSanitizerSecretSet current = currentSanitizerSecrets();
        const QString currentSecretSetSha256 = sanitizerSecretSetSha256(current);
        if (current.forceRedacted) {
            m_collectionWholeRedactionUsed = true;
        }
        const RetrySanitizerMarker marker = retrySanitizerMarker(key);
        if (marker.present) {
            reconcileRetrySanitizerTransition(
                    key, fingerprint, size, offset, bytesAnchor(data, offset),
                    -1, {}, {}, cursor, cursorMatches, currentSecretSetSha256);
        }
        return {};
    }

    amnezia::remoteLogSanitizer::StreamState streamState;
    if (cursorMatches && cursor.streamStateKnown) {
        streamState = cursor.streamState;
    } else if (!advanceBytesStateScan(data, key, fingerprint, offset, streamState)) {
        return {};
    }

    const qint64 requestedBytes = qMin(maxPayloadBytes, size - offset);
    const QByteArray sourceData = data.mid(offset, requestedBytes);
    if (!amnezia::remoteLogCapturedReadIsExact(
                requestedBytes, sourceData.size()) || sourceData.isEmpty()) {
        return {};
    }

    const qint64 nextOffset = offset + sourceData.size();
    const QString offsetAnchor = bytesAnchor(data, offset);
    const QString sourceRangeSha256 = QString::fromLatin1(
            QCryptographicHash::hash(sourceData, QCryptographicHash::Sha256).toHex());
    const QString nextAnchor = bytesAnchor(data, nextOffset);
    const qint64 lookbehindOffset = qMax<qint64>(
            0, offset - amnezia::remoteLogSanitizer::MaximumPrivateKeyMarkerBytes);
    const QByteArray lookbehind = data.mid(lookbehindOffset, offset - lookbehindOffset);
    const bool startsInsideRecord = offset > 0
            && !amnezia::remoteLogByteIsRecordDelimiter(data.at(offset - 1));
    const bool endsInsideRecord = amnezia::remoteLogCapturedTailIsPartial(
            sourceData.size(),
            amnezia::remoteLogByteIsRecordDelimiter(sourceData.back()));
    const amnezia::remoteLogSanitizer::StreamBoundary boundary =
            amnezia::remoteLogSanitizer::inspectStreamBoundary(
                    lookbehind, sourceData, streamState);
    amnezia::remoteLogSanitizer::StreamState nextStreamState;
    QString currentSecretSetSha256;
    const amnezia::RemoteLogSanitizerSecretSet sanitizerSecrets =
            sanitizerSecretsForPayload(key, fingerprint, offset, offsetAnchor,
                                       sourceRangeSha256, nextOffset, nextAnchor,
                                       size, cursor, cursorMatches,
                                       &currentSecretSetSha256);
    const QByteArray sanitizedData = sanitizePayload(sourceData,
                                                     startsInsideRecord,
                                                     endsInsideRecord,
                                                     streamState,
                                                     boundary,
                                                     sanitizerSecrets,
                                                     nextStreamState);
    LogPayload payload;
    payload.kind = kind;
    payload.data = sanitizedData;
    payload.offsetKey = key;
    payload.fingerprint = fingerprint;
    payload.fingerprintBytes = fingerprintBytes;
    payload.offsetAnchor = offsetAnchor;
    payload.nextAnchor = nextAnchor;
    payload.sourceRangeSha256 = sourceRangeSha256;
    payload.sanitizerSecretSetSha256 = sanitizerSecretSetSha256(sanitizerSecrets);
    payload.currentSecretSetSha256 = currentSecretSetSha256;
    payload.offset = offset;
    payload.nextOffset = nextOffset;
    payload.sourceSize = size;
    payload.remainingBytes = size - offset;
    payload.hasMore = nextOffset < size;
    payload.wholeRedacted = sanitizerSecrets.forceRedacted;
    payload.streamState = nextStreamState;
    payload.sourceBytes = sourceData.size();
    return payload;
}

QList<RemoteLogUploader::LogPayload> RemoteLogUploader::collectPayloads()
{
    QList<LogPayload> payloads;
    m_collectionHasReadableSource = false;
    m_collectionAllExpectedSourcesReadable = false;
    m_collectionHasPendingStateScan = false;
    m_collectionPrivacyQuarantined = false;
    m_collectionWholeRedactionUsed = false;

#ifdef Q_OS_ANDROID
    const LogPayload payload = payloadFromBytes(QStringLiteral("android"), AndroidController::instance()->getLogs().toUtf8());
    m_collectionAllExpectedSourcesReadable = true;
        if (!payload.data.isEmpty()) {
            payloads.append(payload);
        }
#elif defined(Q_OS_IOS) || defined(MACOS_NE)
    const LogPayload payload = payloadFromBytes(QStringLiteral("client"), Logger::getLogFile().toUtf8());
    m_collectionAllExpectedSourcesReadable = true;
        if (!payload.data.isEmpty()) {
            payloads.append(payload);
        }
#else
    bool clientSourceReadable = false;
    bool serviceSourceReadable = false;
    const LogPayload clientLog = payloadFromFile(
            QStringLiteral("client"), Logger::userLogsFilePath(), &clientSourceReadable);
        if (!clientLog.data.isEmpty()) {
            payloads.append(clientLog);
        }

    const LogPayload serviceLog = payloadFromFile(
            QStringLiteral("service"), Logger::serviceLogsFilePath(), &serviceSourceReadable);
        if (!serviceLog.data.isEmpty()) {
            payloads.append(serviceLog);
        }
    m_collectionAllExpectedSourcesReadable =
            clientSourceReadable && serviceSourceReadable;
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
    setState(State::Uploading);
    QNetworkRequest request{QUrl(amnezia::clientLogsUtils::bootstrapEndpoint())};
    request.setTransferTimeout(uploadTimeoutMs);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
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
                logger.warning() << "Bootstrap response rejected"
                                 << "target" << targetIdentity(target).left(12)
                                 << "reason" << "response_too_large"
                                 << "responseBytes" << response.size();
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
            ErrorCategory category = ErrorCategory::Bootstrap;
            if (statusCode == 401 || statusCode == 403) {
                category = ErrorCategory::Authentication;
            } else if (reply->error() == QNetworkReply::TimeoutError) {
                category = ErrorCategory::Timeout;
            } else if (reply->error() != QNetworkReply::NoError && statusCode == 0) {
                category = ErrorCategory::Network;
            }
            recordFailure(category);
            logger.warning() << "Bootstrap failed"
                             << "target" << targetIdentity(target).left(12)
                             << "category" << errorCategoryName(category)
                             << "networkError" << static_cast<uint64_t>(reply->error())
                             << "httpStatus" << static_cast<uint64_t>(statusCode);
        } else {
            clearRetry();
            m_consecutiveFailures = 0;
            m_nextTokenRefreshAt = {};
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

    if (m_currentConnectionContextGeneration != m_connectionContextGeneration
        || !sameTarget(findUploadTarget(m_currentConnectionSnapshot), m_currentTarget)) {
        m_pendingPayloads.clear();
        setPendingBytes(0);
        m_uploadRequested = true;
        finishUpload();
        return;
    }

    const LogPayload payload = m_pendingPayloads.takeFirst();
    QNetworkRequest request(QUrl(m_currentTarget.endpoint));
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("text/plain; charset=utf-8"));
    request.setTransferTimeout(uploadTimeoutMs);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    request.setRawHeader("X-Amnezia-Client-Id", m_currentTarget.clientId.toUtf8());
    request.setRawHeader("X-Amnezia-Log-Token", m_currentTarget.token.toUtf8());
    request.setRawHeader("X-Amnezia-Log-Kind", payload.kind.toUtf8());
    request.setRawHeader("X-Amnezia-Batch-Id", batchIdForPayload(payload).toLatin1());
    const QByteArray batchId = request.rawHeader("X-Amnezia-Batch-Id");
    if (m_appSettingsRepository) {
        request.setRawHeader("X-Amnezia-Installation-Id", m_appSettingsRepository->getInstallationUuid(true).toUtf8());
    }

    QNetworkReply *reply = m_networkAccessManager.post(request, payload.data);
    connect(reply, &QNetworkReply::finished, this, [this, reply, payload, batchId]() {
        const int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool httpOk = reply->error() == QNetworkReply::NoError
                && statusCode >= 200 && statusCode < 300;
        const bool receiptAccepted =
                reply->rawHeader("X-Amnezia-Batch-Accepted") == QByteArrayLiteral("1")
                && reply->rawHeader("X-Amnezia-Batch-Id") == batchId;
        const bool ok = httpOk && receiptAccepted;
        if (ok) {
            bool durableCursorAdvanced = true;
            if (payload.advancesCursor) {
                LogCursor nextCursor;
                nextCursor.offset = payload.nextOffset;
                nextCursor.fingerprint = payload.fingerprint;
                nextCursor.fingerprintBytes = payload.fingerprintBytes;
                nextCursor.anchor = payload.nextAnchor;
                nextCursor.sanitizerSecretSetSha256 = payload.currentSecretSetSha256;
                nextCursor.streamState = payload.streamState;
                nextCursor.streamStateKnown = true;
                // Persist phase one before the cursor. A crash between these
                // writes leaves an armed marker ahead of the old cursor, which
                // the next scan safely resets to a redacted retry. The ACK
                // callback never removes quarantine.
                durableCursorAdvanced = armRetrySanitizerStableSource(
                        payload, nextCursor);
                if (durableCursorAdvanced) {
                    durableCursorAdvanced = persistCursor(payload.offsetKey, nextCursor);
                }
                if (durableCursorAdvanced) {
                    m_logCursors.insert(payload.offsetKey, nextCursor);
                    m_stateScans.remove(payload.offsetKey);
                } else {
                    m_retryPersistenceFailClosed = true;
                    recordFailure(ErrorCategory::Source);
                    m_uploadRequested = true;
                }
            }
            if (durableCursorAdvanced) {
                setPendingBytes(qMax<qint64>(0, m_pendingBytes - payload.sourceBytes));
                markUploadSuccess();
                if (payload.hasMore) {
                    m_uploadRequested = true;
                }
            }
        } else {
            if (httpOk && !receiptAccepted) {
                logger.warning() << "Upload response did not contain a matching durable batch receipt"
                                 << "target" << targetIdentity(m_currentTarget).left(12)
                                 << "kind" << payload.kind
                                 << "reason" << "receipt_mismatch"
                                 << "httpStatus" << static_cast<uint64_t>(statusCode);
            }
            if (statusCode == 401 || statusCode == 403) {
                bool retryPrivacyStateDurable = retainRetrySanitizerSecrets(payload);
                for (const LogPayload &pendingPayload : std::as_const(m_pendingPayloads)) {
                    retryPrivacyStateDurable = retainRetrySanitizerSecrets(pendingPayload)
                            && retryPrivacyStateDurable;
                }
                // Bootstrap refresh is a separate availability policy. Never
                // clear the old token until every rejected/pending range has a
                // durable, non-secret fail-closed marker.
                if (m_currentTarget.bootstrap && m_appSettingsRepository
                    && retryPrivacyStateDurable) {
                    m_appSettingsRepository->clearRemoteLogToken(m_currentTarget.tokenCacheKey);
                    m_nextTokenRefreshAt = QDateTime::currentDateTimeUtc().addMSecs(uploadIntervalMs);
                    m_uploadRequested = true;
                }
            }
            ErrorCategory category = ErrorCategory::Server;
            if (statusCode == 401 || statusCode == 403) {
                category = ErrorCategory::Authentication;
            } else if (reply->error() == QNetworkReply::TimeoutError) {
                category = ErrorCategory::Timeout;
            } else if (reply->error() != QNetworkReply::NoError && statusCode == 0) {
                category = ErrorCategory::Network;
            }
            recordFailure(category);
            logger.warning() << "Upload failed"
                             << "target" << targetIdentity(m_currentTarget).left(12)
                             << "kind" << payload.kind
                             << "category" << errorCategoryName(category)
                             << "networkError" << static_cast<uint64_t>(reply->error())
                             << "httpStatus" << static_cast<uint64_t>(statusCode);
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
    if (m_batchHadFailure) {
        const bool stale = m_lastSuccess.isValid()
                && m_lastSuccess.msecsTo(QDateTime::currentDateTimeUtc()) >= staleAfterMs;
        setState(stale ? State::Stale : State::Error);
    } else if (amnezia::remoteLogBatchCanBecomeHealthy(
                       m_batchHadFailure, m_collectionAllExpectedSourcesReadable,
                       m_collectionHasPendingStateScan, runAgain,
                       m_retryPersistenceFailClosed,
                       m_collectionPrivacyQuarantined,
                       m_collectionWholeRedactionUsed)) {
        setState(State::Healthy);
    }
    if (runAgain && !m_retryTimer.isActive()) {
        QTimer::singleShot(0, this, &RemoteLogUploader::uploadNow);
    }
}

void RemoteLogUploader::recordFailure(ErrorCategory category)
{
    m_batchHadFailure = true;
    if (category != ErrorCategory::Source
        && (m_retryPersistenceFailClosed || m_collectionPrivacyQuarantined
            || m_collectionWholeRedactionUsed)) {
        category = ErrorCategory::Source;
    }
    setLastErrorCategory(category);
    const bool stale = m_lastSuccess.isValid() && m_lastSuccess.msecsTo(QDateTime::currentDateTimeUtc()) >= staleAfterMs;
    setState(stale ? State::Stale : State::Error);
    if (!m_retryTimer.isActive()) {
        scheduleRetry();
    }
}

void RemoteLogUploader::markUploadSuccess()
{
    m_lastSuccess = QDateTime::currentDateTimeUtc();
    emit lastSuccessChanged();
    if (!m_healthTargetId.isEmpty()) {
        QSettings settings;
        const QString settingsPrefix = QLatin1String(targetSettingsPrefix)
                + persistentTargetId(m_healthTargetId) + QLatin1Char('/');
        settings.setValue(settingsPrefix + QStringLiteral("lastSuccess"), m_lastSuccess);
        settings.sync();
        if (settings.status() != QSettings::NoError) {
            m_retryPersistenceFailClosed = true;
            recordFailure(ErrorCategory::Source);
            return;
        }
    }
    if (m_retryPersistenceFailClosed || m_collectionPrivacyQuarantined
        || m_collectionWholeRedactionUsed) {
        recordFailure(ErrorCategory::Source);
        return;
    }
    if (!m_batchHadFailure) {
        setLastErrorCategory(ErrorCategory::None);
        clearRetry();
        m_consecutiveFailures = 0;
    }
}

void RemoteLogUploader::scheduleRetry()
{
    m_consecutiveFailures = qMin(m_consecutiveFailures + 1, 16);
    const int exponent = qMin(m_consecutiveFailures - 1, 10);
    const qint64 exponentialDelay = static_cast<qint64>(initialRetryDelayMs) << exponent;
    const int baseDelay = static_cast<int>(qMin<qint64>(exponentialDelay, maxRetryDelayMs));
    const int jitterRange = qMax(1, baseDelay * retryJitterPercent / 100);
    const int jitter = QRandomGenerator::global()->bounded(jitterRange * 2 + 1) - jitterRange;
    const int delay = qBound(1000, baseDelay + jitter, maxRetryDelayMs);
    setNextRetryAt(QDateTime::currentDateTimeUtc().addMSecs(delay));
    m_retryTimer.start(delay);
}

void RemoteLogUploader::clearRetry()
{
    if (m_retryTimer.isActive()) {
        m_retryTimer.stop();
    }
    setNextRetryAt({});
}

void RemoteLogUploader::refreshStaleness()
{
    if (m_state != State::Error && m_state != State::Stale) {
        return;
    }
    if (m_lastSuccess.isValid() && m_lastSuccess.msecsTo(QDateTime::currentDateTimeUtc()) >= staleAfterMs) {
        setState(State::Stale);
    }
}

void RemoteLogUploader::setState(State state)
{
    if (m_state == state) {
        return;
    }
    m_state = state;
    emit stateChanged();
}

void RemoteLogUploader::setPendingBytes(qint64 pendingBytes)
{
    pendingBytes = qMax<qint64>(0, pendingBytes);
    if (m_pendingBytes == pendingBytes) {
        return;
    }
    m_pendingBytes = pendingBytes;
    emit pendingBytesChanged();
}

void RemoteLogUploader::setLastErrorCategory(ErrorCategory category)
{
    if (m_lastErrorCategory == category) {
        return;
    }
    m_lastErrorCategory = category;
    emit lastErrorCategoryChanged();
}

void RemoteLogUploader::setNextRetryAt(const QDateTime &nextRetryAt)
{
    if (m_nextRetryAt == nextRetryAt) {
        return;
    }
    m_nextRetryAt = nextRetryAt;
    emit nextRetryAtChanged();
}
