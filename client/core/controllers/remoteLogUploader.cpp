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
#include <QThread>
#include <QUrl>

#include <utility>

#include "core/repositories/secureAppSettingsRepository.h"
#include "core/repositories/secureServersRepository.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
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
    constexpr auto cursorSettingsPrefix = "Runtime/remoteLogUploader/cursors/";
    constexpr auto targetSettingsPrefix = "Runtime/remoteLogUploader/targets/";

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
        connect(m_vpnConnection, &VpnConnection::connectionStateChanged, this, [this](Vpn::ConnectionState) { retryNow(); });
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
    const QString settingsPrefix = QLatin1String(targetSettingsPrefix) + persistentTargetId(targetId) + QLatin1Char('/');
    const QDateTime lastSuccess = settings.value(settingsPrefix + QStringLiteral("lastSuccess")).toDateTime().toUTC();
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
    if (m_uploadInProgress || m_bootstrapInProgress) {
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
    if (m_uploadInProgress) {
        m_uploadRequested = true;
        return;
    }

    const ConnectionSnapshot snapshot = currentConnectionSnapshot();
    if (snapshot.state != Vpn::ConnectionState::Connected) {
        m_pendingPayloads.clear();
        setPendingBytes(0);
        clearRetry();
        m_consecutiveFailures = 0;
        setState(State::WaitingForVpn);
        return;
    }

    m_currentTarget = findUploadTarget();
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

    m_pendingPayloads = collectPayloads();
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
        m_pendingPayloads.append({ QStringLiteral("client"),
                                   heartbeat,
                                   {},
                                   bytesFingerprint(QByteArrayLiteral("amnezia-empty-sync-v1"), 21),
                                   21,
                                   {},
                                   0,
                                   0,
                                   0,
                                   false,
                                   false });
    }

    m_batchHadFailure = false;
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
    const QString cursorPrefix = QLatin1String(cursorSettingsPrefix) + persistentCursorId(key) + QLatin1Char('/');
    cursor.offset = settings.value(cursorPrefix + QStringLiteral("offset"), -1).toLongLong();
    cursor.fingerprint = settings.value(cursorPrefix + QStringLiteral("fingerprint")).toString();
    cursor.fingerprintBytes = settings.value(cursorPrefix + QStringLiteral("fingerprintBytes"), 0).toLongLong();
    cursor.anchor = settings.value(cursorPrefix + QStringLiteral("anchor")).toString();
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
    m_logCursors.insert(key, cursor);
    return cursor;
}

void RemoteLogUploader::persistCursor(const QString &key, const LogCursor &cursor) const
{
    QSettings settings;
    const QString cursorPrefix = QLatin1String(cursorSettingsPrefix) + persistentCursorId(key) + QLatin1Char('/');
    settings.setValue(cursorPrefix + QStringLiteral("fingerprint"), cursor.fingerprint);
    settings.setValue(cursorPrefix + QStringLiteral("fingerprintBytes"), cursor.fingerprintBytes);
    settings.setValue(cursorPrefix + QStringLiteral("anchor"), cursor.anchor);
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
}

QByteArray RemoteLogUploader::sanitizePayload(const QByteArray &data,
                                              bool startsInsideRecord,
                                              bool endsInsideRecord,
                                              const amnezia::remoteLogSanitizer::StreamState &streamState,
                                              const amnezia::remoteLogSanitizer::StreamBoundary &boundary,
                                              amnezia::remoteLogSanitizer::StreamState &nextStreamState) const
{
    QStringList sensitiveValues;
    if (!m_currentTarget.token.isEmpty()) {
        sensitiveValues.append(m_currentTarget.token);
    }
    if (m_appSettingsRepository) {
        const QString installationUuid = m_appSettingsRepository->getInstallationUuid(true).trimmed();
        if (!installationUuid.isEmpty()) {
            sensitiveValues.append(installationUuid);
            sensitiveValues.append(installationUuid.toLower());
            sensitiveValues.append(installationUuid.toUpper());
        }
    }

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
            amnezia::remoteLogSanitizer::sanitize(data, context, sensitiveValues);
    nextStreamState = sanitized.streamState;
    return sanitized.data;
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
        m_collectionHasReadableSource = true;
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

    const QByteArray sourceData = file.read(maxPayloadBytes);
    if (sourceData.isEmpty()) {
        return {};
    }

    const qint64 nextOffset = offset + sourceData.size();
    const bool startsInsideRecord = offset > 0
            && (lookbehind.isEmpty() || !lookbehind.endsWith('\n'));
    const bool endsInsideRecord = nextOffset < size && !sourceData.endsWith('\n');
    const amnezia::remoteLogSanitizer::StreamBoundary boundary =
            amnezia::remoteLogSanitizer::inspectStreamBoundary(
                    lookbehind, sourceData, streamState);
    amnezia::remoteLogSanitizer::StreamState nextStreamState;
    const QByteArray sanitizedData = sanitizePayload(sourceData,
                                                     startsInsideRecord,
                                                     endsInsideRecord,
                                                     streamState,
                                                     boundary,
                                                     nextStreamState);
    const QString nextAnchor = fileAnchor(file, nextOffset);
    if (nextOffset > 0 && nextAnchor.isEmpty()) {
        return {};
    }
    m_collectionHasReadableSource = true;
    return { kind, sanitizedData, key, fingerprint, fingerprintBytes, nextAnchor,
             offset, nextOffset, size - offset, nextOffset < size, true,
             nextStreamState, sourceData.size() };
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
        return {};
    }

    amnezia::remoteLogSanitizer::StreamState streamState;
    if (cursorMatches && cursor.streamStateKnown) {
        streamState = cursor.streamState;
    } else if (!advanceBytesStateScan(data, key, fingerprint, offset, streamState)) {
        return {};
    }

    const QByteArray sourceData = data.mid(offset, maxPayloadBytes);
    if (sourceData.isEmpty()) {
        return {};
    }

    const qint64 nextOffset = offset + sourceData.size();
    const qint64 lookbehindOffset = qMax<qint64>(
            0, offset - amnezia::remoteLogSanitizer::MaximumPrivateKeyMarkerBytes);
    const QByteArray lookbehind = data.mid(lookbehindOffset, offset - lookbehindOffset);
    const bool startsInsideRecord = offset > 0 && data.at(offset - 1) != '\n';
    const bool endsInsideRecord = nextOffset < size && !sourceData.endsWith('\n');
    const amnezia::remoteLogSanitizer::StreamBoundary boundary =
            amnezia::remoteLogSanitizer::inspectStreamBoundary(
                    lookbehind, sourceData, streamState);
    amnezia::remoteLogSanitizer::StreamState nextStreamState;
    const QByteArray sanitizedData = sanitizePayload(sourceData,
                                                     startsInsideRecord,
                                                     endsInsideRecord,
                                                     streamState,
                                                     boundary,
                                                     nextStreamState);
    return { kind, sanitizedData, key, fingerprint, fingerprintBytes, bytesAnchor(data, nextOffset),
             offset, nextOffset, size - offset, nextOffset < size, true,
             nextStreamState, sourceData.size() };
}

QList<RemoteLogUploader::LogPayload> RemoteLogUploader::collectPayloads()
{
    QList<LogPayload> payloads;
    m_collectionHasReadableSource = false;
    m_collectionHasPendingStateScan = false;

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
                logger.warning() << "Bootstrap response is too large" << target.serverId;
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
                             << static_cast<uint64_t>(reply->error())
                             << static_cast<uint64_t>(statusCode)
                             << reply->errorString();
            if (statusCode == 401 || statusCode == 403) {
                recordFailure(ErrorCategory::Authentication);
            } else if (reply->error() == QNetworkReply::TimeoutError) {
                recordFailure(ErrorCategory::Timeout);
            } else if (reply->error() != QNetworkReply::NoError && statusCode == 0) {
                recordFailure(ErrorCategory::Network);
            } else {
                recordFailure(ErrorCategory::Bootstrap);
            }
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

    if (!sameTarget(findUploadTarget(), m_currentTarget)) {
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
            if (payload.advancesCursor) {
                m_logCursors.insert(payload.offsetKey, { payload.nextOffset, payload.fingerprint });
                m_logCursors[payload.offsetKey].fingerprintBytes = payload.fingerprintBytes;
                m_logCursors[payload.offsetKey].anchor = payload.nextAnchor;
                m_logCursors[payload.offsetKey].streamState = payload.streamState;
                m_logCursors[payload.offsetKey].streamStateKnown = true;
                persistCursor(payload.offsetKey, m_logCursors.value(payload.offsetKey));
                m_stateScans.remove(payload.offsetKey);
            }
            setPendingBytes(qMax<qint64>(0, m_pendingBytes - payload.sourceBytes));
            markUploadSuccess();
            if (payload.hasMore) {
                m_uploadRequested = true;
            }
        } else {
            if (httpOk && !receiptAccepted) {
                logger.warning() << "Upload response did not contain a matching durable batch receipt"
                                 << m_currentTarget.serverId
                                 << payload.kind
                                 << static_cast<uint64_t>(statusCode);
            }
            if ((statusCode == 401 || statusCode == 403) && m_currentTarget.bootstrap && m_appSettingsRepository) {
                m_appSettingsRepository->clearRemoteLogToken(m_currentTarget.tokenCacheKey);
                m_nextTokenRefreshAt = QDateTime::currentDateTimeUtc().addMSecs(uploadIntervalMs);
                m_uploadRequested = true;
            }
            if (statusCode == 401 || statusCode == 403) {
                recordFailure(ErrorCategory::Authentication);
            } else if (reply->error() == QNetworkReply::TimeoutError) {
                recordFailure(ErrorCategory::Timeout);
            } else if (reply->error() != QNetworkReply::NoError && statusCode == 0) {
                recordFailure(ErrorCategory::Network);
            } else {
                recordFailure(ErrorCategory::Server);
            }
            logger.warning() << "Upload failed"
                             << m_currentTarget.serverId
                             << m_currentTarget.endpoint
                             << payload.kind
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
    if (!m_batchHadFailure && !runAgain) {
        setState(State::Healthy);
    }
    if (runAgain && !m_retryTimer.isActive()) {
        QTimer::singleShot(0, this, &RemoteLogUploader::uploadNow);
    }
}

void RemoteLogUploader::recordFailure(ErrorCategory category)
{
    m_batchHadFailure = true;
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
