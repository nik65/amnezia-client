#include "remoteLogUploader.h"

#include <QCryptographicHash>
#include <QFile>
#include <QFileDevice>
#include <QFileInfo>
#include <QEventLoop>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSaveFile>
#include <QTimer>
#include <QUrl>

#include "../client/core/utils/remoteLogSanitizer.h"
#include "../client/core/utils/selfhosted/clientLogsTarget.h"

namespace amnezia::headless
{
namespace
{
constexpr int ConfigVersion = 1;
constexpr qint64 MaximumConfigBytes = 64 * 1024;
constexpr qint64 MaximumStateBytes = 16 * 1024;
constexpr qint64 MaximumBatchBytes = 15 * 1024 * 1024;
constexpr qint64 RebindTailBytes = 1024 * 1024;
constexpr int RequestTimeoutMs = 15000;
const QByteArray RedactedChunk = QByteArrayLiteral("[REDACTED LOG CHUNK]\n");

bool ownerOnly(const QFileInfo &info)
{
    const auto permissions = info.permissions();
    return info.isFile()
            && (permissions & (QFileDevice::ReadOwner | QFileDevice::WriteOwner))
                   == (QFileDevice::ReadOwner | QFileDevice::WriteOwner)
            && !(permissions & (QFileDevice::ReadGroup | QFileDevice::WriteGroup
                                | QFileDevice::ExeGroup | QFileDevice::ReadOther
                                | QFileDevice::WriteOther | QFileDevice::ExeOther));
}

} // namespace

HeadlessRemoteLogUploader::HeadlessRemoteLogUploader(QString configPath, QObject *parent)
    : QObject(parent), m_configPath(std::move(configPath))
{
    m_statePath = m_configPath.isEmpty() ? QString() : m_configPath + QStringLiteral(".state");
}

QString HeadlessRemoteLogUploader::stateName() const
{
    switch (m_state) {
    case State::Disabled: return QStringLiteral("disabled");
    case State::Pending: return QStringLiteral("pending");
    case State::Healthy: return QStringLiteral("healthy");
    case State::Error: return QStringLiteral("error");
    }
    return QStringLiteral("error");
}

QJsonObject HeadlessRemoteLogUploader::status() const
{
    return {
        { QStringLiteral("state"), stateName() },
        { QStringLiteral("reason"), m_lastReason },
        { QStringLiteral("configured"), !m_configPath.isEmpty() },
        { QStringLiteral("offset"), m_offset },
        { QStringLiteral("awaitingStableSource"), m_awaitingStable },
    };
}

void HeadlessRemoteLogUploader::setError(const QString &reason)
{
    m_state = State::Error;
    m_lastReason = reason;
}

bool HeadlessRemoteLogUploader::validateConfig(const QJsonObject &config, QString *error) const
{
    const auto fail = [error](const QString &value) {
        if (error) *error = value;
        return false;
    };
    if (config.value(QStringLiteral("version")).toInt(-1) != ConfigVersion)
        return fail(QStringLiteral("remote log config version is unsupported"));
    if (!config.value(QStringLiteral("enabled")).isBool())
        return fail(QStringLiteral("remote log config enabled is missing"));
    if (!config.value(QStringLiteral("sourcePath")).isString()
        || !QFileInfo(config.value(QStringLiteral("sourcePath")).toString()).isAbsolute())
        return fail(QStringLiteral("remote log sourcePath must be absolute"));
    if (!config.value(QStringLiteral("enabled")).toBool()) return true;
    const QString installationId = config.value(QStringLiteral("installationId")).toString();
    if (installationId.size() < 16 || installationId.size() > 128)
        return fail(QStringLiteral("remote log installationId is invalid"));
    const QJsonValue targetValue = config.value(QStringLiteral("clientLogs"));
    if (!targetValue.isObject()) return fail(QStringLiteral("clientLogs target is missing"));
    QString targetError;
    if (!amnezia::clientLogsTarget::validate(targetValue.toObject(), &targetError))
        return fail(targetError);
    return true;
}

bool HeadlessRemoteLogUploader::load(QString *error)
{
    if (m_configPath.isEmpty()) {
        m_config = {};
        m_state = State::Disabled;
        m_lastReason = QStringLiteral("not_configured");
        return true;
    }
    const QFileInfo configInfo(m_configPath);
    if (!configInfo.exists()) {
        m_config = {};
        m_state = State::Disabled;
        m_lastReason = QStringLiteral("not_configured");
        return true;
    }
    if (!ownerOnly(configInfo) || configInfo.size() > MaximumConfigBytes) {
        setError(QStringLiteral("config_permissions_or_size"));
        if (error) *error = m_lastReason;
        return false;
    }
    QFile file(m_configPath);
    if (!file.open(QIODevice::ReadOnly)) {
        setError(QStringLiteral("config_read_failed"));
        if (error) *error = m_lastReason;
        return false;
    }
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()
        || !validateConfig(document.object(), error)) {
        setError(error && !error->isEmpty() ? *error : QStringLiteral("config_invalid"));
        return false;
    }
    m_config = document.object();
    if (!m_config.value(QStringLiteral("enabled")).toBool()) {
        m_state = State::Disabled;
        m_lastReason = QStringLiteral("disabled_by_provisioning");
        return true;
    }
    if (!loadState(error)) {
        setError(error && !error->isEmpty() ? *error : QStringLiteral("state_read_failed"));
        return false;
    }
    m_state = State::Pending;
    m_lastReason = QStringLiteral("ready");
    return true;
}

bool HeadlessRemoteLogUploader::loadState(QString *error)
{
    m_offset = 0;
    m_fingerprint.clear();
    m_awaitingStable = false;
    m_redactNext = false;
    m_highWater = 0;
    const QFileInfo info(m_statePath);
    if (!info.exists()) return true;
    if (!ownerOnly(info) || info.size() > MaximumStateBytes) {
        if (error) *error = QStringLiteral("state_permissions_or_size");
        return false;
    }
    QFile file(m_statePath);
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("state_read_failed");
        return false;
    }
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (error) *error = QStringLiteral("state_invalid");
        return false;
    }
    const QJsonObject state = document.object();
    m_offset = state.value(QStringLiteral("offset")).toVariant().toLongLong();
    m_fingerprint = state.value(QStringLiteral("fingerprint")).toString();
    m_awaitingStable = state.value(QStringLiteral("awaitingStableSource")).toBool(false);
    m_redactNext = state.value(QStringLiteral("redactNext")).toBool(false);
    m_highWater = state.value(QStringLiteral("highWater")).toVariant().toLongLong();
    if (m_offset < 0 || m_highWater < 0 || m_fingerprint.size() > 128) {
        if (error) *error = QStringLiteral("state_invalid");
        return false;
    }
    return true;
}

bool HeadlessRemoteLogUploader::saveState(QString *error) const
{
    QSaveFile file(m_statePath);
    if (!file.open(QIODevice::WriteOnly)
        || file.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 1 },
            { QStringLiteral("offset"), m_offset },
            { QStringLiteral("fingerprint"), m_fingerprint },
            { QStringLiteral("awaitingStableSource"), m_awaitingStable },
            { QStringLiteral("redactNext"), m_redactNext },
            { QStringLiteral("highWater"), m_highWater },
        }).toJson(QJsonDocument::Compact)) < 0
        || !file.commit()
        || !QFile::setPermissions(m_statePath, QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
        if (error) *error = QStringLiteral("state_write_failed");
        return false;
    }
    return true;
}

QString HeadlessRemoteLogUploader::sourceFingerprint(const QByteArray &prefix, qint64 size) const
{
    Q_UNUSED(size);
    return QString::fromLatin1(QCryptographicHash::hash(
        QByteArrayLiteral("amnezia-headless-log-source-v1\n")
            + m_config.value(QStringLiteral("sourcePath")).toString().toUtf8()
            + '\n' + prefix,
        QCryptographicHash::Sha256).toHex());
}

QString HeadlessRemoteLogUploader::batchId(qint64 offset, qint64 nextOffset,
                                           const QString &fingerprint) const
{
    const QString installation = m_config.value(QStringLiteral("installationId")).toString();
    return QString::fromLatin1(QCryptographicHash::hash(
        installation.toUtf8() + QByteArrayLiteral("\nheadless\n")
            + fingerprint.toUtf8() + QByteArray::number(offset) + ':'
            + QByteArray::number(nextOffset), QCryptographicHash::Sha256).toHex());
}

void HeadlessRemoteLogUploader::poll()
{
    if (m_pollInProgress || m_state == State::Disabled || m_config.isEmpty()) return;
    m_pollInProgress = true;
    QJsonObject target = m_config.value(QStringLiteral("clientLogs")).toObject();
    if (target.value(QStringLiteral("token")).toString().isEmpty()
        && target.value(QStringLiteral("bootstrap")).toBool(false)) {
        QNetworkRequest bootstrapRequest(QUrl(amnezia::clientLogsTarget::bootstrapEndpoint()));
        bootstrapRequest.setTransferTimeout(RequestTimeoutMs);
        bootstrapRequest.setRawHeader("X-Amnezia-Client-Id",
                                      target.value(QStringLiteral("clientId")).toString().toUtf8());
        bootstrapRequest.setRawHeader("X-Amnezia-Installation-Id",
                                      m_config.value(QStringLiteral("installationId")).toString().toUtf8());
        QNetworkAccessManager bootstrapManager;
        QNetworkReply *bootstrapReply = bootstrapManager.post(bootstrapRequest, QByteArray());
        QEventLoop bootstrapLoop;
        QObject::connect(bootstrapReply, &QNetworkReply::finished,
                         &bootstrapLoop, &QEventLoop::quit);
        QTimer::singleShot(RequestTimeoutMs, &bootstrapLoop, &QEventLoop::quit);
        bootstrapLoop.exec();
        const int bootstrapStatus = bootstrapReply->attribute(
                QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QJsonDocument bootstrapDocument = QJsonDocument::fromJson(bootstrapReply->readAll());
        const QJsonObject issued = bootstrapDocument.object();
        const QString issuedEndpoint = issued.value(QStringLiteral("endpoint")).toString();
        const QString issuedClientId = issued.value(QStringLiteral("clientId")).toString();
        const QString issuedToken = issued.value(QStringLiteral("token")).toString();
        const bool enrolled = bootstrapReply->isFinished()
                && bootstrapReply->error() == QNetworkReply::NoError
                && bootstrapStatus >= 200 && bootstrapStatus < 300
                && issuedEndpoint == target.value(QStringLiteral("endpoint")).toString()
                && issuedClientId == target.value(QStringLiteral("clientId")).toString()
                && !issuedToken.isEmpty();
        bootstrapReply->deleteLater();
        if (!enrolled) {
            setError(QStringLiteral("bootstrap_failed"));
            m_pollInProgress = false;
            return;
        }
        target.insert(QStringLiteral("token"), issuedToken);
        target.remove(QStringLiteral("bootstrap"));
        m_config.insert(QStringLiteral("clientLogs"), target);
        QSaveFile configFile(m_configPath);
        if (!configFile.open(QIODevice::WriteOnly)
            || configFile.write(QJsonDocument(m_config).toJson(QJsonDocument::Compact)) < 0
            || !configFile.commit()
            || !QFile::setPermissions(m_configPath,
                                      QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
            setError(QStringLiteral("config_write_failed"));
            m_pollInProgress = false;
            return;
        }
    }
    const QString sourcePath = m_config.value(QStringLiteral("sourcePath")).toString();
    QFile source(sourcePath);
    if (!source.open(QIODevice::ReadOnly)) {
        setError(QStringLiteral("source_read_failed"));
        m_pollInProgress = false;
        return;
    }
    const qint64 size = source.size();
    const qint64 prefixSize = qMin<qint64>(size, 4096);
    const QByteArray prefix = source.read(prefixSize);
    if (prefix.size() != prefixSize) {
        setError(QStringLiteral("source_read_failed"));
        m_pollInProgress = false;
        return;
    }
    const QString fingerprint = sourceFingerprint(prefix, size);
    if (m_fingerprint.isEmpty()) {
        m_fingerprint = fingerprint;
        m_offset = qMax<qint64>(0, size - RebindTailBytes);
        m_redactNext = true;
        m_highWater = size;
    } else if (m_fingerprint != fingerprint) {
        if (m_awaitingStable) {
            setError(QStringLiteral("source_epoch_changed_before_confirmation"));
            m_pollInProgress = false;
            return;
        }
        m_fingerprint = fingerprint;
        m_offset = qMax<qint64>(0, size - RebindTailBytes);
        m_redactNext = true;
        m_highWater = size;
    }
    if (m_offset > size) {
        if (m_awaitingStable) {
            setError(QStringLiteral("source_truncated_before_confirmation"));
            m_pollInProgress = false;
            return;
        }
        m_offset = qMax<qint64>(0, size - RebindTailBytes);
        m_redactNext = true;
    }
    if (m_awaitingStable && size == m_offset && fingerprint == m_fingerprint) {
        m_awaitingStable = false;
        m_highWater = size;
        QString error;
        if (!saveState(&error)) setError(error);
        else { m_state = State::Healthy; m_lastReason = QStringLiteral("stable_source_confirmed"); }
        m_pollInProgress = false;
        return;
    }
    if (m_awaitingStable && size > m_offset) {
        // The source grew after the receipt.  Resume with a whole redacted
        // chunk and require another stable scan; never treat post-receipt
        // bytes as part of the old confirmed epoch.
        m_awaitingStable = false;
        m_redactNext = true;
        m_highWater = size;
    }
    if (m_offset >= size) {
        m_state = State::Pending;
        m_lastReason = QStringLiteral("waiting_for_log_data");
        QString error;
        if (!saveState(&error)) setError(error);
        m_pollInProgress = false;
        return;
    }
    if (!source.seek(m_offset)) {
        setError(QStringLiteral("source_seek_failed"));
        m_pollInProgress = false;
        return;
    }
    const qint64 nextOffset = qMin(size, m_offset + MaximumBatchBytes);
    const QByteArray raw = source.read(nextOffset - m_offset);
    if (raw.size() != nextOffset - m_offset) {
        setError(QStringLiteral("source_read_failed"));
        m_pollInProgress = false;
        return;
    }
    const QByteArray payload = m_redactNext
            ? RedactedChunk
            : amnezia::remoteLogSanitizer::sanitize(raw, {}, {}).data;
    const QString id = batchId(m_offset, nextOffset, fingerprint);
    QNetworkRequest request(QUrl(m_config.value(QStringLiteral("clientLogs")).toObject()
                                     .value(QStringLiteral("endpoint")).toString()));
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("text/plain; charset=utf-8"));
    request.setTransferTimeout(RequestTimeoutMs);
    target = m_config.value(QStringLiteral("clientLogs")).toObject();
    request.setRawHeader("X-Amnezia-Client-Id", target.value(QStringLiteral("clientId")).toString().toUtf8());
    request.setRawHeader("X-Amnezia-Log-Token", target.value(QStringLiteral("token")).toString().toUtf8());
    request.setRawHeader("X-Amnezia-Log-Kind", QByteArrayLiteral("headless"));
    request.setRawHeader("X-Amnezia-Batch-Id", id.toLatin1());
    request.setRawHeader("X-Amnezia-Installation-Id", m_config.value(QStringLiteral("installationId")).toString().toUtf8());
    QNetworkAccessManager manager;
    QNetworkReply *reply = manager.post(request, payload);
    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QTimer::singleShot(RequestTimeoutMs, &loop, &QEventLoop::quit);
    loop.exec();
    const int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const bool accepted = reply->isFinished() && reply->error() == QNetworkReply::NoError
            && statusCode >= 200 && statusCode < 300
            && reply->rawHeader("X-Amnezia-Batch-Accepted") == QByteArrayLiteral("1")
            && reply->rawHeader("X-Amnezia-Batch-Id") == id.toLatin1();
    reply->deleteLater();
    if (!accepted) {
        setError(reply->isFinished() && statusCode >= 200 && statusCode < 300
                         ? QStringLiteral("receipt_mismatch") : QStringLiteral("upload_failed"));
        m_pollInProgress = false;
        return;
    }
    m_offset = nextOffset;
    m_fingerprint = fingerprint;
    m_highWater = size;
    m_awaitingStable = true;
    m_redactNext = false;
    QString error;
    if (!saveState(&error)) setError(error);
    else { m_state = State::Pending; m_lastReason = QStringLiteral("receipt_accepted_waiting_stability"); }
    m_pollInProgress = false;
}

} // namespace amnezia::headless
