#include "remoteLogUploader.h"

#include <QCryptographicHash>
#include <QCoreApplication>
#include <QDateTime>
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

#ifdef Q_OS_WIN
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

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
constexpr qint64 CursorAnchorBytes = 256;
constexpr int RequestTimeoutMs = 15000;
constexpr int StateVersion = 2;
const QByteArray RedactedChunk = QByteArrayLiteral("[REDACTED LOG CHUNK]\n");

bool ownerOnly(const QFileInfo &info)
{
    const auto permissions = info.permissions();
    const auto expected = QFileDevice::ReadOwner | QFileDevice::WriteOwner;
    return info.isFile() && !info.isSymLink()
            && (permissions & (QFileDevice::ReadOwner | QFileDevice::WriteOwner
                               | QFileDevice::ExeOwner | QFileDevice::ReadGroup
                               | QFileDevice::WriteGroup | QFileDevice::ExeGroup
                               | QFileDevice::ReadOther | QFileDevice::WriteOther
                               | QFileDevice::ExeOther)) == expected;
}

bool requiresRootOwner(const QString &path)
{
#ifdef Q_OS_UNIX
    return path.startsWith(QStringLiteral("/etc/amnezia/"))
            || path.startsWith(QStringLiteral("/var/lib/amnezia/"));
#else
    Q_UNUSED(path);
    return false;
#endif
}

bool validEnumValue(int value, int minimum, int maximum)
{
    return value >= minimum && value <= maximum;
}

} // namespace

HeadlessRemoteLogUploader::HeadlessRemoteLogUploader(QString configPath, QObject *parent)
    : HeadlessRemoteLogUploader(std::move(configPath), nullptr, parent)
{
}

HeadlessRemoteLogUploader::HeadlessRemoteLogUploader(
        QString configPath, QNetworkAccessManager *networkManager, QObject *parent)
    : QObject(parent), m_configPath(std::move(configPath))
{
    m_statePath = m_configPath.isEmpty() ? QString() : m_configPath + QStringLiteral(".state");
    if (networkManager) m_networkManager = networkManager;
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
        { QStringLiteral("sourceBound"), !m_sourceIdentity.isEmpty() },
        { QStringLiteral("targetBound"), !m_targetBinding.isEmpty() },
    };
}

void HeadlessRemoteLogUploader::setError(const QString &reason)
{
    m_state = State::Error;
    m_lastReason = reason;
}

bool HeadlessRemoteLogUploader::validateSecureFile(const QFileInfo &info,
                                                   const QString &reason,
                                                   QString *error) const
{
    if (!ownerOnly(info) || (requiresRootOwner(info.absoluteFilePath())
                             && info.ownerId() != 0)) {
        if (error) *error = reason;
        return false;
    }
    return true;
}

QJsonObject HeadlessRemoteLogUploader::sanitizerStateToJson(
        const amnezia::remoteLogSanitizer::StreamState &state) const
{
    return {
        { QStringLiteral("blockKind"), static_cast<int>(state.blockKind) },
        { QStringLiteral("secretArrayOpen"), state.secretArrayOpen },
        { QStringLiteral("secretArrayDepth"), static_cast<qint64>(state.secretArrayDepth) },
        { QStringLiteral("secretArrayQuote"), static_cast<int>(state.secretArrayQuote.unicode()) },
        { QStringLiteral("secretArrayEscaped"), state.secretArrayEscaped },
        { QStringLiteral("pendingSecretKind"), static_cast<int>(state.pendingSecretKind) },
        { QStringLiteral("pendingSecretPhase"), static_cast<int>(state.pendingSecretPhase) },
        { QStringLiteral("pendingSecretWhitespaceBytes"),
          static_cast<qint64>(state.pendingSecretWhitespaceBytes) },
    };
}

bool HeadlessRemoteLogUploader::sanitizerStateFromJson(
        const QJsonObject &object,
        amnezia::remoteLogSanitizer::StreamState *state,
        QString *error) const
{
    const auto fail = [error](const QString &message) {
        if (error) *error = message;
        return false;
    };
    if (!state || !object.value(QStringLiteral("blockKind")).isDouble()
        || !object.value(QStringLiteral("secretArrayOpen")).isBool()
        || !object.value(QStringLiteral("secretArrayDepth")).isDouble()
        || !object.value(QStringLiteral("secretArrayQuote")).isDouble()
        || !object.value(QStringLiteral("secretArrayEscaped")).isBool()
        || !object.value(QStringLiteral("pendingSecretKind")).isDouble()
        || !object.value(QStringLiteral("pendingSecretPhase")).isDouble()
        || !object.value(QStringLiteral("pendingSecretWhitespaceBytes")).isDouble())
        return fail(QStringLiteral("state_sanitizer_fields_missing"));
    const int blockKind = object.value(QStringLiteral("blockKind")).toInt(-1);
    const int pendingKind = object.value(QStringLiteral("pendingSecretKind")).toInt(-1);
    const int pendingPhase = object.value(QStringLiteral("pendingSecretPhase")).toInt(-1);
    const qint64 depth = object.value(QStringLiteral("secretArrayDepth")).toVariant().toLongLong();
    const qint64 quote = object.value(QStringLiteral("secretArrayQuote")).toVariant().toLongLong();
    const qint64 whitespace = object.value(QStringLiteral("pendingSecretWhitespaceBytes"))
                                      .toVariant().toLongLong();
    if (!validEnumValue(blockKind, 0, static_cast<int>(
                            amnezia::remoteLogSanitizer::SecretBlockKind::TlsCrypt))
        || !validEnumValue(pendingKind, 0, static_cast<int>(
                                   amnezia::remoteLogSanitizer::PendingSecretKind::Array))
        || !validEnumValue(pendingPhase, 0, static_cast<int>(
                                   amnezia::remoteLogSanitizer::PendingSecretPhase::RedactingValue))
        || depth < 0 || depth > 1024
        || (quote != 0 && quote != QLatin1Char('"').unicode()
            && quote != QLatin1Char('\'').unicode()) || whitespace < 0
        || whitespace > amnezia::remoteLogSanitizer::MaximumPendingSecretWhitespaceBytes)
        return fail(QStringLiteral("state_sanitizer_fields_invalid"));
    const bool arrayOpen = object.value(QStringLiteral("secretArrayOpen")).toBool();
    const bool escaped = object.value(QStringLiteral("secretArrayEscaped")).toBool();
    const bool pendingInactive = pendingKind == 0 && pendingPhase == 0 && whitespace == 0;
    const bool pendingActive = pendingKind != 0 && pendingPhase != 0
            && ((pendingPhase != static_cast<int>(
                            amnezia::remoteLogSanitizer::PendingSecretPhase::OverflowAwaitingSeparator)
                 && pendingPhase != static_cast<int>(
                            amnezia::remoteLogSanitizer::PendingSecretPhase::OverflowAwaitingValue))
                || whitespace == amnezia::remoteLogSanitizer::MaximumPendingSecretWhitespaceBytes)
            && (pendingPhase != static_cast<int>(
                            amnezia::remoteLogSanitizer::PendingSecretPhase::RedactingValue)
                || whitespace == 0);
    if (arrayOpen != (depth > 0) || (!arrayOpen && (quote != 0 || escaped))
        || (!pendingInactive && !pendingActive)
        || (arrayOpen && !pendingInactive))
        return fail(QStringLiteral("state_sanitizer_fields_invalid"));
    state->blockKind = static_cast<amnezia::remoteLogSanitizer::SecretBlockKind>(blockKind);
    state->secretArrayOpen = object.value(QStringLiteral("secretArrayOpen")).toBool();
    state->secretArrayDepth = static_cast<qsizetype>(depth);
    state->secretArrayQuote = QChar(static_cast<ushort>(quote));
    state->secretArrayEscaped = object.value(QStringLiteral("secretArrayEscaped")).toBool();
    state->pendingSecretKind = static_cast<amnezia::remoteLogSanitizer::PendingSecretKind>(pendingKind);
    state->pendingSecretPhase = static_cast<amnezia::remoteLogSanitizer::PendingSecretPhase>(pendingPhase);
    state->pendingSecretWhitespaceBytes = static_cast<qsizetype>(whitespace);
    return true;
}

QJsonObject HeadlessRemoteLogUploader::stateToJson(const DurableState &state) const
{
    return {
        { QStringLiteral("version"), StateVersion },
        { QStringLiteral("offset"), state.offset },
        { QStringLiteral("fingerprint"), state.fingerprint },
        { QStringLiteral("awaitingStableSource"), state.awaitingStable },
        { QStringLiteral("redactNext"), state.redactNext },
        { QStringLiteral("highWater"), state.highWater },
        { QStringLiteral("sourceIdentity"), state.sourceIdentity },
        { QStringLiteral("cursorAnchor"), state.cursorAnchor },
        { QStringLiteral("targetBinding"), state.targetBinding },
        { QStringLiteral("sanitizerOffset"), state.offset },
        { QStringLiteral("sanitizerState"), sanitizerStateToJson(state.sanitizerState) },
    };
}

HeadlessRemoteLogUploader::DurableState HeadlessRemoteLogUploader::currentState() const
{
    DurableState state;
    state.offset = m_offset;
    state.fingerprint = m_fingerprint;
    state.awaitingStable = m_awaitingStable;
    state.redactNext = m_redactNext;
    state.highWater = m_highWater;
    state.sourceIdentity = m_sourceIdentity;
    state.cursorAnchor = m_cursorAnchor;
    state.targetBinding = m_targetBinding;
    state.sanitizerLookbehind = m_sanitizerLookbehind;
    state.sanitizerState = m_sanitizerState;
    return state;
}

void HeadlessRemoteLogUploader::applyState(const DurableState &state)
{
    m_offset = state.offset;
    m_fingerprint = state.fingerprint;
    m_awaitingStable = state.awaitingStable;
    m_redactNext = state.redactNext;
    m_highWater = state.highWater;
    m_sourceIdentity = state.sourceIdentity;
    m_cursorAnchor = state.cursorAnchor;
    m_targetBinding = state.targetBinding;
    m_sanitizerLookbehind = state.sanitizerLookbehind;
    m_sanitizerState = state.sanitizerState;
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
    if (!config.value(QStringLiteral("enabled")).toBool()) return true;
    const QString sourcePath = config.value(QStringLiteral("sourcePath")).toString().trimmed();
    const QFileInfo sourceInfo(sourcePath);
    if (!config.value(QStringLiteral("sourcePath")).isString()
        || !sourceInfo.isAbsolute() || !sourceInfo.exists()
        || !sourceInfo.isFile() || sourceInfo.isSymLink())
        return fail(QStringLiteral("remote log sourcePath must be an existing regular file"));
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

QString HeadlessRemoteLogUploader::targetBinding() const
{
    const QJsonObject target = m_config.value(QStringLiteral("clientLogs")).toObject();
    const QByteArray token = target.value(QStringLiteral("token")).toString().toUtf8();
    const QByteArray material = target.value(QStringLiteral("endpoint")).toString().toUtf8()
            + '\n' + target.value(QStringLiteral("clientId")).toString().toUtf8()
            + '\n' + m_config.value(QStringLiteral("installationId")).toString().toUtf8()
            + '\n' + m_config.value(QStringLiteral("sourcePath")).toString().toUtf8()
            + '\n' + QCryptographicHash::hash(token, QCryptographicHash::Sha256).toHex();
    return QString::fromLatin1(QCryptographicHash::hash(
            QByteArrayLiteral("amnezia-headless-target-v1\n") + material,
            QCryptographicHash::Sha256).toHex());
}

QString HeadlessRemoteLogUploader::sourceIdentity(const QFile &file) const
{
    if (!file.isOpen()) return {};
#ifdef Q_OS_WIN
    BY_HANDLE_FILE_INFORMATION information {};
    if (!GetFileInformationByHandle(reinterpret_cast<HANDLE>(file.handle()), &information)) {
        return {};
    }
    return QStringLiteral("win:%1:%2:%3")
            .arg(QString::number(information.dwVolumeSerialNumber, 16),
                 QString::number(information.nFileIndexHigh, 16),
                 QString::number(information.nFileIndexLow, 16));
#else
    struct stat information {};
    if (fstat(static_cast<int>(file.handle()), &information) != 0) return {};
    return QStringLiteral("unix:%1:%2")
            .arg(QString::number(static_cast<qulonglong>(information.st_dev), 16),
                 QString::number(static_cast<qulonglong>(information.st_ino), 16));
#endif
}

QString HeadlessRemoteLogUploader::cursorAnchor(QFile &file, qint64 offset, bool *ok) const
{
    if (ok) *ok = false;
    if (offset < 0) return {};
    if (offset == 0) {
        if (ok) *ok = true;
        return {};
    }
    const qint64 start = qMax<qint64>(0, offset - CursorAnchorBytes);
    if (!file.seek(start)) return {};
    const QByteArray bytes = file.read(offset - start);
    if (bytes.size() != offset - start) return {};
    if (ok) *ok = true;
    return QString::fromLatin1(QCryptographicHash::hash(
            QByteArrayLiteral("amnezia-headless-cursor-v1\n")
                + QByteArray::number(start) + ':' + bytes,
            QCryptographicHash::Sha256).toHex());
}

bool HeadlessRemoteLogUploader::sourceStillSafe(const QString &sourcePath, QFile &file,
                                                QString *identity, QString *error) const
{
    const QFileInfo before(sourcePath);
    if (!before.isAbsolute() || !before.exists() || !before.isFile() || before.isSymLink()) {
        if (error) *error = QStringLiteral("source_path_changed_or_unsafe");
        return false;
    }
    const QString openedIdentity = sourceIdentity(file);
    if (openedIdentity.isEmpty()) {
        if (error) *error = QStringLiteral("source_identity_unavailable");
        return false;
    }
    QFileInfo after(sourcePath);
    if (!after.isFile() || after.isSymLink()) {
        if (error) *error = QStringLiteral("source_path_changed_or_unsafe");
        return false;
    }
    QFile reopened(sourcePath);
    if (!reopened.open(QIODevice::ReadOnly) || sourceIdentity(reopened) != openedIdentity) {
        if (error) *error = QStringLiteral("source_path_changed_or_unsafe");
        return false;
    }
    if (identity) *identity = openedIdentity;
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
    QString configSecurityError;
    if (!validateSecureFile(configInfo, QStringLiteral("config_permissions_or_size"),
                            &configSecurityError)
        || configInfo.size() > MaximumConfigBytes) {
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
    m_targetBinding = targetBinding();
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

bool HeadlessRemoteLogUploader::provisionFromDesktopTarget(
        const QJsonObject &desktopExport, const QString &sourcePath,
        const QString &installationId, QString *error)
{
    QJsonObject target = desktopExport.value(QStringLiteral("clientLogs")).toObject();
    if (target.isEmpty()) target = desktopExport;
    QJsonObject config {
        { QStringLiteral("version"), ConfigVersion },
        { QStringLiteral("enabled"), true },
        { QStringLiteral("sourcePath"), sourcePath.trimmed() },
        { QStringLiteral("installationId"), installationId.trimmed() },
        { QStringLiteral("clientLogs"), target },
    };
    if (!validateConfig(config, error)) return false;
    if (m_configPath.isEmpty()) {
        if (error) *error = QStringLiteral("remote log config path is not provisioned");
        return false;
    }
    const QFileInfo existingConfig(m_configPath);
    if (existingConfig.exists() && !validateSecureFile(
                existingConfig, QStringLiteral("config_permissions_or_size"), error)) {
        return false;
    }
    QSaveFile file(m_configPath);
    if (!file.open(QIODevice::WriteOnly)
        || file.write(QJsonDocument(config).toJson(QJsonDocument::Compact)) < 0
        || !file.commit()
        || !QFile::setPermissions(m_configPath,
                                  QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
        if (error) *error = QStringLiteral("config_write_failed");
        return false;
    }
    QFileInfo writtenConfig(m_configPath);
    if (!validateSecureFile(writtenConfig, QStringLiteral("config_write_failed"), error))
        return false;
    return load(error);
}

bool HeadlessRemoteLogUploader::loadState(QString *error)
{
    applyState({});
    m_targetBinding = targetBinding();
    const QFileInfo info(m_statePath);
    if (!info.exists()) return true;
    if (!validateSecureFile(info, QStringLiteral("state_permissions_or_size"), error)
        || info.size() > MaximumStateBytes) {
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
    DurableState state;
    QString stateError;
    if (!stateFromJson(document.object(), &state, &stateError)) {
        // Legacy state carried no sanitizer continuation or target binding. Keep
        // the source untouched, quarantine only its metadata, and start a new
        // bounded redacted epoch.
        if (!quarantineState(QStringLiteral("legacy_state"), error)) return false;
        applyState({});
        m_targetBinding = targetBinding();
        return true;
    }
    const QString binding = targetBinding();
    if (state.targetBinding != binding) {
        if (!quarantineState(QStringLiteral("target_binding_changed"), error)) return false;
        applyState({});
        m_targetBinding = binding;
        return true;
    }
    state.targetBinding = binding;
    applyState(state);
    return true;
}

bool HeadlessRemoteLogUploader::stateFromJson(const QJsonObject &object,
                                              DurableState *state, QString *error) const
{
    const auto fail = [error](const QString &message) {
        if (error) *error = message;
        return false;
    };
    if (!state || object.value(QStringLiteral("version")).toInt(-1) != StateVersion)
        return fail(QStringLiteral("state_version_unsupported"));
    const QStringList requiredStrings { QStringLiteral("fingerprint"),
                                       QStringLiteral("sourceIdentity"),
                                       QStringLiteral("cursorAnchor"),
                                       QStringLiteral("targetBinding") };
    for (const QString &key : requiredStrings) {
        if (!object.value(key).isString()) return fail(QStringLiteral("state_field_invalid"));
    }
    for (const QString &key : { QStringLiteral("offset"), QStringLiteral("highWater") }) {
        if (!object.value(key).isDouble()) return fail(QStringLiteral("state_field_invalid"));
    }
    if (!object.value(QStringLiteral("sanitizerOffset")).isDouble()
        || !object.value(QStringLiteral("sanitizerState")).isObject())
        return fail(QStringLiteral("state_field_invalid"));
    for (const QString &key : { QStringLiteral("awaitingStableSource"),
                                QStringLiteral("redactNext") }) {
        if (!object.value(key).isBool()) return fail(QStringLiteral("state_field_invalid"));
    }
    state->offset = object.value(QStringLiteral("offset")).toVariant().toLongLong();
    state->highWater = object.value(QStringLiteral("highWater")).toVariant().toLongLong();
    state->fingerprint = object.value(QStringLiteral("fingerprint")).toString();
    state->awaitingStable = object.value(QStringLiteral("awaitingStableSource")).toBool();
    state->redactNext = object.value(QStringLiteral("redactNext")).toBool();
    state->sourceIdentity = object.value(QStringLiteral("sourceIdentity")).toString();
    state->cursorAnchor = object.value(QStringLiteral("cursorAnchor")).toString();
    state->targetBinding = object.value(QStringLiteral("targetBinding")).toString();
    state->sanitizerLookbehind.clear();
    if (state->offset < 0 || state->highWater < 0 || state->offset > state->highWater
        || state->fingerprint.size() > 128 || state->sourceIdentity.size() > 512
        || state->cursorAnchor.size() > 128 || state->targetBinding.size() != 64
        || object.value(QStringLiteral("sanitizerOffset")).toVariant().toLongLong()
                != state->offset
        || (state->offset > 0 && state->cursorAnchor.size() != 64)
        || !object.value(QStringLiteral("sanitizerState")).isObject())
        return fail(QStringLiteral("state_invalid"));
    if (!sanitizerStateFromJson(object.value(QStringLiteral("sanitizerState")).toObject(),
                                &state->sanitizerState, error)) {
        return false;
    }
    return true;
}

bool HeadlessRemoteLogUploader::saveState(const DurableState &state, QString *error) const
{
    QSaveFile file(m_statePath);
    if (!file.open(QIODevice::WriteOnly)
        || file.write(QJsonDocument(stateToJson(state)).toJson(QJsonDocument::Compact)) < 0
        || !file.commit()
        || !QFile::setPermissions(m_statePath,
                                   QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
        if (error) *error = QStringLiteral("state_write_failed");
        return false;
    }
    QFileInfo info(m_statePath);
    if (!validateSecureFile(info, QStringLiteral("state_write_failed"), error)) return false;
    return true;
}

bool HeadlessRemoteLogUploader::quarantineState(const QString &reason, QString *error)
{
    Q_UNUSED(reason);
    if (!QFileInfo::exists(m_statePath)) return true;
    const QString prefix = m_statePath + QStringLiteral(".quarantine.")
            + QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMddhhmmsszzz"))
            + QStringLiteral(".") + QString::number(QCoreApplication::applicationPid());
    QString destination = prefix;
    for (int attempt = 0; QFileInfo::exists(destination) && attempt < 100; ++attempt) {
        destination = prefix + QStringLiteral(".") + QString::number(attempt + 1);
    }
    if (!QFile::rename(m_statePath, destination)) {
        if (error) *error = QStringLiteral("state_quarantine_failed");
        return false;
    }
    return true;
}

QString HeadlessRemoteLogUploader::sourceFingerprint(const QByteArray &prefix, qint64 size,
                                                     const QString &identity) const
{
    Q_UNUSED(size);
    return QString::fromLatin1(QCryptographicHash::hash(
        QByteArrayLiteral("amnezia-headless-log-source-v1\n")
            + m_config.value(QStringLiteral("sourcePath")).toString().toUtf8()
            + '\n' + identity.toUtf8()
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
    if (m_pollInProgress || m_state == State::Disabled || m_state == State::Error
        || m_config.isEmpty()) return;
    m_pollInProgress = true;
    const auto finish = [this]() { m_pollInProgress = false; };
    QJsonObject target = m_config.value(QStringLiteral("clientLogs")).toObject();
    if (target.value(QStringLiteral("token")).toString().isEmpty()
        && target.value(QStringLiteral("bootstrap")).toBool(false)) {
        QNetworkRequest bootstrapRequest(QUrl(amnezia::clientLogsTarget::bootstrapEndpoint()));
        bootstrapRequest.setTransferTimeout(RequestTimeoutMs);
        bootstrapRequest.setRawHeader("X-Amnezia-Client-Id",
                                      target.value(QStringLiteral("clientId")).toString().toUtf8());
        bootstrapRequest.setRawHeader("X-Amnezia-Installation-Id",
                                      m_config.value(QStringLiteral("installationId")).toString().toUtf8());
        QNetworkReply *bootstrapReply = m_networkManager->post(bootstrapRequest, QByteArray());
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
            finish();
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
            finish();
            return;
        }
        QFileInfo writtenConfig(m_configPath);
        QString configError;
        if (!validateSecureFile(writtenConfig, QStringLiteral("config_write_failed"),
                                &configError)) {
            setError(configError);
            finish();
            return;
        }
        const QString newBinding = targetBinding();
        if (!m_targetBinding.isEmpty() && m_targetBinding != newBinding) {
            if (!quarantineState(QStringLiteral("bootstrap_target_changed"))) {
                setError(QStringLiteral("state_quarantine_failed"));
                finish();
                return;
            }
            applyState({});
        }
        m_targetBinding = newBinding;
    }
    const QString sourcePath = m_config.value(QStringLiteral("sourcePath")).toString();
    QFile source(sourcePath);
    if (!source.open(QIODevice::ReadOnly)) {
        setError(QStringLiteral("source_read_failed"));
        finish();
        return;
    }
    QString identity;
    QString sourceError;
    if (!sourceStillSafe(sourcePath, source, &identity, &sourceError)) {
        setError(sourceError);
        finish();
        return;
    }
    const QString openedIdentity = identity;
    const qint64 size = source.size();
    const qint64 prefixSize = qMin<qint64>(size, 4096);
    const QByteArray prefix = source.read(prefixSize);
    if (prefix.size() != prefixSize) {
        setError(QStringLiteral("source_read_failed"));
        finish();
        return;
    }
    if (!sourceStillSafe(sourcePath, source, &identity, &sourceError)) {
        setError(sourceError);
        finish();
        return;
    }
    if (identity != openedIdentity) {
        setError(QStringLiteral("source_path_changed_or_unsafe"));
        finish();
        return;
    }
    DurableState working = currentState();
    const QString binding = targetBinding();
    if (working.targetBinding.isEmpty()) working.targetBinding = binding;
    if (working.targetBinding != binding) {
        if (!quarantineState(QStringLiteral("target_binding_changed"), &sourceError)) {
            setError(sourceError);
            finish();
            return;
        }
        working = {};
        working.targetBinding = binding;
        applyState(working);
    }
    if (!working.redactNext && working.offset > 0 && working.sanitizerLookbehind.isEmpty()) {
        const qint64 lookbehindStart = qMax<qint64>(0,
                working.offset - amnezia::remoteLogSanitizer::MaximumPrivateKeyMarkerBytes);
        if (!source.seek(lookbehindStart)) {
            setError(QStringLiteral("sanitizer_lookbehind_failed"));
            finish();
            return;
        }
        working.sanitizerLookbehind = source.read(working.offset - lookbehindStart);
        if (working.sanitizerLookbehind.size() != working.offset - lookbehindStart) {
            setError(QStringLiteral("sanitizer_lookbehind_failed"));
            finish();
            return;
        }
    }
    const QString fingerprint = sourceFingerprint(prefix, size, identity);
    const bool identityChanged = !working.sourceIdentity.isEmpty()
            && working.sourceIdentity != identity;
    if (identityChanged) {
        if (working.awaitingStable || size >= working.offset) {
            setError(QStringLiteral("source_identity_changed"));
            finish();
            return;
        }
        working.fingerprint.clear();
        working.offset = qMax<qint64>(0, size - RebindTailBytes);
        working.redactNext = true;
        working.highWater = size;
        working.cursorAnchor.clear();
        working.sanitizerLookbehind.clear();
        working.sanitizerState = {};
    }
    if (!working.cursorAnchor.isEmpty() && working.offset <= size) {
        bool anchorOk = false;
        const QString actualAnchor = cursorAnchor(source, working.offset, &anchorOk);
        if (!anchorOk || actualAnchor != working.cursorAnchor) {
            setError(QStringLiteral("cursor_anchor_mismatch"));
            finish();
            return;
        }
    }
    if (working.fingerprint.isEmpty()) {
        working.fingerprint = fingerprint;
        working.offset = qMax<qint64>(0, size - RebindTailBytes);
        working.redactNext = true;
        working.highWater = size;
        working.cursorAnchor.clear();
        working.sanitizerLookbehind.clear();
        working.sanitizerState = {};
    } else if (working.fingerprint != fingerprint) {
        if (working.awaitingStable) {
            setError(QStringLiteral("source_epoch_changed_before_confirmation"));
            finish();
            return;
        }
        working.fingerprint = fingerprint;
        working.offset = qMax<qint64>(0, size - RebindTailBytes);
        working.redactNext = true;
        working.highWater = size;
        working.cursorAnchor.clear();
        working.sanitizerLookbehind.clear();
        working.sanitizerState = {};
    }
    working.sourceIdentity = identity;
    if (working.offset > size) {
        if (working.awaitingStable) {
            setError(QStringLiteral("source_truncated_before_confirmation"));
            finish();
            return;
        }
        working.offset = qMax<qint64>(0, size - RebindTailBytes);
        working.redactNext = true;
        working.cursorAnchor.clear();
        working.sanitizerLookbehind.clear();
        working.sanitizerState = {};
    }
    if (working.awaitingStable && size == working.offset && fingerprint == working.fingerprint) {
        working.awaitingStable = false;
        working.highWater = size;
        bool anchorOk = false;
        working.cursorAnchor = cursorAnchor(source, working.offset, &anchorOk);
        QString error;
        if (!anchorOk || !saveState(working, &error)) {
            setError(anchorOk ? error : QStringLiteral("cursor_anchor_failed"));
        } else {
            applyState(working);
            m_state = State::Healthy;
            m_lastReason = QStringLiteral("stable_source_confirmed");
        }
        finish();
        return;
    }
    if (working.awaitingStable && size > working.offset) {
        // The source grew after the receipt.  Resume with a whole redacted
        // chunk and require another stable scan; never treat post-receipt
        // bytes as part of the old confirmed epoch.
        working.awaitingStable = false;
        working.redactNext = true;
        working.highWater = size;
        working.sanitizerLookbehind.clear();
        working.sanitizerState = {};
    }
    if (working.offset >= size) {
        bool anchorOk = false;
        working.cursorAnchor = cursorAnchor(source, working.offset, &anchorOk);
        if (!anchorOk) {
            setError(QStringLiteral("cursor_anchor_failed"));
            finish();
            return;
        }
        m_state = State::Pending;
        m_lastReason = QStringLiteral("waiting_for_log_data");
        QString error;
        if (!saveState(working, &error)) setError(error);
        else applyState(working);
        finish();
        return;
    }
    if (!source.seek(working.offset)) {
        setError(QStringLiteral("source_seek_failed"));
        finish();
        return;
    }
    const qint64 nextOffset = qMin(size, working.offset + MaximumBatchBytes);
    const QByteArray raw = source.read(nextOffset - working.offset);
    if (raw.size() != nextOffset - working.offset) {
        setError(QStringLiteral("source_read_failed"));
        finish();
        return;
    }
    DurableState candidate = working;
    QByteArray payload;
    if (working.redactNext) {
        payload = RedactedChunk;
        candidate.sanitizerLookbehind.clear();
        candidate.sanitizerState = {};
    } else {
        const auto boundary = amnezia::remoteLogSanitizer::inspectStreamBoundary(
                working.sanitizerLookbehind, raw, working.sanitizerState);
        amnezia::remoteLogSanitizer::ChunkContext context;
        context.startsInsideRecord = !working.sanitizerLookbehind.isEmpty()
                && !working.sanitizerLookbehind.endsWith('\n')
                && !working.sanitizerLookbehind.endsWith('\r');
        context.endsInsideRecord = !raw.isEmpty() && !raw.endsWith('\n') && !raw.endsWith('\r');
        context.streamState = working.sanitizerState;
        context.boundaryBlockKind = boundary.beginBlockKind;
        context.secretBlockEndMarkerCharacters = boundary.endBlockMarkerCharactersInInput;
        context.secretArrayStartCharacters = boundary.secretArrayStartCharactersInInput;
        context.boundaryPendingSecretKind = boundary.pendingSecretKind;
        context.boundaryPendingSecretPhase = boundary.pendingSecretPhase;
        context.boundaryPendingSecretCharacters = boundary.pendingSecretCharactersInInput;
        context.boundaryPendingSecretWhitespaceBytes = boundary.pendingSecretWhitespaceBytes;
        const auto sanitized = amnezia::remoteLogSanitizer::sanitize(raw, context, {});
        payload = sanitized.data;
        candidate.sanitizerState = sanitized.streamState;
        candidate.sanitizerLookbehind =
                (working.sanitizerLookbehind + raw).right(
                        amnezia::remoteLogSanitizer::MaximumPrivateKeyMarkerBytes);
    }
    candidate.offset = nextOffset;
    candidate.fingerprint = fingerprint;
    candidate.sourceIdentity = identity;
    candidate.targetBinding = binding;
    candidate.redactNext = false;
    candidate.highWater = size;
    candidate.awaitingStable = true;
    bool anchorOk = false;
    candidate.cursorAnchor = cursorAnchor(source, nextOffset, &anchorOk);
    if (!anchorOk) {
        setError(QStringLiteral("cursor_anchor_failed"));
        finish();
        return;
    }
    const QString id = batchId(working.offset, nextOffset, fingerprint);
    QNetworkRequest request(QUrl(m_config.value(QStringLiteral("clientLogs")).toObject()
                                     .value(QStringLiteral("endpoint")).toString()));
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("text/plain; charset=utf-8"));
    request.setTransferTimeout(RequestTimeoutMs);
    target = m_config.value(QStringLiteral("clientLogs")).toObject();
    request.setRawHeader("X-Amnezia-Client-Id", target.value(QStringLiteral("clientId")).toString().toUtf8());
    request.setRawHeader("X-Amnezia-Log-Token", target.value(QStringLiteral("token")).toString().toUtf8());
    // The deployed collector allowlist is android/client/service. Headless
    // is a producer mode, not a new storage kind, so use the existing client
    // bucket and keep the server contract unchanged.
    request.setRawHeader("X-Amnezia-Log-Kind", QByteArrayLiteral("client"));
    request.setRawHeader("X-Amnezia-Batch-Id", id.toLatin1());
    request.setRawHeader("X-Amnezia-Installation-Id", m_config.value(QStringLiteral("installationId")).toString().toUtf8());
    QNetworkReply *reply = m_networkManager->post(request, payload);
    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QTimer::singleShot(RequestTimeoutMs, &loop, &QEventLoop::quit);
    loop.exec();
    const int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const bool transportAccepted = reply->isFinished()
            && reply->error() == QNetworkReply::NoError;
    const bool accepted = transportAccepted
            && statusCode >= 200 && statusCode < 300
            && reply->rawHeader("X-Amnezia-Batch-Accepted") == QByteArrayLiteral("1")
            && reply->rawHeader("X-Amnezia-Batch-Id") == id.toLatin1();
    reply->deleteLater();
    if (!accepted) {
        setError(transportAccepted && statusCode >= 200 && statusCode < 300
                         ? QStringLiteral("receipt_mismatch") : QStringLiteral("upload_failed"));
        finish();
        return;
    }
    QString error;
    if (!saveState(candidate, &error)) {
        setError(error);
        finish();
        return;
    }
    applyState(candidate);
    m_state = State::Pending;
    m_lastReason = QStringLiteral("receipt_accepted_waiting_stability");
    finish();
}

} // namespace amnezia::headless
