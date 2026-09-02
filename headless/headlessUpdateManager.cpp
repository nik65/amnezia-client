#include "headlessUpdateManager.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QProcess>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSet>
#include <QTimer>
#include <QUuid>
#include <QUrl>
#include <QVersionNumber>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <cerrno>
#include <cmath>
#include <cstring>
#include <utility>

#ifndef Q_OS_WIN
#include <unistd.h>
#endif

namespace amnezia::headless
{
namespace
{

constexpr qsizetype MaximumManifestBytes = 1024 * 1024;
constexpr qint64 MaximumArtifactBytes = 512LL * 1024 * 1024;
constexpr int NetworkTimeoutMs = 20'000;
constexpr int ArchiveTimeoutMs = 60'000;
constexpr auto HeadlessArtifactFormat = "amnezia-headless-tar-v1";
constexpr auto UpdateServiceName = "amneziad.service";
constexpr auto TrustedUpdateKeyPath = "/etc/amnezia/update-public-key.pem";

QString utcNow()
{
    return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
}

bool isObjectWithOnly(const QJsonObject &object, const QStringList &allowed)
{
    for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
        if (!allowed.contains(it.key())) {
            return false;
        }
    }
    return true;
}

bool jsonInteger(const QJsonValue &value, qint64 minimum, qint64 maximum, qint64 &result)
{
    if (!value.isDouble()) {
        return false;
    }
    const double number = value.toDouble();
    if (!std::isfinite(number) || std::floor(number) != number
        || number < static_cast<double>(minimum)
        || number > static_cast<double>(maximum)) {
        return false;
    }
    result = static_cast<qint64>(number);
    return true;
}

} // namespace

HeadlessUpdateManager::HeadlessUpdateManager(std::shared_ptr<CommandRunner> runner,
                                             QString statePath,
                                             QString installDirectory)
    : m_runner(runner ? std::move(runner) : std::make_shared<RealCommandRunner>()),
      m_statePath(std::move(statePath)),
      m_installDirectory(installDirectory.trimmed().isEmpty()
                             ? QCoreApplication::applicationDirPath()
                             : std::move(installDirectory))
{
    if (!m_statePath.isEmpty()) {
        m_updateRoot = QFileInfo(m_statePath).absolutePath();
        m_updateRoot = QDir(m_updateRoot).filePath(QStringLiteral("updates"));
        m_journalPath = QDir(m_updateRoot).filePath(QStringLiteral("transaction.json"));
    }
    loadState();
}

HeadlessUpdateResult HeadlessUpdateManager::checkAndApply(const Profile &profile,
                                                          const QString &currentVersion)
{
    if (m_updateInProgress) {
        return failure(QStringLiteral("update_in_progress"),
                       QStringLiteral("a headless update transaction is already in progress"));
    }
    m_updateInProgress = true;
    struct UpdateGuard {
        bool &active;
        ~UpdateGuard() { active = false; }
    } updateGuard { m_updateInProgress };
    m_lastCheckedAt = utcNow();
    m_lastError.clear();
    m_candidatePlatform.clear();

    if (!m_stateValid || m_lastState == QStringLiteral("recovery_required")) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("headless update state is invalid; manual recovery is required"));
    }

    // The previous transaction persisted this receipt before asking systemd
    // to restart us. Seeing the same version from a newly started daemon is
    // the post-restart health acknowledgement; keep rollback available.
    if (m_lastState == QStringLiteral("restart_pending")
        && !m_lastAppliedVersion.isEmpty() && currentVersion == m_lastAppliedVersion) {
        QString healthError;
        if (!verifyInstallFile(QDir(m_installDirectory).filePath(QStringLiteral("amneziad")), &healthError)
            || !verifyInstallFile(QDir(m_installDirectory).filePath(QStringLiteral("amnezia-cli")), &healthError)) {
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("updated headless binaries failed post-restart health validation"));
        }
        m_lastState = QStringLiteral("updated");
        QJsonObject journal;
        QFile journalFile(m_journalPath);
        QJsonParseError journalError;
        const QJsonDocument journalDocument = journalFile.open(QIODevice::ReadOnly)
                ? QJsonDocument::fromJson(journalFile.readAll(), &journalError) : QJsonDocument();
        if (!journalDocument.isObject()) {
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("headless update acknowledgement journal is missing or invalid"));
        }
        journal = journalDocument.object();
        journal.insert(QStringLiteral("phase"), QStringLiteral("acknowledged"));
        QString receiptError;
        if (!writeJournal(journal, &receiptError) || !QFile::remove(m_journalPath)) {
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("headless update health acknowledgement could not be persisted"));
        }
        if (!saveState()) {
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("headless update acknowledgement state could not be persisted"));
        }
    }
    if (m_lastState == QStringLiteral("rollback_restart_pending")
        && !m_rollbackVersion.isEmpty() && currentVersion == m_rollbackVersion) {
        QString healthError;
        if (!verifyInstallFile(QDir(m_installDirectory).filePath(QStringLiteral("amneziad")), &healthError)
            || !verifyInstallFile(QDir(m_installDirectory).filePath(QStringLiteral("amnezia-cli")), &healthError)) {
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("rolled-back headless binaries failed post-restart health validation"));
        }
        if (!m_rollbackDirectory.isEmpty() && !QDir(m_rollbackDirectory).removeRecursively()) {
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("rollback evidence could not be retired after health acknowledgement"));
        }
        if (!m_journalPath.isEmpty()) QFile::remove(m_journalPath);
        m_rollbackDirectory.clear();
        m_rollbackVersion.clear();
        m_rollbackHashes.clear();
        m_lastState = QStringLiteral("rolled_back");
        m_lastError.clear();
        if (!saveState()) {
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("rollback health acknowledgement state could not be persisted"));
        }
    }

    if (!profile.autoUpdate || profile.updateManifestUrl.isEmpty()
        || profile.updatePublicKeyPath.isEmpty()) {
        m_lastState = QStringLiteral("disabled");
        saveState();
        return { true, QStringLiteral("disabled"), QStringLiteral("automatic updates are disabled") };
    }

    QString trustError;
    if (!verifyTrustedKey(profile.updatePublicKeyPath, &trustError)) {
        return failure(QStringLiteral("update_trust_invalid"), trustError);
    }
    const QUrl manifestUrl(profile.updateManifestUrl, QUrl::StrictMode);
    if (!manifestUrl.isValid() || manifestUrl.scheme() != QStringLiteral("https")
        || manifestUrl.host().isEmpty() || manifestUrl.userInfo().size() > 0
        || manifestUrl.hasFragment()) {
        return failure(QStringLiteral("update_transport_invalid"),
                       QStringLiteral("automatic update manifests require an authenticated HTTPS endpoint"));
    }

    QNetworkAccessManager manager;
    QNetworkRequest request(QUrl(profile.updateManifestUrl));
    request.setTransferTimeout(NetworkTimeoutMs);
    QNetworkReply *reply = manager.get(request);
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    timer.start(NetworkTimeoutMs);
    loop.exec();

    if (!reply->isFinished()) {
        reply->abort();
        reply->deleteLater();
        return failure(QStringLiteral("update_timeout"),
                       QStringLiteral("headless update manifest request timed out"));
    }
    const int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QByteArray manifest = reply->readAll();
    const QString networkError = reply->error() == QNetworkReply::NoError
            ? QString() : reply->errorString();
    reply->deleteLater();
    if (!networkError.isEmpty()) {
        return failure(QStringLiteral("update_unreachable"),
                       QStringLiteral("headless update manifest request failed"));
    }
    if (statusCode < 200 || statusCode >= 300) {
        return failure(QStringLiteral("update_http_error"),
                       QStringLiteral("headless update manifest returned an unexpected status"));
    }
    if (manifest.isEmpty() || manifest.size() > MaximumManifestBytes) {
        return failure(QStringLiteral("update_manifest_too_large"),
                       QStringLiteral("headless update manifest exceeds the byte limit"));
    }

    Candidate candidate;
    const HeadlessUpdateResult parsed = parseManifest(
            manifest, QUrl(profile.updateManifestUrl), profile.updatePublicKeyPath,
            currentVersion, candidate);
    if (!parsed.ok || parsed.code == QStringLiteral("no_update")
        || parsed.code == QStringLiteral("no_headless_artifact")) {
        m_lastState = parsed.code;
        if (!parsed.ok) {
            m_lastError = parsed.message;
        }
        saveState();
        return parsed;
    }
    m_candidatePlatform = candidate.platform;
    if (!candidate.autoInstall) {
        m_lastState = QStringLiteral("update_available");
        saveState();
        return { true, QStringLiteral("update_available"),
                 QStringLiteral("a signed headless update is available") };
    }

    if (m_updateRoot.isEmpty() || !QDir().mkpath(m_updateRoot)) {
        return failure(QStringLiteral("update_storage_unavailable"),
                       QStringLiteral("headless update storage is unavailable"));
    }
    const QString transaction = QDir(m_updateRoot).filePath(
            QStringLiteral("transaction-%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces)));
    const QString payloadDirectory = QDir(transaction).filePath(QStringLiteral("payload"));
    const QString archivePath = QDir(transaction).filePath(QStringLiteral("artifact.tar.gz"));
    if (!QDir().mkpath(payloadDirectory)) {
        return failure(QStringLiteral("update_storage_unavailable"),
                       QStringLiteral("headless update staging directory cannot be created"));
    }

    QString error;
    if (!download(candidate, archivePath, &error)
        || !extract(candidate, archivePath, payloadDirectory, &error)
        || !install(candidate, payloadDirectory, currentVersion, &error)) {
        // Keep the transaction journal and any rollback evidence for recovery;
        // only a failed download/extraction without a journal is disposable.
        if (!QFileInfo::exists(m_journalPath)) {
            QDir(transaction).removeRecursively();
        }
        return failure(QStringLiteral("update_install_failed"),
                       error.isEmpty() ? QStringLiteral("headless update installation failed") : error);
    }
    if (m_lastState != QStringLiteral("restart_pending")) {
        m_lastState = QStringLiteral("applied");
        m_lastAppliedVersion = candidate.version;
    }
    if (!saveState()) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("headless update state could not be persisted after transaction"));
    }
    return { true, m_lastState == QStringLiteral("restart_pending")
                      ? QStringLiteral("restart_pending") : QStringLiteral("updated"),
             QStringLiteral("headless update transaction committed; restart health acknowledgement is pending") };
}

HeadlessUpdateResult HeadlessUpdateManager::rollback()
{
    m_lastError.clear();
    QString error;
    if (m_rollbackDirectory.isEmpty()) {
        return failure(QStringLiteral("no_rollback"),
                       QStringLiteral("no verified headless rollback is available"));
    }
    if (!restoreRollback(&error)) {
        return failure(m_lastState == QStringLiteral("recovery_required")
                           ? QStringLiteral("recovery_required") : QStringLiteral("rollback_failed"),
                       error.isEmpty() ? QStringLiteral("headless rollback failed") : error);
    }
    m_lastState = QStringLiteral("rollback_restart_pending");
    m_lastAppliedVersion.clear();
    if (!saveState()) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("headless rollback state could not be persisted"));
    }
    return { true, QStringLiteral("rollback_restart_pending"),
             QStringLiteral("headless rollback installed; restart health acknowledgement is pending") };
}

QJsonObject HeadlessUpdateManager::status() const
{
    return QJsonObject {
        { QStringLiteral("state"), m_lastState },
        { QStringLiteral("lastCheckedAt"), m_lastCheckedAt },
        { QStringLiteral("lastAppliedVersion"), m_lastAppliedVersion },
        { QStringLiteral("candidatePlatform"), m_candidatePlatform },
        { QStringLiteral("rollbackAvailable"), !m_rollbackDirectory.isEmpty() },
        { QStringLiteral("rollbackVersion"), m_rollbackVersion },
        { QStringLiteral("recoveryRequired"), !m_stateValid
                                               || m_lastState == QStringLiteral("recovery_required") },
        { QStringLiteral("lastError"), m_lastError },
    };
}

HeadlessUpdateResult HeadlessUpdateManager::failure(const QString &code,
                                                    const QString &message)
{
    m_lastState = code;
    m_lastError = message;
    saveState();
    return { false, code, message };
}

HeadlessUpdateResult HeadlessUpdateManager::parseManifest(
        const QByteArray &manifest, const QUrl &manifestUrl,
        const QString &publicKeyPath, const QString &currentVersion,
        Candidate &candidate) const
{
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(manifest, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        return { false, QStringLiteral("invalid_manifest"), QStringLiteral("headless update manifest is not JSON") };
    }
    const QJsonObject envelope = document.object();
    if (!isObjectWithOnly(envelope, { QStringLiteral("schema"),
                                      QStringLiteral("signatureAlgorithm"),
                                      QStringLiteral("payload"), QStringLiteral("signature") })
        || envelope.value(QStringLiteral("schema")).toString()
               != QStringLiteral("amnezia-selfhosted-update-v1")
        || envelope.value(QStringLiteral("signatureAlgorithm")).toString()
               != QStringLiteral("Ed25519")) {
        return { false, QStringLiteral("invalid_manifest"), QStringLiteral("headless update manifest envelope is invalid") };
    }

    QByteArray payloadBytes;
    if (!verifyEnvelope(envelope, publicKeyPath, payloadBytes)
        || payloadBytes.size() > MaximumManifestBytes) {
        return { false, QStringLiteral("signature_invalid"), QStringLiteral("headless update manifest signature is invalid") };
    }
    const QJsonDocument payloadDocument = QJsonDocument::fromJson(payloadBytes, &parseError);
    if (parseError.error != QJsonParseError::NoError || !payloadDocument.isObject()) {
        return { false, QStringLiteral("invalid_manifest"), QStringLiteral("signed headless update payload is invalid") };
    }
    const QJsonObject payload = payloadDocument.object();
    if (!isObjectWithOnly(payload, { QStringLiteral("schema"), QStringLiteral("version"),
                                     QStringLiteral("platforms"), QStringLiteral("autoInstall"),
                                     QStringLiteral("changelog"), QStringLiteral("releaseDate") })) {
        return { false, QStringLiteral("invalid_manifest"), QStringLiteral("signed headless update payload has unknown fields") };
    }
    qint64 schema = 0;
    if (!jsonInteger(payload.value(QStringLiteral("schema")), 1, 1, schema)
        || !payload.value(QStringLiteral("version")).isString()
        || !validVersion(payload.value(QStringLiteral("version")).toString())) {
        return { false, QStringLiteral("invalid_manifest"), QStringLiteral("signed headless update version is invalid") };
    }
    const QString version = payload.value(QStringLiteral("version")).toString();
    QVersionNumber current;
    QVersionNumber next;
    if (!validVersion(currentVersion)) {
        // A malformed local version can never be treated as an invitation to
        // update.
        return { false, QStringLiteral("invalid_current_version"), QStringLiteral("running headless version is invalid") };
    }
    current = QVersionNumber::fromString(currentVersion);
    next = QVersionNumber::fromString(version);
    if (next <= current) {
        return { true, QStringLiteral("no_update"), QStringLiteral("headless client is up to date") };
    }

    const QJsonValue platformsValue = payload.value(QStringLiteral("platforms"));
    if (!platformsValue.isObject()) {
        return { false, QStringLiteral("invalid_manifest"), QStringLiteral("headless update platforms are missing") };
    }
    const QJsonObject platforms = platformsValue.toObject();
    QString selectedPlatform;
    for (const QString &platform : { QStringLiteral("linux-headless-x64"),
                                      QStringLiteral("linux-headless") }) {
        if (platforms.value(platform).isObject()) {
            selectedPlatform = platform;
            break;
        }
    }
    if (selectedPlatform.isEmpty()) {
        return { true, QStringLiteral("no_headless_artifact"),
                 QStringLiteral("manifest contains no Linux headless artifact") };
    }
    const QJsonObject artifact = platforms.value(selectedPlatform).toObject();
    if (!isObjectWithOnly(artifact, { QStringLiteral("url"), QStringLiteral("path"),
                                      QStringLiteral("sha256"), QStringLiteral("size"),
                                      QStringLiteral("autoInstall"), QStringLiteral("format") })) {
        return { false, QStringLiteral("invalid_manifest"), QStringLiteral("headless artifact has unknown fields") };
    }
    const QString rawUrl = artifact.value(QStringLiteral("url")).toString(
            artifact.value(QStringLiteral("path")).toString());
    QUrl resolved;
    if (!validArtifactUrl(manifestUrl, rawUrl, resolved)
        || artifact.value(QStringLiteral("sha256")).toString()
               != artifact.value(QStringLiteral("sha256")).toString().toLower()
        || !validSha256(artifact.value(QStringLiteral("sha256")).toString())
        || artifact.value(QStringLiteral("format")).toString()
               != QString::fromLatin1(HeadlessArtifactFormat)) {
        return { false, QStringLiteral("invalid_manifest"), QStringLiteral("headless artifact metadata is invalid") };
    }
    qint64 size = -1;
    if (!jsonInteger(artifact.value(QStringLiteral("size")), 1, MaximumArtifactBytes, size)) {
        return { false, QStringLiteral("invalid_manifest"), QStringLiteral("headless artifact size is invalid") };
    }
    if (artifact.contains(QStringLiteral("autoInstall"))
        && !artifact.value(QStringLiteral("autoInstall")).isBool()) {
        return { false, QStringLiteral("invalid_manifest"), QStringLiteral("headless artifact autoInstall is invalid") };
    }
    candidate.version = version;
    candidate.platform = selectedPlatform;
    candidate.url = resolved;
    candidate.sha256 = artifact.value(QStringLiteral("sha256")).toString();
    candidate.size = size;
    candidate.autoInstall = artifact.value(QStringLiteral("autoInstall"))
            .toBool(payload.value(QStringLiteral("autoInstall")).toBool(false));
    candidate.format = artifact.value(QStringLiteral("format")).toString();
    return { true, QStringLiteral("update_available"), QStringLiteral("signed headless update is available") };
}

bool HeadlessUpdateManager::download(const Candidate &candidate, const QString &path,
                                     QString *error) const
{
    QNetworkAccessManager manager;
    QNetworkRequest request(candidate.url);
    request.setTransferTimeout(NetworkTimeoutMs);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::ManualRedirectPolicy);
    QNetworkReply *reply = manager.get(request);
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        reply->abort();
        reply->deleteLater();
        if (error) *error = QStringLiteral("headless update artifact cannot be staged");
        return false;
    }
    QCryptographicHash hash(QCryptographicHash::Sha256);
    qint64 received = 0;
    bool writeFailed = false;
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(reply, &QIODevice::readyRead, &loop, [&]() {
        const QByteArray chunk = reply->readAll();
        received += chunk.size();
        if (received > candidate.size || received > MaximumArtifactBytes
            || file.write(chunk) != chunk.size()) {
            writeFailed = true;
            reply->abort();
            return;
        }
        hash.addData(chunk);
    });
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    timer.start(NetworkTimeoutMs);
    loop.exec();
    if (!reply->isFinished()) {
        reply->abort();
    }
    const QByteArray tail = reply->readAll();
    if (!tail.isEmpty() && !writeFailed) {
        received += tail.size();
        if (received > candidate.size || file.write(tail) != tail.size()) {
            writeFailed = true;
        } else {
            hash.addData(tail);
        }
    }
    file.close();
    const bool ok = reply->isFinished() && !writeFailed
            && reply->error() == QNetworkReply::NoError
            && received == candidate.size
            && QString::fromLatin1(hash.result().toHex()) == candidate.sha256;
    reply->deleteLater();
    if (!ok) {
        QFile::remove(path);
        if (error) *error = QStringLiteral("headless update artifact failed size or SHA-256 verification");
    }
    return ok;
}

bool HeadlessUpdateManager::extract(const Candidate &candidate, const QString &archivePath,
                                    const QString &directory, QString *error) const
{
    Q_UNUSED(candidate);
    const QString tar = m_runner->resolveExecutable({ QStringLiteral("tar"), QStringLiteral("/usr/bin/tar") });
    if (tar.isEmpty()) {
        if (error) *error = QStringLiteral("tar is not installed for headless update extraction");
        return false;
    }
    QString listing;
    if (!runProcess(tar, { QStringLiteral("--list"), QStringLiteral("--gzip"),
                           QStringLiteral("--file"), archivePath },
                    ArchiveTimeoutMs, &listing, error)) {
        return false;
    }
    QSet<QString> members;
    for (const QByteArray &lineBytes : listing.toUtf8().split('\n')) {
        QString member = QString::fromUtf8(lineBytes).trimmed();
        if (member.startsWith(QStringLiteral("./"))) {
            member.remove(0, 2);
        }
        if (member.isEmpty() || member.contains(QLatin1Char('/'))
            || member == QStringLiteral(".") || member == QStringLiteral("..")) {
            if (!member.isEmpty()) {
                if (error) *error = QStringLiteral("headless update archive contains an unsafe path");
                return false;
            }
            continue;
        }
        members.insert(member);
    }
    if (!members.contains(QStringLiteral("amneziad"))
        || !members.contains(QStringLiteral("amnezia-cli"))
        || members.size() > 3) {
        if (error) *error = QStringLiteral("headless update archive has an unexpected file set");
        return false;
    }
    if (!runProcess(tar, { QStringLiteral("--extract"), QStringLiteral("--gzip"),
                           QStringLiteral("--file"), archivePath,
                           QStringLiteral("--directory"), directory,
                           QStringLiteral("--no-same-owner"), QStringLiteral("--no-same-permissions") },
                    ArchiveTimeoutMs, nullptr, error)) {
        return false;
    }
    for (const QString &name : { QStringLiteral("amneziad"), QStringLiteral("amnezia-cli") }) {
        const QFileInfo info(QDir(directory).filePath(name));
        if (!info.exists() || !info.isFile() || info.isSymLink()) {
            if (error) *error = QStringLiteral("headless update archive contains a non-regular binary");
            return false;
        }
    }
    return true;
}

bool HeadlessUpdateManager::install(const Candidate &candidate,
                                    const QString &payloadDirectory,
                                    const QString &currentVersion,
                                    QString *error)
{
    const QStringList files { QStringLiteral("amneziad"), QStringLiteral("amnezia-cli") };
    const QFileInfo installInfo(m_installDirectory);
    if (!installInfo.isDir() || installInfo.isSymLink()) {
        if (error) *error = QStringLiteral("headless install directory is not a safe directory");
        return false;
    }
    const QString rollbackDirectory = QDir(m_updateRoot).filePath(
            QStringLiteral("rollback-%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces)));
    if (!QDir().mkpath(rollbackDirectory)) {
        if (error) *error = QStringLiteral("headless rollback directory cannot be created");
        return false;
    }
    QJsonObject journal {
        { QStringLiteral("version"), 1 },
        { QStringLiteral("phase"), QStringLiteral("prepared") },
        { QStringLiteral("candidateVersion"), candidate.version },
        { QStringLiteral("currentVersion"), currentVersion },
        { QStringLiteral("transactionDirectory"), QFileInfo(payloadDirectory).absolutePath() },
        { QStringLiteral("rollbackDirectory"), rollbackDirectory },
        { QStringLiteral("installDirectory"), QFileInfo(m_installDirectory).canonicalFilePath() },
    };
    QJsonObject rollbackHashes;
    for (const QString &name : files) {
        const QString destination = QDir(m_installDirectory).filePath(name);
        if (!verifyInstallFile(destination, error)
            || !QFile::copy(destination, QDir(rollbackDirectory).filePath(name))) {
            QDir(rollbackDirectory).removeRecursively();
            if (error) *error = QStringLiteral("existing headless binary cannot be backed up");
            return false;
        }
        const QString digest = sha256ForFile(QDir(rollbackDirectory).filePath(name));
        if (digest.isEmpty()) {
            QDir(rollbackDirectory).removeRecursively();
            if (error) *error = QStringLiteral("existing headless binary hash cannot be recorded");
            return false;
        }
        m_rollbackHashes.insert(name, digest);
        rollbackHashes.insert(name, digest);
    }
    journal.insert(QStringLiteral("rollbackHashes"), rollbackHashes);
    if (!writeJournal(journal, error)) {
        QDir(rollbackDirectory).removeRecursively();
        return false;
    }

    QStringList replaced;
    for (const QString &name : files) {
        const QString source = QDir(payloadDirectory).filePath(name);
        const QString destination = QDir(m_installDirectory).filePath(name);
        if (!atomicReplace(source, destination, error)) {
            QString rollbackError;
            for (const QString &restored : replaced) {
                if (!atomicReplace(QDir(rollbackDirectory).filePath(restored),
                                   QDir(m_installDirectory).filePath(restored), &rollbackError)) {
                    const QString message = QStringLiteral("headless update failed and rollback also failed; recovery is required");
                    if (error) *error = message;
                    m_lastState = QStringLiteral("recovery_required");
                    m_lastError = message;
                    saveState();
                    return false;
                }
            }
            return false;
        }
        replaced.append(name);
    }

    journal.insert(QStringLiteral("phase"), QStringLiteral("replaced"));
    if (!writeJournal(journal, error)) {
        if (error) *error = QStringLiteral("headless update replacement receipt cannot be persisted; recovery is required");
        m_lastState = QStringLiteral("recovery_required");
        saveState();
        return false;
    }

    m_rollbackDirectory = rollbackDirectory;
    m_rollbackVersion = currentVersion;
    if (!saveState()) {
        if (error) *error = QStringLiteral("headless update receipt cannot be persisted");
        return false;
    }
    m_lastAppliedVersion = candidate.version;
    m_lastState = QStringLiteral("restart_pending");
    if (!saveState()) {
        if (error) *error = QStringLiteral("headless restart receipt cannot be persisted");
        QString rollbackError;
        for (const QString &name : files) {
            if (!atomicReplace(QDir(rollbackDirectory).filePath(name),
                               QDir(m_installDirectory).filePath(name), &rollbackError)) {
                if (error) *error = QStringLiteral("headless update receipt failed and rollback also failed; recovery is required");
                m_lastState = QStringLiteral("recovery_required");
                saveState();
                return false;
            }
        }
        QDir(rollbackDirectory).removeRecursively();
        m_rollbackDirectory.clear();
        m_rollbackVersion.clear();
        m_lastAppliedVersion.clear();
        m_lastState = QStringLiteral("update_install_failed");
        return false;
    }
    if (!restartService(error)) {
        // The new binaries and verified rollback are intentionally retained.
        // A restart failure is recoverable through the explicit rollback RPC.
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = error ? *error : QStringLiteral("headless service restart failed");
        saveState();
        return false;
    }
    journal.insert(QStringLiteral("phase"), QStringLiteral("restart_pending"));
    if (!writeJournal(journal, error)) {
        m_lastState = QStringLiteral("recovery_required");
        if (error && error->isEmpty()) {
            *error = QStringLiteral("headless restart transaction journal could not be persisted");
        }
        saveState();
        return false;
    }
    Q_UNUSED(candidate);
    return true;
}

bool HeadlessUpdateManager::restartService(QString *error) const
{
    const QString systemdRun = m_runner->resolveExecutable(
            { QStringLiteral("systemd-run"), QStringLiteral("/usr/bin/systemd-run") });
    const QString systemctl = m_runner->resolveExecutable(
            { QStringLiteral("systemctl"), QStringLiteral("/usr/bin/systemctl") });
    if (systemdRun.isEmpty() || systemctl.isEmpty()) {
        if (error) *error = QStringLiteral("systemd-run/systemctl is not installed for headless update restart");
        return false;
    }
    const QString unit = QStringLiteral("amnezia-headless-restart-%1")
            .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
    if (!m_runner->startDetached(systemdRun,
                                  { QStringLiteral("--unit=%1").arg(unit),
                                    QStringLiteral("--collect"),
                                    QStringLiteral("--no-block"), systemctl,
                                    QStringLiteral("restart"),
                                    QString::fromLatin1(UpdateServiceName) }).ok) {
        if (error) *error = QStringLiteral("headless service restart failed");
        return false;
    }
    return true;
}

bool HeadlessUpdateManager::restoreRollback(QString *error)
{
    if (m_rollbackDirectory.isEmpty()) {
        if (error) *error = QStringLiteral("no rollback directory is recorded");
        return false;
    }
    const QStringList files { QStringLiteral("amneziad"), QStringLiteral("amnezia-cli") };
    QStringList replaced;
    for (const QString &name : files) {
        const QString backup = QDir(m_rollbackDirectory).filePath(name);
        if (!verifyRollbackFile(backup, m_rollbackHashes.value(name), error)) {
            if (error && error->isEmpty()) {
                *error = QStringLiteral("rollback binary failed containment or hash verification");
            }
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = error ? *error : QStringLiteral("rollback binary failed verification");
            saveState();
            return false;
        }
        const QString staged = QDir(m_rollbackDirectory).filePath(
                QStringLiteral(".%1.restore-%2").arg(name,
                    QUuid::createUuid().toString(QUuid::WithoutBraces)));
        if (!QFile::copy(backup, staged)
            || !atomicReplace(staged, QDir(m_installDirectory).filePath(name), error)) {
            if (error && error->isEmpty()) *error = QStringLiteral("rollback binary could not be staged");
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = error ? *error : QStringLiteral("rollback staging failed");
            saveState();
            return false;
        }
        replaced.append(name);
    }
    if (!restartService(error)) {
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = error ? *error : QStringLiteral("headless rollback restart failed");
        saveState();
        return false;
    }
    QJsonObject journalObject;
    if (!m_journalPath.isEmpty()) {
        QFile journalFile(m_journalPath);
        QJsonParseError journalError;
        const QJsonDocument journal = journalFile.open(QIODevice::ReadOnly)
                ? QJsonDocument::fromJson(journalFile.readAll(), &journalError) : QJsonDocument();
        if (journal.isObject()) journalObject = journal.object();
    }
    if (journalObject.isEmpty()) {
        if (error) *error = QStringLiteral("rollback transaction journal is missing or invalid");
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = error ? *error : QStringLiteral("rollback transaction journal is missing or invalid");
        saveState();
        return false;
    }
    journalObject.insert(QStringLiteral("phase"), QStringLiteral("rollback_restart_pending"));
    if (!writeJournal(journalObject, error)) {
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = error ? *error : QStringLiteral("rollback transaction journal failed");
        saveState();
        return false;
    }
    return true;
}

bool HeadlessUpdateManager::loadState()
{
    if (m_statePath.isEmpty()) {
        return true;
    }
    QFile file(m_statePath);
    if (!file.exists()) {
        return true;
    }
    if (!file.open(QIODevice::ReadOnly)) {
        m_stateValid = false;
        return false;
    }
    QJsonParseError error;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &error);
    if (error.error != QJsonParseError::NoError || !document.isObject()) {
        m_stateValid = false;
        return false;
    }
    const QJsonObject object = document.object();
    m_lastCheckedAt = object.value(QStringLiteral("lastCheckedAt")).toString();
    m_lastAppliedVersion = object.value(QStringLiteral("lastAppliedVersion")).toString();
    m_lastState = object.value(QStringLiteral("state")).toString(m_lastState);
    m_rollbackDirectory = object.value(QStringLiteral("rollbackDirectory")).toString();
    m_rollbackVersion = object.value(QStringLiteral("rollbackVersion")).toString();
    m_lastError = object.value(QStringLiteral("lastError")).toString();
    m_rollbackHashes.clear();
    const QJsonObject rollbackHashes = object.value(QStringLiteral("rollbackHashes")).toObject();
    for (auto it = rollbackHashes.constBegin(); it != rollbackHashes.constEnd(); ++it) {
        if (!it.value().isString() || !validSha256(it.value().toString())) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless rollback hash receipt is invalid");
            return false;
        }
        m_rollbackHashes.insert(it.key(), it.value().toString());
    }
    if (!m_rollbackDirectory.isEmpty()
        && !QFileInfo(m_rollbackDirectory).isDir()) {
        m_rollbackDirectory.clear();
        m_rollbackVersion.clear();
        m_rollbackHashes.clear();
    } else if (!m_rollbackDirectory.isEmpty()) {
        const QString rootPath = QFileInfo(m_updateRoot).canonicalFilePath();
        const QString rollbackPath = QFileInfo(m_rollbackDirectory).canonicalFilePath();
        if (rootPath.isEmpty() || rollbackPath.isEmpty()
            || !rollbackPath.startsWith(rootPath + QDir::separator())
            || !validVersion(m_rollbackVersion)
            || !m_rollbackHashes.contains(QStringLiteral("amneziad"))
            || !m_rollbackHashes.contains(QStringLiteral("amnezia-cli"))) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless rollback receipt is outside the trusted update root");
            return false;
        }
    }
    if (!m_journalPath.isEmpty() && QFileInfo::exists(m_journalPath)) {
        QFile journalFile(m_journalPath);
        QJsonParseError journalError;
        if (!journalFile.open(QIODevice::ReadOnly)) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            return false;
        }
        const QJsonDocument journal = QJsonDocument::fromJson(journalFile.readAll(), &journalError);
        const QString phase = journal.isObject()
                ? journal.object().value(QStringLiteral("phase")).toString() : QString();
        if (journalError.error != QJsonParseError::NoError
            || !journal.isObject()
            || (phase != QStringLiteral("restart_pending")
                && phase != QStringLiteral("rollback_restart_pending")
                && phase != QStringLiteral("replaced")
                && phase != QStringLiteral("prepared"))) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless update transaction journal is invalid");
            return false;
        }
        if (m_rollbackDirectory.isEmpty() && journal.object().value(QStringLiteral("rollbackDirectory")).isString()) {
            m_rollbackDirectory = journal.object().value(QStringLiteral("rollbackDirectory")).toString();
            m_rollbackVersion = journal.object().value(QStringLiteral("currentVersion")).toString();
            const QJsonObject hashes = journal.object().value(QStringLiteral("rollbackHashes")).toObject();
            for (auto it = hashes.constBegin(); it != hashes.constEnd(); ++it) {
                if (it.value().isString() && validSha256(it.value().toString())) {
                    m_rollbackHashes.insert(it.key(), it.value().toString());
                }
            }
        }
        if ((phase == QStringLiteral("restart_pending")
             || phase == QStringLiteral("rollback_restart_pending"))
            && (m_rollbackDirectory.isEmpty() || !validVersion(m_rollbackVersion)
                || !m_rollbackHashes.contains(QStringLiteral("amneziad"))
                || !m_rollbackHashes.contains(QStringLiteral("amnezia-cli")))) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless transaction journal has incomplete rollback evidence");
            return false;
        }
        if ((phase == QStringLiteral("restart_pending")
             || phase == QStringLiteral("rollback_restart_pending"))
            && (!verifyRollbackFile(QDir(m_rollbackDirectory).filePath(QStringLiteral("amneziad")),
                                    m_rollbackHashes.value(QStringLiteral("amneziad")), nullptr)
                || !verifyRollbackFile(QDir(m_rollbackDirectory).filePath(QStringLiteral("amnezia-cli")),
                                       m_rollbackHashes.value(QStringLiteral("amnezia-cli")), nullptr))) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless transaction journal rollback evidence is unsafe");
            return false;
        }
        if (phase == QStringLiteral("restart_pending")
            && !m_lastAppliedVersion.isEmpty()) {
            // This is the expected post-restart acknowledgement window.  The
            // next checkAndApply() must health-check both binaries before
            // removing the journal.
            m_lastState = QStringLiteral("restart_pending");
        } else if (phase == QStringLiteral("rollback_restart_pending")
                   && !m_rollbackVersion.isEmpty()) {
            m_lastState = QStringLiteral("rollback_restart_pending");
        } else {
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless update transaction requires recovery");
        }
    } else if (m_lastState == QStringLiteral("restart_pending")) {
        // Legacy v1 persisted the state before restart but had no durable
        // transaction journal. Do not silently acknowledge an unverifiable
        // binary pair; require explicit rollback/recovery.
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("legacy restart_pending state has no transaction journal");
    }
    return true;
}

bool HeadlessUpdateManager::saveState() const
{
    if (m_statePath.isEmpty()) {
        return true;
    }
    const QFileInfo info(m_statePath);
    if (!QDir().mkpath(info.absolutePath())) {
        return false;
    }
    QSaveFile file(m_statePath);
    if (!file.open(QIODevice::WriteOnly)) {
        return false;
    }
    QJsonObject rollbackHashes;
    for (auto it = m_rollbackHashes.cbegin(); it != m_rollbackHashes.cend(); ++it) {
        rollbackHashes.insert(it.key(), it.value());
    }
    const QJsonObject object {
        { QStringLiteral("version"), 2 },
        { QStringLiteral("state"), m_lastState },
        { QStringLiteral("lastCheckedAt"), m_lastCheckedAt },
        { QStringLiteral("lastAppliedVersion"), m_lastAppliedVersion },
        { QStringLiteral("rollbackDirectory"), m_rollbackDirectory },
        { QStringLiteral("rollbackVersion"), m_rollbackVersion },
        { QStringLiteral("rollbackHashes"), rollbackHashes },
        { QStringLiteral("lastError"), m_lastError },
    };
    if (file.write(QJsonDocument(object).toJson(QJsonDocument::Compact)) < 0
        || !file.commit()) {
        return false;
    }
#ifndef Q_OS_WIN
    QFile::setPermissions(m_statePath, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
#endif
    return true;
}

bool HeadlessUpdateManager::writeJournal(const QJsonObject &journal, QString *error) const
{
    if (m_journalPath.isEmpty()) {
        if (error) *error = QStringLiteral("headless update journal path is unavailable");
        return false;
    }
    const QFileInfo info(m_journalPath);
    if (!QDir().mkpath(info.absolutePath())) {
        if (error) *error = QStringLiteral("headless update journal directory cannot be created");
        return false;
    }
    QSaveFile file(m_journalPath);
    if (!file.open(QIODevice::WriteOnly)
        || file.write(QJsonDocument(journal).toJson(QJsonDocument::Compact)) < 0
        || !file.commit()) {
        if (error) *error = QStringLiteral("headless update journal cannot be persisted");
        return false;
    }
#ifndef Q_OS_WIN
    QFile::setPermissions(m_journalPath, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
#endif
    return true;
}

QString HeadlessUpdateManager::trustedUpdatePublicKeyPath()
{
    return QString::fromLatin1(TrustedUpdateKeyPath);
}

bool HeadlessUpdateManager::verifyTrustedKey(const QString &configuredPath, QString *error) const
{
    const QString trusted = trustedUpdatePublicKeyPath();
    const QFileInfo configured(configuredPath);
    const QFileInfo expected(trusted);
    if (configuredPath != trusted || configured.canonicalFilePath() != expected.canonicalFilePath()
        || !configured.isFile() || configured.isSymLink()) {
        if (error) *error = QStringLiteral("update trust anchor must be the fixed root-owned key at /etc/amnezia/update-public-key.pem");
        return false;
    }
#ifndef Q_OS_WIN
    if (configured.ownerId() != 0 || (configured.permissions() & (QFileDevice::WriteGroup
            | QFileDevice::WriteOther)) != 0) {
        if (error) *error = QStringLiteral("update trust anchor must be root-owned and not group/world writable");
        return false;
    }
#endif
    return true;
}

bool HeadlessUpdateManager::verifyInstallFile(const QString &path, QString *error) const
{
    const QFileInfo info(path);
    const QFileInfo root(m_installDirectory);
    const QString rootPath = root.canonicalFilePath();
    const QString filePath = info.canonicalFilePath();
    if (!root.isDir() || root.isSymLink() || filePath.isEmpty()
        || !filePath.startsWith(rootPath + QDir::separator())
        || !info.isFile() || info.isSymLink()) {
        if (error) *error = QStringLiteral("headless install file is outside the trusted installation root");
        return false;
    }
#ifndef Q_OS_WIN
    if (info.ownerId() != 0 || (info.permissions() & (QFileDevice::WriteGroup
            | QFileDevice::WriteOther)) != 0) {
        if (error) *error = QStringLiteral("headless install file must be root-owned and not group/world writable");
        return false;
    }
#endif
    return true;
}

QString HeadlessUpdateManager::sha256ForFile(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }
    QCryptographicHash hash(QCryptographicHash::Sha256);
    while (!file.atEnd()) {
        const QByteArray chunk = file.read(1024 * 1024);
        if (chunk.isEmpty() && !file.atEnd()) return {};
        hash.addData(chunk);
    }
    return QString::fromLatin1(hash.result().toHex());
}

bool HeadlessUpdateManager::verifyRollbackFile(const QString &path,
                                               const QString &expectedSha256,
                                               QString *error) const
{
    const QFileInfo info(path);
    const QFileInfo root(m_updateRoot);
    const QString rootPath = root.canonicalFilePath();
    const QString filePath = info.canonicalFilePath();
    if (!root.isDir() || filePath.isEmpty()
        || !filePath.startsWith(rootPath + QDir::separator())
        || !info.isFile() || info.isSymLink()
        || expectedSha256.isEmpty() || sha256ForFile(path) != expectedSha256) {
        if (error) *error = QStringLiteral("rollback evidence failed containment, ownership or SHA-256 verification");
        return false;
    }
#ifndef Q_OS_WIN
    if (info.ownerId() != 0 || (info.permissions() & (QFileDevice::WriteGroup
            | QFileDevice::WriteOther)) != 0) {
        if (error) *error = QStringLiteral("rollback evidence must be root-owned and not group/world writable");
        return false;
    }
#endif
    return true;
}

bool HeadlessUpdateManager::verifyEnvelope(const QJsonObject &envelope,
                                           const QString &publicKeyPath,
                                           QByteArray &payload)
{
    if (!envelope.value(QStringLiteral("payload")).isString()
        || !envelope.value(QStringLiteral("signature")).isString()) {
        return false;
    }
    QByteArray signature;
    if (!decodeStrict(envelope.value(QStringLiteral("payload")).toString().toUtf8(), true, payload)
        || !decodeStrict(envelope.value(QStringLiteral("signature")).toString().toUtf8(), false, signature)
        || payload.isEmpty() || signature.size() != 64) {
        return false;
    }
    QFile keyFile(publicKeyPath);
    if (!keyFile.open(QIODevice::ReadOnly) || keyFile.size() > 16 * 1024) {
        return false;
    }
    const QByteArray pem = keyFile.readAll();
    BIO *bio = BIO_new_mem_buf(pem.constData(), pem.size());
    if (!bio) {
        return false;
    }
    EVP_PKEY *key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!key) {
        return false;
    }
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    const bool ok = context && EVP_PKEY_base_id(key) == EVP_PKEY_ED25519
            && EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key) == 1
            && EVP_DigestVerify(context,
                                reinterpret_cast<const unsigned char *>(signature.constData()),
                                static_cast<size_t>(signature.size()),
                                reinterpret_cast<const unsigned char *>(payload.constData()),
                                static_cast<size_t>(payload.size())) == 1;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return ok;
}

bool HeadlessUpdateManager::decodeStrict(const QByteArray &encoded, bool urlSafe,
                                         QByteArray &decoded)
{
    if (encoded.isEmpty()) {
        return false;
    }
    bool padding = false;
    int paddingCount = 0;
    for (const char ch : encoded) {
        const bool alpha = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
        const bool digit = ch >= '0' && ch <= '9';
        const bool symbol = urlSafe ? (ch == '-' || ch == '_') : (ch == '+' || ch == '/');
        if (ch == '=') {
            padding = true;
            ++paddingCount;
        } else if (padding || (!alpha && !digit && !symbol)) {
            return false;
        }
    }
    if (paddingCount > 2 || (urlSafe && paddingCount != 0)
        || encoded.size() % 4 == 1) {
        return false;
    }
    const QByteArray::Base64Options options = urlSafe
            ? QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals
            : QByteArray::Base64Encoding;
    decoded = QByteArray::fromBase64(encoded, options);
    if (decoded.isEmpty()) {
        return false;
    }
    const QByteArray canonical = decoded.toBase64(urlSafe
            ? QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals
            : QByteArray::Base64Encoding);
    return canonical == encoded;
}

bool HeadlessUpdateManager::validVersion(const QString &value)
{
    const QStringList parts = value.split(QLatin1Char('.'), Qt::KeepEmptyParts);
    if (parts.size() != 4 || value != value.trimmed()) {
        return false;
    }
    for (const QString &part : parts) {
        if (part.isEmpty() || (part.size() > 1 && part.startsWith(QLatin1Char('0')))) {
            return false;
        }
        for (const QChar ch : part) {
            if (!ch.isDigit()) {
                return false;
            }
        }
    }
    return !QVersionNumber::fromString(value).isNull();
}

bool HeadlessUpdateManager::validSha256(const QString &value)
{
    if (value.size() != 64) {
        return false;
    }
    for (const QChar ch : value) {
        if (!((ch >= QLatin1Char('0') && ch <= QLatin1Char('9'))
              || (ch >= QLatin1Char('a') && ch <= QLatin1Char('f')))) {
            return false;
        }
    }
    return true;
}

bool HeadlessUpdateManager::validArtifactUrl(const QUrl &manifestUrl,
                                             const QString &rawUrl,
                                             QUrl &resolved)
{
    if (rawUrl.trimmed().isEmpty()) {
        return false;
    }
    const QUrl candidate(rawUrl, QUrl::StrictMode);
    if (!candidate.isValid() || candidate.userInfo().size() > 0
        || candidate.hasFragment()) {
        return false;
    }
    resolved = candidate.isRelative() ? manifestUrl.resolved(candidate) : candidate;
    return resolved.isValid() && resolved.scheme() == QStringLiteral("https")
            && !resolved.host().isEmpty() && resolved.userInfo().isEmpty()
            && !resolved.hasFragment()
            && resolved.host().compare(manifestUrl.host(), Qt::CaseInsensitive) == 0
            && (resolved.port() == -1 || manifestUrl.port() == -1
                || resolved.port() == manifestUrl.port());
}

bool HeadlessUpdateManager::runProcess(const QString &program,
                                       const QStringList &arguments,
                                       int timeoutMs, QString *output,
                                       QString *error)
{
    QProcess process;
    process.setProgram(program);
    process.setArguments(arguments);
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start();
    if (!process.waitForStarted(3000) || !process.waitForFinished(timeoutMs)) {
        process.kill();
        process.waitForFinished(2000);
        if (error) *error = QStringLiteral("headless update archive command failed to start or timed out");
        return false;
    }
    const QByteArray bytes = process.readAll();
    if (bytes.size() > 64 * 1024 || process.exitStatus() != QProcess::NormalExit
        || process.exitCode() != 0) {
        if (error) *error = QStringLiteral("headless update archive command failed");
        return false;
    }
    if (output) {
        *output = QString::fromUtf8(bytes);
    }
    return true;
}

bool HeadlessUpdateManager::atomicReplace(const QString &source,
                                          const QString &destination,
                                          QString *error)
{
    const QFileInfo sourceInfo(source);
    if (!sourceInfo.isFile() || sourceInfo.isSymLink()) {
        if (error) *error = QStringLiteral("headless update source is not a regular file");
        return false;
    }
    const QString temporary = QDir(QFileInfo(destination).absolutePath()).filePath(
            QStringLiteral(".%1.update-%2").arg(QFileInfo(destination).fileName(),
                                                  QUuid::createUuid().toString(QUuid::WithoutBraces)));
    QFile::remove(temporary);
    if (!QFile::copy(source, temporary)) {
        if (error) *error = QStringLiteral("headless update binary cannot be copied into place");
        return false;
    }
#ifndef Q_OS_WIN
    QFile::setPermissions(temporary, QFileDevice::ReadOwner | QFileDevice::WriteOwner
                              | QFileDevice::ExeOwner | QFileDevice::ReadGroup
                              | QFileDevice::ExeGroup | QFileDevice::ReadOther
                              | QFileDevice::ExeOther);
    if (::rename(temporary.toLocal8Bit().constData(), destination.toLocal8Bit().constData()) != 0) {
        QFile::remove(temporary);
        if (error) *error = QStringLiteral("headless update binary cannot be atomically replaced");
        return false;
    }
#else
    if (!QFile::remove(destination) || !QFile::rename(temporary, destination)) {
        QFile::remove(temporary);
        if (error) *error = QStringLiteral("headless update binary cannot be replaced");
        return false;
    }
#endif
    return true;
}

} // namespace amnezia::headless
