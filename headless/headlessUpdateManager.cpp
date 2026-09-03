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
#include <QHostAddress>
#include <QLockFile>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <cerrno>
#include <cmath>
#include <cstring>
#include <cstdio>
#include <utility>
#include <algorithm>

#ifndef Q_OS_WIN
#include <fcntl.h>
#include <sys/stat.h>
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
constexpr auto GcMarkerFileName = "garbage-collection.json";

const QStringList &managedPayloadFiles()
{
    static const QStringList files {
        // The signed auto-update payload is deliberately binary-only.  The
        // systemd unit, installer and runtime metadata belong to the separate
        // operator-invoked provisioning bundle.
        QStringLiteral("amneziad"), QStringLiteral("amnezia-cli")
    };
    return files;
}

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

int effectivePort(const QUrl &url)
{
    if (url.port() != -1) return url.port();
    if (url.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0) return 443;
    if (url.scheme().compare(QStringLiteral("http"), Qt::CaseInsensitive) == 0) return 80;
    return -1;
}

bool samePinnedUrl(const QUrl &expected, const QUrl &actual)
{
    return actual.isValid()
        && actual.scheme().compare(expected.scheme(), Qt::CaseInsensitive) == 0
        && actual.host().compare(expected.host(), Qt::CaseInsensitive) == 0
        && effectivePort(actual) == effectivePort(expected)
        && actual.path() == expected.path()
        && actual.query() == expected.query();
}

bool ipv4ContainedByRoute(const QHostAddress &address, const QString &route)
{
    if (address.protocol() != QAbstractSocket::IPv4Protocol) return false;
    const QStringList parts = route.trimmed().split(QLatin1Char('/'));
    if (parts.size() < 1 || parts.size() > 2) return false;
    QHostAddress network(parts.at(0));
    if (network.protocol() != QAbstractSocket::IPv4Protocol) return false;
    bool ok = true;
    const int prefix = parts.size() == 2 ? parts.at(1).toInt(&ok) : 32;
    if (!ok || prefix < 0 || prefix > 32) return false;
    const quint32 mask = prefix == 0 ? 0u : 0xffffffffu << (32 - prefix);
    return (address.toIPv4Address() & mask) == (network.toIPv4Address() & mask);
}

bool privateOrLocalIpv4(const QHostAddress &address)
{
    if (address.protocol() != QAbstractSocket::IPv4Protocol) return false;
    const quint32 value = address.toIPv4Address();
    return ((value >> 24) == 10u)
        || ((value & 0xfff00000u) == 0xac100000u) // RFC 1918 172.16/12
        || ((value & 0xffff0000u) == 0xc0a80000u) // RFC 1918 192.168/16
        || ((value & 0xffc00000u) == 0x64400000u) // RFC 6598 CGNAT
        || ((value & 0xffffff00u) == 0xc0000000u) // RFC 5737 documentation
        || ((value & 0xff000000u) == 0x7f000000u); // loopback
}

bool safeUpdateUrl(const Profile &profile, const QUrl &url)
{
    if (!url.isValid() || url.host().isEmpty() || !url.userInfo().isEmpty()
        || url.hasFragment() || (url.port() != -1 && (url.port() < 1 || url.port() > 65535))) {
        return false;
    }
    if (url.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0) {
        // The updater has no DNS pinning facility.  Requiring a literal IP
        // prevents a signed manifest request from being redirected by DNS to
        // an attacker-controlled endpoint.
        QHostAddress literal(url.host());
        return literal.protocol() != QAbstractSocket::UnknownNetworkLayerProtocol;
    }
    if (url.scheme().compare(QStringLiteral("http"), Qt::CaseInsensitive) != 0) return false;
    QHostAddress literal(url.host());
    if (literal.protocol() != QAbstractSocket::IPv4Protocol) return false;
    if (!privateOrLocalIpv4(literal)) return false;
    return std::any_of(profile.forwardRoutes.cbegin(), profile.forwardRoutes.cend(),
                       [&literal](const QString &route) {
        return ipv4ContainedByRoute(literal, route);
    });
}

bool stableUpdateState(const QString &state)
{
    return state == QStringLiteral("never_checked")
        || state == QStringLiteral("disabled")
        || state == QStringLiteral("no_update")
        || state == QStringLiteral("no_headless_artifact")
        || state == QStringLiteral("unsupported_payload_contract")
        || state == QStringLiteral("applied")
        || state == QStringLiteral("update_available")
        || state == QStringLiteral("updated")
        || state == QStringLiteral("rolled_back")
        || state == QStringLiteral("no_rollback");
}

bool checkableUpdateState(const QString &state)
{
    return stableUpdateState(state)
        || state == QStringLiteral("restart_pending")
        || state == QStringLiteral("rollback_restart_pending");
}

bool hasExactManagedFileSet(const QJsonObject &object)
{
    if (object.size() != managedPayloadFiles().size()) {
        return false;
    }
    for (const QString &name : managedPayloadFiles()) {
        if (!object.contains(name)) {
            return false;
        }
    }
    return true;
}

bool hasUnsupportedThreeFileReceipt(const QJsonObject &object)
{
    // Releases before the binary-only contract recorded the systemd unit as a
    // third managed payload. Keep this stable and operator-visible rather
    // than silently rewriting it as a valid two-file receipt.
    return object.size() == 3
        && object.contains(QString::fromLatin1("amneziad"))
        && object.contains(QString::fromLatin1("amnezia-cli"))
        && object.contains(QString::fromLatin1("amneziad.service"));
}

bool hasExactManagedHashMap(const QMap<QString, QString> &hashes)
{
    const QStringList files = managedPayloadFiles();
    if (hashes.size() != files.size()) {
        return false;
    }
    return std::all_of(files.cbegin(), files.cend(),
                       [&hashes](const QString &name) { return hashes.contains(name); });
}

bool hasExactHeadlessProvisioningFiles(const QJsonValue &value)
{
    if (!value.isArray()) return false;
    const QJsonArray files = value.toArray();
    static const QStringList expected {
        QStringLiteral("install_headless.sh"), QStringLiteral("amneziad"),
        QStringLiteral("amnezia-cli"), QStringLiteral("amneziad.service"),
        QStringLiteral("package-manifest.json"), QStringLiteral("runtime-dependencies.json"),
        QStringLiteral("runtime-dependencies.txt"), QStringLiteral("SHA256SUMS")
    };
    if (files.size() != expected.size()) return false;
    for (qsizetype index = 0; index < files.size(); ++index) {
        if (!files.at(index).isString() || files.at(index).toString() != expected.at(index)) {
            return false;
        }
    }
    return true;
}

#ifndef Q_OS_WIN
bool directorySyncUnsupported(int errorCode)
{
    return errorCode == EINVAL
#ifdef ENOTSUP
        || errorCode == ENOTSUP
#endif
#ifdef EOPNOTSUPP
        || errorCode == EOPNOTSUPP
#endif
        ;
}
#endif

bool durableSyncFileAndDirectory(const QString &path)
{
#ifndef Q_OS_WIN
    const QFileInfo fileInfo(path);
    const QByteArray filePath = fileInfo.absoluteFilePath().toLocal8Bit();
    const int fileFlags = O_RDONLY
#ifdef O_CLOEXEC
        | O_CLOEXEC
#endif
        ;
    const int fileDescriptor = ::open(filePath.constData(), fileFlags);
    if (fileDescriptor < 0) {
        return false;
    }
    const int fileSyncResult = ::fsync(fileDescriptor);
    ::close(fileDescriptor);
    if (fileSyncResult != 0) {
        return false;
    }

    // QSaveFile has already committed the file.  Syncing its parent makes the
    // rename visible after a power loss on filesystems that support directory
    // fsync.  Some Unix filesystems reject directory fsync; the file fsync
    // above remains the portable durable fallback in that case.
    const QByteArray directoryPath = fileInfo.absolutePath().toLocal8Bit();
    const int directoryDescriptor = ::open(directoryPath.constData(), fileFlags);
    if (directoryDescriptor < 0) {
        return directorySyncUnsupported(errno);
    }
    struct stat directoryStatus {};
    const bool isDirectory = ::fstat(directoryDescriptor, &directoryStatus) == 0
        && S_ISDIR(directoryStatus.st_mode);
    if (!isDirectory) {
        ::close(directoryDescriptor);
        return false;
    }
    const int directorySyncResult = ::fsync(directoryDescriptor);
    const int directorySyncError = errno;
    ::close(directoryDescriptor);
    return directorySyncResult == 0 || directorySyncUnsupported(directorySyncError);
#else
    // QSaveFile::commit() uses the native platform commit path on Windows;
    // there is no POSIX descriptor/dirsync fallback in this translation unit.
    Q_UNUSED(path);
    return true;
#endif
}

} // namespace

HeadlessUpdateManager::HeadlessUpdateManager(std::shared_ptr<CommandRunner> runner,
                                             QString statePath,
                                             QString installDirectory,
                                             bool requireRootOwnedFiles)
    : m_runner(runner ? std::move(runner) : std::make_shared<RealCommandRunner>()),
      m_statePath(std::move(statePath)),
      m_installDirectory(installDirectory.trimmed().isEmpty()
                             ? QCoreApplication::applicationDirPath()
                             : std::move(installDirectory)),
      m_requireRootOwnedFiles(requireRootOwnedFiles)
{
    if (!m_statePath.isEmpty()) {
        m_updateRoot = QFileInfo(m_statePath).absolutePath();
        m_updateRoot = QDir(m_updateRoot).filePath(QStringLiteral("updates"));
        m_journalPath = QDir(m_updateRoot).filePath(QStringLiteral("transaction.json"));
        m_rollbackReceiptPath = QDir(m_updateRoot).filePath(QStringLiteral("rollback-receipt.json"));
        m_gcMarkerPath = QDir(m_updateRoot).filePath(QString::fromLatin1(GcMarkerFileName));
        // The update root is part of the state identity.  Create it before
        // reading/writing receipts so canonical paths are stable even when
        // automatic updates are disabled on first start.
        QString directoryError;
        if (!ensureSecureDirectory(m_updateRoot, &directoryError)) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = directoryError;
        }
    }
    loadState();
    collectGarbage();
    if (!m_stateValid && m_lastError.isEmpty()) {
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("headless update storage is not secure");
    }
    if (m_stateValid && m_lastState != QStringLiteral("unsupported_payload_contract")) {
        if (!m_rollbackDirectory.isEmpty() && !loadRollbackReceipt()) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless rollback receipt is invalid");
        } else if (m_rollbackDirectory.isEmpty() && !m_rollbackReceiptPath.isEmpty()
                   && QFileInfo::exists(m_rollbackReceiptPath)) {
            // Once the stable state has cleared rollback identity, a sidecar
            // left by an interrupted cleanup is disposable evidence.  It must
            // not become an independent recovery authority or poison startup.
            // Removal is best-effort so cleanup remains idempotent if another
            // process has already retired the sidecar.
            QFile::remove(m_rollbackReceiptPath);
        }
    }
}

bool HeadlessUpdateManager::ensureSecureDirectory(const QString &path, QString *error) const
{
    if (path.trimmed().isEmpty() || !QDir().mkpath(path)) {
        if (error) *error = QStringLiteral("headless update directory cannot be created");
        return false;
    }
    const QFileInfo directory(path);
    const QFileInfo parent(directory.absolutePath());
    if (!directory.isDir() || directory.isSymLink()
        || !parent.isDir() || parent.isSymLink()) {
        if (error) *error = QStringLiteral("headless update directory is not a safe directory");
        return false;
    }
#ifndef Q_OS_WIN
    if (!QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                      | QFileDevice::ExeOwner)) {
        if (error) *error = QStringLiteral("headless update directory permissions cannot be restricted");
        return false;
    }
    const QFileInfo secured(path);
    const QFileInfo securedParent(parent.absoluteFilePath());
    const auto unsafe = [this](const QFileInfo &info) {
        return !info.isDir() || info.isSymLink()
            || (m_requireRootOwnedFiles && info.ownerId() != 0)
            || (info.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther)) != 0;
    };
    if (unsafe(secured) || (m_requireRootOwnedFiles && unsafe(securedParent))) {
        if (error) *error = QStringLiteral("headless update directory chain must be root-owned and not group/world writable");
        return false;
    }
#endif
    return true;
}

bool HeadlessUpdateManager::writeGcMarker(const QStringList &paths) const
{
    if (m_gcMarkerPath.isEmpty() || paths.isEmpty()) return false;
    if (!ensureSecureDirectory(QFileInfo(m_gcMarkerPath).absolutePath(), nullptr)) return false;
    QSet<QString> entries;
    QFile existing(m_gcMarkerPath);
    if (existing.open(QIODevice::ReadOnly)) {
        QJsonParseError parseError;
        qint64 existingVersion = 0;
        const QJsonDocument document = QJsonDocument::fromJson(existing.readAll(), &parseError);
        if (parseError.error == QJsonParseError::NoError && document.isObject()
            && jsonInteger(document.object().value(QStringLiteral("version")), 1, 1,
                            existingVersion)) {
            const QJsonValue value = document.object().value(QStringLiteral("paths"));
            if (value.isArray()) {
                for (const QJsonValue &entry : value.toArray()) {
                    if (entry.isString() && !entry.toString().trimmed().isEmpty()) {
                        entries.insert(entry.toString());
                    }
                }
            }
        }
    }
    for (const QString &path : paths) {
        if (!path.trimmed().isEmpty()) entries.insert(path);
    }
    QJsonArray pathsJson;
    for (const QString &path : std::as_const(entries)) pathsJson.append(path);
    QSaveFile marker(m_gcMarkerPath);
    if (!marker.open(QIODevice::WriteOnly)
        || marker.write(QJsonDocument(QJsonObject {
                { QStringLiteral("version"), 1 },
                { QStringLiteral("paths"), pathsJson }
            }).toJson(QJsonDocument::Compact)) < 0
        || !marker.commit()) {
        return false;
    }
#ifndef Q_OS_WIN
    QFile::setPermissions(m_gcMarkerPath, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
#endif
    return durableSyncFileAndDirectory(m_gcMarkerPath);
}

void HeadlessUpdateManager::collectGarbage() const
{
    if (m_gcMarkerPath.isEmpty() || !QFileInfo::exists(m_gcMarkerPath)) return;
    QFile marker(m_gcMarkerPath);
    if (!marker.open(QIODevice::ReadOnly)) return;
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(marker.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) return;
    qint64 version = 0;
    const QJsonValue pathValue = document.object().value(QStringLiteral("paths"));
    if (!jsonInteger(document.object().value(QStringLiteral("version")), 1, 1, version)
        || !pathValue.isArray()) return;

    const QString root = QFileInfo(m_updateRoot).canonicalFilePath();
    if (root.isEmpty()) return;
    bool complete = true;
    for (const QJsonValue &entry : pathValue.toArray()) {
        if (!entry.isString()) {
            complete = false;
            continue;
        }
        const QString rawPath = entry.toString();
        const QFileInfo rawInfo(rawPath);
        if (!rawInfo.exists()) continue;
        const QString canonical = rawInfo.canonicalFilePath();
        const QString name = QFileInfo(canonical).fileName();
        const bool safeName = name == QString::fromLatin1("transaction.json")
            || name == QString::fromLatin1("rollback-receipt.json")
            || name.startsWith(QStringLiteral("transaction-"))
            || name.startsWith(QStringLiteral("rollback-"))
            || name.startsWith(QStringLiteral("rollback-current-"))
            || name.startsWith(QStringLiteral("recovery-receipt-"));
        if (rawInfo.isSymLink() || canonical.isEmpty()
            || (canonical != root && !canonical.startsWith(root + QDir::separator()))
            || !safeName) {
            complete = false;
            continue;
        }
        const bool removed = rawInfo.isDir()
            ? QDir(canonical).removeRecursively() : QFile::remove(canonical);
        if (!removed && QFileInfo::exists(canonical)) complete = false;
    }
    if (complete && QFile::remove(m_gcMarkerPath)) {
        durableSyncFileAndDirectory(root);
    }
}

HeadlessUpdateResult HeadlessUpdateManager::checkAndApply(const Profile &profile,
                                                          const QString &currentVersion)
{
    QLockFile processLock(QDir(m_updateRoot).filePath(QStringLiteral("update.lock")));
    processLock.setStaleLockTime(0);
    if (!m_updateRoot.isEmpty() && !processLock.tryLock(0)) {
        return { false, QStringLiteral("update_in_progress"),
                 QStringLiteral("another headless update operation owns the transaction lock") };
    }
    if (m_updateInProgress) {
        return failure(QStringLiteral("update_in_progress"),
                       QStringLiteral("a headless update transaction is already in progress"));
    }
    if (m_lastState == QStringLiteral("unsupported_payload_contract")) {
        return failure(QStringLiteral("unsupported_payload_contract"),
                       QStringLiteral("headless update receipt uses the retired three-file payload contract; run manual provisioning recovery"));
    }
    if (!m_stateValid || !checkableUpdateState(m_lastState)) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("headless update state is not stable; pending evidence requires recovery"));
    }
    if (!m_journalPath.isEmpty() && QFileInfo::exists(m_journalPath)) {
        QFile journalFile(m_journalPath);
        QJsonParseError journalError;
        const QJsonDocument journal = journalFile.open(QIODevice::ReadOnly)
                ? QJsonDocument::fromJson(journalFile.readAll(), &journalError) : QJsonDocument();
        const QString phase = journal.isObject()
                ? journal.object().value(QStringLiteral("phase")).toString() : QString();
        const bool acknowledged = phase == QStringLiteral("acknowledged")
                || phase == QStringLiteral("rollback_acknowledged");
        const bool pendingResume = (m_lastState == QStringLiteral("restart_pending")
                                    && phase == QStringLiteral("restart_pending"))
                || (m_lastState == QStringLiteral("rollback_restart_pending")
                    && phase == QStringLiteral("rollback_restart_pending"));
        if (!acknowledged && !pendingResume) {
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("headless update transaction is not acknowledged; explicit rollback is required"));
        }
    }
    m_updateInProgress = true;
    struct UpdateGuard {
        bool &active;
        ~UpdateGuard() { active = false; }
    } updateGuard { m_updateInProgress };
    m_lastCheckedAt = utcNow();
    m_lastError.clear();
    m_candidatePlatform.clear();

    if (m_lastState == QStringLiteral("restart_pending")
        && (m_lastAppliedVersion.isEmpty() || currentVersion != m_lastAppliedVersion)) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("pending headless update version does not match the running binary"));
    }
    if (m_lastState == QStringLiteral("rollback_restart_pending")
        && (m_rollbackVersion.isEmpty() || currentVersion != m_rollbackVersion)) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("pending headless rollback version does not match the running binary"));
    }

    // The previous transaction persisted this receipt before asking systemd
    // to restart us. Seeing the same version from a newly started daemon is
    // the post-restart health acknowledgement; cleanup remains journal-bound.
    if (m_lastState == QStringLiteral("restart_pending")
        && !m_lastAppliedVersion.isEmpty() && currentVersion == m_lastAppliedVersion) {
        QString healthError;
        for (const QString &name : managedPayloadFiles()) {
            if (!verifyManagedInstallFile(name, &healthError)) {
                return failure(QStringLiteral("recovery_required"),
                               QStringLiteral("updated headless managed files failed post-restart health validation"));
            }
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
        const QJsonObject candidateHashes = journal.value(QStringLiteral("candidateHashes")).toObject();
        const QJsonObject candidateSizes = journal.value(QStringLiteral("candidateSizes")).toObject();
        if (!hasExactManagedFileSet(candidateHashes)
            || !hasExactManagedFileSet(candidateSizes)) {
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("headless update journal has no candidate binary hashes"));
        }
        for (const QString &name : managedPayloadFiles()) {
            qint64 candidateSize = -1;
            if (!jsonInteger(candidateSizes.value(name), 1, MaximumArtifactBytes, candidateSize)
                || !verifyManagedInstalledFile(name,
                                         candidateHashes.value(name).toString(),
                                         candidateSize, &healthError)) {
                return failure(QStringLiteral("recovery_required"),
                               QStringLiteral("installed headless binary does not match the acknowledged candidate"));
            }
        }
        journal.insert(QStringLiteral("phase"), QStringLiteral("acknowledged"));
        QString receiptError;
        if (!writeJournal(journal, &receiptError)) {
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("headless update health acknowledgement could not be persisted"));
        }
        if (!saveState()) {
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("headless update acknowledgement state could not be persisted"));
        }
        receiptError.clear();
        if (!writeRollbackReceipt(&receiptError)) {
            return failure(QStringLiteral("recovery_required"),
                           receiptError.isEmpty()
                               ? QStringLiteral("headless rollback receipt could not be persisted")
                                : receiptError);
        }
        QString retireError;
        if (!retireAcknowledgedJournal(&retireError)) {
            return failure(QStringLiteral("recovery_required"),
                           retireError.isEmpty()
                               ? QStringLiteral("headless update acknowledgement evidence could not be retired")
                               : retireError);
        }
    }
    if (m_lastState == QStringLiteral("rollback_restart_pending")
        && !m_rollbackVersion.isEmpty() && currentVersion == m_rollbackVersion) {
        QString healthError;
        for (const QString &name : managedPayloadFiles()) {
            if (!verifyManagedInstalledFile(name, m_rollbackHashes.value(name), -1, &healthError)) {
                return failure(QStringLiteral("recovery_required"),
                               QStringLiteral("rolled-back headless managed files failed post-restart health validation"));
            }
        }
        QFile rollbackJournalFile(m_journalPath);
        QJsonParseError rollbackJournalError;
        const QJsonDocument rollbackJournal = rollbackJournalFile.open(QIODevice::ReadOnly)
                ? QJsonDocument::fromJson(rollbackJournalFile.readAll(), &rollbackJournalError) : QJsonDocument();
        m_lastState = QStringLiteral("rolled_back");
        m_lastError.clear();
        if (!saveState()) {
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("rollback health acknowledgement state could not be persisted"));
        }
        // Mark the journal acknowledged before retiring any evidence.  The
        // journal must remain durable until the final state commit below; a
        // crash in the retirement window then leaves a self-consistent,
        // recoverable receipt instead of a pending transaction with no proof.
        if (!m_journalPath.isEmpty()) {
            QJsonObject acknowledgedJournal = rollbackJournal.isObject()
                    ? rollbackJournal.object() : QJsonObject();
            if (acknowledgedJournal.isEmpty()) {
                return failure(QStringLiteral("recovery_required"),
                               QStringLiteral("rollback acknowledgement journal is missing"));
            }
            // Rollback acknowledgement has its own identity: the installed
            // pair is the rollback pair, not the superseded candidate pair.
            acknowledgedJournal.insert(QStringLiteral("operation"), QStringLiteral("rollback"));
            acknowledgedJournal.insert(QStringLiteral("candidateVersion"), m_rollbackVersion);
            acknowledgedJournal.insert(QStringLiteral("currentVersion"), m_rollbackVersion);
            QJsonObject rollbackHashes;
            QJsonObject rollbackSizes;
            for (const QString &name : managedPayloadFiles()) {
                rollbackHashes.insert(name, m_rollbackHashes.value(name));
                rollbackSizes.insert(name, QJsonValue(QFileInfo(managedInstallPath(name)).size()));
            }
            acknowledgedJournal.insert(QStringLiteral("candidateHashes"), rollbackHashes);
            acknowledgedJournal.insert(QStringLiteral("candidateSizes"), rollbackSizes);
            acknowledgedJournal.insert(QStringLiteral("phase"), QStringLiteral("rollback_acknowledged"));
            QString journalError;
            if (!writeJournal(acknowledgedJournal, &journalError)) {
                return failure(QStringLiteral("recovery_required"),
                               journalError.isEmpty()
                                   ? QStringLiteral("rollback acknowledgement journal could not be persisted")
                                   : journalError);
            }
        }
        QString retireError;
        if (!retireAcknowledgedJournal(&retireError)) {
            return failure(QStringLiteral("recovery_required"),
                           retireError.isEmpty()
                               ? QStringLiteral("rollback acknowledgement evidence could not be retired")
                               : retireError);
        }
    }

    // A stable receipt may still have an acknowledged journal after a crash
    // during cleanup.  Finish that bounded cleanup before any new network or
    // replacement work; an active/prepared journal is never overwritten.
    if (stableUpdateState(m_lastState) && !m_journalPath.isEmpty()
        && QFileInfo::exists(m_journalPath)) {
        QString cleanupError;
        if (!retireAcknowledgedJournal(&cleanupError)) {
            return failure(QStringLiteral("recovery_required"),
                           cleanupError.isEmpty()
                               ? QStringLiteral("headless transaction journal requires recovery")
                               : cleanupError);
        }
    }

    if (!profile.autoUpdate || profile.updateManifestUrl.isEmpty()
        || profile.updatePublicKeyPath.isEmpty()) {
        m_lastState = QStringLiteral("disabled");
        if (!saveState()) {
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("headless disabled-update state could not be persisted"));
        }
        return { true, QStringLiteral("disabled"), QStringLiteral("automatic updates are disabled") };
    }

    QString trustError;
    QByteArray pinnedPublicKey;
    if (!verifyTrustedKey(profile.updatePublicKeyPath, &pinnedPublicKey, &trustError)) {
        return failure(QStringLiteral("update_trust_invalid"), trustError);
    }
    const QUrl manifestUrl(profile.updateManifestUrl, QUrl::StrictMode);
    if (!safeUpdateUrl(profile, manifestUrl)) {
        return failure(QStringLiteral("update_transport_invalid"),
                       QStringLiteral("automatic update manifest endpoint is not a pinned HTTPS or internal IPv4 HTTP URL"));
    }

    QNetworkAccessManager manager;
    QNetworkRequest request(manifestUrl);
    request.setTransferTimeout(NetworkTimeoutMs);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::ManualRedirectPolicy);
    QNetworkReply *reply = manager.get(request);
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    bool manifestTooLarge = false;
    QObject::connect(reply, &QIODevice::readyRead, &loop, [&]() {
        if (reply->bytesAvailable() > MaximumManifestBytes) {
            manifestTooLarge = true;
            reply->abort();
        }
    });
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
    const bool finalUrlPinned = samePinnedUrl(request.url(), reply->url());
    const QByteArray manifest = reply->readAll();
    const QString networkError = reply->error() == QNetworkReply::NoError
            ? QString() : reply->errorString();
    reply->deleteLater();
    if (!finalUrlPinned) {
        return failure(QStringLiteral("update_redirect_rejected"),
                       QStringLiteral("headless update manifest final URL changed unexpectedly"));
    }
    if (!networkError.isEmpty()) {
        return failure(QStringLiteral("update_unreachable"),
                       QStringLiteral("headless update manifest request failed"));
    }
    if (statusCode < 200 || statusCode >= 300) {
        return failure(QStringLiteral("update_http_error"),
                       QStringLiteral("headless update manifest returned an unexpected status"));
    }
    if (manifestTooLarge || manifest.isEmpty() || manifest.size() > MaximumManifestBytes) {
        return failure(QStringLiteral("update_manifest_too_large"),
                       QStringLiteral("headless update manifest exceeds the byte limit"));
    }

    Candidate candidate;
    const HeadlessUpdateResult parsed = parseManifest(
            manifest, manifestUrl, profile, profile.updatePublicKeyPath,
            pinnedPublicKey, currentVersion, candidate);
    if (!parsed.ok || parsed.code == QStringLiteral("no_update")
        || parsed.code == QStringLiteral("no_headless_artifact")) {
        m_lastState = parsed.code;
        if (!parsed.ok) {
            m_lastError = parsed.message;
        }
        if (!saveState()) {
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("headless update state could not be persisted after parsing the manifest"));
        }
        return parsed;
    }
    m_candidatePlatform = candidate.platform;
    if (!candidate.autoInstall) {
        m_lastState = QStringLiteral("update_available");
        if (!saveState()) {
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("headless update availability state could not be persisted"));
        }
        return { true, QStringLiteral("update_available"),
                 QStringLiteral("a signed headless update is available") };
    }

    QString storageError;
    if (m_updateRoot.isEmpty() || !ensureSecureDirectory(m_updateRoot, &storageError)) {
        return failure(QStringLiteral("update_storage_unavailable"),
                       storageError.isEmpty() ? QStringLiteral("headless update storage is unavailable")
                                              : storageError);
    }
    const QString transaction = QDir(m_updateRoot).filePath(
            QStringLiteral("transaction-%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces)));
    const QString payloadDirectory = QDir(transaction).filePath(QStringLiteral("payload"));
    const QString archivePath = QDir(transaction).filePath(QStringLiteral("artifact.tar.gz"));
    QString error;
    if (!ensureSecureDirectory(transaction, &error)
        || !ensureSecureDirectory(payloadDirectory, &error)) {
        return failure(QStringLiteral("update_storage_unavailable"),
                       error.isEmpty() ? QStringLiteral("headless update staging directory cannot be created")
                                       : error);
    }
    error.clear();
    if (!download(candidate, archivePath, &error)
        || !extract(candidate, archivePath, payloadDirectory, &error)
        || !install(candidate, payloadDirectory, currentVersion, &error)) {
        // Keep the transaction journal and any rollback evidence for recovery;
        // only a failed download/extraction without a journal is disposable.
        if (!QFileInfo::exists(m_journalPath)) {
            // Queue disposable evidence before deletion so a crash or a
            // transient filesystem failure cannot strand an orphan tree or
            // poison an otherwise stable updater state.
            if (!writeGcMarker({ transaction })) {
                QDir(transaction).removeRecursively();
            }
            collectGarbage();
        }
        return failure(m_lastState == QStringLiteral("recovery_required")
                           ? QStringLiteral("recovery_required") : QStringLiteral("update_install_failed"),
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
    QLockFile processLock(QDir(m_updateRoot).filePath(QStringLiteral("update.lock")));
    processLock.setStaleLockTime(0);
    if (!m_updateRoot.isEmpty() && !processLock.tryLock(0)) {
        return { false, QStringLiteral("update_in_progress"),
                 QStringLiteral("another headless update operation owns the transaction lock") };
    }
    if (m_updateInProgress) {
        return failure(QStringLiteral("update_in_progress"),
                       QStringLiteral("a headless update transaction is already in progress"));
    }
    if (m_lastState == QStringLiteral("unsupported_payload_contract")) {
        return failure(QStringLiteral("unsupported_payload_contract"),
                       QStringLiteral("headless rollback receipt uses the retired three-file payload contract; run manual provisioning recovery"));
    }
    if (!m_journalPath.isEmpty() && QFileInfo::exists(m_journalPath)) {
        QFile journalFile(m_journalPath);
        QJsonParseError parseError;
        const QJsonDocument journal = journalFile.open(QIODevice::ReadOnly)
                ? QJsonDocument::fromJson(journalFile.readAll(), &parseError) : QJsonDocument();
        const QString phase = journal.isObject()
                ? journal.object().value(QStringLiteral("phase")).toString() : QString();
        if (phase == QStringLiteral("acknowledged")
            || phase == QStringLiteral("rollback_acknowledged")) {
            QString cleanupError;
            if (!retireAcknowledgedJournal(&cleanupError)) {
                return failure(QStringLiteral("recovery_required"),
                               cleanupError.isEmpty()
                                   ? QStringLiteral("headless acknowledgement cleanup requires recovery")
                                   : cleanupError);
            }
            return { true, QStringLiteral("no_rollback"),
                     QStringLiteral("headless acknowledged transaction cleanup completed") };
        }
    }
    // A normal invalid state must remain fail-closed.  An explicit rollback is
    // the one recovery operation allowed to proceed when the state receipt
    // itself is marked invalid, but only if the independently verified backup
    // pair is still present.  restoreRollback() performs the journal identity
    // and transaction checks before replacing anything.
    const QStringList managedFiles = managedPayloadFiles();
    if ((!m_stateValid || m_lastState == QStringLiteral("recovery_required"))
        && (m_rollbackDirectory.isEmpty()
            || !validVersion(m_rollbackVersion)
            || m_rollbackHashes.size() != managedFiles.size()
            || std::any_of(managedFiles.cbegin(), managedFiles.cend(),
                           [this](const QString &name) { return !m_rollbackHashes.contains(name); })) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("headless update state is invalid; manual recovery is required"));
    }
    m_updateInProgress = true;
    struct UpdateGuard {
        bool &active;
        ~UpdateGuard() { active = false; }
    } updateGuard { m_updateInProgress };
    m_lastError.clear();
    QString error;
    if (m_lastState == QStringLiteral("rollback_restart_pending")) {
        bool rollbackAlreadyInstalled = true;
        for (const QString &name : managedPayloadFiles()) {
            rollbackAlreadyInstalled = verifyManagedInstalledFile(name,
                                                                    m_rollbackHashes.value(name), -1, nullptr)
                    && rollbackAlreadyInstalled;
        }
        if (rollbackAlreadyInstalled) {
            if (!restartService(&error)) {
                m_lastState = QStringLiteral("rollback_failed");
                m_lastError = error;
                if (!saveState()) m_stateValid = false;
                return { false, QStringLiteral("rollback_failed"),
                         QStringLiteral("headless rollback service restart could not be scheduled") };
            }
            return { true, QStringLiteral("rollback_restart_pending"),
                     QStringLiteral("headless rollback restart was scheduled again") };
        }
        // A mixed pair is repaired by restoreRollback() using the existing
        // journal/current evidence; never delete that evidence before the
        // repair attempt.
    }
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
    // The restored version is the currently installed version.  Keeping it in
    // the receipt makes a successful rollback stable across the next daemon
    // restart and avoids manufacturing a recovery error from an empty version.
    m_lastAppliedVersion = m_rollbackVersion;
    if (!saveState()) {
        m_stateValid = false;
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("headless rollback state could not be persisted");
        // Do not restore or delete anything here: the journal and current
        // pair are the durable evidence needed for retry after a restart.
        return { false, QStringLiteral("recovery_required"), m_lastError };
    }
    if (!restartService(&error)) {
        m_lastState = QStringLiteral("rollback_failed");
        m_lastError = error;
        // Keep the rollback-installed pair, journal and current-pair evidence
        // so a later process can retry deterministically after restart fails.
        if (!saveState()) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
        }
        return { false, QStringLiteral("rollback_failed"),
                 QStringLiteral("headless rollback service restart could not be scheduled") };
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
    bool cleanupRetryable = false;
    if (code == QStringLiteral("recovery_required") && stableUpdateState(m_lastState)
        && !m_journalPath.isEmpty() && QFileInfo::exists(m_journalPath)) {
        QFile journalFile(m_journalPath);
        QJsonParseError parseError;
        const QJsonDocument journal = journalFile.open(QIODevice::ReadOnly)
                ? QJsonDocument::fromJson(journalFile.readAll(), &parseError) : QJsonDocument();
        if (parseError.error == QJsonParseError::NoError && journal.isObject()) {
            const QString phase = journal.object().value(QStringLiteral("phase")).toString();
            cleanupRetryable = phase == QStringLiteral("acknowledged")
                    || phase == QStringLiteral("rollback_acknowledged");
        }
    }
    if (cleanupRetryable) {
        // Keep the completed stable state while the acknowledged journal is
        // retried.  Marking it recovery_required would make loadState reject
        // the very journal needed to finish bounded evidence retirement.
        m_lastError = message;
        if (!saveState()) m_stateValid = false;
    } else if (code == QStringLiteral("recovery_required")) {
        m_lastState = code;
        m_stateValid = false;
    } else if (code == QStringLiteral("rollback_failed")
               || code == QStringLiteral("no_rollback")) {
        m_lastState = code;
    } else if (!stableUpdateState(m_lastState)
               && m_lastState != QStringLiteral("rollback_failed")
               && m_lastState != QStringLiteral("recovery_required")
               && m_lastState != QStringLiteral("restart_pending")
               && m_lastState != QStringLiteral("rollback_restart_pending")) {
        m_lastState = QStringLiteral("never_checked");
    }
    if (code == QStringLiteral("unsupported_payload_contract")) {
        // Do not rewrite the legacy receipt through the two-file serializer;
        // the original evidence must remain available for manual recovery.
        m_lastError = message;
        return { false, code, message };
    }
    m_lastError = message;
    if (!saveState() && code != QStringLiteral("update_in_progress")) {
        m_stateValid = false;
        m_lastState = QStringLiteral("recovery_required");
    }
    return { false, code, message };
}

HeadlessUpdateResult HeadlessUpdateManager::parseManifest(
        const QByteArray &manifest, const QUrl &manifestUrl, const Profile &profile,
        const QString &publicKeyPath, const QByteArray &pinnedPublicKey,
        const QString &currentVersion,
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

    // Re-check the fixed trust anchor immediately before manifest
    // verification.  The first read is retained in private memory and the
    // second read is used only to prove that owner, mode, and key bytes did
    // not change while the network request was in flight.
    QByteArray currentPublicKey;
    QString trustError;
    if (!verifyTrustedKey(publicKeyPath, &currentPublicKey, &trustError)
        || QCryptographicHash::hash(currentPublicKey, QCryptographicHash::Sha256)
               != QCryptographicHash::hash(pinnedPublicKey, QCryptographicHash::Sha256)) {
        return { false, QStringLiteral("signature_invalid"),
                 QStringLiteral("headless update trust anchor changed during manifest verification") };
    }
    QByteArray payloadBytes;
    if (!verifyEnvelope(envelope, pinnedPublicKey, payloadBytes)
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
                                     QStringLiteral("changelog"), QStringLiteral("releaseDate"),
                                     QStringLiteral("headlessProvisioning") })) {
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
    const QJsonValue platformsValue = payload.value(QStringLiteral("platforms"));
    const bool hasHeadlessPlatform = platformsValue.isObject()
        && (platformsValue.toObject().contains(QStringLiteral("linux-headless-x64"))
            || platformsValue.toObject().contains(QStringLiteral("linux-headless")));
    if (hasHeadlessPlatform != payload.contains(QStringLiteral("headlessProvisioning"))) {
        return { false, QStringLiteral("invalid_manifest"),
                 QStringLiteral("headless artifact and provisioning metadata must be published together") };
    }
    if (payload.contains(QStringLiteral("headlessProvisioning"))) {
        const QJsonObject provisioning = payload.value(QStringLiteral("headlessProvisioning")).toObject();
        if (!payload.value(QStringLiteral("headlessProvisioning")).isObject()
            || !isObjectWithOnly(provisioning, { QStringLiteral("url"), QStringLiteral("sha256"),
                                                 QStringLiteral("size"), QStringLiteral("format"),
                                                 QStringLiteral("version"),
                                                 QStringLiteral("packageManifestSha256"),
                                                 QStringLiteral("checksumsSha256"),
                                                 QStringLiteral("packageVersion"),
                                                 QStringLiteral("packageFiles") })) {
            return { false, QStringLiteral("invalid_manifest"),
                     QStringLiteral("headless provisioning metadata is invalid") };
        }
        QUrl provisioningUrl;
        qint64 provisioningSize = -1;
        if (provisioning.value(QStringLiteral("version")).toString() != version
            || provisioning.value(QStringLiteral("packageVersion")).toString() != version
            || provisioning.value(QStringLiteral("format")).toString()
                   != QStringLiteral("amnezia-headless-provisioning-tar-v1")
            || !validArtifactUrl(profile, manifestUrl, provisioning.value(QStringLiteral("url")).toString(),
                                 provisioningUrl)
            || !validSha256(provisioning.value(QStringLiteral("sha256")).toString())
            || !validSha256(provisioning.value(QStringLiteral("packageManifestSha256")).toString())
            || !validSha256(provisioning.value(QStringLiteral("checksumsSha256")).toString())
            || !hasExactHeadlessProvisioningFiles(provisioning.value(QStringLiteral("packageFiles")))
            || !jsonInteger(provisioning.value(QStringLiteral("size")), 1, MaximumArtifactBytes,
                            provisioningSize)) {
            return { false, QStringLiteral("invalid_manifest"),
                     QStringLiteral("headless provisioning metadata is invalid") };
        }
    }
    current = QVersionNumber::fromString(currentVersion);
    next = QVersionNumber::fromString(version);
    if (next <= current) {
        return { true, QStringLiteral("no_update"), QStringLiteral("headless client is up to date") };
    }

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
    if (!validArtifactUrl(profile, manifestUrl, rawUrl, resolved)
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
    const bool durable = !writeFailed && durableSyncFileAndDirectory(path);
    const int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const bool ok = reply->isFinished() && !writeFailed
            && samePinnedUrl(candidate.url, reply->url())
            && reply->error() == QNetworkReply::NoError
            && statusCode >= 200 && statusCode < 300
            && received == candidate.size
            && durable
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
    const QFileInfo archiveInfo(archivePath);
    if (!archiveInfo.isFile() || archiveInfo.isSymLink()
        || archiveInfo.size() != candidate.size
        || sha256ForFile(archivePath) != candidate.sha256) {
        if (error) *error = QStringLiteral("headless update archive failed expected hash or size verification");
        return false;
    }
    // The download path is mutable staging evidence.  Copy the verified
    // bytes into a private read-only file and use that same inode for both tar
    // passes, so verification cannot be separated from extraction by a path
    // replacement.
    const QString verifiedArchivePath = QDir(QFileInfo(directory).absolutePath()).filePath(
            QStringLiteral(".verified-artifact-%1.tar.gz")
                .arg(QUuid::createUuid().toString(QUuid::WithoutBraces)));
    if (!QFile::copy(archivePath, verifiedArchivePath)) {
        if (error) *error = QStringLiteral("headless update archive cannot be privately staged");
        return false;
    }
    if (!QFile::setPermissions(verifiedArchivePath, QFileDevice::ReadOwner)
        || !durableSyncFileAndDirectory(verifiedArchivePath)) {
        QFile::remove(verifiedArchivePath);
        if (error) *error = QStringLiteral("headless verified archive cannot be durably staged");
        return false;
    }
    const QFileInfo verifiedInfo(verifiedArchivePath);
    if (!verifiedInfo.isFile() || verifiedInfo.isSymLink()
        || verifiedInfo.size() != candidate.size
        || sha256ForFile(verifiedArchivePath) != candidate.sha256) {
        QFile::remove(verifiedArchivePath);
        if (error) *error = QStringLiteral("headless private archive failed expected hash or size verification");
        return false;
    }
    const QString tar = m_runner->resolveExecutable({ QStringLiteral("tar"), QStringLiteral("/usr/bin/tar") });
    if (tar.isEmpty()) {
        if (error) *error = QStringLiteral("tar is not installed for headless update extraction");
        return false;
    }
    QString listing;
    if (!runProcess(tar, { QStringLiteral("--list"), QStringLiteral("--gzip"),
                           QStringLiteral("--file"), verifiedArchivePath },
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
        if (members.contains(member)) {
            if (error) *error = QStringLiteral("headless update archive contains duplicate members");
            return false;
        }
        members.insert(member);
    }
    QSet<QString> expectedMembers;
    for (const QString &name : managedPayloadFiles()) expectedMembers.insert(name);
    if (members != expectedMembers) {
        if (error) *error = QStringLiteral("headless update archive has an unexpected file set");
        return false;
    }
    // Re-check the immutable copy immediately before extraction as an
    // additional integrity assertion for filesystems without immutable
    // inode flags.
    if (QFileInfo(verifiedArchivePath).size() != candidate.size
        || sha256ForFile(verifiedArchivePath) != candidate.sha256) {
        if (error) *error = QStringLiteral("headless private archive changed before extraction");
        return false;
    }
    if (!runProcess(tar, { QStringLiteral("--extract"), QStringLiteral("--gzip"),
                           QStringLiteral("--file"), verifiedArchivePath,
                           QStringLiteral("--directory"), directory,
                           QStringLiteral("--no-same-owner"), QStringLiteral("--no-same-permissions") },
                    ArchiveTimeoutMs, nullptr, error)) {
        return false;
    }
    const QStringList files = managedPayloadFiles();
    for (const QString &name : files) {
        const QFileInfo info(QDir(directory).filePath(name));
        if (!info.exists() || !info.isFile() || info.isSymLink()) {
            if (error) *error = QStringLiteral("headless update archive contains a non-regular binary");
            return false;
        }
        if (!durableSyncFileAndDirectory(info.absoluteFilePath())) {
            if (error) *error = QStringLiteral("headless extracted binary cannot be durably staged");
            return false;
        }
    }
    qint64 unpackedSize = 0;
    for (const QString &name : members) {
        const qint64 size = QFileInfo(QDir(directory).filePath(name)).size();
        if (size < 1 || size > MaximumArtifactBytes - unpackedSize) {
            if (error) *error = QStringLiteral("headless update archive unpacked size exceeds the safety limit");
            return false;
        }
        unpackedSize += size;
    }
    if (!durableSyncFileAndDirectory(directory)) {
        if (error) *error = QStringLiteral("headless payload directory cannot be durably staged");
        return false;
    }
    return true;
}

bool HeadlessUpdateManager::install(const Candidate &candidate,
                                    const QString &payloadDirectory,
                                    const QString &currentVersion,
                                    QString *error)
{
    const QStringList files = managedPayloadFiles();
    const QFileInfo installInfo(m_installDirectory);
    if (!installInfo.isDir() || installInfo.isSymLink()) {
        if (error) *error = QStringLiteral("headless install directory is not a safe directory");
        return false;
    }
    const QString rollbackDirectory = QDir(m_updateRoot).filePath(
            QStringLiteral("rollback-%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces)));
    if (!ensureSecureDirectory(rollbackDirectory, error)) {
        if (error) *error = QStringLiteral("headless rollback directory cannot be created");
        return false;
    }
    QJsonObject journal {
        { QStringLiteral("version"), 1 },
        { QStringLiteral("operation"), QStringLiteral("update") },
        { QStringLiteral("phase"), QStringLiteral("prepared") },
        { QStringLiteral("candidateVersion"), candidate.version },
        { QStringLiteral("currentVersion"), currentVersion },
        { QStringLiteral("transactionDirectory"), QFileInfo(payloadDirectory).absolutePath() },
        { QStringLiteral("rollbackDirectory"), rollbackDirectory },
        { QStringLiteral("installDirectory"), QFileInfo(m_installDirectory).canonicalFilePath() },
    };
    QJsonObject rollbackHashes;
    QMap<QString, QString> newRollbackHashes;
    QJsonObject candidateHashes;
    QJsonObject candidateSizes;
    for (const QString &name : files) {
        const QString source = QDir(payloadDirectory).filePath(name);
        const QFileInfo sourceInfo(source);
        const QString candidateDigest = sha256ForFile(source);
        if (!sourceInfo.isFile() || sourceInfo.isSymLink() || candidateDigest.isEmpty()) {
            QDir(rollbackDirectory).removeRecursively();
            if (error) *error = QStringLiteral("headless candidate binary hash cannot be recorded");
            return false;
        }
        candidateHashes.insert(name, candidateDigest);
        candidateSizes.insert(name, QJsonValue(sourceInfo.size()));
        const QString destination = managedInstallPath(name);
        const QString backup = QDir(rollbackDirectory).filePath(name);
        if (!verifyManagedInstallFile(name, error)
            || !QFile::copy(destination, backup)
            || !durableSyncFileAndDirectory(backup)) {
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
        newRollbackHashes.insert(name, digest);
        rollbackHashes.insert(name, digest);
    }
    if (!durableSyncFileAndDirectory(rollbackDirectory)) {
        QDir(rollbackDirectory).removeRecursively();
        if (error) *error = QStringLiteral("rollback directory cannot be durably staged");
        return false;
    }
    journal.insert(QStringLiteral("rollbackHashes"), rollbackHashes);
    journal.insert(QStringLiteral("candidateHashes"), candidateHashes);
    journal.insert(QStringLiteral("candidateSizes"), candidateSizes);
    if (!writeJournal(journal, error)) {
        QDir(rollbackDirectory).removeRecursively();
        return false;
    }
    m_rollbackHashes = newRollbackHashes;

    QStringList replaced;
    for (const QString &name : files) {
        const QString source = QDir(payloadDirectory).filePath(name);
        const QString destination = managedInstallPath(name);
        if (!QFileInfo(source).isFile()
            || sha256ForFile(source) != candidateHashes.value(name).toString()
            || QFileInfo(source).size() != candidateSizes.value(name).toInteger()) {
            if (error) *error = QStringLiteral("headless candidate changed before replacement");
            m_lastState = QStringLiteral("recovery_required");
            m_stateValid = false;
            if (!saveState()) m_stateValid = false;
            return false;
        }
        bool destinationRemoved = false;
        if (!atomicReplace(source, destination, error, &destinationRemoved,
                           candidateHashes.value(name).toString(),
                           candidateSizes.value(name).toInteger(-1))) {
            if (destinationRemoved && !replaced.contains(name)) replaced.append(name);
            QString rollbackError;
            for (const QString &restored : replaced) {
                const QString restoredPath = QDir(rollbackDirectory).filePath(restored);
                if (!atomicReplace(restoredPath, managedInstallPath(restored), &rollbackError,
                                   nullptr, newRollbackHashes.value(restored),
                                   QFileInfo(restoredPath).size())) {
                    const QString message = QStringLiteral("headless update failed and rollback also failed; recovery is required");
                    if (error) *error = message;
                    m_lastState = QStringLiteral("recovery_required");
                    m_lastError = message;
                    if (!saveState()) m_stateValid = false;
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
        if (!saveState()) m_stateValid = false;
        return false;
    }

    m_rollbackDirectory = rollbackDirectory;
    m_rollbackVersion = currentVersion;
    if (!saveState()) {
        if (error) *error = QStringLiteral("headless update receipt cannot be persisted");
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = error ? *error : QStringLiteral("headless update receipt cannot be persisted");
        if (!saveState()) m_stateValid = false;
        return false;
    }
    m_lastAppliedVersion = candidate.version;
    m_lastState = QStringLiteral("restart_pending");
    journal.insert(QStringLiteral("phase"), QStringLiteral("restart_pending"));
    if (!writeJournal(journal, error)) {
        m_lastState = QStringLiteral("recovery_required");
        m_stateValid = false;
        m_lastError = error ? *error : QStringLiteral("headless restart transaction journal could not be persisted");
        if (error && error->isEmpty()) {
            *error = QStringLiteral("headless restart transaction journal could not be persisted");
        }
        if (!saveState()) m_stateValid = false;
        return false;
    }
    if (!saveState()) {
        if (error) *error = QStringLiteral("headless restart receipt cannot be persisted");
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = error ? *error : QStringLiteral("headless restart receipt cannot be persisted");
        if (!saveState()) m_stateValid = false;
        return false;
    }
    if (!restartService(error)) {
        // The new binaries and verified rollback are intentionally retained.
        // A restart failure is recoverable through the explicit rollback RPC.
        m_lastState = QStringLiteral("rollback_failed");
        m_lastError = error ? *error : QStringLiteral("headless service restart failed");
        if (!saveState()) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
        }
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
    if (!m_runner->run(systemctl, { QStringLiteral("daemon-reload") }).ok) {
        if (error) *error = QStringLiteral("headless service daemon-reload failed");
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

bool HeadlessUpdateManager::retireAcknowledgedJournal(QString *error)
{
    if (m_journalPath.isEmpty() || !QFileInfo::exists(m_journalPath)) {
        return true;
    }

    QFile journalFile(m_journalPath);
    QJsonParseError parseError;
    if (!journalFile.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("headless acknowledgement journal cannot be opened");
        return false;
    }
    const QJsonDocument document = QJsonDocument::fromJson(journalFile.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (error) *error = QStringLiteral("headless acknowledgement journal is invalid");
        return false;
    }
    const QJsonObject journal = document.object();
    const QString phase = journal.value(QStringLiteral("phase")).toString();
    const QJsonValue operation = journal.value(QStringLiteral("operation"));
    if (phase != QStringLiteral("acknowledged")
        && phase != QStringLiteral("rollback_acknowledged")) {
        if (error) *error = QStringLiteral("headless transaction journal is not acknowledged");
        return false;
    }
    if (!operation.isString()
        || (phase == QStringLiteral("acknowledged")
            && operation.toString() != QStringLiteral("update"))
        || (phase == QStringLiteral("rollback_acknowledged")
            && operation.toString() != QStringLiteral("rollback"))) {
        if (error) *error = QStringLiteral("headless acknowledgement journal operation is invalid");
        return false;
    }
    const bool rollbackAcknowledged = phase == QStringLiteral("rollback_acknowledged");

    const QString rootPath = QFileInfo(m_updateRoot).canonicalFilePath();
    if (rootPath.isEmpty()) {
        if (error) *error = QStringLiteral("headless update root is unavailable for cleanup");
        return false;
    }
    const auto boundedDirectory = [&rootPath](const QString &rawPath) {
        if (rawPath.trimmed().isEmpty()) return true;
        const QFileInfo rawInfo(rawPath);
        if (!rawInfo.exists()) return true; // already retired after a crash
        if (rawInfo.isSymLink()) return false;
        const QString canonical = rawInfo.canonicalFilePath();
        return !canonical.isEmpty() && canonical != rootPath
            && canonical.startsWith(rootPath + QDir::separator())
            && QFileInfo(canonical).isDir() && !QFileInfo(canonical).isSymLink();
    };
    const QStringList evidence {
        journal.value(QStringLiteral("transactionDirectory")).toString(),
        rollbackAcknowledged
            ? journal.value(QStringLiteral("rollbackDirectory")).toString() : QString(),
        journal.value(QStringLiteral("previousDirectory")).toString()
    };
    for (const QString &path : evidence) {
        if (!boundedDirectory(path)) {
            if (error) *error = QStringLiteral("headless acknowledgement evidence has an unsafe path");
            return false;
        }
    }

    // Publish the stable state before the journal commit point.  Update
    // acknowledgement deliberately retains its verified rollback pair for an
    // explicit operator rollback; rollback acknowledgement clears it because
    // the rollback pair is now installed and no longer recovery evidence.
    if (rollbackAcknowledged) {
        m_rollbackDirectory.clear();
        m_rollbackVersion.clear();
        m_rollbackHashes.clear();
        m_currentRollbackDirectory.clear();
    }
    if (!saveState()) {
        m_stateValid = false;
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("headless acknowledgement cleanup state could not be persisted");
        if (error) *error = m_lastError;
        return false;
    }

    // Removing the journal is the durable commit point.  Once it succeeds,
    // the loader must not turn an inability to delete disposable evidence
    // into recovery_required.  A later invocation may retry this garbage
    // collection, but it must never reopen the completed transaction.
    QStringList garbage;
    if (QFileInfo::exists(m_journalPath) && !QFile::remove(m_journalPath)) {
        garbage.append(m_journalPath);
    }
    durableSyncFileAndDirectory(rootPath);
    const QString receiptPath = m_rollbackReceiptPath;
    if (rollbackAcknowledged && !receiptPath.isEmpty() && QFileInfo::exists(receiptPath)) {
        if (!QFile::remove(receiptPath)) garbage.append(receiptPath);
    }
    QSet<QString> retired;
    for (const QString &path : evidence) {
        if (path.trimmed().isEmpty()) continue;
        const QString canonical = QFileInfo(path).canonicalFilePath();
        if (canonical.isEmpty() || retired.contains(canonical)) continue;
        if (QFileInfo::exists(canonical) && !QDir(canonical).removeRecursively()) {
            garbage.append(canonical);
        }
        retired.insert(canonical);
    }
    if (!garbage.isEmpty()) {
        writeGcMarker(garbage);
        collectGarbage();
    }
    return true;
}

bool HeadlessUpdateManager::restoreRollback(QString *error)
{
    if (m_rollbackDirectory.isEmpty()) {
        if (error) *error = QStringLiteral("no rollback directory is recorded");
        return false;
    }
    const QStringList files = managedPayloadFiles();
    // Validate the complete backup pair before touching the installation.
    for (const QString &name : files) {
        const QString backup = QDir(m_rollbackDirectory).filePath(name);
        if (!verifyRollbackFile(backup, m_rollbackHashes.value(name), error)) {
            if (error && error->isEmpty()) {
                *error = QStringLiteral("rollback binary failed containment or hash verification");
            }
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = error ? *error : QStringLiteral("rollback binary failed verification");
            m_stateValid = false;
            if (!saveState()) m_stateValid = false;
            return false;
        }
    }
    // A rollback must never replace either installed binary until the
    // transaction identity and the durable rollback journal have been
    // validated.  This makes a missing/corrupt journal a non-mutating,
    // fail-closed condition even after a daemon crash.
    QJsonObject journalObject;
    bool journalExists = false;
    if (!m_journalPath.isEmpty()) {
        journalExists = QFileInfo::exists(m_journalPath);
        QFile journalFile(m_journalPath);
        QJsonParseError journalError;
        const QJsonDocument journal = journalFile.open(QIODevice::ReadOnly)
                ? QJsonDocument::fromJson(journalFile.readAll(), &journalError) : QJsonDocument();
        if (journalError.error == QJsonParseError::NoError && journal.isObject()) {
            journalObject = journal.object();
        }
    }
    if (journalExists && journalObject.isEmpty()) {
        if (error) *error = QStringLiteral("rollback transaction journal is corrupt");
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = error ? *error : QStringLiteral("rollback transaction journal is corrupt");
        m_stateValid = false;
        if (!saveState()) m_stateValid = false;
        return false;
    }
    qint64 journalVersion = 0;
    if (journalObject.isEmpty()) {
        // A healthy update owns a durable rollback receipt in state.  The
        // active transaction journal is intentionally retired after
        // acknowledgement, so an explicit rollback must remain possible
        // without resurrecting a stale transaction file.
        const QString stableState = m_lastState;
        if (!validVersion(m_rollbackVersion)
            || !validVersion(m_lastAppliedVersion)
            || (stableState != QStringLiteral("updated")
                && stableState != QStringLiteral("applied")
                && stableState != QStringLiteral("disabled")
                && stableState != QStringLiteral("no_update")
                && stableState != QStringLiteral("rollback_failed")
                && stableState != QStringLiteral("recovery_required"))) {
            if (error) *error = QStringLiteral("rollback transaction journal is missing and state is not a completed update receipt");
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = error ? *error : QStringLiteral("rollback transaction journal is missing");
            m_stateValid = false;
            if (!saveState()) m_stateValid = false;
            return false;
        }
        const QString recoveryTransaction = QDir(m_updateRoot).filePath(
                QStringLiteral("recovery-receipt-%1").arg(
                    QUuid::createUuid().toString(QUuid::WithoutBraces)));
        if (!ensureSecureDirectory(recoveryTransaction, error)) {
            if (error) *error = QStringLiteral("rollback recovery receipt directory cannot be created");
            return false;
        }
        journalObject = QJsonObject {
            { QStringLiteral("version"), 1 },
            { QStringLiteral("operation"), QStringLiteral("rollback") },
            { QStringLiteral("phase"), QStringLiteral("acknowledged") },
            { QStringLiteral("candidateVersion"), m_rollbackVersion },
            { QStringLiteral("currentVersion"), m_rollbackVersion },
            { QStringLiteral("transactionDirectory"), QFileInfo(recoveryTransaction).canonicalFilePath() },
            { QStringLiteral("rollbackDirectory"), QFileInfo(m_rollbackDirectory).canonicalFilePath() },
            { QStringLiteral("installDirectory"), QFileInfo(m_installDirectory).canonicalFilePath() },
        };
        QJsonObject receiptHashes;
        QJsonObject currentSizes;
        for (auto it = m_rollbackHashes.cbegin(); it != m_rollbackHashes.cend(); ++it) {
            receiptHashes.insert(it.key(), it.value());
            currentSizes.insert(it.key(), QJsonValue(
                QFileInfo(QDir(m_rollbackDirectory).filePath(it.key())).size()));
        }
        journalObject.insert(QStringLiteral("rollbackHashes"), receiptHashes);
        journalObject.insert(QStringLiteral("candidateHashes"), receiptHashes);
        journalObject.insert(QStringLiteral("candidateSizes"), currentSizes);
    }
    const QString journalPhase = journalObject.value(QStringLiteral("phase")).toString();
    const QString journalInstall = journalObject.value(QStringLiteral("installDirectory")).toString();
    const QString canonicalInstall = QFileInfo(m_installDirectory).canonicalFilePath();
    const QString journalRollback = journalObject.value(QStringLiteral("rollbackDirectory")).toString();
    const QString canonicalRollback = QFileInfo(m_rollbackDirectory).canonicalFilePath();
    const QJsonObject journalRollbackHashes = journalObject.value(QStringLiteral("rollbackHashes")).toObject();
    if (!jsonInteger(journalObject.value(QStringLiteral("version")), 1, 1, journalVersion)
        || (journalPhase != QStringLiteral("restart_pending")
            && journalPhase != QStringLiteral("rollback_restart_pending")
            && journalPhase != QStringLiteral("replaced")
            && journalPhase != QStringLiteral("prepared")
            && journalPhase != QStringLiteral("acknowledged"))
        || journalInstall != canonicalInstall
        || journalRollback != canonicalRollback
         || std::any_of(files.cbegin(), files.cend(),
                        [&journalRollbackHashes, this](const QString &name) {
             return journalRollbackHashes.value(name).toString() != m_rollbackHashes.value(name);
         })
        || !validVersion(journalObject.value(QStringLiteral("candidateVersion")).toString())
        || !validVersion(journalObject.value(QStringLiteral("currentVersion")).toString())
        || journalObject.value(QStringLiteral("currentVersion")).toString() != m_rollbackVersion) {
        if (error) *error = QStringLiteral("rollback transaction journal is missing or invalid");
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = error ? *error : QStringLiteral("rollback transaction journal is missing or invalid");
        m_stateValid = false;
        if (!saveState()) m_stateValid = false;
        return false;
    }
    QString currentDirectory = journalObject.value(QStringLiteral("previousDirectory")).toString();
    const bool resumingRollback = journalPhase == QStringLiteral("rollback_restart_pending");
    if (resumingRollback) {
        const QString rootPath = QFileInfo(m_updateRoot).canonicalFilePath();
        const QString canonicalPrevious = QFileInfo(currentDirectory).canonicalFilePath();
        if (rootPath.isEmpty() || canonicalPrevious.isEmpty()
            || !canonicalPrevious.startsWith(rootPath + QDir::separator())) {
            if (error) *error = QStringLiteral("rollback restart receipt has unsafe current-pair evidence");
            return false;
        }
        currentDirectory = canonicalPrevious;
        const QJsonObject previousHashes = journalObject.value(QStringLiteral("previousHashes")).toObject();
        for (const QString &name : files) {
            if (!previousHashes.value(name).isString()
                || !verifyRollbackFile(QDir(currentDirectory).filePath(name),
                                       previousHashes.value(name).toString(), error)) {
                if (error && error->isEmpty()) *error = QStringLiteral("rollback restart current-pair evidence is invalid");
                return false;
            }
        }
    } else {
        currentDirectory = QDir(m_updateRoot).filePath(
                QStringLiteral("rollback-current-%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces)));
        if (!ensureSecureDirectory(currentDirectory, error)) {
            if (error) *error = QStringLiteral("current headless binary pair cannot be staged for rollback recovery");
            return false;
        }
        QJsonObject previousHashes;
        QJsonObject previousSizes;
        for (const QString &name : files) {
            const QString current = managedInstallPath(name);
            const QString backup = QDir(currentDirectory).filePath(name);
            if (!verifyInstallFile(current, error)
                || !QFile::copy(current, backup)
                || !durableSyncFileAndDirectory(backup)) {
                QDir(currentDirectory).removeRecursively();
                if (error && error->isEmpty()) *error = QStringLiteral("current headless binary pair cannot be backed up");
                return false;
            }
            previousHashes.insert(name, sha256ForFile(QDir(currentDirectory).filePath(name)));
            previousSizes.insert(name, QJsonValue(QFileInfo(QDir(currentDirectory).filePath(name)).size()));
        }
        if (!durableSyncFileAndDirectory(currentDirectory)) {
            if (error) *error = QStringLiteral("current headless binary pair cannot be durably staged");
            return false;
        }
        journalObject.insert(QStringLiteral("previousHashes"), previousHashes);
        journalObject.insert(QStringLiteral("previousSizes"), previousSizes);
    }
    Q_UNUSED(journalVersion);
    m_currentRollbackDirectory = currentDirectory;
    // A rollback journal has a single, unambiguous installed identity: both
    // version fields and candidate hashes describe the rollback pair.  The
    // superseded pair is kept separately in previousDirectory/previousHashes
    // solely for recovery if replacement is interrupted.
    QJsonObject previousHashes = journalObject.value(QStringLiteral("previousHashes")).toObject();
    QJsonObject previousSizes = journalObject.value(QStringLiteral("previousSizes")).toObject();
    if (!hasExactManagedFileSet(previousHashes)) {
        previousHashes.clear();
        previousSizes.clear();
        for (const QString &name : files) {
            const QString current = QDir(currentDirectory).filePath(name);
            const QString digest = sha256ForFile(current);
            if (!validSha256(digest)) {
                if (error) *error = QStringLiteral("rollback current-pair hash evidence is invalid");
                return false;
            }
            previousHashes.insert(name, digest);
            previousSizes.insert(name, QJsonValue(QFileInfo(current).size()));
        }
    }
    QJsonObject targetHashes;
    QJsonObject targetSizes;
    for (const QString &name : files) {
        const QString backup = QDir(m_rollbackDirectory).filePath(name);
        targetHashes.insert(name, m_rollbackHashes.value(name));
        targetSizes.insert(name, QJsonValue(QFileInfo(backup).size()));
    }
    journalObject.insert(QStringLiteral("operation"), QStringLiteral("rollback"));
    journalObject.insert(QStringLiteral("candidateVersion"), m_rollbackVersion);
    journalObject.insert(QStringLiteral("currentVersion"), m_rollbackVersion);
    journalObject.insert(QStringLiteral("rollbackHashes"), targetHashes);
    journalObject.insert(QStringLiteral("candidateHashes"), targetHashes);
    journalObject.insert(QStringLiteral("candidateSizes"), targetSizes);
    journalObject.insert(QStringLiteral("previousHashes"), previousHashes);
    journalObject.insert(QStringLiteral("previousSizes"), previousSizes);
    // Persist rollback intent and the current-pair recovery evidence before
    // replacing the first installed binary.  A crash in the replacement loop
    // therefore leaves enough durable information for a deterministic retry.
    journalObject.insert(QStringLiteral("phase"), QStringLiteral("rollback_restart_pending"));
    journalObject.insert(QStringLiteral("previousDirectory"), currentDirectory);
    if (!writeJournal(journalObject, error)) {
        QDir(currentDirectory).removeRecursively();
        m_currentRollbackDirectory.clear();
        return false;
    }
    QStringList replaced;
    auto restoreCurrent = [&]() {
        bool ok = true;
        for (const QString &name : replaced) {
            const QString staged = QDir(currentDirectory).filePath(
                    QStringLiteral(".%1.restore-%2").arg(name,
                        QUuid::createUuid().toString(QUuid::WithoutBraces)));
            if (!QFile::copy(QDir(currentDirectory).filePath(name), staged)
                || !durableSyncFileAndDirectory(staged)) {
                ok = false;
                continue;
            }
            const QJsonObject expectedHashes = journalObject.value(QStringLiteral("previousHashes")).toObject();
            const QJsonObject expectedSizes = journalObject.value(QStringLiteral("previousSizes")).toObject();
            if (!atomicReplace(staged, managedInstallPath(name), nullptr, nullptr,
                               expectedHashes.value(name).toString(),
                               expectedSizes.value(name).toInteger(-1))) {
                ok = false;
            }
        }
        return ok;
    };
    for (const QString &name : files) {
        const QString backup = QDir(m_rollbackDirectory).filePath(name);
        const QString staged = QDir(m_rollbackDirectory).filePath(
                    QStringLiteral(".%1.restore-%2").arg(name,
                        QUuid::createUuid().toString(QUuid::WithoutBraces)));
        bool destinationRemoved = false;
        if (!verifyRollbackFile(backup, m_rollbackHashes.value(name), error)
            || !QFile::copy(backup, staged)
            || !durableSyncFileAndDirectory(staged)
            || !atomicReplace(staged, managedInstallPath(name), error,
                              &destinationRemoved,
                              m_rollbackHashes.value(name), QFileInfo(backup).size())) {
            if (destinationRemoved && !replaced.contains(name)) replaced.append(name);
            if (error && error->isEmpty()) *error = QStringLiteral("rollback binary could not be staged");
            const bool restored = restoreCurrent();
            if (!restored) {
                m_lastState = QStringLiteral("recovery_required");
                m_lastError = QStringLiteral("rollback failed and restoration of the current pair also failed");
                m_stateValid = false;
                if (!saveState()) m_stateValid = false;
                // Keep previousDirectory and the journal on disk so a later
                // daemon can resume recovery; deleting it would make the
                // mixed installation unrecoverable.
                return false;
            }
            // The installed pair was restored, but rollback did not commit.
            // Keep a valid transaction phase so the next explicit rollback
            // can stage fresh current-pair evidence and retry safely.
            journalObject.insert(QStringLiteral("phase"), QStringLiteral("replaced"));
            QString receiptError;
            if (!writeJournal(journalObject, &receiptError)) {
                m_lastState = QStringLiteral("recovery_required");
                m_lastError = receiptError;
                m_stateValid = false;
                if (!saveState()) m_stateValid = false;
            }
            return false;
        }
        replaced.append(name);
    }
    journalObject.insert(QStringLiteral("phase"), QStringLiteral("rollback_restart_pending"));
    if (!writeJournal(journalObject, error)) {
        const bool restored = restoreCurrent();
        if (!restored) {
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("rollback journal failed and restoration of the current pair also failed");
            m_stateValid = false;
            if (!saveState()) m_stateValid = false;
            return false;
        }
        journalObject.insert(QStringLiteral("phase"), QStringLiteral("replaced"));
        QString receiptError;
        if (!writeJournal(journalObject, &receiptError)) {
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = receiptError;
            m_stateValid = false;
            if (!saveState()) m_stateValid = false;
        }
        // Keep the journal and current pair evidence for deterministic retry.
        return false;
    }
    return true;
}

bool HeadlessUpdateManager::restoreCurrentPair(QString *error)
{
    if (m_currentRollbackDirectory.isEmpty()) {
        if (error) *error = QStringLiteral("no current binary pair recovery evidence is recorded");
        return false;
    }
    bool ok = true;
    for (const QString &name : managedPayloadFiles()) {
        const QString backup = QDir(m_currentRollbackDirectory).filePath(name);
        const QString staged = QDir(m_currentRollbackDirectory).filePath(
                QStringLiteral(".%1.restore-%2").arg(name,
                    QUuid::createUuid().toString(QUuid::WithoutBraces)));
        const QString expected = sha256ForFile(backup);
        if (!verifyRollbackFile(backup, expected, error)
            || !QFile::copy(backup, staged)
            || !durableSyncFileAndDirectory(staged)
            || sha256ForFile(staged) != expected) {
            ok = false;
            continue;
        }
        if (!atomicReplace(staged, managedInstallPath(name), error, nullptr,
                           expected, QFileInfo(backup).size())) {
            ok = false;
        }
    }
    if (ok && !QDir(m_currentRollbackDirectory).removeRecursively()) ok = false;
    if (ok) m_currentRollbackDirectory.clear();
    return ok;
}

bool HeadlessUpdateManager::loadState()
{
    const QStringList managedFiles = managedPayloadFiles();
    if (m_statePath.isEmpty()) {
        return true;
    }
    QFile file(m_statePath);
    if (!file.exists()) {
        if (!m_journalPath.isEmpty() && QFileInfo::exists(m_journalPath)) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless transaction journal exists without a state receipt");
            return false;
        }
        return true;
    }
    const QFileInfo stateFileInfo(m_statePath);
    if (!stateFileInfo.isFile() || stateFileInfo.isSymLink()) {
        m_stateValid = false;
        return false;
    }
#ifndef Q_OS_WIN
    if (m_requireRootOwnedFiles
        && (stateFileInfo.ownerId() != 0
            || (stateFileInfo.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther)) != 0)) {
        m_stateValid = false;
        return false;
    }
#endif
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
    if (!isObjectWithOnly(object, {
            QStringLiteral("version"), QStringLiteral("state"),
            QStringLiteral("lastCheckedAt"), QStringLiteral("lastAppliedVersion"),
            QStringLiteral("rollbackDirectory"), QStringLiteral("rollbackVersion"),
            QStringLiteral("rollbackHashes"), QStringLiteral("installDirectory"),
            QStringLiteral("updateRoot"), QStringLiteral("lastError") })) {
        m_stateValid = false;
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("headless update state contains unknown fields");
        return false;
    }
    qint64 stateVersion = 0;
    if (!jsonInteger(object.value(QStringLiteral("version")), 1, 2, stateVersion)) {
        m_stateValid = false;
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("headless update state schema version is invalid");
        return false;
    }
    if (stateVersion == 2) {
        // Version 2 is a complete, self-bound receipt.  Optional parsing here
        // would let a truncated stable state look healthy after a crash.
        for (const QString &key : { QStringLiteral("version"), QStringLiteral("state"),
                                    QStringLiteral("lastCheckedAt"),
                                    QStringLiteral("lastAppliedVersion"),
                                    QStringLiteral("rollbackDirectory"),
                                    QStringLiteral("rollbackVersion"),
                                    QStringLiteral("rollbackHashes"),
                                    QStringLiteral("installDirectory"),
                                    QStringLiteral("updateRoot"),
                                    QStringLiteral("lastError") }) {
            if (!object.contains(key)) {
                m_stateValid = false;
                m_lastState = QStringLiteral("recovery_required");
                m_lastError = QStringLiteral("headless update state is missing a required field");
                return false;
            }
        }
    }
    const QString serializedState = object.value(QStringLiteral("state")).toString();
    if (stateVersion == 1) {
        const QJsonValue legacyHashes = object.value(QStringLiteral("rollbackHashes"));
        const bool hasLegacyRollback = !object.value(QStringLiteral("rollbackDirectory"))
                                             .toString().isEmpty()
                || !object.value(QStringLiteral("rollbackVersion")).toString().isEmpty()
                || (legacyHashes.isObject() && !legacyHashes.toObject().isEmpty());
        const bool safeLegacyState = serializedState == QStringLiteral("never_checked")
                || serializedState == QStringLiteral("disabled")
                || serializedState == QStringLiteral("no_update")
         || serializedState == QStringLiteral("no_headless_artifact")
         || serializedState == QStringLiteral("unsupported_payload_contract")
                || serializedState == QStringLiteral("applied")
                || serializedState == QStringLiteral("update_available")
                || serializedState == QStringLiteral("updated")
                || serializedState == QStringLiteral("no_rollback");
        if (hasLegacyRollback || !safeLegacyState
            || (!m_journalPath.isEmpty() && QFileInfo::exists(m_journalPath))
            || serializedState == QStringLiteral("restart_pending")
            || serializedState == QStringLiteral("rollback_restart_pending")
            || serializedState == QStringLiteral("rollback_failed")
            || serializedState == QStringLiteral("recovery_required")) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("legacy in-flight or rollback state requires manual recovery");
            return false;
        }
    }
    for (const QString &key : { QStringLiteral("state"), QStringLiteral("lastCheckedAt"),
                                QStringLiteral("lastAppliedVersion"), QStringLiteral("rollbackDirectory"),
                                QStringLiteral("rollbackVersion"), QStringLiteral("lastError") }) {
        if (object.contains(key) && !object.value(key).isString()) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless update state contains a field with an invalid type");
            return false;
        }
    }
    if (!object.value(QStringLiteral("state")).isString()) {
        m_stateValid = false;
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("headless update state has no explicit state");
        return false;
    }
    if (stateVersion == 2 && (!object.value(QStringLiteral("installDirectory")).isString()
        || !object.value(QStringLiteral("updateRoot")).isString()
        || object.value(QStringLiteral("installDirectory")).toString()
               != QFileInfo(m_installDirectory).canonicalFilePath()
        || object.value(QStringLiteral("updateRoot")).toString()
               != QFileInfo(m_updateRoot).canonicalFilePath())) {
        m_stateValid = false;
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("headless update state is bound to another installation");
        return false;
    }
    m_lastCheckedAt = object.value(QStringLiteral("lastCheckedAt")).toString();
    m_lastAppliedVersion = object.value(QStringLiteral("lastAppliedVersion")).toString();
    m_lastState = object.value(QStringLiteral("state")).toString();
    const QStringList validStates {
        QStringLiteral("never_checked"), QStringLiteral("disabled"),
        QStringLiteral("no_update"), QStringLiteral("no_headless_artifact"),
        QStringLiteral("unsupported_payload_contract"),
        QStringLiteral("update_available"), QStringLiteral("applied"),
        QStringLiteral("updated"), QStringLiteral("restart_pending"),
        QStringLiteral("rollback_restart_pending"), QStringLiteral("rolled_back"),
        QStringLiteral("rollback_failed"), QStringLiteral("recovery_required"),
        QStringLiteral("no_rollback")
    };
    if (!validStates.contains(m_lastState)) {
        m_stateValid = false;
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("headless update state contains an unknown state");
        return false;
    }
    m_rollbackDirectory = object.value(QStringLiteral("rollbackDirectory")).toString();
    m_rollbackVersion = object.value(QStringLiteral("rollbackVersion")).toString();
    m_lastError = object.value(QStringLiteral("lastError")).toString();
    m_rollbackHashes.clear();
    if (stateVersion != 1 && !object.value(QStringLiteral("rollbackHashes")).isObject()) {
        m_stateValid = false;
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("headless rollback hash receipt is not an object");
        return false;
    }
    const QJsonObject rollbackHashes = object.value(QStringLiteral("rollbackHashes")).isObject()
            ? object.value(QStringLiteral("rollbackHashes")).toObject() : QJsonObject();
    if (hasUnsupportedThreeFileReceipt(rollbackHashes)) {
        m_stateValid = true;
        m_lastState = QStringLiteral("unsupported_payload_contract");
        m_lastError = QStringLiteral("headless update receipt uses the retired three-file payload contract; run manual provisioning recovery");
        return true;
    }
        if (!rollbackHashes.isEmpty() && !hasExactManagedFileSet(rollbackHashes)) {
        m_stateValid = false;
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("headless rollback hash receipt contains an unexpected file");
        return false;
    }
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
        // A previously advertised rollback must never silently disappear.
        // Losing the backup is an unrecoverable transaction condition, not a
        // reason to downgrade the receipt to a healthy stable state.
        m_stateValid = false;
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("headless rollback receipt directory is missing");
        return false;
    } else if (!m_rollbackDirectory.isEmpty()) {
        const QString rootPath = QFileInfo(m_updateRoot).canonicalFilePath();
        const QString rollbackPath = QFileInfo(m_rollbackDirectory).canonicalFilePath();
        if (rootPath.isEmpty() || rollbackPath.isEmpty()
            || !rollbackPath.startsWith(rootPath + QDir::separator())
            || !validVersion(m_rollbackVersion)) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless rollback receipt is outside the trusted update root");
            return false;
        }
        if (!hasExactManagedHashMap(m_rollbackHashes)) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless rollback receipt is incomplete");
            return false;
        }
        for (const QString &name : managedPayloadFiles()) {
            if (!verifyRollbackFile(QDir(m_rollbackDirectory).filePath(name),
                                    m_rollbackHashes.value(name), nullptr)) {
                m_stateValid = false;
                m_lastState = QStringLiteral("recovery_required");
                m_lastError = QStringLiteral("headless rollback receipt binary is missing or unverifiable");
                return false;
            }
        }
    }
    if (m_rollbackDirectory.isEmpty()
        && (!m_rollbackVersion.isEmpty() || !m_rollbackHashes.isEmpty())) {
        m_stateValid = false;
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("headless rollback receipt has incomplete identity");
        return false;
    }
    if (m_lastAppliedVersion.isEmpty() == false && !validVersion(m_lastAppliedVersion)) {
        m_stateValid = false;
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("headless update receipt contains an invalid applied version");
        return false;
    }
    if ((m_lastState == QStringLiteral("applied")
         || m_lastState == QStringLiteral("updated")
         || m_lastState == QStringLiteral("rolled_back"))
        && m_lastAppliedVersion.isEmpty()) {
        m_stateValid = false;
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("completed headless update receipt has no applied version");
        return false;
    }
    if (!m_journalPath.isEmpty() && QFileInfo::exists(m_journalPath)) {
        const QFileInfo journalInfo(m_journalPath);
        if (!journalInfo.isFile() || journalInfo.isSymLink()) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless update journal is not a trusted regular file");
            return false;
        }
#ifndef Q_OS_WIN
        if (m_requireRootOwnedFiles
            && (journalInfo.ownerId() != 0
                || (journalInfo.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther)) != 0)) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless update journal ownership is invalid");
            return false;
        }
#endif
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
                && phase != QStringLiteral("prepared")
                && phase != QStringLiteral("acknowledged")
                && phase != QStringLiteral("rollback_acknowledged"))) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless update transaction journal is invalid");
            return false;
        }
        const QJsonObject journalObject = journal.object();
        if (!isObjectWithOnly(journalObject, {
                 QStringLiteral("version"), QStringLiteral("operation"), QStringLiteral("phase"),
                QStringLiteral("candidateVersion"), QStringLiteral("currentVersion"),
                QStringLiteral("transactionDirectory"), QStringLiteral("rollbackDirectory"),
                QStringLiteral("installDirectory"), QStringLiteral("rollbackHashes"),
                QStringLiteral("candidateHashes"), QStringLiteral("candidateSizes"),
                QStringLiteral("previousDirectory"), QStringLiteral("previousHashes"),
                QStringLiteral("previousSizes") })) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless update journal contains unknown fields");
            return false;
        }
        const QString journalInstall = journalObject.value(QStringLiteral("installDirectory")).toString();
        const QString canonicalInstall = QFileInfo(m_installDirectory).canonicalFilePath();
        const QString journalTransaction = journalObject.value(QStringLiteral("transactionDirectory")).toString();
        const QString canonicalUpdateRoot = QFileInfo(m_updateRoot).canonicalFilePath();
        const QString canonicalTransaction = QFileInfo(journalTransaction).canonicalFilePath();
        const QString journalCandidate = journalObject.value(QStringLiteral("candidateVersion")).toString();
        const QString journalCurrent = journalObject.value(QStringLiteral("currentVersion")).toString();
        const QJsonValue operationValue = journalObject.value(QStringLiteral("operation"));
        const QString journalOperation = operationValue.toString();
        qint64 journalVersion = 0;
        if (!jsonInteger(journalObject.value(QStringLiteral("version")), 1, 1, journalVersion)
            || journalInstall != canonicalInstall
            || journalTransaction.isEmpty() || canonicalTransaction.isEmpty()
            || !canonicalTransaction.startsWith(canonicalUpdateRoot + QDir::separator())
            || !operationValue.isString() || journalOperation.isEmpty()
            || (journalOperation != QStringLiteral("update")
                && journalOperation != QStringLiteral("rollback"))
            || !validVersion(journalCandidate) || !validVersion(journalCurrent)
            || (!m_lastAppliedVersion.isEmpty() && phase == QStringLiteral("restart_pending")
                && m_lastAppliedVersion != journalCandidate)) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless transaction journal identity is invalid");
            return false;
        }
        if (journalObject.contains(QStringLiteral("operation"))
            && (!journalObject.value(QStringLiteral("operation")).isString()
                || (journalOperation != QStringLiteral("update")
                    && journalOperation != QStringLiteral("rollback")))) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless transaction journal operation is invalid");
            return false;
        }
        if ((phase == QStringLiteral("rollback_restart_pending")
             || phase == QStringLiteral("rollback_acknowledged"))
            && journalOperation != QStringLiteral("rollback")) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless rollback journal has no rollback operation identity");
            return false;
        }
        if ((journalOperation == QStringLiteral("update")
             && QVersionNumber::fromString(journalCandidate)
                    <= QVersionNumber::fromString(journalCurrent))
            || (journalOperation == QStringLiteral("rollback")
                && journalCandidate != journalCurrent)) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless transaction journal is a replay or downgrade");
            return false;
        }
        if (!journalObject.value(QStringLiteral("candidateHashes")).isObject()
            || !journalObject.value(QStringLiteral("candidateSizes")).isObject()
            || !journalObject.value(QStringLiteral("rollbackHashes")).isObject()) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless transaction journal receipts are not objects");
            return false;
        }
        const QJsonObject candidateHashes = journalObject.value(QStringLiteral("candidateHashes")).toObject();
        const QJsonObject candidateSizes = journalObject.value(QStringLiteral("candidateSizes")).toObject();
        if (hasUnsupportedThreeFileReceipt(candidateHashes)
            || hasUnsupportedThreeFileReceipt(candidateSizes)
            || hasUnsupportedThreeFileReceipt(journalObject.value(QStringLiteral("rollbackHashes")).toObject())) {
            m_stateValid = true;
            m_lastState = QStringLiteral("unsupported_payload_contract");
            m_lastError = QStringLiteral("headless update journal uses the retired three-file payload contract; run manual provisioning recovery");
            return true;
        }
        if (!hasExactManagedFileSet(candidateHashes) || !hasExactManagedFileSet(candidateSizes)) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless transaction journal managed-file receipt is incomplete");
            return false;
        }
        for (const QString &name : managedPayloadFiles()) {
            qint64 candidateSize = -1;
            if (!candidateHashes.value(name).isString()
                || !validSha256(candidateHashes.value(name).toString())
                || !jsonInteger(candidateSizes.value(name), 1, MaximumArtifactBytes, candidateSize)) {
                m_stateValid = false;
                m_lastState = QStringLiteral("recovery_required");
                m_lastError = QStringLiteral("headless transaction journal hash or size receipt is invalid");
                return false;
            }
        }
        if (phase == QStringLiteral("acknowledged")) {
            // Journal-only adoption is allowed only when the journal binds
            // the current installed pair and the rollback pair exactly.
            if (!validVersion(m_lastAppliedVersion) || m_lastAppliedVersion != journalCandidate
                || (m_lastState != QStringLiteral("updated")
                    && m_lastState != QStringLiteral("disabled")
                     && m_lastState != QStringLiteral("no_update")
                     && m_lastState != QStringLiteral("no_headless_artifact")
                     && m_lastState != QStringLiteral("rolled_back")
                     && m_lastState != QStringLiteral("rollback_failed"))) {
                m_stateValid = false;
                m_lastState = QStringLiteral("recovery_required");
                m_lastError = QStringLiteral("acknowledged journal candidate does not match state");
                return false;
            }
            for (const QString &name : managedPayloadFiles()) {
                qint64 candidateSize = -1;
                if (!verifyManagedInstalledFile(name,
                                         candidateHashes.value(name).toString(),
                                         jsonInteger(candidateSizes.value(name), 1, MaximumArtifactBytes,
                                                     candidateSize) ? candidateSize : -1, nullptr)) {
                    m_stateValid = false;
                    m_lastState = QStringLiteral("recovery_required");
                    m_lastError = QStringLiteral("acknowledged journal current evidence is invalid");
                    return false;
                }
            }
        } else if (phase == QStringLiteral("rollback_acknowledged")) {
            if (journalOperation != QStringLiteral("rollback")
                || m_lastState != QStringLiteral("rolled_back")
                || !validVersion(m_lastAppliedVersion)
                || m_lastAppliedVersion != journalCandidate
                || journalCandidate != journalCurrent) {
                m_stateValid = false;
                m_lastState = QStringLiteral("recovery_required");
                m_lastError = QStringLiteral("rollback acknowledgement does not match state");
                return false;
            }
            for (const QString &name : managedPayloadFiles()) {
                qint64 candidateSize = -1;
                if (!jsonInteger(candidateSizes.value(name), 1, MaximumArtifactBytes, candidateSize)
                    || !verifyManagedInstalledFile(name, candidateHashes.value(name).toString(),
                                                   candidateSize, nullptr)) {
                    m_stateValid = false;
                    m_lastState = QStringLiteral("recovery_required");
                    m_lastError = QStringLiteral("rollback acknowledgement current evidence is invalid");
                    return false;
                }
            }
        }
        Q_UNUSED(journalVersion);
        const bool adoptingJournalRollback = m_rollbackDirectory.isEmpty();
        if (adoptingJournalRollback
            && phase != QStringLiteral("rollback_restart_pending")
            && phase != QStringLiteral("replaced")) {
            // A journal without a state receipt is usable only when its
            // recorded installed pair is still present.  This prevents an
            // old, otherwise valid rollback directory from being replayed as
            // a new transaction after the state file was lost.
            const QJsonObject installedHashes = phase == QStringLiteral("prepared")
                    ? journalRollbackHashes : candidateHashes;
            for (const QString &name : managedPayloadFiles()) {
                // A prepared transaction has not replaced the installed pair
                // yet, so it must still match the recorded current identity.
                // Once replacement has begun, however, a crash can leave a
                // mixed pair.  The journal rollback pair is authoritative and
                // explicit rollback below is the deterministic recovery path.
                if (!verifyManagedInstalledFile(name, installedHashes.value(name).toString(),
                                                -1, nullptr)) {
                    m_stateValid = false;
                    m_lastState = QStringLiteral("recovery_required");
                    m_lastError = QStringLiteral("headless journal is not bound to the installed binary pair");
                    return false;
                }
            }
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
        const QString journalRollbackPath = journalObject.value(QStringLiteral("rollbackDirectory")).toString();
        const QString journalRollbackCanonical = QFileInfo(journalRollbackPath).canonicalFilePath();
        if (canonicalUpdateRoot.isEmpty() || journalRollbackCanonical.isEmpty()
            || !journalRollbackCanonical.startsWith(canonicalUpdateRoot + QDir::separator())) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless transaction rollback path is outside the trusted update root");
            return false;
        }
        const QString stateRollbackCanonical = QFileInfo(m_rollbackDirectory).canonicalFilePath();
        const QJsonObject journalRollbackHashes = journalObject.value(QStringLiteral("rollbackHashes")).toObject();
        if (!hasExactManagedFileSet(journalRollbackHashes)
            || std::any_of(managedFiles.cbegin(), managedFiles.cend(),
                           [&journalRollbackHashes](const QString &name) {
                return !journalRollbackHashes.value(name).isString()
                    || !validSha256(journalRollbackHashes.value(name).toString());
            })) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless transaction journal rollback hash receipt is invalid");
            return false;
        }
        if (!m_rollbackDirectory.isEmpty()
            && (journalRollbackCanonical.isEmpty() || stateRollbackCanonical != journalRollbackCanonical
             || m_rollbackVersion != journalCurrent
             || std::any_of(managedFiles.cbegin(), managedFiles.cend(),
                            [&journalRollbackHashes, this](const QString &name) {
                 return journalRollbackHashes.value(name).toString() != m_rollbackHashes.value(name);
             })) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless rollback receipt is not bound to its transaction journal");
            return false;
        }
        if (adoptingJournalRollback && phase != QStringLiteral("acknowledged")
             && phase != QStringLiteral("restart_pending")
             && phase != QStringLiteral("rollback_restart_pending")
             && phase != QStringLiteral("rollback_acknowledged")
             && phase != QStringLiteral("replaced")
             && phase != QStringLiteral("prepared")) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("unbound journal rollback evidence cannot be adopted");
            return false;
        }
        if ((phase == QStringLiteral("restart_pending")
             || phase == QStringLiteral("rollback_restart_pending")
             || phase == QStringLiteral("rollback_acknowledged")
             || phase == QStringLiteral("acknowledged")
             || phase == QStringLiteral("replaced")
             || phase == QStringLiteral("prepared"))
            && (m_rollbackDirectory.isEmpty() || !validVersion(m_rollbackVersion)
                || !hasExactManagedHashMap(m_rollbackHashes))) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless transaction journal has incomplete rollback evidence");
            return false;
        }
        if (phase == QStringLiteral("rollback_restart_pending")) {
            const QString previousDirectory = journalObject.value(QStringLiteral("previousDirectory")).toString();
            const QString canonicalPrevious = QFileInfo(previousDirectory).canonicalFilePath();
            if (canonicalPrevious.isEmpty()
                || !canonicalPrevious.startsWith(canonicalUpdateRoot + QDir::separator())
                || !QFileInfo(canonicalPrevious).isDir()
                 || std::any_of(managedFiles.cbegin(), managedFiles.cend(),
                                [this, &canonicalPrevious, &journalObject](const QString &name) {
                     return !verifyRollbackFile(QDir(canonicalPrevious).filePath(name),
                                                journalObject.value(QStringLiteral("previousHashes"))
                                                    .toObject().value(name).toString(), nullptr);
                 })) {
                m_stateValid = false;
                m_lastState = QStringLiteral("recovery_required");
                m_lastError = QStringLiteral("rollback current-pair evidence is invalid");
                return false;
            }
            m_currentRollbackDirectory = canonicalPrevious;
        }
        if ((phase == QStringLiteral("restart_pending")
             || phase == QStringLiteral("rollback_restart_pending")
             || phase == QStringLiteral("rollback_acknowledged")
             || phase == QStringLiteral("acknowledged"))
             && std::any_of(managedFiles.cbegin(), managedFiles.cend(),
                            [this](const QString &name) {
                 return !verifyRollbackFile(QDir(m_rollbackDirectory).filePath(name),
                                            m_rollbackHashes.value(name), nullptr);
             })) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless transaction journal rollback evidence is unsafe");
            return false;
        }
        if (phase == QStringLiteral("rollback_restart_pending")) {
            const QString previousDirectory = journalObject.value(QStringLiteral("previousDirectory")).toString();
            const QJsonObject previousHashes = journalObject.value(QStringLiteral("previousHashes")).toObject();
            const QString rootPath = QFileInfo(m_updateRoot).canonicalFilePath();
            const QString previousPath = QFileInfo(previousDirectory).canonicalFilePath();
            if (previousPath.isEmpty() || rootPath.isEmpty()
                || !previousPath.startsWith(rootPath + QDir::separator())
            || !hasExactManagedFileSet(previousHashes)) {
                m_stateValid = false;
                m_lastState = QStringLiteral("recovery_required");
                m_lastError = QStringLiteral("rollback restart current-pair receipt is invalid");
                return false;
            }
            for (const QString &name : managedPayloadFiles()) {
                if (!previousHashes.value(name).isString()
                    || !validSha256(previousHashes.value(name).toString())
                    || !verifyRollbackFile(QDir(previousPath).filePath(name),
                                           previousHashes.value(name).toString(), nullptr)) {
                    m_stateValid = false;
                    m_lastState = QStringLiteral("recovery_required");
                    m_lastError = QStringLiteral("rollback restart current-pair hash receipt is invalid");
                    return false;
                }
            }
        }
        if (phase == QStringLiteral("acknowledged")) {
            // The final state was committed before journal retirement.  Keep
            // this receipt valid so a crash in the retirement window is
            // recoverable and harmless on the next start.
            // Acknowledgement is a completed transaction.  It is valid to
            // observe it with any stable post-update state (disabled,
            // no_update, or a later check), because the rollback receipt is
            // carried by state and the journal is only a crash-window hint.
            // Treating only "updated" as valid made the normal disabled/
            // no-update path self-lock the daemon on its next restart.
            if (m_lastState == QStringLiteral("restart_pending")
                || m_lastState == QStringLiteral("rollback_restart_pending")
                || m_lastState == QStringLiteral("recovery_required")) {
                m_stateValid = false;
                m_lastState = QStringLiteral("recovery_required");
                m_lastError = QStringLiteral("acknowledged transaction has an invalid final state");
                return false;
            }
        } else if (phase == QStringLiteral("rollback_acknowledged")
                   && m_lastState == QStringLiteral("rolled_back")) {
            m_lastState = QStringLiteral("rolled_back");
        } else if (phase == QStringLiteral("restart_pending")
                   && !m_lastAppliedVersion.isEmpty()
                   && m_lastState != QStringLiteral("rollback_failed")) {
            // This is the expected post-restart acknowledgement window.  The
            // next checkAndApply() must health-check both binaries before
            // removing the journal.
            m_lastState = QStringLiteral("restart_pending");
        } else if (phase == QStringLiteral("rollback_restart_pending")
                   && !m_rollbackVersion.isEmpty()
                   && m_lastState != QStringLiteral("rollback_failed")) {
            m_lastState = QStringLiteral("rollback_restart_pending");
        } else {
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("headless update transaction requires recovery");
        }
    } else if (m_lastState == QStringLiteral("restart_pending")
               || m_lastState == QStringLiteral("rollback_restart_pending")) {
        // A restart/rollback state without a durable transaction journal is
        // never safe to acknowledge. Do not silently continue with an
        // unverifiable binary pair; require explicit recovery.
        m_lastState = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("pending headless transaction has no journal");
    }
    if (stateVersion == 1) {
        // Legacy receipts predate installation binding.  All fields above
        // were validated before migration; bind the receipt to this process
        // now and immediately rewrite it in the v2 schema.
        if (!saveState()) {
            m_stateValid = false;
            m_lastState = QStringLiteral("recovery_required");
            m_lastError = QStringLiteral("legacy headless update state could not be migrated");
            return false;
        }
    }
    return true;
}

bool HeadlessUpdateManager::saveState() const
{
    if (m_statePath.isEmpty()) {
        return true;
    }
    const QFileInfo info(m_statePath);
    QString directoryError;
    if (!ensureSecureDirectory(info.absolutePath(), &directoryError)) {
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
        { QStringLiteral("installDirectory"), QFileInfo(m_installDirectory).canonicalFilePath() },
        { QStringLiteral("updateRoot"), QFileInfo(m_updateRoot).canonicalFilePath() },
        { QStringLiteral("lastError"), m_lastError },
    };
    if (file.write(QJsonDocument(object).toJson(QJsonDocument::Compact)) < 0
        || !file.commit()) {
        return false;
    }
#ifndef Q_OS_WIN
    QFile::setPermissions(m_statePath, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
#endif
    return durableSyncFileAndDirectory(m_statePath);
}

bool HeadlessUpdateManager::writeJournal(const QJsonObject &journal, QString *error) const
{
    if (m_journalPath.isEmpty()) {
        if (error) *error = QStringLiteral("headless update journal path is unavailable");
        return false;
    }
    const QFileInfo info(m_journalPath);
    QString directoryError;
    if (!ensureSecureDirectory(info.absolutePath(), &directoryError)) {
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
    return durableSyncFileAndDirectory(m_journalPath);
}

bool HeadlessUpdateManager::writeRollbackReceipt(QString *error) const
{
    if (m_rollbackReceiptPath.isEmpty()) return true;
    if (m_rollbackDirectory.isEmpty() || !validVersion(m_rollbackVersion)
        || !hasExactManagedHashMap(m_rollbackHashes)) {
        if (error) *error = QStringLiteral("rollback receipt is incomplete");
        return false;
    }
    QString directoryError;
    if (!ensureSecureDirectory(QFileInfo(m_rollbackReceiptPath).absolutePath(), &directoryError)) {
        if (error) *error = directoryError.isEmpty()
                ? QStringLiteral("rollback receipt directory cannot be secured") : directoryError;
        return false;
    }
    QJsonObject hashes;
    for (auto it = m_rollbackHashes.cbegin(); it != m_rollbackHashes.cend(); ++it) {
        hashes.insert(it.key(), it.value());
    }
    QSaveFile file(m_rollbackReceiptPath);
    if (!file.open(QIODevice::WriteOnly)) {
        if (error) *error = QStringLiteral("rollback receipt cannot be opened");
        return false;
    }
    const QJsonObject receipt {
        { QStringLiteral("version"), 1 },
        { QStringLiteral("rollbackDirectory"), QFileInfo(m_rollbackDirectory).canonicalFilePath() },
        { QStringLiteral("rollbackVersion"), m_rollbackVersion },
        { QStringLiteral("rollbackHashes"), hashes },
        { QStringLiteral("installDirectory"), QFileInfo(m_installDirectory).canonicalFilePath() },
        { QStringLiteral("updateRoot"), QFileInfo(m_updateRoot).canonicalFilePath() },
    };
    if (file.write(QJsonDocument(receipt).toJson(QJsonDocument::Compact)) < 0
        || !file.commit()) {
        if (error) *error = QStringLiteral("rollback receipt cannot be persisted");
        return false;
    }
#ifndef Q_OS_WIN
    QFile::setPermissions(m_rollbackReceiptPath, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
#endif
    return durableSyncFileAndDirectory(m_rollbackReceiptPath);
}

bool HeadlessUpdateManager::loadRollbackReceipt()
{
    if (m_rollbackReceiptPath.isEmpty() || !QFileInfo::exists(m_rollbackReceiptPath)) {
        return true;
    }
    // A sidecar receipt is never an independent source of rollback authority.
    // With no rollback identity in stable state it is stale disposable
    // evidence; otherwise it must be paired with the state receipt so a
    // copied old receipt cannot replay an unrelated in-root backup.
    if (m_rollbackDirectory.isEmpty()) return true;
    const QFileInfo receiptInfo(m_rollbackReceiptPath);
    if (!receiptInfo.isFile() || receiptInfo.isSymLink()) return false;
#ifndef Q_OS_WIN
    if (m_requireRootOwnedFiles
        && (receiptInfo.ownerId() != 0
            || (receiptInfo.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther)) != 0)) {
        return false;
    }
#endif
    QFile file(m_rollbackReceiptPath);
    QJsonParseError parseError;
    if (!file.open(QIODevice::ReadOnly)) return false;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) return false;
    const QJsonObject receipt = document.object();
    qint64 receiptVersion = 0;
    if (!isObjectWithOnly(receipt, { QStringLiteral("version"),
                                     QStringLiteral("rollbackDirectory"),
                                     QStringLiteral("rollbackVersion"),
                                     QStringLiteral("rollbackHashes"),
                                     QStringLiteral("installDirectory"),
                                     QStringLiteral("updateRoot") })
        || !jsonInteger(receipt.value(QStringLiteral("version")), 1, 1, receiptVersion)
        || receipt.value(QStringLiteral("rollbackDirectory")).isString() == false
        || receipt.value(QStringLiteral("rollbackVersion")).isString() == false
        || receipt.value(QStringLiteral("rollbackHashes")).isObject() == false
        || receipt.value(QStringLiteral("installDirectory")).toString()
               != QFileInfo(m_installDirectory).canonicalFilePath()
        || receipt.value(QStringLiteral("updateRoot")).toString()
               != QFileInfo(m_updateRoot).canonicalFilePath()) {
        return false;
    }
    const QString directory = receipt.value(QStringLiteral("rollbackDirectory")).toString();
    const QString root = QFileInfo(m_updateRoot).canonicalFilePath();
    const QString canonical = QFileInfo(directory).canonicalFilePath();
    if (root.isEmpty() || canonical.isEmpty()
        || !canonical.startsWith(root + QDir::separator())
        || !validVersion(receipt.value(QStringLiteral("rollbackVersion")).toString())) {
        return false;
    }
    if (!m_rollbackDirectory.isEmpty()) {
        if (QFileInfo(m_rollbackDirectory).canonicalFilePath() != canonical
            || m_rollbackVersion != receipt.value(QStringLiteral("rollbackVersion")).toString()) {
            return false;
        }
        const QJsonObject stateHashes = receipt.value(QStringLiteral("rollbackHashes")).toObject();
        for (const QString &name : managedPayloadFiles()) {
            if (m_rollbackHashes.value(name) != stateHashes.value(name).toString()) return false;
        }
    }
    QMap<QString, QString> hashes;
    const QJsonObject hashObject = receipt.value(QStringLiteral("rollbackHashes")).toObject();
    if (!hasExactManagedFileSet(hashObject)) return false;
    for (const QString &name : managedPayloadFiles()) {
        if (!hashObject.value(name).isString() || !validSha256(hashObject.value(name).toString())
            || !verifyRollbackFile(QDir(canonical).filePath(name),
                                   hashObject.value(name).toString(), nullptr)) {
            return false;
        }
        hashes.insert(name, hashObject.value(name).toString());
    }
    m_rollbackDirectory = canonical;
    m_rollbackVersion = receipt.value(QStringLiteral("rollbackVersion")).toString();
    m_rollbackHashes = hashes;
    return true;
}

QString HeadlessUpdateManager::trustedUpdatePublicKeyPath()
{
    return QString::fromLatin1(TrustedUpdateKeyPath);
}

bool HeadlessUpdateManager::verifyTrustedKey(const QString &configuredPath,
                                             QByteArray *keyBytes,
                                             QString *error) const
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
    QFile keyFile(configuredPath);
    if (!keyFile.open(QIODevice::ReadOnly) || keyFile.size() <= 0
        || keyFile.size() > 16 * 1024) {
        if (error) *error = QStringLiteral("update trust anchor cannot be read safely");
        return false;
    }
    const QByteArray bytes = keyFile.readAll();
    if (bytes.size() != keyFile.size()) {
        if (error) *error = QStringLiteral("update trust anchor could not be read completely");
        return false;
    }
    if (keyBytes) {
        // Force a detached, immutable-in-practice memory copy.  Manifest
        // verification never hands the pathname back to OpenSSL.
        *keyBytes = QByteArray(bytes.constData(), bytes.size());
    }
    return true;
}

bool HeadlessUpdateManager::verifyInstallFile(const QString &path, QString *error) const
{
    const QFileInfo info(path);
    const QFileInfo root(m_installDirectory);
    const QString rootPath = root.canonicalFilePath();
    const QString filePath = info.canonicalFilePath();
    const QFileInfo parent(info.absolutePath());
    if (!root.isDir() || root.isSymLink() || rootPath.isEmpty()
        || !parent.isDir() || parent.isSymLink() || filePath.isEmpty()
        || !filePath.startsWith(rootPath + QDir::separator())
        || !info.isFile() || info.isSymLink()) {
        if (error) *error = QStringLiteral("headless install file is outside the trusted installation root");
        return false;
    }
#ifndef Q_OS_WIN
    if (m_requireRootOwnedFiles && (info.ownerId() != 0 || parent.ownerId() != 0
            || (info.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther)) != 0
            || (parent.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther)) != 0)) {
        if (error) *error = QStringLiteral("headless install file must be root-owned and not group/world writable");
        return false;
    }
#endif
    return true;
}

QString HeadlessUpdateManager::managedInstallPath(const QString &name) const
{
    if (!managedPayloadFiles().contains(name)) return {};
    return QDir(m_installDirectory).filePath(name);
}

bool HeadlessUpdateManager::verifyManagedInstallFile(const QString &name, QString *error) const
{
    const QString path = managedInstallPath(name);
    if (path.isEmpty()) {
        if (error) *error = QStringLiteral("headless managed install file name is invalid");
        return false;
    }
    return verifyInstallFile(path, error);
}

bool HeadlessUpdateManager::verifyManagedInstalledFile(const QString &name,
                                                       const QString &expectedSha256,
                                                       qint64 expectedSize,
                                                       QString *error) const
{
    const QString path = managedInstallPath(name);
    if (!verifyManagedInstallFile(name, error)
        || !validSha256(expectedSha256)
        || sha256ForFile(path) != expectedSha256
        || (expectedSize >= 0 && QFileInfo(path).size() != expectedSize)) {
        if (error) *error = QStringLiteral("installed headless managed file failed exact hash or size verification");
        return false;
    }
    return true;
}

bool HeadlessUpdateManager::verifyInstalledFile(const QString &path,
                                                const QString &expectedSha256,
                                                qint64 expectedSize,
                                                QString *error) const
{
    if (!verifyInstallFile(path, error) || !validSha256(expectedSha256)
        || sha256ForFile(path) != expectedSha256
        || (expectedSize >= 0 && QFileInfo(path).size() != expectedSize)) {
        if (error) *error = QStringLiteral("installed headless binary failed exact hash or size verification");
        return false;
    }
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
    const QFileInfo parent(info.absolutePath());
    if (!root.isDir() || root.isSymLink() || rootPath.isEmpty()
        || !parent.isDir() || parent.isSymLink() || filePath.isEmpty()
        || !filePath.startsWith(rootPath + QDir::separator())
        || !info.isFile() || info.isSymLink()
        || expectedSha256.isEmpty() || sha256ForFile(path) != expectedSha256) {
        if (error) *error = QStringLiteral("rollback evidence failed containment, ownership or SHA-256 verification");
        return false;
    }
#ifndef Q_OS_WIN
    if (m_requireRootOwnedFiles && (info.ownerId() != 0 || parent.ownerId() != 0
            || (info.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther)) != 0
            || (parent.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther)) != 0)) {
        if (error) *error = QStringLiteral("rollback evidence must be root-owned and not group/world writable");
        return false;
    }
#endif
    return true;
}

bool HeadlessUpdateManager::verifyEnvelope(const QJsonObject &envelope,
                                           const QByteArray &publicKeyBytes,
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
    if (publicKeyBytes.isEmpty() || publicKeyBytes.size() > 16 * 1024) {
        return false;
    }
    BIO *bio = BIO_new_mem_buf(publicKeyBytes.constData(), publicKeyBytes.size());
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

bool HeadlessUpdateManager::validArtifactUrl(const Profile &profile,
                                             const QUrl &manifestUrl,
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
    return safeUpdateUrl(profile, resolved)
            && !resolved.host().isEmpty() && resolved.userInfo().isEmpty()
            && !resolved.hasFragment()
            && resolved.scheme().compare(manifestUrl.scheme(), Qt::CaseInsensitive) == 0
            && resolved.host().compare(manifestUrl.host(), Qt::CaseInsensitive) == 0
            && effectivePort(resolved) == effectivePort(manifestUrl);
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
                                          QString *error,
                                          bool *destinationRemoved,
                                          const QString &expectedSha256,
                                          qint64 expectedSize)
{
    if (destinationRemoved) *destinationRemoved = false;
    const QFileInfo sourceInfo(source);
    const QString updateRoot = QFileInfo(m_updateRoot).canonicalFilePath();
    const QString sourceCanonical = sourceInfo.canonicalFilePath();
    const QString sourceParent = QFileInfo(sourceInfo.absolutePath()).canonicalFilePath();
    const QString installRoot = QFileInfo(m_installDirectory).canonicalFilePath();
    const QString destinationParent = QFileInfo(QFileInfo(destination).absolutePath()).canonicalFilePath();
    if (!sourceInfo.isFile() || sourceInfo.isSymLink()
        || updateRoot.isEmpty() || sourceCanonical.isEmpty()
        || !sourceCanonical.startsWith(updateRoot + QDir::separator())
        || sourceParent.isEmpty() || !sourceParent.startsWith(updateRoot + QDir::separator())
        || installRoot.isEmpty() || destinationParent != installRoot) {
        if (error) *error = QStringLiteral("headless update source is not a regular file");
        return false;
    }
    if ((!expectedSha256.isEmpty() && (!validSha256(expectedSha256)
                                       || sha256ForFile(sourceCanonical) != expectedSha256))
        || (expectedSize >= 0 && sourceInfo.size() != expectedSize)) {
        if (error) *error = QStringLiteral("headless update source failed expected hash or size verification");
        return false;
    }
    const QString temporary = QDir(QFileInfo(destination).absolutePath()).filePath(
            QStringLiteral(".%1.update-%2").arg(QFileInfo(destination).fileName(),
                                                  QUuid::createUuid().toString(QUuid::WithoutBraces)));
    QFile::remove(temporary);
    // Re-stat and re-canonicalize immediately before the copy to close the
    // check/use gap for a writable staging root.
    const QFileInfo sourceBeforeCopy(source);
    if (!sourceBeforeCopy.isFile() || sourceBeforeCopy.isSymLink()
        || sourceBeforeCopy.canonicalFilePath() != sourceCanonical
        || QFileInfo(sourceBeforeCopy.absolutePath()).canonicalFilePath() != sourceParent
        || !QFile::copy(sourceCanonical, temporary)) {
        if (error) *error = QStringLiteral("headless update binary cannot be copied into place");
        return false;
    }
    // The staging file is private to this operation.  Rehash it after the
    // copy and immediately before rename so a changed source or partial copy
    // can never become the installed candidate.
    const QFileInfo temporaryInfo(temporary);
    if (!temporaryInfo.isFile() || temporaryInfo.isSymLink()
        || (expectedSize >= 0 && temporaryInfo.size() != expectedSize)
        || (!expectedSha256.isEmpty() && sha256ForFile(temporary) != expectedSha256)) {
        QFile::remove(temporary);
        if (error) *error = QStringLiteral("headless update private staging file failed expected hash or size verification");
        return false;
    }
    if (!durableSyncFileAndDirectory(temporary)
        || !durableSyncFileAndDirectory(sourceCanonical)
        || !durableSyncFileAndDirectory(sourceParent)) {
        QFile::remove(temporary);
        if (error) *error = QStringLiteral("headless update staging copy cannot be durably synced");
        return false;
    }
#ifndef Q_OS_WIN
    const bool hadDestination = QFileInfo::exists(destination);
    if (!QFile::setPermissions(temporary, QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                      | QFileDevice::ExeOwner)) {
        QFile::remove(temporary);
        if (error) *error = QStringLiteral("headless update temporary permissions cannot be restricted");
        return false;
    }
    if (::rename(temporary.toLocal8Bit().constData(), destination.toLocal8Bit().constData()) != 0) {
        QFile::remove(temporary);
        if (error) *error = QStringLiteral("headless update binary cannot be atomically replaced");
        return false;
    }
    if (destinationRemoved) *destinationRemoved = hadDestination;
    if (!durableSyncFileAndDirectory(destination)) {
        if (error) *error = QStringLiteral("headless update destination cannot be durably synced");
        return false;
    }
#else
    const bool hadDestination = QFileInfo::exists(destination);
    if (hadDestination && !QFile::remove(destination)) {
        QFile::remove(temporary);
        if (error) *error = QStringLiteral("headless update destination cannot be removed");
        return false;
    }
    if (destinationRemoved) *destinationRemoved = hadDestination;
    if (!QFile::rename(temporary, destination)) {
        // The destination may already have been removed.  Preserve a best
        // effort recovery copy so a failed replacement cannot turn a missing
        // managed file into an unrecoverable gap without evidence.
        if (!QFileInfo::exists(destination)) {
            QFile::copy(temporary, destination);
        }
        QFile::remove(temporary);
        if (error) *error = QStringLiteral("headless update binary cannot be replaced");
        return false;
    }
    if (destinationRemoved) *destinationRemoved = false;
    if (!durableSyncFileAndDirectory(destination)) {
        if (error) *error = QStringLiteral("headless update destination cannot be durably synced");
        return false;
    }
#endif
    return true;
}

} // namespace amnezia::headless
