#pragma once

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QLockFile>
#include <QRegularExpression>
#include <QSet>
#include <QStandardPaths>
#include <QUuid>
#include <memory>
#include <utility>

#include "commonStructs.h"
#include "secureQSettings.h"
#include "../../../common/awgMigrationSecretStore.h"

// Local administrator authority, separate from the imported profile and the
// server's unsigned transaction journal. No receipt can manufacture a digest.
namespace amnezia::awgControlAuthority {
inline bool digest(const QString &value)
{
    return value.size() == 64
        && QRegularExpression(QStringLiteral("^[a-f0-9]{64}$")).match(value).hasMatch();
}

inline bool boundedText(const QString &value, qsizetype limit)
{
    if (value.isEmpty() || value.size() > limit) return false;
    for (const QChar ch : value) if (ch.unicode() < 32 || ch.unicode() == 127) return false;
    return true;
}

inline bool validIdentity(const QJsonObject &value)
{
    if (value.size() != 6) return false;
    const auto source = value.value(QStringLiteral("source")).toString();
    const auto port = value.value(QStringLiteral("port"));
    const auto fingerprint = value.value(QStringLiteral("sshHostKeyFingerprint")).toString();
    return boundedText(value.value(QStringLiteral("serverId")).toString(), 256)
        && boundedText(value.value(QStringLiteral("host")).toString(), 253)
        && boundedText(value.value(QStringLiteral("user")).toString(), 256)
        && port.isDouble() && port.toDouble() == port.toInt()
        && port.toInt() > 0 && port.toInt() <= 65535
        && fingerprint.size() == 50
        && QRegularExpression(QStringLiteral("^SHA256:[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$"))
                .match(fingerprint).hasMatch()
        && (source == QStringLiteral("amnezia-awg") || source == QStringLiteral("amnezia-awg2"));
}

inline QJsonObject identity(const QString &serverId, const ServerCredentials &credentials,
                            const QString &source)
{
    // Password rotation does not reset a trusted identity. A host-key, account,
    // endpoint or source change selects a different, initially untrusted scope.
    const QJsonObject value{{QStringLiteral("serverId"), serverId},
        {QStringLiteral("host"), credentials.hostName.trimmed().toLower()},
        {QStringLiteral("port"), credentials.port},
        {QStringLiteral("user"), credentials.userName},
        {QStringLiteral("sshHostKeyFingerprint"), credentials.sshHostKeyFingerprint},
        {QStringLiteral("source"), source}};
    return validIdentity(value) ? value : QJsonObject{};
}

inline bool generation(qint64 value) { return value > 0 && value <= 9007199254740991LL; }

struct LoadResult {
    bool ok = false;
    bool missing = false;
    QJsonObject record;
    QString error;
};

class Store {
public:
    Store(SecureQSettings *settings, QJsonObject scope)
        : m_identity(std::move(scope)),
          m_organization(QCoreApplication::organizationName()),
          m_application(QCoreApplication::applicationName())
    {
        // Retain the call shape, but never turn the one-shot operator's
        // read-only application settings into a mutable generic settings path.
        // The authority backend always owns a dedicated settings namespace.
        Q_UNUSED(settings);
        m_hash = QString::fromLatin1(QCryptographicHash::hash(
            QJsonDocument(m_identity).toJson(QJsonDocument::Compact), QCryptographicHash::Sha256).toHex());
    }

    bool matches(const ServerCredentials &credentials, const QString &source) const
    {
        return validIdentity(m_identity) && m_identity == identity(
            m_identity.value(QStringLiteral("serverId")).toString(), credentials, source);
    }

    // Keep this object alive and locked across read, remote operation and commit.
    // Never reset pending state just because a transport reply was lost.
    bool lock(QString *error = nullptr)
    {
        if (m_lock && m_lock->isLocked()) return true;
        if (!validIdentity(m_identity)) return fail(error, "authority_identity_invalid");
        QString directory;
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
        // key() refuses to create a new key in a nonempty store. Initialize it
        // before creating any lock directory so locks cannot cause a false reset.
        if (!awgMigrationSecretStore::available()) return fail(error, "authority_store_unavailable");
        m_storeDirectory = awgMigrationSecretStore::directory();
        if (m_storeDirectory.isEmpty()) return fail(error, "authority_store_unavailable");
        directory = m_storeDirectory + QStringLiteral("/control-authority-locks");
#else
        // Async PREPARE and the one-shot operator both own a dedicated settings
        // object. Never migrate/write the ordinary app settings, and never
        // retain an application-owned QObject across worker/app lifetime.
        if (m_organization.isEmpty() || m_application.isEmpty())
            return fail(error, "authority_store_unavailable");
        const QString base = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
        if (base.isEmpty()) return fail(error, "authority_store_unavailable");
        directory = base + QStringLiteral("/control-authority-locks");
#endif
        if (!QDir().mkpath(directory) || QFileInfo(directory).isSymLink()
            || !QFile::setPermissions(directory, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner))
            return fail(error, "authority_lock_directory_invalid");
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
        struct stat st {};
        if (::lstat(QFile::encodeName(directory).constData(), &st) != 0
            || !S_ISDIR(st.st_mode) || st.st_uid != ::geteuid() || (st.st_mode & 077))
            return fail(error, "authority_lock_directory_invalid");
#endif
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
        const QString path = directory + QLatin1Char('/') + m_hash + QStringLiteral(".lock");
#else
        // All identities share one settings file and keychain material. Lock
        // the entire backend, including first key creation and migration.
        const QString path = directory + QStringLiteral("/settings.lock");
#endif
        if (QFileInfo(path).isSymLink()) return fail(error, "authority_lock_invalid");
        m_lock = std::make_unique<QLockFile>(path);
        m_lock->setStaleLockTime(0); // never expire a live operation by elapsed time
        if (!m_lock->tryLock(0)) return fail(error, "authority_busy");
#if !defined(Q_OS_LINUX) || defined(Q_OS_ANDROID)
        if (!m_settings) {
            m_ownedSettings = std::make_unique<SecureQSettings>(m_organization, m_application, nullptr,
                SecureQSettings::AccessMode::ReadWrite, true, SecureQSettings::StorageScope::ControlAuthority);
            m_settings = m_ownedSettings.get();
        }
#endif
        return true;
    }

    // Async callers close on their worker thread before releasing the shared
    // Store itself. QSettings/QObject teardown never migrates to the UI thread.
    void close()
    {
        m_ownedSettings.reset();
        m_settings = nullptr;
        m_lock.reset();
    }

    LoadResult load() const
    {
        if (!m_lock || !m_lock->isLocked()) return {false, false, {}, QStringLiteral("authority_not_locked")};
        QByteArray bytes;
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
        if (m_storeDirectory.isEmpty() || awgMigrationSecretStore::directory() != m_storeDirectory
            || !awgMigrationSecretStore::available())
            return {false, false, {}, QStringLiteral("authority_store_unavailable")};
        const QString path = awgMigrationSecretStore::journalPath(m_storeDirectory, storageId());
        struct stat st {};
        if (::lstat(QFile::encodeName(path).constData(), &st) != 0) {
            if (errno == ENOENT) return {true, true, {}, {}};
            return {false, false, {}, QStringLiteral("authority_read_failed")};
        }
        bytes = awgMigrationSecretStore::read(storageId());
#else
        QVariant value;
        if (!m_settings->readFreshValue(settingsKey(), value))
            return {false, false, {}, QStringLiteral("authority_read_failed")};
        if (!value.isValid()) return {true, true, {}, {}};
        if (value.userType() != QMetaType::QByteArray)
            return {false, false, {}, QStringLiteral("authority_read_failed")};
        bytes = value.toByteArray();
#endif
        if (bytes.isEmpty() || bytes.size() > 16384)
            return {false, false, {}, QStringLiteral("authority_corrupt")};
        const QJsonDocument document = QJsonDocument::fromJson(bytes);
        if (!document.isObject() || !validRecord(document.object())
            || document.toJson(QJsonDocument::Compact) != bytes)
            return {false, false, {}, QStringLiteral("authority_corrupt")};
        return {true, false, document.object(), {}};
    }

    // Separate from CURRENT: PREPARE creates private staging roots before its
    // preflight can authorize a durable prepare intent. Losing their cleanup
    // acknowledgement must not manufacture a pending main transaction.
    LoadResult loadPrepareCleanup() const
    {
        if (!m_lock || !m_lock->isLocked()) return {false, false, {}, QStringLiteral("authority_not_locked")};
        QByteArray bytes;
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
        if (m_storeDirectory.isEmpty() || awgMigrationSecretStore::directory() != m_storeDirectory
            || !awgMigrationSecretStore::available())
            return {false, false, {}, QStringLiteral("authority_store_unavailable")};
        const QString path = awgMigrationSecretStore::journalPath(m_storeDirectory, prepareCleanupStorageId());
        struct stat st {};
        if (::lstat(QFile::encodeName(path).constData(), &st) != 0) {
            if (errno == ENOENT) return {true, true, {}, {}};
            return {false, false, {}, QStringLiteral("authority_prepare_cleanup_read_failed")};
        }
        bytes = awgMigrationSecretStore::read(prepareCleanupStorageId());
#else
        QVariant value;
        if (!m_settings->readFreshValue(prepareCleanupSettingsKey(), value))
            return {false, false, {}, QStringLiteral("authority_prepare_cleanup_read_failed")};
        if (!value.isValid()) return {true, true, {}, {}};
        if (value.userType() != QMetaType::QByteArray)
            return {false, false, {}, QStringLiteral("authority_prepare_cleanup_read_failed")};
        bytes = value.toByteArray();
#endif
        if (bytes.isEmpty() || bytes.size() > 16384)
            return {false, false, {}, QStringLiteral("authority_prepare_cleanup_corrupt")};
        const QJsonDocument document = QJsonDocument::fromJson(bytes);
        if (!document.isObject() || !validPrepareCleanup(document.object())
            || document.toJson(QJsonDocument::Compact) != bytes)
            return {false, false, {}, QStringLiteral("authority_prepare_cleanup_corrupt")};
        return {true, false, document.object(), {}};
    }

    bool beginPrepareCleanup(const QJsonObject &roots, QString *error = nullptr)
    {
        const auto previous = loadPrepareCleanup();
        if (!previous.ok) return fail(error, previous.error);
        if (!previous.missing) return fail(error, "authority_prepare_cleanup_required");
        if (!validPrepareCleanupRoots(roots)) return fail(error, "authority_prepare_cleanup_invalid");
        auto value = roots;
        value.insert(QStringLiteral("schema"), 1);
        value.insert(QStringLiteral("identity"), m_identity);
        value.insert(QStringLiteral("programFiles"), prepareProgramFiles());
        value.insert(QStringLiteral("stagingFiles"), prepareStagingFiles());
        return writePrepareCleanup(value, error);
    }

    // Call only after every exact remote leaf/root is proven removed (or
    // already ABSENT after a lost acknowledgement). Never clear main state.
    bool completePrepareCleanup(const QJsonObject &roots, QString *error = nullptr)
    {
        const auto previous = loadPrepareCleanup();
        if (!previous.ok) return fail(error, previous.error);
        if (previous.missing || !validPrepareCleanupRoots(roots)
            || prepareCleanupRoots(previous.record) != roots)
            return fail(error, "authority_prepare_cleanup_conflict");
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
        const QString path = awgMigrationSecretStore::journalPath(m_storeDirectory, prepareCleanupStorageId());
        struct stat st {};
        if (::lstat(QFile::encodeName(path).constData(), &st) != 0
            || !awgMigrationSecretStore::safePrivateFile(st)
            || ::unlink(QFile::encodeName(path).constData()) != 0
            || !awgMigrationSecretStore::syncDirectory(m_storeDirectory))
            return fail(error, "authority_prepare_cleanup_write_failed");
#else
        m_settings->remove(prepareCleanupSettingsKey());
#endif
        const auto cleared = loadPrepareCleanup();
        return cleared.ok && cleared.missing ? true : fail(error, "authority_prepare_cleanup_write_failed");
    }

    bool beginPrepare(const QString &bundledSha, QString *error = nullptr,
                      const QString &endpointHost = QString())
    {
        const auto previous = load();
        if (!previous.ok) return fail(error, previous.error);
        const bool retired = !previous.missing && previous.record.value("state") == "retiredPrepare";
        if (!previous.missing && !retired) return fail(error, "authority_already_exists");
        if (!digest(bundledSha)) return fail(error, "authority_digest_invalid");
        if (!endpointHost.isEmpty() && !validEndpointHost(endpointHost))
            return fail(error, "authority_endpoint_invalid");
        auto value = base(QStringLiteral("pendingPrepare"), bundledSha);
        if (previous.record.contains(QStringLiteral("probeCleanup")))
            value.insert(QStringLiteral("probeCleanup"), previous.record.value(QStringLiteral("probeCleanup")));
        if (retired) {
            const auto predecessors = previous.record.value(QStringLiteral("retiredPredecessors")).toArray();
            if (predecessors.size() >= 32) return fail(error, "authority_retired_history_exhausted");
            const qint64 retiredGeneration = previous.record.value("generation").toInteger();
            if (retiredGeneration == 9007199254740991LL)
                return fail(error, "authority_generation_exhausted");
            value.insert(QStringLiteral("minimumGeneration"), retiredGeneration + 1);
            value.insert(QStringLiteral("retiredPredecessors"), predecessors);
        }
        if (!endpointHost.isEmpty()) value.insert(QStringLiteral("endpointHost"), endpointHost);
        value.insert(QStringLiteral("operationId"), QUuid::createUuid().toString(QUuid::WithoutBraces));
        return write(value, error);
    }

    bool commitPrepare(qint64 number, const QString &bundledSha, QString *error = nullptr)
    {
        const auto previous = load();
        if (!previous.ok) return fail(error, previous.error);
        if (previous.missing || previous.record.value("state") != "pendingPrepare"
            || previous.record.value("currentSha") != bundledSha || !generation(number)
            || number < previous.record.value("minimumGeneration").toInteger())
            return fail(error, "authority_prepare_conflict");
        auto value = current(number, bundledSha);
        value.insert(QStringLiteral("prepareOperationId"), previous.record.value(QStringLiteral("operationId")));
        if (previous.record.contains(QStringLiteral("endpointHost")))
            value.insert(QStringLiteral("endpointHost"), previous.record.value(QStringLiteral("endpointHost")));
        if (previous.record.contains(QStringLiteral("minimumGeneration")))
            value.insert(QStringLiteral("minimumGeneration"), previous.record.value(QStringLiteral("minimumGeneration")));
        if (previous.record.contains(QStringLiteral("retiredPredecessors")))
            value.insert(QStringLiteral("retiredPredecessors"), previous.record.value(QStringLiteral("retiredPredecessors")));
        if (previous.record.contains(QStringLiteral("probeCleanup")))
            value.insert(QStringLiteral("probeCleanup"), previous.record.value(QStringLiteral("probeCleanup")));
        return write(value, error);
    }

    // The caller has verified the installed control through the trusted native
    // consumer. A transport failure alone never authorizes this transition.
    bool resolvePendingPrepare(qint64 number, const QString &knownSha, QString *error = nullptr)
    {
        return commitPrepare(number, knownSha, error);
    }

    // A trusted native abort receipt proved this exact prepare intent retired.
    // Keep a tombstone instead of resetting to missing: the next attempt must
    // use a fresh operation identity and a strictly higher generation.
    bool retirePrepare(qint64 number, const QString &knownSha, const QString &knownOperationId,
                       const QString &retiredJournalSha, QString *error = nullptr)
    {
        const auto previous = load();
        if (!previous.ok) return fail(error, previous.error);
        if (previous.missing || previous.record.value("state") != "pendingPrepare"
            || previous.record.value("currentSha") != knownSha
            || previous.record.value("operationId") != knownOperationId || !generation(number)
            || !digest(retiredJournalSha)
            || number < previous.record.value("minimumGeneration").toInteger())
            return fail(error, "authority_retire_conflict");
        auto predecessors = previous.record.value(QStringLiteral("retiredPredecessors")).toArray();
        if (predecessors.size() >= 32) return fail(error, "authority_retired_history_exhausted");
        if (!predecessors.isEmpty() && number <= predecessors.last().toObject().value("generation").toInteger())
            return fail(error, "authority_retire_conflict");
        predecessors.append(QJsonObject{{QStringLiteral("generation"), number},
            {QStringLiteral("sha256"), knownSha}, {QStringLiteral("operationId"), knownOperationId},
            {QStringLiteral("journalSha256"), retiredJournalSha}});
        auto value = base(QStringLiteral("retiredPrepare"), knownSha);
        value.insert(QStringLiteral("generation"), number);
        value.insert(QStringLiteral("operationId"), knownOperationId);
        value.insert(QStringLiteral("retiredVerified"), true);
        value.insert(QStringLiteral("retiredPredecessors"), predecessors);
        if (previous.record.contains(QStringLiteral("probeCleanup")))
            value.insert(QStringLiteral("probeCleanup"), previous.record.value(QStringLiteral("probeCleanup")));
        if (previous.record.contains(QStringLiteral("endpointHost")))
            value.insert(QStringLiteral("endpointHost"), previous.record.value(QStringLiteral("endpointHost")));
        return write(value, error);
    }

    bool currentMatches(const QJsonObject &record, qint64 number, const QString &sha) const
    {
        if (!validRecord(record)) return false;
        auto binding = record;
        binding.remove(QStringLiteral("cleanup"));
        binding.remove(QStringLiteral("prepareOperationId"));
        binding.remove(QStringLiteral("endpointHost"));
        binding.remove(QStringLiteral("minimumGeneration"));
        binding.remove(QStringLiteral("retiredPredecessors"));
        binding.remove(QStringLiteral("probeCleanup"));
        return binding == current(number, sha);
    }

    // Explicit operator CURRENT may anchor missing state, never overwrite a
    // different existing pin or discard an uncertain transaction.
    bool anchorCurrent(qint64 number, const QString &callerSha, QString *error = nullptr)
    {
        if (!generation(number) || !digest(callerSha)) return fail(error, "authority_binding_invalid");
        const auto previous = load();
        if (!previous.ok) return fail(error, previous.error);
        if (previous.missing) return write(current(number, callerSha), error);
        if (currentMatches(previous.record, number, callerSha)) return true;
        return fail(error, "authority_current_conflict");
    }

    bool beginMaintenance(qint64 number, const QString &currentSha, const QString &replacementSha,
                          const QString &expectedJournal, QString *error = nullptr,
                          const QString &recoveryDirectory = QString(),
                          const QString &recoveryIdentity = QString(),
                          const QString &recoveryUpload = QString())
    {
        const auto previous = load();
        if (!previous.ok) return fail(error, previous.error);
        if (!generation(number) || !digest(currentSha) || !digest(replacementSha) || !digest(expectedJournal)
            || previous.missing || !currentMatches(previous.record, number, currentSha))
            return fail(error, "authority_maintenance_conflict");
        if (previous.record.contains(QStringLiteral("cleanup")))
            return fail(error, "authority_cleanup_required");
        if (!recoveryDirectory.isEmpty() && !validRecoveryDirectory(recoveryDirectory))
            return fail(error, "authority_recovery_directory_invalid");
        if (recoveryDirectory.isEmpty() != recoveryIdentity.isEmpty()
            || (!recoveryIdentity.isEmpty() && !validRecoveryIdentity(recoveryIdentity)))
            return fail(error, "authority_recovery_identity_invalid");
        if (!recoveryUpload.isEmpty() && (recoveryDirectory.isEmpty() || recoveryIdentity.isEmpty()
            || !validRecoveryUpload(recoveryUpload)))
            return fail(error, "authority_recovery_upload_invalid");
        QJsonObject recoveryCleanup{{QStringLiteral("directory"), recoveryDirectory},
            {QStringLiteral("identity"), recoveryIdentity}, {QStringLiteral("replacementSha"), replacementSha}};
        if (!recoveryUpload.isEmpty()) recoveryCleanup.insert(QStringLiteral("upload"), recoveryUpload);
        if (previous.record.contains(QStringLiteral("probeCleanup"))
            && previous.record.value(QStringLiteral("probeCleanup")).toObject() != recoveryCleanup)
            return fail(error, "authority_probe_cleanup_conflict");
        auto value = previous.record;
        // The original files become transaction recovery inputs atomically.
        // They must not remain eligible for generic probe cleanup afterwards.
        value.remove(QStringLiteral("probeCleanup"));
        if (!recoveryDirectory.isEmpty()) value.insert(QStringLiteral("retainedDirectory"), recoveryDirectory);
        if (!recoveryIdentity.isEmpty()) value.insert(QStringLiteral("retainedIdentity"), recoveryIdentity);
        if (!recoveryUpload.isEmpty()) value.insert(QStringLiteral("retainedUpload"), recoveryUpload);
        value.insert(QStringLiteral("state"), QStringLiteral("pendingMaintenance"));
        value.insert(QStringLiteral("replacementSha"), replacementSha);
        value.insert(QStringLiteral("expectedJournal"), expectedJournal);
        value.insert(QStringLiteral("operationId"), QUuid::createUuid().toString(QUuid::WithoutBraces));
        return write(value, error);
    }

    // Call only after the actual trusted native consumer receipt was validated;
    // cleanup failure after a committed replacement must not retain the old pin.
    bool commitMaintenance(qint64 number, const QString &oldSha, const QString &newSha,
                           QString *error = nullptr)
    {
        const auto previous = load();
        if (!previous.ok) return fail(error, previous.error);
        if (previous.missing || previous.record.value("state") != "pendingMaintenance"
            || previous.record.value("generation").toDouble() != number
            || previous.record.value("currentSha") != oldSha
            || previous.record.value("replacementSha") != newSha)
            return fail(error, "authority_commit_conflict");
        return writeMaintenanceCurrent(previous.record, number, newSha, error);
    }

    // This is an explicit recovery gate, not journal-derived pin discovery.
    // The caller must verify the trusted native recovery receipt against this
    // exact previously authorized old/new candidate before invoking it.
    bool resolvePendingMaintenance(qint64 number, const QString &knownSha, QString *error = nullptr)
    {
        const auto previous = load();
        if (!previous.ok) return fail(error, previous.error);
        if (previous.missing || previous.record.value("state") != "pendingMaintenance"
            || previous.record.value("generation").toDouble() != number
            || (previous.record.value("currentSha") != knownSha
                && previous.record.value("replacementSha") != knownSha))
            return fail(error, "authority_recovery_conflict");
        return writeMaintenanceCurrent(previous.record, number, knownSha, error);
    }

    // Invoke only after the caller proved removal of this exact owned tree.
    // A mismatch cannot erase the durable cleanup obligation or change CURRENT.
    bool completeCleanup(const QString &directory, const QString &identity, QString *error = nullptr)
    {
        const auto previous = load();
        if (!previous.ok) return fail(error, previous.error);
        const auto cleanup = previous.record.value(QStringLiteral("cleanup")).toObject();
        if (previous.missing || previous.record.value(QStringLiteral("state")) != QStringLiteral("current")
            || !validCleanup(cleanup)
            || cleanup.value(QStringLiteral("directory")) != directory
            || cleanup.value(QStringLiteral("identity")) != identity)
            return fail(error, "authority_cleanup_conflict");
        auto value = previous.record;
        value.remove(QStringLiteral("cleanup"));
        return write(value, error);
    }

    bool beginProbeCleanup(const QString &directory, const QString &identity, const QString &sha,
                           const QString &upload = QString(), QString *error = nullptr)
    {
        const auto previous = load();
        if (!previous.ok) return fail(error, previous.error);
        if (previous.missing) return fail(error, "authority_probe_cleanup_conflict");
        if (previous.record.contains(QStringLiteral("probeCleanup")))
            return fail(error, "authority_probe_cleanup_required");
        if (previous.record.value(QStringLiteral("retainedDirectory")) == directory
            || previous.record.value(QStringLiteral("cleanup")).toObject().value(QStringLiteral("directory")) == directory)
            return fail(error, "authority_probe_cleanup_conflict");
        QJsonObject cleanup{{QStringLiteral("directory"), directory}, {QStringLiteral("identity"), identity},
            {QStringLiteral("replacementSha"), sha}};
        if (!upload.isEmpty()) cleanup.insert(QStringLiteral("upload"), upload);
        if (!validCleanup(cleanup)) return fail(error, "authority_probe_cleanup_invalid");
        auto value = previous.record;
        value.insert(QStringLiteral("probeCleanup"), cleanup);
        return write(value, error);
    }

    // The caller proved all exact input removals; this never settles a remote
    // transaction and cannot clear its separate original recovery obligation.
    bool completeProbeCleanup(const QString &directory, const QString &identity, QString *error = nullptr)
    {
        const auto previous = load();
        if (!previous.ok) return fail(error, previous.error);
        const auto cleanup = previous.record.value(QStringLiteral("probeCleanup")).toObject();
        if (previous.missing || !validCleanup(cleanup)
            || cleanup.value(QStringLiteral("directory")) != directory
            || cleanup.value(QStringLiteral("identity")) != identity)
            return fail(error, "authority_probe_cleanup_conflict");
        auto value = previous.record;
        value.remove(QStringLiteral("probeCleanup"));
        return write(value, error);
    }

private:
    bool fail(QString *error, const QString &reason) const { if (error) *error = reason; return false; }
    QString storageId() const { return QStringLiteral("control-authority-v1:") + m_hash; }
    QString settingsKey() const { return QStringLiteral("Conf/awgMigration/controlAuthority/") + m_hash; }
    QString prepareCleanupStorageId() const { return QStringLiteral("control-prepare-cleanup-v1:") + m_hash; }
    QString prepareCleanupSettingsKey() const { return QStringLiteral("Conf/awgMigration/controlPrepareCleanup/") + m_hash; }
    QJsonObject base(const QString &state, const QString &sha) const
    {
        return {{QStringLiteral("schema"), 1}, {QStringLiteral("identity"), m_identity},
            {QStringLiteral("state"), state}, {QStringLiteral("currentSha"), sha}};
    }
    QJsonObject current(qint64 number, const QString &sha) const
    {
        auto value = base(QStringLiteral("current"), sha);
        value.insert(QStringLiteral("generation"), number);
        return value;
    }
    static bool validRecoveryDirectory(const QString &path)
    {
        return QRegularExpression(QStringLiteral("\\A/tmp/amnezia-migration-maintenance-[A-Za-z0-9]{24}\\z"))
                .match(path).hasMatch();
    }
    static bool validEndpointHost(const QString &host)
    {
        return boundedText(host, 253)
            && QRegularExpression(QStringLiteral("\\A[A-Za-z0-9.-]{1,253}\\z")).match(host).hasMatch();
    }
    static QJsonArray prepareProgramFiles()
    {
        return {QStringLiteral("native-feed"), QStringLiteral("native-collector")};
    }
    static QJsonArray prepareStagingFiles()
    {
        return {QStringLiteral("native-feed.upload"), QStringLiteral("native-collector.upload"),
            QStringLiteral("prepare.py"), QStringLiteral("automatic.py"), QStringLiteral("trusted_image.py"),
            QStringLiteral("service.py"), QStringLiteral("target.py"), QStringLiteral("policy.py"),
            QStringLiteral("journal.py"), QStringLiteral("feeds.py"), QStringLiteral("ready_validation.py")};
    }
    static QJsonObject prepareCleanupRoots(const QJsonObject &value)
    {
        return {{QStringLiteral("programDirectory"), value.value(QStringLiteral("programDirectory"))},
            {QStringLiteral("programIdentity"), value.value(QStringLiteral("programIdentity"))},
            {QStringLiteral("stagingDirectory"), value.value(QStringLiteral("stagingDirectory"))},
            {QStringLiteral("stagingIdentity"), value.value(QStringLiteral("stagingIdentity"))}};
    }
    static bool validStagingIdentity(const QString &identity)
    {
        const auto match = QRegularExpression(QStringLiteral(
            "\\A(0|[1-9][0-9]{0,9}) (0|[1-9][0-9]{0,9}) 700 (0|[1-9][0-9]{0,19}) (0|[1-9][0-9]{0,19})\\z")).match(identity);
        if (!match.hasMatch()) return false;
        for (int field = 1; field <= 4; ++field) {
            bool ok = false;
            const auto number = match.captured(field).toULongLong(&ok);
            if (!ok || QString::number(number) != match.captured(field)
                || (field <= 2 && number > 4294967295ULL)) return false;
        }
        return true;
    }
    static bool validPrepareCleanupRoots(const QJsonObject &roots)
    {
        return roots.size() == 4
            && QRegularExpression(QStringLiteral("\\A/tmp/amnezia-migration-programs-[A-Za-z0-9]{24}\\z"))
                .match(roots.value(QStringLiteral("programDirectory")).toString()).hasMatch()
            && validRecoveryIdentity(roots.value(QStringLiteral("programIdentity")).toString())
            && QRegularExpression(QStringLiteral("\\A/tmp/amnezia-migration-[A-Za-z0-9]{24}\\z"))
                .match(roots.value(QStringLiteral("stagingDirectory")).toString()).hasMatch()
            && validStagingIdentity(roots.value(QStringLiteral("stagingIdentity")).toString());
    }
    bool validPrepareCleanup(const QJsonObject &value) const
    {
        return value.size() == 8 && value.value(QStringLiteral("schema")).isDouble()
            && value.value(QStringLiteral("schema")).toDouble() == 1
            && value.value(QStringLiteral("identity")).isObject()
            && value.value(QStringLiteral("identity")).toObject() == m_identity
            && validPrepareCleanupRoots(prepareCleanupRoots(value))
            && value.value(QStringLiteral("programFiles")).toArray() == prepareProgramFiles()
            && value.value(QStringLiteral("stagingFiles")).toArray() == prepareStagingFiles();
    }
    bool writePrepareCleanup(const QJsonObject &value, QString *error)
    {
        if (!m_lock || !m_lock->isLocked() || !validPrepareCleanup(value))
            return fail(error, "authority_prepare_cleanup_write_invalid");
        const QByteArray bytes = QJsonDocument(value).toJson(QJsonDocument::Compact);
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
        if (!awgMigrationSecretStore::write(prepareCleanupStorageId(), bytes))
            return fail(error, "authority_prepare_cleanup_write_failed");
#else
        m_settings->setValue(prepareCleanupSettingsKey(), bytes);
#endif
        const auto stored = loadPrepareCleanup();
        return stored.ok && !stored.missing && stored.record == value
            ? true : fail(error, "authority_prepare_cleanup_write_failed");
    }
    static bool validRecoveryIdentity(const QString &identity)
    {
        const auto match = QRegularExpression(QStringLiteral(
                "\\A0 0 700 (0|[1-9][0-9]{0,19}) (0|[1-9][0-9]{0,19})\\z")).match(identity);
        if (!match.hasMatch()) return false;
        bool deviceOk = false, inodeOk = false;
        const auto device = match.captured(1).toULongLong(&deviceOk);
        const auto inode = match.captured(2).toULongLong(&inodeOk);
        return deviceOk && inodeOk && QString::number(device) == match.captured(1)
            && QString::number(inode) == match.captured(2);
    }
    static bool validRecoveryUpload(const QString &path)
    {
        return QRegularExpression(QStringLiteral("\\A/tmp/amnezia-migration-upload-[A-Za-z0-9]{24}\\z"))
                .match(path).hasMatch();
    }
    static bool validCleanup(const QJsonObject &cleanup)
    {
        const bool hasUpload = cleanup.contains(QStringLiteral("upload"));
        return cleanup.size() == 3 + int(hasUpload)
            && validRecoveryDirectory(cleanup.value(QStringLiteral("directory")).toString())
            && validRecoveryIdentity(cleanup.value(QStringLiteral("identity")).toString())
            && digest(cleanup.value(QStringLiteral("replacementSha")).toString())
            && (!hasUpload || validRecoveryUpload(cleanup.value(QStringLiteral("upload")).toString()));
    }
    bool writeMaintenanceCurrent(const QJsonObject &pending, qint64 number, const QString &sha,
                                 QString *error)
    {
        auto value = current(number, sha);
        if (pending.contains(QStringLiteral("prepareOperationId")))
            value.insert(QStringLiteral("prepareOperationId"), pending.value(QStringLiteral("prepareOperationId")));
        if (pending.contains(QStringLiteral("endpointHost")))
            value.insert(QStringLiteral("endpointHost"), pending.value(QStringLiteral("endpointHost")));
        if (pending.contains(QStringLiteral("minimumGeneration")))
            value.insert(QStringLiteral("minimumGeneration"), pending.value(QStringLiteral("minimumGeneration")));
        if (pending.contains(QStringLiteral("retiredPredecessors")))
            value.insert(QStringLiteral("retiredPredecessors"), pending.value(QStringLiteral("retiredPredecessors")));
        if (pending.contains(QStringLiteral("probeCleanup")))
            value.insert(QStringLiteral("probeCleanup"), pending.value(QStringLiteral("probeCleanup")));
        if (pending.contains(QStringLiteral("retainedDirectory"))) {
            // Old records may retain a path without a proven inode. Preserve
            // that pending state for explicit recovery; never invent ownership
            // or silently discard the only retained input location.
            if (!pending.contains(QStringLiteral("retainedIdentity")))
                return fail(error, "authority_recovery_identity_required");
            QJsonObject cleanup{
                {QStringLiteral("directory"), pending.value(QStringLiteral("retainedDirectory"))},
                {QStringLiteral("identity"), pending.value(QStringLiteral("retainedIdentity"))},
                {QStringLiteral("replacementSha"), pending.value(QStringLiteral("replacementSha"))}};
            if (pending.contains(QStringLiteral("retainedUpload")))
                cleanup.insert(QStringLiteral("upload"), pending.value(QStringLiteral("retainedUpload")));
            value.insert(QStringLiteral("cleanup"), cleanup);
        }
        return write(value, error);
    }
    static bool validRetiredPredecessors(const QJsonArray &predecessors)
    {
        if (predecessors.isEmpty() || predecessors.size() > 32) return false;
        qint64 previousGeneration = 0;
        QSet<QString> operations;
        for (const auto &entry : predecessors) {
            if (!entry.isObject()) return false;
            const auto proof = entry.toObject();
            const auto number = proof.value(QStringLiteral("generation"));
            const QString operation = proof.value(QStringLiteral("operationId")).toString();
            if (proof.size() != 4 || !number.isDouble() || number.toDouble() < 1
                || number.toDouble() > 9007199254740991.0
                || number.toDouble() != static_cast<double>(number.toInteger())
                || number.toInteger() <= previousGeneration
                || !digest(proof.value(QStringLiteral("sha256")).toString())
                || !digest(proof.value(QStringLiteral("journalSha256")).toString())
                || QUuid(operation).isNull() || QUuid(operation).toString(QUuid::WithoutBraces) != operation
                || operations.contains(operation)) return false;
            previousGeneration = number.toInteger();
            operations.insert(operation);
        }
        return true;
    }
    bool validRecord(const QJsonObject &value) const
    {
        if (!value.value("schema").isDouble() || value.value("schema").toDouble() != 1
            || !value.value("identity").isObject() || value.value("identity").toObject() != m_identity
            || !digest(value.value("currentSha").toString())) return false;
        const QString state = value.value("state").toString();
        const bool hasProbeCleanup = value.contains(QStringLiteral("probeCleanup"));
        if (hasProbeCleanup && (!value.value(QStringLiteral("probeCleanup")).isObject()
            || !validCleanup(value.value(QStringLiteral("probeCleanup")).toObject()))) return false;
        if (hasProbeCleanup) {
            const auto directory = value.value(QStringLiteral("probeCleanup")).toObject().value(QStringLiteral("directory"));
            if (directory == value.value(QStringLiteral("retainedDirectory"))
                || directory == value.value(QStringLiteral("cleanup")).toObject().value(QStringLiteral("directory"))) return false;
        }
        const bool hasEndpoint = value.contains(QStringLiteral("endpointHost"));
        if (hasEndpoint && !validEndpointHost(value.value(QStringLiteral("endpointHost")).toString())) return false;
        const bool hasMinimum = value.contains(QStringLiteral("minimumGeneration"));
        const auto minimum = value.value(QStringLiteral("minimumGeneration"));
        if (hasMinimum && (!minimum.isDouble() || minimum.toDouble() < 1
            || minimum.toDouble() > 9007199254740991.0
            || minimum.toDouble() != static_cast<double>(minimum.toInteger()))) return false;
        const bool hasHistory = value.contains(QStringLiteral("retiredPredecessors"));
        const auto history = value.value(QStringLiteral("retiredPredecessors")).toArray();
        if (hasHistory && (!value.value(QStringLiteral("retiredPredecessors")).isArray()
            || !validRetiredPredecessors(history))) return false;
        if (hasHistory && state != QStringLiteral("retiredPrepare")) {
            const auto lastGeneration = history.last().toObject().value(QStringLiteral("generation")).toInteger();
            if (!hasMinimum || lastGeneration == 9007199254740991LL
                || minimum.toInteger() != lastGeneration + 1) return false;
        }
        if (state != QStringLiteral("current")) {
            const QString operation = value.value("operationId").toString();
            if (QUuid(operation).isNull() || QUuid(operation).toString(QUuid::WithoutBraces) != operation) return false;
        }
        if (state == QStringLiteral("pendingPrepare")) {
            for (const auto &proof : history)
                if (proof.toObject().value(QStringLiteral("operationId")) == value.value(QStringLiteral("operationId"))) return false;
            return value.size() == 5 + int(hasEndpoint) + int(hasMinimum) + int(hasHistory) + int(hasProbeCleanup);
        }
        const bool hasPrepareOperation = value.contains(QStringLiteral("prepareOperationId"));
        if (hasPrepareOperation) {
            const QString operation = value.value(QStringLiteral("prepareOperationId")).toString();
            if (QUuid(operation).isNull() || QUuid(operation).toString(QUuid::WithoutBraces) != operation) return false;
        }
        const auto number = value.value("generation");
        if (!number.isDouble() || number.toDouble() < 1 || number.toDouble() > 9007199254740991.0
            || number.toDouble() != static_cast<double>(number.toInteger())) return false;
        if (hasMinimum && number.toInteger() < minimum.toInteger()) return false;
        if (state == QStringLiteral("retiredPrepare"))
            return value.size() == 8 + int(hasEndpoint) + int(hasProbeCleanup) && hasHistory
                && value.value(QStringLiteral("retiredVerified")).isBool()
                && value.value(QStringLiteral("retiredVerified")).toBool()
                && history.last().toObject().value(QStringLiteral("generation")) == number
                && history.last().toObject().value(QStringLiteral("sha256")) == value.value(QStringLiteral("currentSha"))
                && history.last().toObject().value(QStringLiteral("operationId")) == value.value(QStringLiteral("operationId"));
        if (hasHistory && !hasPrepareOperation) return false;
        for (const auto &proof : history)
            if (proof.toObject().value(QStringLiteral("operationId")) == value.value(QStringLiteral("prepareOperationId"))) return false;
        if (state == QStringLiteral("current")) {
            const bool hasCleanup = value.contains(QStringLiteral("cleanup"));
            return value.size() == 5 + int(hasCleanup) + int(hasPrepareOperation) + int(hasEndpoint)
                + int(hasMinimum) + int(hasHistory) + int(hasProbeCleanup)
                && (!hasCleanup || (value.value(QStringLiteral("cleanup")).isObject()
                                    && validCleanup(value.value(QStringLiteral("cleanup")).toObject())));
        }
        const bool hasDirectory = value.contains(QStringLiteral("retainedDirectory"));
        const bool hasIdentity = value.contains(QStringLiteral("retainedIdentity"));
        const bool hasUpload = value.contains(QStringLiteral("retainedUpload"));
        return state == QStringLiteral("pendingMaintenance")
            && value.size() == 8 + int(hasDirectory) + int(hasIdentity) + int(hasUpload)
                + int(hasPrepareOperation) + int(hasEndpoint) + int(hasMinimum) + int(hasHistory) + int(hasProbeCleanup)
            && (!hasDirectory || validRecoveryDirectory(value.value("retainedDirectory").toString()))
            && (!hasIdentity || (hasDirectory
                && validRecoveryIdentity(value.value("retainedIdentity").toString())))
            && (!hasUpload || (hasDirectory && hasIdentity
                && validRecoveryUpload(value.value(QStringLiteral("retainedUpload")).toString())))
            && digest(value.value("replacementSha").toString())
            && digest(value.value("expectedJournal").toString());
    }
    bool write(const QJsonObject &value, QString *error)
    {
        if (!m_lock || !m_lock->isLocked() || !validRecord(value)) return fail(error, "authority_write_invalid");
        const QByteArray bytes = QJsonDocument(value).toJson(QJsonDocument::Compact);
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
        if (!awgMigrationSecretStore::write(storageId(), bytes)) return fail(error, "authority_write_failed");
#else
        m_settings->setValue(settingsKey(), bytes);
#endif
        const auto stored = load();
        return stored.ok && !stored.missing && stored.record == value ? true : fail(error, "authority_write_failed");
    }

    SecureQSettings *m_settings = nullptr;
    QJsonObject m_identity;
    QString m_hash;
    QString m_storeDirectory;
    QString m_organization;
    QString m_application;
    // Release the settings backend (including teardown sync) before the lock.
    std::unique_ptr<QLockFile> m_lock;
    std::unique_ptr<SecureQSettings> m_ownedSettings;
};
} // namespace amnezia::awgControlAuthority
