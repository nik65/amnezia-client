#pragma once

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLockFile>
#include <QRegularExpression>
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

    bool beginPrepare(const QString &bundledSha, QString *error = nullptr)
    {
        const auto previous = load();
        if (!previous.ok) return fail(error, previous.error);
        if (!previous.missing) return fail(error, "authority_already_exists");
        if (!digest(bundledSha)) return fail(error, "authority_digest_invalid");
        auto value = base(QStringLiteral("pendingPrepare"), bundledSha);
        value.insert(QStringLiteral("operationId"), QUuid::createUuid().toString(QUuid::WithoutBraces));
        return write(value, error);
    }

    bool commitPrepare(qint64 number, const QString &bundledSha, QString *error = nullptr)
    {
        const auto previous = load();
        if (!previous.ok) return fail(error, previous.error);
        if (previous.missing || previous.record.value("state") != "pendingPrepare"
            || previous.record.value("currentSha") != bundledSha || !generation(number))
            return fail(error, "authority_prepare_conflict");
        return write(current(number, bundledSha), error);
    }

    // Explicit operator CURRENT may anchor missing state, never overwrite a
    // different existing pin or discard an uncertain transaction.
    bool anchorCurrent(qint64 number, const QString &callerSha, QString *error = nullptr)
    {
        if (!generation(number) || !digest(callerSha)) return fail(error, "authority_binding_invalid");
        const auto previous = load();
        if (!previous.ok) return fail(error, previous.error);
        if (previous.missing) return write(current(number, callerSha), error);
        if (previous.record == current(number, callerSha)) return true;
        return fail(error, "authority_current_conflict");
    }

    bool beginMaintenance(qint64 number, const QString &currentSha, const QString &replacementSha,
                          const QString &expectedJournal, QString *error = nullptr,
                          const QString &recoveryDirectory = QString())
    {
        const auto previous = load();
        if (!previous.ok) return fail(error, previous.error);
        if (!generation(number) || !digest(currentSha) || !digest(replacementSha) || !digest(expectedJournal)
            || previous.missing || previous.record != current(number, currentSha))
            return fail(error, "authority_maintenance_conflict");
        if (!recoveryDirectory.isEmpty() && !validRecoveryDirectory(recoveryDirectory))
            return fail(error, "authority_recovery_directory_invalid");
        auto value = current(number, currentSha);
        if (!recoveryDirectory.isEmpty()) value.insert(QStringLiteral("retainedDirectory"), recoveryDirectory);
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
        return write(current(number, newSha), error);
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
        return write(current(number, knownSha), error);
    }

private:
    bool fail(QString *error, const QString &reason) const { if (error) *error = reason; return false; }
    QString storageId() const { return QStringLiteral("control-authority-v1:") + m_hash; }
    QString settingsKey() const { return QStringLiteral("Conf/awgMigration/controlAuthority/") + m_hash; }
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
    bool validRecord(const QJsonObject &value) const
    {
        if (!value.value("schema").isDouble() || value.value("schema").toDouble() != 1
            || !value.value("identity").isObject() || value.value("identity").toObject() != m_identity
            || !digest(value.value("currentSha").toString())) return false;
        const QString state = value.value("state").toString();
        if (state != QStringLiteral("current")) {
            const QString operation = value.value("operationId").toString();
            if (QUuid(operation).isNull() || QUuid(operation).toString(QUuid::WithoutBraces) != operation) return false;
        }
        if (state == QStringLiteral("pendingPrepare")) return value.size() == 5;
        const auto number = value.value("generation");
        if (!number.isDouble() || number.toDouble() < 1 || number.toDouble() > 9007199254740991.0
            || number.toDouble() != static_cast<double>(number.toInteger())) return false;
        if (state == QStringLiteral("current")) return value.size() == 5;
        const bool hasDirectory = value.contains(QStringLiteral("retainedDirectory"));
        return state == QStringLiteral("pendingMaintenance") && value.size() == (hasDirectory ? 9 : 8)
            && (!hasDirectory || validRecoveryDirectory(value.value("retainedDirectory").toString()))
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
