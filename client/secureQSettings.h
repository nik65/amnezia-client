#ifndef SECUREQSETTINGS_H
#define SECUREQSETTINGS_H

#include <QMutex>
#include <QMutexLocker>
#include <QQueue>
#include <QRecursiveMutex>
#include <QObject>
#include <QSettings>
#include <QStringList>

namespace amnezia::secureSettingsPolicy
{
    inline constexpr bool keychainReadAllowed(bool unixBackendMayMigrate,
                                              bool readOnlyAccess) noexcept
    {
        return !unixBackendMayMigrate || !readOnlyAccess;
    }

    inline constexpr bool keychainMaterialCreationAllowed(
            bool encryptedPayloadExists, bool readOnlyAccess) noexcept
    {
        return !encryptedPayloadExists && !readOnlyAccess;
    }

    inline constexpr int MaximumKeychainBrokerPendingOperations = 8;

    enum class KeychainBrokerStartStatus {
        Accepted,
        Busy,
        FailedClosed,
    };

    struct KeychainBrokerStartDecision
    {
        KeychainBrokerStartStatus status = KeychainBrokerStartStatus::FailedClosed;
        quint64 operationId = 0;
    };

    enum class KeychainBrokerAdmissionStatus {
        Started,
        Queued,
        QueueFull,
        FailedClosed,
        ShuttingDown,
    };

    struct KeychainBrokerAdmissionDecision
    {
        KeychainBrokerAdmissionStatus status =
                KeychainBrokerAdmissionStatus::FailedClosed;
        quint64 operationId = 0;
    };

    struct KeychainBrokerCompletionDecision
    {
        bool accepted = false;
        quint64 nextOperationId = 0;
    };

    // Pure state gate shared by the production broker and deterministic tests.
    // A deadline permanently poisons the process-local broker: the native
    // backend may still own the timed-out job, so starting another job would
    // recreate the unbounded thread/job fan-out this gate exists to prevent.
    class KeychainBrokerGate
    {
    public:
        explicit KeychainBrokerGate(
                int maximumPendingOperations =
                        MaximumKeychainBrokerPendingOperations) noexcept
            : m_maximumPendingOperations(qMax(0, maximumPendingOperations))
        {
        }

        KeychainBrokerAdmissionDecision admitOperation() noexcept
        {
            if (m_shuttingDown) {
                return { KeychainBrokerAdmissionStatus::ShuttingDown, 0 };
            }
            if (m_failedClosed) {
                return { KeychainBrokerAdmissionStatus::FailedClosed, 0 };
            }

            if (m_activeOperationId == 0) {
                const quint64 operationId = nextOperationId();
                m_activeOperationId = operationId;
                ++m_startedOperationCount;
                return { KeychainBrokerAdmissionStatus::Started, operationId };
            }
            if (m_pendingOperationIds.size() >= m_maximumPendingOperations) {
                return { KeychainBrokerAdmissionStatus::QueueFull, 0 };
            }

            const quint64 operationId = nextOperationId();
            m_pendingOperationIds.enqueue(operationId);
            return { KeychainBrokerAdmissionStatus::Queued, operationId };
        }

        KeychainBrokerCompletionDecision completeAndStartNext(
                quint64 operationId) noexcept
        {
            if (operationId == 0 || operationId != m_activeOperationId) {
                return {};
            }

            m_activeOperationId = 0;
            if (!m_failedClosed && !m_shuttingDown
                && !m_pendingOperationIds.isEmpty()) {
                m_activeOperationId = m_pendingOperationIds.dequeue();
                ++m_startedOperationCount;
            }
            return { true, m_activeOperationId };
        }

        KeychainBrokerStartDecision beginOperation() noexcept
        {
            if (m_failedClosed || m_shuttingDown) {
                return { KeychainBrokerStartStatus::FailedClosed, 0 };
            }
            if (m_activeOperationId != 0 || !m_pendingOperationIds.isEmpty()) {
                return { KeychainBrokerStartStatus::Busy, 0 };
            }

            m_activeOperationId = nextOperationId();
            ++m_startedOperationCount;
            return { KeychainBrokerStartStatus::Accepted, m_activeOperationId };
        }

        bool completeOperation(quint64 operationId) noexcept
        {
            return completeAndStartNext(operationId).accepted;
        }

        bool deadlineExceeded(quint64 operationId) noexcept
        {
            if (operationId == 0
                || (operationId != m_activeOperationId
                    && !m_pendingOperationIds.contains(operationId))) {
                return false;
            }
            m_failedClosed = true;
            m_pendingOperationIds.clear();
            return true;
        }

        void failClosed() noexcept
        {
            m_failedClosed = true;
            m_pendingOperationIds.clear();
        }

        bool beginShutdown() noexcept
        {
            if (m_shuttingDown) {
                return false;
            }
            m_shuttingDown = true;
            m_failedClosed = true;
            m_pendingOperationIds.clear();
            return true;
        }

        bool isFailedClosed() const noexcept { return m_failedClosed; }
        bool isShuttingDown() const noexcept { return m_shuttingDown; }
        bool hasActiveOperation() const noexcept { return m_activeOperationId != 0; }
        bool isPendingOperation(quint64 operationId) const noexcept
        {
            return m_pendingOperationIds.contains(operationId);
        }
        quint64 activeOperationId() const noexcept { return m_activeOperationId; }
        int pendingOperationCount() const noexcept
        {
            return m_pendingOperationIds.size();
        }
        int maximumPendingOperations() const noexcept
        {
            return m_maximumPendingOperations;
        }
        quint64 startedOperationCount() const noexcept { return m_startedOperationCount; }

    private:
        quint64 nextOperationId() noexcept
        {
            ++m_nextOperationId;
            if (m_nextOperationId == 0) {
                ++m_nextOperationId;
            }
            return m_nextOperationId;
        }

        bool m_failedClosed = false;
        bool m_shuttingDown = false;
        const int m_maximumPendingOperations;
        QQueue<quint64> m_pendingOperationIds;
        quint64 m_nextOperationId = 0;
        quint64 m_activeOperationId = 0;
        quint64 m_startedOperationCount = 0;
    };

    inline bool isValidSettingsKey(const QString &key)
    {
        if (key.isEmpty()) {
            return false;
        }
        for (const QChar character : key) {
            const ushort codePoint = character.unicode();
            // QSettings::NativeFormat ultimately passes Windows registry key
            // names through NUL-terminated APIs. Reject every control code on
            // every platform before normalization so an imported key cannot
            // be truncated into a protected updater setting.
            if (codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f)) {
                return false;
            }
        }
        return true;
    }

    inline QString canonicalKey(QString key)
    {
        if (!isValidSettingsKey(key)) {
            return {};
        }
        key.replace(QLatin1Char('\\'), QLatin1Char('/'));
        return key.split(QLatin1Char('/'), Qt::SkipEmptyParts).join(QLatin1Char('/'));
    }

    inline bool keyListContains(const QStringList &keys, const QString &key)
    {
#if defined(Q_OS_WINDOWS)
        for (const QString &candidate : keys) {
            if (candidate.compare(key, Qt::CaseInsensitive) == 0) {
                return true;
            }
        }
        return false;
#else
        return keys.contains(key);
#endif
    }

    inline bool isSameSettingOrChild(const QString &key, const QString &setting)
    {
        return key.compare(setting, Qt::CaseInsensitive) == 0
                || key.startsWith(setting + QLatin1Char('/'), Qt::CaseInsensitive);
    }

    inline bool isEncryptedSetting(const QString &rawKey)
    {
        if (!isValidSettingsKey(rawKey)) {
            return false;
        }
        const QString key = canonicalKey(rawKey);
        return key.compare(QLatin1String("Servers/serversList"), Qt::CaseInsensitive) == 0
                || isSameSettingOrChild(key, QStringLiteral("Conf/remoteLogTokens"));
    }

    inline bool isLocalOnlySetting(const QString &rawKey)
    {
        if (!isValidSettingsKey(rawKey)) {
            return true;
        }
        const QString key = canonicalKey(rawKey);
        if (key.compare(QLatin1String("Conf/installationUuid"), Qt::CaseInsensitive) == 0
            || isSameSettingOrChild(key, QStringLiteral("Conf/remoteLogTokens"))
            || isSameSettingOrChild(key, QStringLiteral("Conf/selfHostedUpdate"))
            || key.compare(QLatin1String("Conf/selfHostedUpdateLastAutoInstallAttempt"),
                           Qt::CaseInsensitive) == 0) {
            return true;
        }
        return false;
    }

    inline bool requiresDurableWrite(const QString &rawKey)
    {
        if (!isValidSettingsKey(rawKey)) {
            return true;
        }
        const QString key = canonicalKey(rawKey);
        return isLocalOnlySetting(key);
    }

    inline bool isRetainedAcrossSettingsClear(const QString &rawKey)
    {
        // Never send an invalid/truncatable key to a native remove API. Public
        // writes reject it; retaining an already-present legacy key is the only
        // fail-closed reset behavior.
        if (!isValidSettingsKey(rawKey)) {
            return true;
        }
        const QString key = canonicalKey(rawKey);
        return key.compare(QLatin1String("Conf/installationUuid"), Qt::CaseInsensitive) == 0
                || isSameSettingOrChild(key, QStringLiteral("Conf/selfHostedUpdate"));
    }

    inline QString cacheKey(const QString &canonicalKey)
    {
#if defined(Q_OS_WINDOWS)
        return canonicalKey.toCaseFolded();
#else
        return canonicalKey;
#endif
    }
}

class SecureQSettings : public QObject
{
    Q_OBJECT

public:
    enum class AccessMode {
        ReadWrite,
        ReadOnly,
    };

    explicit SecureQSettings(const QString &organization, const QString &application = QString(),
                             QObject *parent = nullptr, AccessMode accessMode = AccessMode::ReadWrite);

    QVariant value(const QString &key, const QVariant &defaultValue = QVariant()) const;
    void setValue(const QString &key, const QVariant &value);
    void remove(const QString &key);

    QByteArray backupAppConfig() const;
    bool restoreAppConfig(const QByteArray &json);

    void clearSettings();

private:
    QByteArray encryptText(const QByteArray &value) const;
    QByteArray decryptText(const QByteArray &ba) const;

    bool encryptionRequired() const;
    bool hasEncryptedPayloads() const;
    bool migrateEncryptedSettings();

    QByteArray getEncKey(bool allowCreate) const;
    QByteArray getEncIv(bool allowCreate) const;

    static QByteArray getSecTag(const QString &tag, bool *readCompleted = nullptr,
                                bool *entryNotFound = nullptr);
    bool setSecTag(const QString &tag, const QByteArray &data) const;

    QSettings m_settings;

    mutable QHash<QString, QVariant> m_cache;

    QStringList encryptedKeys; // encode only key listed here
    // only this fields need for backup
    QStringList m_fieldsToBackup = {
        "Conf/", "Servers/",
    };

    mutable QByteArray m_key;
    mutable QByteArray m_iv;
    mutable bool m_keyReadAttempted = false;
    mutable bool m_ivReadAttempted = false;

    const QByteArray magicString { "EncData" }; // Magic keyword used for mark encrypted QByteArray

    const AccessMode m_accessMode;

    mutable QRecursiveMutex m_mutex;
};

#endif // SECUREQSETTINGS_H
