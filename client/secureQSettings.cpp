#include "secureQSettings.h"

#include "3rd/qtkeychain/qtkeychain/keychain.h"
#include "cryptoUtils.h"
#include "core/utils/utilities.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDeadlineTimer>
#include <QDataStream>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QIODevice>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QRandomGenerator>
#include <QSharedPointer>
#include <QSet>
#include <QStandardPaths>
#include <QThread>
#include <QWaitCondition>

#include <utility>

using namespace QKeychain;

namespace {
    constexpr const char *settingsKeyTag = "settingsKeyTag";
    constexpr const char *settingsIvTag = "settingsIvTag";
    #ifndef CLIENT_KEYCHAIN_NAME_STR
#define CLIENT_KEYCHAIN_NAME_STR "AmneziaVPN-Keychain"
#endif
    constexpr const char *keyChainName = CLIENT_KEYCHAIN_NAME_STR;
    constexpr int keychainOperationDeadlineMs = 1500;
    constexpr int keychainBrokerShutdownWaitMs = 250;

    enum class KeychainOperationKind {
        Read,
        Write,
    };

    enum class KeychainOperationStatus {
        Success,
        EntryNotFound,
        BackendError,
        DeadlineExceeded,
        QueueCapacityExceeded,
        BrokerFailedClosed,
        BrokerShuttingDown,
        DispatchFailed,
    };

    struct KeychainOperationResult
    {
        KeychainOperationStatus status = KeychainOperationStatus::BrokerFailedClosed;
        QByteArray data;
        QString errorString;
        QKeychain::Error error = QKeychain::OtherError;
    };

    struct KeychainOperationState
    {
        KeychainOperationState(KeychainOperationKind operationKind,
                               QString operationTag,
                               QByteArray operationData)
            : kind(operationKind), tag(std::move(operationTag)),
              data(std::move(operationData))
        {
        }

        QWaitCondition completion;
        KeychainOperationResult result;
        KeychainOperationKind kind;
        QString tag;
        QByteArray data;
        quint64 operationId = 0;
        bool finished = false;
        bool cancelled = false;
    };

    class KeychainBroker final
    {
    public:
        static KeychainBroker &instance()
        {
            // Process-lifetime ownership is intentional. A backend call may
            // never return; destroying a running QThread during static teardown
            // would turn a bounded caller timeout into a shutdown crash.
            static KeychainBroker *const broker = new KeychainBroker();
            return *broker;
        }

        KeychainOperationResult read(const QString &tag)
        {
            return execute(KeychainOperationKind::Read, tag, {});
        }

        KeychainOperationResult write(const QString &tag, const QByteArray &data)
        {
            return execute(KeychainOperationKind::Write, tag, data);
        }

    private:
        KeychainBroker()
        {
            m_workerThread = new QThread();
            m_workerThread->setObjectName(QStringLiteral("SecureQSettingsKeychainBroker"));
            m_worker = new QObject();
            m_worker->moveToThread(m_workerThread);
            m_workerThread->start();

            if (QCoreApplication *application = QCoreApplication::instance()) {
                QObject::connect(
                        application, &QCoreApplication::aboutToQuit,
                        application, [this]() { shutdown(); },
                        Qt::DirectConnection);
            }
        }

        KeychainOperationResult execute(KeychainOperationKind kind,
                                        const QString &tag,
                                        const QByteArray &data)
        {
            auto state = QSharedPointer<KeychainOperationState>::create(
                    kind, tag, data);
            QMutexLocker locker(&m_mutex);

            if (QThread::currentThread() == m_workerThread) {
                m_gate.failClosed();
                failPendingLocked(
                        KeychainOperationStatus::BrokerFailedClosed,
                        QStringLiteral("recursive keychain broker call"));
                return { KeychainOperationStatus::DispatchFailed, {},
                         QStringLiteral("recursive broker call"),
                         QKeychain::OtherError };
            }

            const auto admission = m_gate.admitOperation();
            using AdmissionStatus =
                    amnezia::secureSettingsPolicy::KeychainBrokerAdmissionStatus;
            if (admission.status == AdmissionStatus::QueueFull) {
                return { KeychainOperationStatus::QueueCapacityExceeded, {},
                         QStringLiteral("keychain broker queue capacity exceeded"),
                         QKeychain::OtherError };
            }
            if (admission.status == AdmissionStatus::FailedClosed) {
                return { KeychainOperationStatus::BrokerFailedClosed, {},
                         QStringLiteral("keychain broker failed closed"),
                         QKeychain::OtherError };
            }
            if (admission.status == AdmissionStatus::ShuttingDown) {
                return { KeychainOperationStatus::BrokerShuttingDown, {},
                         QStringLiteral("keychain broker is shutting down"),
                         QKeychain::OtherError };
            }

            state->operationId = admission.operationId;
            if (admission.status == AdmissionStatus::Queued) {
                m_pendingOperations.enqueue(state);
            } else {
                Q_ASSERT(admission.status == AdmissionStatus::Started);
                m_activeOperation = state;
                if (!dispatchActiveLocked(state)) {
                    failActiveDispatchLocked(state);
                    return state->result;
                }
            }

            QDeadlineTimer deadline(keychainOperationDeadlineMs);
            while (!state->finished && !deadline.hasExpired()) {
                state->completion.wait(&m_mutex, deadline);
            }
            if (!state->finished) {
                state->cancelled = true;
                state->finished = true;
                state->result = {
                    KeychainOperationStatus::DeadlineExceeded, {},
                    QStringLiteral("keychain operation deadline exceeded"),
                    QKeychain::OtherError
                };
                if (!m_gate.deadlineExceeded(state->operationId)) {
                    m_gate.failClosed();
                }
                failPendingLocked(
                        KeychainOperationStatus::BrokerFailedClosed,
                        QStringLiteral("keychain broker quarantined after deadline"));
                state->completion.wakeAll();
            }
            return state->result;
        }

        bool dispatchActiveLocked(
                const QSharedPointer<KeychainOperationState> &state)
        {
            return QMetaObject::invokeMethod(
                    m_worker,
                    [this, state]() { startOperation(state); },
                    Qt::QueuedConnection);
        }

        void startOperation(const QSharedPointer<KeychainOperationState> &state)
        {
            Q_ASSERT(QThread::currentThread() == m_workerThread);
            {
                QMutexLocker locker(&m_mutex);
                if (state->cancelled || !m_activeOperation
                    || m_activeOperation->operationId != state->operationId) {
                    if (m_activeOperation
                        && m_activeOperation->operationId == state->operationId) {
                        m_gate.completeOperation(state->operationId);
                        m_activeOperation.clear();
                    }
                    return;
                }
            }
            if (state->kind == KeychainOperationKind::Read) {
                auto *job = new ReadPasswordJob(
                        QString::fromLatin1(keyChainName), m_worker);
                job->setAutoDelete(false);
                job->setKey(state->tag);
                QObject::connect(
                        job, &ReadPasswordJob::finished, m_worker,
                        [this, state, job](QKeychain::Job *) {
                            KeychainOperationResult result;
                            result.data = job->binaryData();
                            result.errorString = job->errorString();
                            result.error = job->error();
                            result.status = result.error == QKeychain::NoError
                                    ? KeychainOperationStatus::Success
                                    : result.error == QKeychain::EntryNotFound
                                            ? KeychainOperationStatus::EntryNotFound
                                            : KeychainOperationStatus::BackendError;
                            finishOperation(state, result);
                            job->deleteLater();
                        });
                job->start();
                return;
            }

            auto *job = new WritePasswordJob(
                    QString::fromLatin1(keyChainName), m_worker);
            job->setAutoDelete(false);
            job->setKey(state->tag);
            job->setBinaryData(state->data);
            QObject::connect(
                    job, &WritePasswordJob::finished, m_worker,
                    [this, state, job](QKeychain::Job *) {
                        KeychainOperationResult result;
                        result.errorString = job->errorString();
                        result.error = job->error();
                        result.status = result.error == QKeychain::NoError
                                ? KeychainOperationStatus::Success
                                : KeychainOperationStatus::BackendError;
                        finishOperation(state, result);
                        job->deleteLater();
                    });
            job->start();
        }

        void finishOperation(const QSharedPointer<KeychainOperationState> &state,
                             const KeychainOperationResult &result)
        {
            QMutexLocker locker(&m_mutex);
            if (!m_activeOperation
                || m_activeOperation->operationId != state->operationId) {
                return;
            }
            if (!state->cancelled) {
                state->result = result;
            }
            state->finished = true;
            state->completion.wakeAll();

            const auto completion =
                    m_gate.completeAndStartNext(state->operationId);
            m_activeOperation.clear();
            if (!completion.accepted || completion.nextOperationId == 0) {
                return;
            }

            if (m_pendingOperations.isEmpty()
                || m_pendingOperations.head()->operationId
                        != completion.nextOperationId) {
                m_gate.failClosed();
                m_gate.completeOperation(completion.nextOperationId);
                failPendingLocked(
                        KeychainOperationStatus::BrokerFailedClosed,
                        QStringLiteral("keychain broker queue state mismatch"));
                return;
            }

            const auto next = m_pendingOperations.dequeue();
            m_activeOperation = next;
            if (!dispatchActiveLocked(next)) {
                failActiveDispatchLocked(next);
            }
        }

        void failActiveDispatchLocked(
                const QSharedPointer<KeychainOperationState> &state)
        {
            m_gate.failClosed();
            m_gate.completeOperation(state->operationId);
            if (m_activeOperation
                && m_activeOperation->operationId == state->operationId) {
                m_activeOperation.clear();
            }
            state->cancelled = true;
            state->finished = true;
            state->result = {
                KeychainOperationStatus::DispatchFailed, {},
                QStringLiteral("keychain worker dispatch failed"),
                QKeychain::OtherError
            };
            state->completion.wakeAll();
            failPendingLocked(
                    KeychainOperationStatus::BrokerFailedClosed,
                    QStringLiteral("keychain broker quarantined after dispatch failure"));
        }

        void failPendingLocked(KeychainOperationStatus status,
                               const QString &errorString)
        {
            while (!m_pendingOperations.isEmpty()) {
                const auto pending = m_pendingOperations.dequeue();
                if (!pending->finished) {
                    pending->cancelled = true;
                    pending->finished = true;
                    pending->result = {
                        status, {}, errorString, QKeychain::OtherError
                    };
                }
                pending->completion.wakeAll();
            }
        }

        void shutdown()
        {
            {
                QMutexLocker locker(&m_mutex);
                if (!m_gate.beginShutdown()) {
                    return;
                }
                if (m_activeOperation && !m_activeOperation->finished) {
                    m_activeOperation->cancelled = true;
                    m_activeOperation->finished = true;
                    m_activeOperation->result = {
                        KeychainOperationStatus::BrokerShuttingDown, {},
                        QStringLiteral("keychain broker is shutting down"),
                        QKeychain::OtherError
                    };
                    m_activeOperation->completion.wakeAll();
                }
                failPendingLocked(
                        KeychainOperationStatus::BrokerShuttingDown,
                        QStringLiteral("keychain broker is shutting down"));
            }

            m_workerThread->requestInterruption();
            m_workerThread->quit();
            if (QThread::currentThread() != m_workerThread) {
                // Never make application teardown depend on a native secret
                // service. Process-lifetime ownership keeps an unresponsive
                // worker/job alive safely until the operating system exits.
                m_workerThread->wait(keychainBrokerShutdownWaitMs);
            }
        }

        QMutex m_mutex;
        amnezia::secureSettingsPolicy::KeychainBrokerGate m_gate;
        QQueue<QSharedPointer<KeychainOperationState>> m_pendingOperations;
        QSharedPointer<KeychainOperationState> m_activeOperation;
        QThread *m_workerThread = nullptr;
        QObject *m_worker = nullptr;
    };

    bool keychainReadAllowed(SecureQSettings::AccessMode accessMode)
    {
#if defined(Q_OS_UNIX) && !defined(Q_OS_MACOS) && !defined(Q_OS_MAC) \
        && !defined(Q_OS_ANDROID) && !defined(Q_OS_HAIKU)
        constexpr bool backendReadMayMigratePlaintext = true;
#else
        constexpr bool backendReadMayMigratePlaintext = false;
#endif
        return amnezia::secureSettingsPolicy::keychainReadAllowed(
                backendReadMayMigratePlaintext,
                accessMode == SecureQSettings::AccessMode::ReadOnly);
    }

    QJsonValue withoutRemoteLogTokens(const QJsonValue &value)
    {
        if (value.isArray()) {
            QJsonArray result;
            const QJsonArray array = value.toArray();
            for (const QJsonValue &item : array) {
                result.append(withoutRemoteLogTokens(item));
            }
            return result;
        }

        if (!value.isObject()) {
            return value;
        }

        QJsonObject result;
        const QJsonObject object = value.toObject();
        for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
            if (it.key() == QLatin1String("clientLogs") && it.value().isObject()) {
                QJsonObject clientLogs = it.value().toObject();
                clientLogs.remove(QStringLiteral("token"));
                if (clientLogs.contains(QStringLiteral("clientId"))) {
                    clientLogs.insert(QStringLiteral("bootstrap"), true);
                }
                result.insert(it.key(), withoutRemoteLogTokens(clientLogs));
            } else {
                result.insert(it.key(), withoutRemoteLogTokens(it.value()));
            }
        }
        return result;
    }

    QVariant sanitizedBackupValue(const QString &key, const QVariant &value, bool *ok = nullptr)
    {
        if (ok) {
            *ok = true;
        }
        if (key.compare(QLatin1String("Servers/serversList"), Qt::CaseInsensitive) != 0) {
            return value;
        }

        const QJsonDocument document = QJsonDocument::fromJson(value.toByteArray());
        if (document.isNull()) {
            if (ok) {
                *ok = false;
            }
            return {};
        }

        QJsonDocument sanitized;
        if (document.isArray()) {
            sanitized = QJsonDocument(withoutRemoteLogTokens(document.array()).toArray());
        } else if (document.isObject()) {
            sanitized = QJsonDocument(withoutRemoteLogTokens(document.object()).toObject());
        } else {
            if (ok) {
                *ok = false;
            }
            return {};
        }
        return sanitized.toJson(QJsonDocument::Compact);
    }

#if defined(Q_OS_ANDROID)
    QString androidSettingsFilePath(SecureQSettings::StorageScope scope, bool *available)
    {
        *available = true;
        if (scope == SecureQSettings::StorageScope::ControlAuthority) {
            // CURRENT cannot follow whichever directory happens to be writable
            // today: a later relocation would look like a fresh empty store.
            // Pin this backend to one app-private QStandardPaths location.
            *available = false;
            const QString base = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
            if (base.isEmpty() || !QDir::isAbsolutePath(base)) {
                qCritical() << "SecureQSettings: Android authority config location is unavailable";
                // QSettings must receive a nonempty filename even on failure.
                // This inert name is never read/written: the availability flag
                // gates constructor migration and every subsequent accessor.
                return QStringLiteral("/__amnezia_control_authority_unavailable__/control-authority.ini");
            }
            const QString directory = QDir::cleanPath(base);
            const QString fixedPath = QDir(directory).filePath(QStringLiteral("control-authority.ini"));
            if (!QDir().mkpath(directory) || QFileInfo(directory).isSymLink()) {
                qCritical() << "SecureQSettings: Android authority config directory is unavailable";
                return fixedPath;
            }
            const QString probePath = QDir(directory).filePath(QStringLiteral(".amnezia-control-authority-write-probe"));
            QFile probe(probePath);
            if (!probe.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                qCritical() << "SecureQSettings: Android authority config directory is not writable";
                return fixedPath;
            }
            const bool probeOk = probe.write("ok", 2) == 2 && probe.flush();
            probe.close();
            (void)QFile::remove(probePath);
            *available = probeOk;
            if (!probeOk) qCritical() << "SecureQSettings: Android authority storage probe failed";
            return fixedPath;
        }
        // Do not construct QSettings with an empty filename.  On Android the
        // NativeFormat fallback can resolve to a read-only/invalid location
        // and reports AccessError only when a durable value is written.  Pick
        // an app-private directory that is proven writable before constructing
        // the settings object.
        const QStringList candidates {
            QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation),
            QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation),
            QStandardPaths::writableLocation(QStandardPaths::AppDataLocation),
            QStandardPaths::writableLocation(QStandardPaths::TempLocation)
        };
        for (const QString &candidate : candidates) {
            const QString directory = QDir::cleanPath(candidate);
            if (directory.isEmpty() || !QDir().mkpath(directory)) {
                continue;
            }
            const QString probePath = QDir(directory).filePath(QStringLiteral(".amnezia-settings-write-probe"));
            QFile probe(probePath);
            if (!probe.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                continue;
            }
            const bool probeOk = probe.write("ok", 2) == 2 && probe.flush();
            probe.close();
            (void)QFile::remove(probePath);
            if (probeOk) {
                return QDir(directory).filePath(QStringLiteral("settings.ini"));
            }
        }
        qCritical() << "SecureQSettings: no writable app-private Android settings directory";
        return QDir(QDir::tempPath()).filePath(QStringLiteral("amnezia-settings-unavailable.ini"));
    }
#endif
}

SecureQSettings::SecureQSettings(const QString &organization, const QString &application, QObject *parent,
                                 AccessMode accessMode, bool enableEncryption, StorageScope storageScope)
    : QObject { parent }, m_storageAvailable(true),
#if defined(Q_OS_ANDROID)
      // Qt's Android NativeFormat backend can report AccessError for durable
      // writes on some Qt/device combinations. Keep the same encrypted-value
      // layer, but put the QSettings file explicitly in app-private storage.
      m_settings(androidSettingsFilePath(storageScope, &m_storageAvailable), QSettings::IniFormat, parent),
#else
      m_settings(organization, storageScope == StorageScope::ControlAuthority
          ? application + QStringLiteral("-ControlAuthority") : application, parent),
#endif
      encryptedKeys({ "Servers/serversList", "Conf/remoteLogTokens",
                      "Conf/favoriteLocations", "Conf/proxyUrls/agw_state" }),
      m_accessMode(accessMode), m_encryptionEnabled(enableEncryption), m_storageScope(storageScope),
      m_keychainScope(storageScope == StorageScope::ControlAuthority
          ? QString::fromLatin1(QCryptographicHash::hash(QJsonDocument(QJsonArray{organization, application})
                .toJson(QJsonDocument::Compact), QCryptographicHash::Sha256).toHex()) : QString())
{
    if (!m_storageAvailable) return;
#if defined(Q_OS_ANDROID)
    // Some Android filesystems do not support QSettings' temporary rename
    // used for atomic sync even though direct writes to the app-private file
    // are valid. The path was already proven writable above; disable only the
    // failing rename requirement, while retaining the explicit sync/readback
    // checks for every durable updater value.
    // Authority intents require atomic replacement; unsupported filesystems
    // fail before remote mutation rather than truncating CURRENT after a crash.
    m_settings.setAtomicSyncRequired(storageScope == StorageScope::ControlAuthority);
    m_settings.setFallbacksEnabled(false);
    // Preserve values from an older APK when the new private file has not
    // been created yet. A failed legacy read is ignored; new writes remain
    // fail-closed through the normal sync/status check below.
    if (storageScope == StorageScope::Application && m_settings.allKeys().isEmpty()) {
        QSettings legacy(organization, application, parent);
        if (legacy.status() == QSettings::NoError) {
            for (const QString &key : legacy.allKeys()) {
                m_settings.setValue(key, legacy.value(key));
            }
            m_settings.sync();
        }
    }
#endif
    if (storageScope == StorageScope::ControlAuthority) m_settings.setFallbacksEnabled(false);
    // Operator-mode processes are strictly read-only observers. In particular,
    // they must never migrate settings or create replacement keychain material:
    // doing so could race the authoritative process and make encrypted settings
    // permanently unreadable.
    if (m_accessMode == AccessMode::ReadOnly) {
        return;
    }

    const bool encrypted = m_settings.value("Conf/encrypted").toBool();

    // convert settings to encrypted for if updated to >= 2.1.0
    bool needsMigration = !encrypted;
    if (encryptionRequired() && !needsMigration) {
        // New protected keys can be plaintext even when an older version set
        // the global encryption marker. Stage their migration together while
        // preserving the existing no-replacement rule for ciphertext/key loss.
        for (const QString &key : m_settings.allKeys()) {
            if (!amnezia::secureSettingsPolicy::isEncryptedSetting(key)) continue;
            const QVariant value = m_settings.value(key);
            if (value.userType() != QMetaType::QByteArray
                || !value.toByteArray().startsWith(magicString)) {
                needsMigration = true;
                break;
            }
        }
    }
    if (encryptionRequired() && needsMigration) {
        if (!migrateEncryptedSettings()) {
            qCritical() << "SecureQSettings migration did not complete";
        }
    }
}

SecureQSettings::SecureQSettings(const QString &organization, const QString &application,
                                 QObject *parent, bool enableEncryption)
    : SecureQSettings(organization, application, parent, AccessMode::ReadWrite,
                      enableEncryption)
{
}

QVariant SecureQSettings::value(const QString &key, const QVariant &defaultValue) const
{
    QMutexLocker locker(&m_mutex);
    if (!m_storageAvailable) return defaultValue;
    if (!amnezia::secureSettingsPolicy::isValidSettingsKey(key)) {
        qWarning() << "SecureQSettings::value rejected invalid settings key";
        return defaultValue;
    }
    const QString canonicalKey = amnezia::secureSettingsPolicy::canonicalKey(key);
    if (canonicalKey.isEmpty()) {
        return defaultValue;
    }

    const QString normalizedCacheKey = amnezia::secureSettingsPolicy::cacheKey(canonicalKey);
    if (m_cache.contains(normalizedCacheKey)) {
        return m_cache.value(normalizedCacheKey);
    }

    if (!m_settings.contains(canonicalKey))
        return defaultValue;

    QVariant retVal;

    // check if value is not encrypted, v. < 2.0.x
    retVal = m_settings.value(canonicalKey);
    if (retVal.isValid()) {
        if (retVal.userType() == QMetaType::QByteArray && retVal.toByteArray().mid(0, magicString.size()) == magicString) {

            if (getEncKey(false).isEmpty() || getEncIv(false).isEmpty()) {
                qCritical() << "SecureQSettings::value Decryption requested, but key is empty";
                return {};
            }

            QByteArray encryptedValue = retVal.toByteArray().mid(magicString.size());

            QByteArray decryptedValue = decryptText(encryptedValue);
            QDataStream ds(&decryptedValue, QIODevice::ReadOnly);

            ds >> retVal;

            if (!retVal.isValid()) {
                qWarning() << "SecureQSettings::value settings decryption failed";
                retVal = QVariant();
            }
        }
    } else {
        qWarning() << "SecureQSettings::value invalid QVariant value";
        retVal = QVariant();
    }

    m_cache.insert(normalizedCacheKey, retVal);
    return retVal;
}

bool SecureQSettings::readFreshValue(const QString &key, QVariant &result)
{
    QMutexLocker locker(&m_mutex);
    result = {};
    if (!m_storageAvailable) return false;
    if (!amnezia::secureSettingsPolicy::isValidSettingsKey(key)) return false;
    const QString canonical = amnezia::secureSettingsPolicy::canonicalKey(key);
    if (canonical.isEmpty()) return false;
    m_settings.sync();
    if (m_settings.status() != QSettings::NoError) return false;
    m_cache.remove(amnezia::secureSettingsPolicy::cacheKey(canonical));
    if (!m_settings.contains(canonical)) return true;
    result = value(canonical);
    return result.isValid() && m_settings.status() == QSettings::NoError;
}

void SecureQSettings::setValue(const QString &key, const QVariant &value)
{
    QMutexLocker locker(&m_mutex);
    if (!m_storageAvailable) return;
    if (m_accessMode == AccessMode::ReadOnly) {
        qWarning() << "SecureQSettings::setValue rejected in read-only mode";
        return;
    }
    if (!amnezia::secureSettingsPolicy::isValidSettingsKey(key)) {
        qCritical() << "SecureQSettings::setValue rejected invalid settings key";
        return;
    }
    const QString canonicalKey = amnezia::secureSettingsPolicy::canonicalKey(key);
    if (canonicalKey.isEmpty()) {
        qCritical() << "SecureQSettings::setValue empty settings key";
        return;
    }
    const bool durableWrite = amnezia::secureSettingsPolicy::requiresDurableWrite(canonicalKey);
    const QString normalizedCacheKey = amnezia::secureSettingsPolicy::cacheKey(canonicalKey);

    if (encryptionRequired()
        && amnezia::secureSettingsPolicy::isEncryptedSetting(canonicalKey)) {
        const bool allowMaterialCreation =
                amnezia::secureSettingsPolicy::keychainMaterialCreationAllowed(
                        hasEncryptedPayloads(),
                        m_accessMode == AccessMode::ReadOnly);
        if (!getEncKey(allowMaterialCreation).isEmpty()
            && !getEncIv(allowMaterialCreation).isEmpty()) {
            QByteArray decryptedValue;
            {
                QDataStream ds(&decryptedValue, QIODevice::WriteOnly);
                ds << value;
            }

            const QByteArray encryptedValue = encryptText(decryptedValue);
            if (encryptedValue.isEmpty()) {
                qCritical() << "SecureQSettings::setValue encryption failed";
                if (durableWrite) {
                    m_cache.insert(normalizedCacheKey, QVariant());
                }
                return;
            }
            m_settings.setValue(canonicalKey, magicString + encryptedValue);
        } else {
            qCritical() << "SecureQSettings::setValue Encryption required, but key is empty";
            if (durableWrite) {
                m_cache.insert(normalizedCacheKey, QVariant());
            }
            return;
        }

    } else {
        m_settings.setValue(canonicalKey, value);
    }

    if (durableWrite) {
        m_settings.sync();
        if (m_settings.status() != QSettings::NoError) {
            // Do not let a cache read masquerade as durable anti-replay or
            // rollback state. An invalid cached value makes callers fail closed.
            m_cache.insert(normalizedCacheKey, QVariant());
            qCritical() << "SecureQSettings::setValue durable settings write failed for"
                        << canonicalKey << "status" << static_cast<int>(m_settings.status());
            return;
        }
    }

    m_cache.insert(normalizedCacheKey, value);
}

void SecureQSettings::remove(const QString &key)
{
    QMutexLocker locker(&m_mutex);
    if (!m_storageAvailable) return;
    if (m_accessMode == AccessMode::ReadOnly) {
        qWarning() << "SecureQSettings::remove rejected in read-only mode";
        return;
    }
    if (!amnezia::secureSettingsPolicy::isValidSettingsKey(key)) {
        qWarning() << "SecureQSettings::remove rejected invalid settings key";
        return;
    }
    const QString canonicalKey = amnezia::secureSettingsPolicy::canonicalKey(key);
    if (canonicalKey.isEmpty()) {
        return;
    }

    const QString normalizedCacheKey = amnezia::secureSettingsPolicy::cacheKey(canonicalKey);
    m_settings.remove(canonicalKey);
    if (amnezia::secureSettingsPolicy::requiresDurableWrite(canonicalKey)) {
        m_settings.sync();
        if (m_settings.status() != QSettings::NoError) {
            m_cache.insert(normalizedCacheKey, QVariant());
            qCritical() << "SecureQSettings::remove durable settings write failed for"
                        << canonicalKey << "status" << static_cast<int>(m_settings.status());
            return;
        }
    }
    m_cache.remove(normalizedCacheKey);
}

QByteArray SecureQSettings::backupAppConfig() const
{
    QMutexLocker locker(&m_mutex);
    if (!m_storageAvailable) return {};

    QJsonObject cfg;

    const auto needToBackup = [this](const QString &key) {
        if (isExcludedFromBackup(key)) return false;
        for (const QString &item : m_fieldsToBackup) {
            if (key.startsWith(item, Qt::CaseInsensitive)) return true;
        }
        return false;
    };

    for (const QString &storedKey : m_settings.allKeys()) {
        const QString key = amnezia::secureSettingsPolicy::canonicalKey(storedKey);

        if (key.isEmpty() || !needToBackup(key))
        {
            continue;
        }

        bool sanitized = false;
        const QVariant backupValue = sanitizedBackupValue(key, value(storedKey), &sanitized);
        if (!sanitized) {
            qWarning() << "SecureQSettings::backupAppConfig rejected malformed protected value";
            return {};
        }
        cfg.insert(key, QJsonValue::fromVariant(backupValue));
    }

    return QJsonDocument(cfg).toJson();
}

bool SecureQSettings::restoreAppConfig(const QByteArray &json)
{
    QMutexLocker locker(&m_mutex);
    if (!m_storageAvailable) return false;
    if (m_accessMode == AccessMode::ReadOnly) {
        qWarning() << "SecureQSettings::restoreAppConfig rejected in read-only mode";
        return false;
    }

    QJsonObject cfg = QJsonDocument::fromJson(json).object();
    if (cfg.isEmpty())
        return false;

    // Preflight the complete import before the first write. Skipping a key is
    // not sufficient on Windows: an embedded NUL can make the native registry
    // backend write a shorter, security-sensitive key than Qt compared above.
    QSet<QString> normalizedKeys;
    QVariantMap sanitizedValues;
    for (const QString &storedKey : cfg.keys()) {
        if (!amnezia::secureSettingsPolicy::isValidSettingsKey(storedKey)
            || amnezia::secureSettingsPolicy::canonicalKey(storedKey).isEmpty()) {
            qWarning() << "SecureQSettings::restoreAppConfig rejected invalid settings key";
            return false;
        }
        const QString key = amnezia::secureSettingsPolicy::canonicalKey(storedKey);
#if defined(Q_OS_WINDOWS)
        const QString identity = key.toCaseFolded();
#else
        const QString identity = key;
#endif
        if (normalizedKeys.contains(identity)) {
            qWarning() << "SecureQSettings::restoreAppConfig rejected aliased settings keys";
            return false;
        }
        normalizedKeys.insert(identity);
        if (isExcludedFromBackup(key)) {
            continue;
        }
        bool sanitized = false;
        const QVariant sanitizedValue = sanitizedBackupValue(
                key, cfg.value(storedKey).toVariant(), &sanitized);
        if (!sanitized) {
            qWarning() << "SecureQSettings::restoreAppConfig rejected malformed protected value";
            return false;
        }
        sanitizedValues.insert(key, sanitizedValue);
    }

    for (auto it = sanitizedValues.constBegin(); it != sanitizedValues.constEnd(); ++it) {
        setValue(it.key(), it.value());
    }

    return true;
}

bool SecureQSettings::isExcludedFromBackup(const QString &key) const
{
    if (amnezia::secureSettingsPolicy::isLocalOnlySetting(key)) return true;
    const QString canonical = amnezia::secureSettingsPolicy::canonicalKey(key);
    for (const QString &item : m_fieldsExcludedFromBackup) {
        const QString excluded = amnezia::secureSettingsPolicy::canonicalKey(item);
        if (amnezia::secureSettingsPolicy::isSameSettingOrChild(canonical, excluded)) {
            return true;
        }
    }
    return false;
}

void SecureQSettings::clearSettings()
{
    QMutexLocker locker(&m_mutex);
    if (!m_storageAvailable) return;
    if (m_accessMode == AccessMode::ReadOnly) {
        qWarning() << "SecureQSettings::clearSettings rejected in read-only mode";
        return;
    }
    // Keep installation identity and update security state in place instead of
    // clearing and restoring them later. That avoids a crash window in which a
    // settings reset could erase the durable anti-replay generation floor or a
    // pending health/rollback receipt. Other local-only data (for example log
    // upload tokens) is still cleared as expected.
    const QStringList storedKeys = m_settings.allKeys();
    for (const QString &storedKey : storedKeys) {
        if (!amnezia::secureSettingsPolicy::isRetainedAcrossSettingsClear(storedKey)) {
            m_settings.remove(storedKey);
        }
    }
    m_settings.sync();
    if (m_settings.status() != QSettings::NoError) {
        qCritical() << "SecureQSettings::clearSettings failed, status"
                    << static_cast<int>(m_settings.status());
    }
    m_cache.clear();
}

QByteArray SecureQSettings::encryptText(const QByteArray &value) const
{
    const QByteArray result = CryptoUtils::encryptAes256Cbc(
            value, getEncKey(false), getEncIv(false));
    if (result.isEmpty() && !value.isEmpty()) {
        qCritical() << "error when encrypting the settings value";
    }
    return result;
}

QByteArray SecureQSettings::decryptText(const QByteArray &ba) const
{
    const QByteArray result = CryptoUtils::decryptAes256Cbc(
            ba, getEncKey(false), getEncIv(false));
    if (result.isEmpty() && !ba.isEmpty()) {
        qCritical() << "error when decrypting the settings value";
    }
    return result;
}

bool SecureQSettings::encryptionRequired() const
{
    if (!m_encryptionEnabled) return false;
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    // QtKeyChain failing on Linux
    return false;
#endif
    return true;
}

bool SecureQSettings::hasEncryptedPayloads() const
{
    for (const QString &storedKey : m_settings.allKeys()) {
        if (!amnezia::secureSettingsPolicy::isEncryptedSetting(storedKey)) {
            continue;
        }
        const QVariant storedValue = m_settings.value(storedKey);
        if (storedValue.userType() == QMetaType::QByteArray
            && storedValue.toByteArray().startsWith(magicString)) {
            return true;
        }
    }
    return false;
}

bool SecureQSettings::migrateEncryptedSettings()
{
    if (m_accessMode != AccessMode::ReadWrite) {
        return false;
    }

    QStringList keysToMigrate;
    bool existingCiphertext = false;
    for (const QString &storedKey : m_settings.allKeys()) {
        if (!amnezia::secureSettingsPolicy::isEncryptedSetting(storedKey)) {
            continue;
        }
        keysToMigrate.append(storedKey);
        const QVariant storedValue = m_settings.value(storedKey);
        existingCiphertext = existingCiphertext
                || (storedValue.userType() == QMetaType::QByteArray
                    && storedValue.toByteArray().startsWith(magicString));
    }

    QHash<QString, QByteArray> stagedValues;
    if (!keysToMigrate.isEmpty()) {
        // Existing ciphertext is authoritative evidence that key material once
        // existed. Never replace a missing key/IV in that case: doing so would
        // make the stored data permanently unreadable.
        const bool allowMaterialCreation =
                amnezia::secureSettingsPolicy::keychainMaterialCreationAllowed(
                        existingCiphertext,
                        m_accessMode == AccessMode::ReadOnly);
        if (getEncKey(allowMaterialCreation).isEmpty()
            || getEncIv(allowMaterialCreation).isEmpty()) {
            return false;
        }

        for (const QString &storedKey : keysToMigrate) {
            const QVariant storedValue = m_settings.value(storedKey);
            if (storedValue.userType() == QMetaType::QByteArray
                && storedValue.toByteArray().startsWith(magicString)) {
                continue;
            }

            QByteArray serializedValue;
            {
                QDataStream stream(&serializedValue, QIODevice::WriteOnly);
                stream << storedValue;
            }
            const QByteArray encryptedValue = encryptText(serializedValue);
            if (encryptedValue.isEmpty()) {
                return false;
            }
            stagedValues.insert(storedKey, magicString + encryptedValue);
        }
    }

    // Persist payloads before the marker. A crash between these sync points is
    // recoverable: the next mutable startup recognizes already-encrypted values
    // and completes the remaining idempotent migration.
    for (auto it = stagedValues.constBegin(); it != stagedValues.constEnd(); ++it) {
        m_settings.setValue(it.key(), it.value());
    }
    if (!stagedValues.isEmpty()) {
        m_settings.sync();
        if (m_settings.status() != QSettings::NoError) {
            return false;
        }
    }

    m_settings.setValue(QStringLiteral("Conf/encrypted"), true);
    m_settings.sync();
    return m_settings.status() == QSettings::NoError;
}

QByteArray SecureQSettings::getEncKey(bool allowCreate) const
{

    if (!m_key.isEmpty()) {
        return m_key;
    }
    if (m_keyReadAttempted) {
        return {};
    }
    m_keyReadAttempted = true;
    if (!keychainReadAllowed(m_accessMode)) {
        qWarning() << "SecureQSettings::getEncKey keychain reads are disabled in Unix read-only mode";
        return {};
    }
    // load keys from system key storage
    // An empty authority store must never replace the application's existing
    // shared key/IV after their loss. Its keychain slots are separate as well.
    const QString keyTag = m_storageScope == StorageScope::ControlAuthority
        ? QStringLiteral("controlAuthorityKeyTag-v1-") + m_keychainScope
        : QString::fromLatin1(settingsKeyTag);
    bool readCompleted = false;
    bool entryNotFound = false;
    m_key = getSecTag(keyTag, &readCompleted, &entryNotFound);

    if (m_key.isEmpty()) {
        if (m_accessMode == AccessMode::ReadOnly || !allowCreate) {
            qWarning() << "SecureQSettings::getEncKey key is unavailable and replacement is disabled";
            return {};
        }
        if (!readCompleted || !entryNotFound) {
            qCritical() << "SecureQSettings::getEncKey refusing replacement key after incomplete keychain read";
            return {};
        }
        // Create new key
        const QByteArray key = CryptoUtils::generateRandomBytes(32);
        if (key.isEmpty()) {
            qCritical() << "SecureQSettings::getEncKey Unable to generate new enc key";
            return {};
        }

        if (!setSecTag(keyTag, key)) {
            qCritical() << "SecureQSettings::getEncKey keychain write failed";
            return {};
        }

        // check
        bool verifyCompleted = false;
        m_key = getSecTag(keyTag, &verifyCompleted);
        if (!verifyCompleted) {
            qCritical() << "SecureQSettings::getEncKey keychain verification timed out";
            return {};
        }
        if (key != m_key) {
            qCritical() << "SecureQSettings::getEncKey Unable to store key in keychain" << key.size() << m_key.size();
            return {};
        }
    }

    return m_key;
}

QByteArray SecureQSettings::getEncIv(bool allowCreate) const
{
    if (!m_iv.isEmpty()) {
        return m_iv;
    }
    if (m_ivReadAttempted) {
        return {};
    }
    m_ivReadAttempted = true;
    if (!keychainReadAllowed(m_accessMode)) {
        qWarning() << "SecureQSettings::getEncIv keychain reads are disabled in Unix read-only mode";
        return {};
    }
    // load keys from system key storage
    const QString ivTag = m_storageScope == StorageScope::ControlAuthority
        ? QStringLiteral("controlAuthorityIvTag-v1-") + m_keychainScope
        : QString::fromLatin1(settingsIvTag);
    bool readCompleted = false;
    bool entryNotFound = false;
    m_iv = getSecTag(ivTag, &readCompleted, &entryNotFound);

    if (m_iv.isEmpty()) {
        if (m_accessMode == AccessMode::ReadOnly || !allowCreate) {
            qWarning() << "SecureQSettings::getEncIv IV is unavailable and replacement is disabled";
            return {};
        }
        if (!readCompleted || !entryNotFound) {
            qCritical() << "SecureQSettings::getEncIv refusing replacement IV after incomplete keychain read";
            return {};
        }
        // Create new IV
        const QByteArray iv = CryptoUtils::generateRandomBytes(32);
        if (iv.isEmpty()) {
            qCritical() << "SecureQSettings::getEncIv Unable to generate new enc IV";
            return {};
        }
        if (!setSecTag(ivTag, iv)) {
            qCritical() << "SecureQSettings::getEncIv keychain write failed";
            return {};
        }

        // check
        bool verifyCompleted = false;
        m_iv = getSecTag(ivTag, &verifyCompleted);
        if (!verifyCompleted) {
            qCritical() << "SecureQSettings::getEncIv keychain verification timed out";
            return {};
        }
        if (iv != m_iv) {
            qCritical() << "SecureQSettings::getEncIv Unable to store IV in keychain" << iv.size() << m_iv.size();
            return {};
        }
    }

    return m_iv;
}

QByteArray SecureQSettings::getSecTag(const QString &tag, bool *readCompleted,
                                      bool *entryNotFound)
{
    if (readCompleted) {
        *readCompleted = false;
    }
    if (entryNotFound) {
        *entryNotFound = false;
    }

    const KeychainOperationResult result = KeychainBroker::instance().read(tag);
    const bool backendResponded = result.status == KeychainOperationStatus::Success
            || result.status == KeychainOperationStatus::EntryNotFound
            || result.status == KeychainOperationStatus::BackendError;
    if (readCompleted) {
        *readCompleted = backendResponded;
    }
    if (entryNotFound) {
        *entryNotFound = result.status == KeychainOperationStatus::EntryNotFound;
    }
    if (!backendResponded) {
        qCritical() << "SecureQSettings::getSecTag unavailable:"
                    << result.errorString;
        return {};
    }
    if (result.status == KeychainOperationStatus::BackendError) {
        qCritical() << "SecureQSettings::getSecTag Error:"
                    << result.errorString;
        return {};
    }
    return result.status == KeychainOperationStatus::Success
            ? result.data : QByteArray();
}

bool SecureQSettings::setSecTag(const QString &tag, const QByteArray &data) const
{
    if (m_accessMode != AccessMode::ReadWrite) {
        qCritical() << "SecureQSettings::setSecTag rejected in read-only mode";
        return false;
    }
    const KeychainOperationResult result = KeychainBroker::instance().write(tag, data);
    if (result.status != KeychainOperationStatus::Success) {
        qCritical() << "SecureQSettings::setSecTag Error:"
                    << result.errorString;
        return false;
    }
    return true;
}
