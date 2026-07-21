#include "secureQSettings.h"

#include "cryptoUtils.h"
#include "core/utils/utilities.h"
#include <QDataStream>
#include <QDebug>
#include <QEventLoop>
#include <QIODevice>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QRandomGenerator>
#include <QSharedPointer>
#include <QSet>
#include <QTimer>

using namespace QKeychain;

namespace {
    constexpr const char *settingsKeyTag = "settingsKeyTag";
    constexpr const char *settingsIvTag = "settingsIvTag";
    constexpr const char *keyChainName = "AmneziaVPN-Keychain";

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
}

SecureQSettings::SecureQSettings(const QString &organization, const QString &application, QObject *parent, bool enableEncryption)
    : QObject { parent }, m_settings(organization, application, parent),
      encryptedKeys({ "Servers/serversList", "Conf/remoteLogTokens" }),
      m_encryptionEnabled(enableEncryption)
{
    bool encrypted = m_settings.value("Conf/encrypted").toBool();

    // convert settings to encrypted for if updated to >= 2.1.0
    if (encryptionRequired() && !encrypted) {
        for (const QString &key : m_settings.allKeys()) {
            if (amnezia::secureSettingsPolicy::isEncryptedSetting(key)) {
                const QVariant &val = value(key);
                setValue(key, val);
            }
        }
        m_settings.setValue("Conf/encrypted", true);
    }
}

QVariant SecureQSettings::value(const QString &key, const QVariant &defaultValue) const
{
    QMutexLocker locker(&m_mutex);
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

            if (getEncKey().isEmpty() || getEncIv().isEmpty()) {
                qCritical() << "SecureQSettings::setValue Decryption requested, but key is empty";
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

void SecureQSettings::setValue(const QString &key, const QVariant &value)
{
    QMutexLocker locker(&m_mutex);
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
        if (!getEncKey().isEmpty() && !getEncIv().isEmpty()) {
            QByteArray decryptedValue;
            {
                QDataStream ds(&decryptedValue, QIODevice::WriteOnly);
                ds << value;
            }

            QByteArray encryptedValue = encryptText(decryptedValue);
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

    QJsonObject cfg;

    const auto needToBackup = [this](const auto &key) {
      if (amnezia::secureSettingsPolicy::isLocalOnlySetting(key))
      {
        return false;
      }

      for (const auto &item : m_fieldsToBackup)
      {
        if (key.startsWith(item, Qt::CaseInsensitive))
        {
            return true;
        }
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
        if (amnezia::secureSettingsPolicy::isLocalOnlySetting(key)) {
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

void SecureQSettings::clearSettings()
{
    QMutexLocker locker(&m_mutex);
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
    const QByteArray result = CryptoUtils::encryptAes256Cbc(value, getEncKey(), getEncIv());
    if (result.isEmpty() && !value.isEmpty()) {
        qCritical() << "error when encrypting the settings value";
    }
    return result;
}

QByteArray SecureQSettings::decryptText(const QByteArray &ba) const
{
    const QByteArray result = CryptoUtils::decryptAes256Cbc(ba, getEncKey(), getEncIv());
    if (result.isEmpty() && !ba.isEmpty()) {
        qCritical() << "error when decrypting the settings value";
    }
    return result;
}

bool SecureQSettings::encryptionRequired() const
{
    if (!m_encryptionEnabled) {
        return false;
    }
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    // QtKeyChain failing on Linux
    return false;
#endif
    return true;
}

QByteArray SecureQSettings::getEncKey() const
{

    if (!m_key.isEmpty()) {
        return m_key;
    }
    // load keys from system key storage
    m_key = getSecTag(settingsKeyTag);

    if (m_key.isEmpty()) {
        // Create new key
        const QByteArray key = CryptoUtils::generateRandomBytes(32);
        if (key.isEmpty()) {
            qCritical() << "SecureQSettings::getEncKey Unable to generate new enc key";
        }

        setSecTag(settingsKeyTag, key);

        // check
        m_key = getSecTag(settingsKeyTag);
        if (key != m_key) {
            qCritical() << "SecureQSettings::getEncKey Unable to store key in keychain" << key.size() << m_key.size();
            return {};
        }
    }

    return m_key;
}

QByteArray SecureQSettings::getEncIv() const
{
    if (!m_iv.isEmpty()) {
        return m_iv;
    }
    // load keys from system key storage
    m_iv = getSecTag(settingsIvTag);

    if (m_iv.isEmpty()) {
        // Create new IV
        const QByteArray iv = CryptoUtils::generateRandomBytes(32);
        if (iv.isEmpty()) {
            qCritical() << "SecureQSettings::getEncIv Unable to generate new enc IV";
        }
        setSecTag(settingsIvTag, iv);

        // check
        m_iv = getSecTag(settingsIvTag);
        if (iv != m_iv) {
            qCritical() << "SecureQSettings::getEncIv Unable to store IV in keychain" << iv.size() << m_iv.size();
            return {};
        }
    }

    return m_iv;
}

QByteArray SecureQSettings::getSecTag(const QString &tag)
{
    auto job = QSharedPointer<ReadPasswordJob>(new ReadPasswordJob(keyChainName), &QObject::deleteLater);
    job->setAutoDelete(false);
    job->setKey(tag);
    QEventLoop loop;
    job->connect(job.data(), &ReadPasswordJob::finished, job.data(), [&loop]() { loop.quit(); });
    job->start();
    loop.exec();

    if (job->error()) {
        qCritical() << "SecureQSettings::getSecTag Error:" << job->errorString();
    }

    return job->binaryData();
}

void SecureQSettings::setSecTag(const QString &tag, const QByteArray &data)
{
    auto job = QSharedPointer<WritePasswordJob>(new WritePasswordJob(keyChainName), &QObject::deleteLater);
    job->setAutoDelete(false);
    job->setKey(tag);
    job->setBinaryData(data);
    QEventLoop loop;
    QTimer::singleShot(1000, &loop, SLOT(quit()));
    job->connect(job.data(), &WritePasswordJob::finished, job.data(), [&loop]() { loop.quit(); });
    job->start();
    loop.exec();

    if (job->error()) {
        qCritical() << "SecureQSettings::setSecTag Error:" << job->errorString();
    }
}
