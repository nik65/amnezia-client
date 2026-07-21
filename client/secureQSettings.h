#ifndef SECUREQSETTINGS_H
#define SECUREQSETTINGS_H

#include <QMutex>
#include <QMutexLocker>
#include <QRecursiveMutex>
#include <QObject>
#include <QSettings>
#include <QStringList>

#include "../client/3rd/qtkeychain/qtkeychain/keychain.h"

namespace amnezia::secureSettingsPolicy
{
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
    explicit SecureQSettings(const QString &organization, const QString &application = QString(),
                             QObject *parent = nullptr, bool enableEncryption = true);

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

    QByteArray getEncKey() const;
    QByteArray getEncIv() const;

    static QByteArray getSecTag(const QString &tag);
    static void setSecTag(const QString &tag, const QByteArray &data);

    QSettings m_settings;

    mutable QHash<QString, QVariant> m_cache;

    QStringList encryptedKeys; // encode only key listed here
    // only this fields need for backup
    QStringList m_fieldsToBackup = {
        "Conf/", "Servers/",
    };

    mutable QByteArray m_key;
    mutable QByteArray m_iv;

    const QByteArray magicString { "EncData" }; // Magic keyword used for mark encrypted QByteArray

    bool m_encryptionEnabled;

    mutable QRecursiveMutex m_mutex;
};

#endif // SECUREQSETTINGS_H
