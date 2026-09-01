#ifndef AMNEZIA_HEADLESS_PROFILE_STORE_H
#define AMNEZIA_HEADLESS_PROFILE_STORE_H

#include <QJsonObject>
#include <QList>
#include <QString>

namespace amnezia::headless
{

struct Profile
{
    QString id;
    QString name;
    QString protocol;
    QString configPath;
    QStringList forwardRoutes;
    QStringList dnsServers;
    QStringList dnsDomains;
    // Optional, secret-free Linux runtime metadata.  Existing profile files
    // remain valid when these fields are absent.
    QString interfaceName;
    QString routingMode;
    QString serverRulesUrl;
    QString updateManifestUrl;
    QString updatePublicKeyPath;
    bool autoConnect = false;
    bool autoUpdate = false;
};

class ProfileStore final
{
public:
    explicit ProfileStore(QString path = {});

    bool load();
    bool add(const Profile &profile);
    bool remove(const QString &id);

    QList<Profile> profiles() const;
    bool contains(const QString &id) const;
    bool profile(const QString &id, Profile &result) const;
    QJsonObject toJson(const Profile &profile) const;
    bool fromJson(const QJsonObject &object, Profile &profile);

    QString path() const;
    QString lastError() const;

private:
    bool save();
    bool validate(const Profile &profile, bool checkDuplicate) const;
    void setError(const QString &message) const;
    static QString defaultPath();
    static QString normalizeProtocol(const QString &protocol);
    static bool isSupportedProtocol(const QString &protocol);

    QString m_path;
    QList<Profile> m_profiles;
    mutable QString m_lastError;
};

} // namespace amnezia::headless

#endif // AMNEZIA_HEADLESS_PROFILE_STORE_H
