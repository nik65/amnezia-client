#include "profileStore.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QSaveFile>
#include <QStandardPaths>
#include <QUrl>
#include <QRegularExpression>

#include "../client/core/utils/managedRoutePolicy.h"

#include <algorithm>
#include <iterator>
#include <utility>

namespace amnezia::headless
{
namespace
{

constexpr int StoreVersion = 1;

} // namespace

ProfileStore::ProfileStore(QString path)
    : m_path(path.trimmed().isEmpty() ? defaultPath() : std::move(path))
{
}

bool ProfileStore::load()
{
    m_lastError.clear();
    m_profiles.clear();

    QFile file(m_path);
    if (!file.exists()) {
        return true;
    }
    if (!file.open(QIODevice::ReadOnly)) {
        m_lastError = QStringLiteral("unable to read profile store");
        return false;
    }

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        m_lastError = QStringLiteral("profile store is not a JSON object");
        return false;
    }

    const QJsonObject root = document.object();
    if (root.value(QStringLiteral("version")).toInt(-1) != StoreVersion
        || !root.value(QStringLiteral("profiles")).isArray()) {
        m_lastError = QStringLiteral("unsupported profile store format");
        return false;
    }

    const QJsonArray entries = root.value(QStringLiteral("profiles")).toArray();
    for (const QJsonValue &entry : entries) {
        Profile profile;
        if (!entry.isObject() || !fromJson(entry.toObject(), profile) || !validate(profile, true)) {
            if (m_lastError.isEmpty()) {
                m_lastError = QStringLiteral("profile store contains an invalid profile");
            }
            m_profiles.clear();
            return false;
        }
        m_profiles.append(profile);
    }
    m_lastError.clear();
    return true;
}

bool ProfileStore::add(const Profile &profile)
{
    m_lastError.clear();
    if (!validate(profile, true)) {
        return false;
    }

    m_profiles.append(profile);
    if (!save()) {
        m_profiles.removeLast();
        return false;
    }
    return true;
}

bool ProfileStore::remove(const QString &id)
{
    m_lastError.clear();
    const auto it = std::find_if(m_profiles.cbegin(), m_profiles.cend(),
                                 [&id](const Profile &profile) { return profile.id == id; });
    if (it == m_profiles.cend()) {
        m_lastError = QStringLiteral("profile not found");
        return false;
    }

    const int index = static_cast<int>(std::distance(m_profiles.cbegin(), it));
    const Profile removed = *it;
    m_profiles.removeAt(index);
    if (!save()) {
        m_profiles.insert(index, removed);
        return false;
    }
    return true;
}

QList<Profile> ProfileStore::profiles() const
{
    return m_profiles;
}

bool ProfileStore::contains(const QString &id) const
{
    return std::any_of(m_profiles.cbegin(), m_profiles.cend(),
                       [&id](const Profile &profile) { return profile.id == id; });
}

bool ProfileStore::profile(const QString &id, Profile &result) const
{
    const auto it = std::find_if(m_profiles.cbegin(), m_profiles.cend(),
                                 [&id](const Profile &profile) { return profile.id == id; });
    if (it == m_profiles.cend()) {
        return false;
    }
    result = *it;
    return true;
}

QJsonObject ProfileStore::toJson(const Profile &profile) const
{
    QJsonObject result {
        { QStringLiteral("id"), profile.id },
        { QStringLiteral("name"), profile.name },
        { QStringLiteral("protocol"), normalizeProtocol(profile.protocol) },
        { QStringLiteral("configPath"), profile.configPath },
    };
    if (!profile.forwardRoutes.isEmpty()) {
        QJsonArray routes;
        for (const QString &route : profile.forwardRoutes) {
            routes.append(route);
        }
        result.insert(QStringLiteral("forwardRoutes"), routes);
    }
    if (!profile.dnsServers.isEmpty()) {
        result.insert(QStringLiteral("dnsServers"), QJsonArray::fromStringList(profile.dnsServers));
    }
    if (!profile.dnsDomains.isEmpty()) {
        result.insert(QStringLiteral("dnsDomains"), QJsonArray::fromStringList(profile.dnsDomains));
    }
    if (!profile.interfaceName.isEmpty()) {
        result.insert(QStringLiteral("interfaceName"), profile.interfaceName);
    }
    if (!profile.routingMode.isEmpty()) {
        result.insert(QStringLiteral("routingMode"), profile.routingMode);
    }
    if (!profile.serverRulesUrl.isEmpty()) {
        result.insert(QStringLiteral("serverRulesUrl"), profile.serverRulesUrl);
    }
    if (!profile.updateManifestUrl.isEmpty()) {
        result.insert(QStringLiteral("updateManifestUrl"), profile.updateManifestUrl);
    }
    if (!profile.updatePublicKeyPath.isEmpty()) {
        result.insert(QStringLiteral("updatePublicKeyPath"), profile.updatePublicKeyPath);
    }
    if (profile.autoConnect) {
        result.insert(QStringLiteral("autoConnect"), true);
    }
    if (profile.autoUpdate) {
        result.insert(QStringLiteral("autoUpdate"), true);
    }
    return result;
}

bool ProfileStore::fromJson(const QJsonObject &object, Profile &profile)
{
    m_lastError.clear();
    profile = {};
    const QJsonValue id = object.value(QStringLiteral("id"));
    const QJsonValue name = object.value(QStringLiteral("name"));
    const QJsonValue protocol = object.value(QStringLiteral("protocol"));
    const QJsonValue configPath = object.value(QStringLiteral("configPath"));
    if (!id.isString() || !name.isString() || !protocol.isString() || !configPath.isString()) {
        m_lastError = QStringLiteral("profile metadata is incomplete");
        return false;
    }

    profile.id = id.toString().trimmed();
    profile.name = name.toString().trimmed();
    profile.protocol = normalizeProtocol(protocol.toString());
    profile.configPath = configPath.toString().trimmed();
    const QJsonValue forwardRoutesValue = object.value(QStringLiteral("forwardRoutes"));
    if (!forwardRoutesValue.isUndefined() && !forwardRoutesValue.isArray()) {
        m_lastError = QStringLiteral("forwardRoutes must be an array");
        return false;
    }
    if (forwardRoutesValue.isArray()) {
        for (const QJsonValue &routeValue : forwardRoutesValue.toArray()) {
            if (!routeValue.isString()) {
                m_lastError = QStringLiteral("forwardRoutes must contain strings");
                return false;
            }
            profile.forwardRoutes.append(routeValue.toString().trimmed());
        }
    }
    const auto readStringList = [&object](const QString &key, QStringList &target) {
        const QJsonValue value = object.value(key);
        if (!value.isUndefined() && !value.isArray()) {
            return false;
        }
        if (value.isArray()) {
            for (const QJsonValue &item : value.toArray()) {
                if (!item.isString()) {
                    return false;
                }
                target.append(item.toString().trimmed());
            }
        }
        return true;
    };
    if (!readStringList(QStringLiteral("dnsServers"), profile.dnsServers)
        || !readStringList(QStringLiteral("dnsDomains"), profile.dnsDomains)) {
        m_lastError = QStringLiteral("DNS metadata must be arrays of strings");
        return false;
    }
    const auto readString = [&object](const QString &key, QString &target) {
        const QJsonValue value = object.value(key);
        if (object.contains(key) && !value.isString()) {
            return false;
        }
        target = value.toString().trimmed();
        return true;
    };
    if (!readString(QStringLiteral("interfaceName"), profile.interfaceName)
        || !readString(QStringLiteral("routingMode"), profile.routingMode)
        || !readString(QStringLiteral("serverRulesUrl"), profile.serverRulesUrl)
        || !readString(QStringLiteral("updateManifestUrl"), profile.updateManifestUrl)
        || !readString(QStringLiteral("updatePublicKeyPath"), profile.updatePublicKeyPath)) {
        m_lastError = QStringLiteral("profile metadata has an invalid type");
        return false;
    }
    const QJsonValue autoConnectValue = object.value(QStringLiteral("autoConnect"));
    if (object.contains(QStringLiteral("autoConnect")) && !autoConnectValue.isBool()) {
        m_lastError = QStringLiteral("autoConnect must be a boolean");
        return false;
    }
    profile.autoConnect = autoConnectValue.toBool(false);
    const QJsonValue autoUpdateValue = object.value(QStringLiteral("autoUpdate"));
    if (object.contains(QStringLiteral("autoUpdate")) && !autoUpdateValue.isBool()) {
        m_lastError = QStringLiteral("autoUpdate must be a boolean");
        return false;
    }
    profile.autoUpdate = autoUpdateValue.toBool(false);
    return true;
}

QString ProfileStore::path() const
{
    return m_path;
}

QString ProfileStore::lastError() const
{
    return m_lastError;
}

bool ProfileStore::save()
{
    const QFileInfo fileInfo(m_path);
    if (!fileInfo.absolutePath().isEmpty() && !QDir().mkpath(fileInfo.absolutePath())) {
        m_lastError = QStringLiteral("unable to create profile store directory");
        return false;
    }

    QJsonArray entries;
    for (const Profile &profile : m_profiles) {
        entries.append(toJson(profile));
    }
    const QJsonObject root {
        { QStringLiteral("version"), StoreVersion },
        { QStringLiteral("profiles"), entries },
    };

    QSaveFile file(m_path);
    if (!file.open(QIODevice::WriteOnly)) {
        m_lastError = QStringLiteral("unable to write profile store");
        return false;
    }
    if (file.write(QJsonDocument(root).toJson(QJsonDocument::Indented)) < 0
        || !file.commit()) {
        m_lastError = QStringLiteral("unable to commit profile store");
        return false;
    }
#ifndef Q_OS_WIN
    QFile::setPermissions(m_path, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
#endif
    return true;
}

bool ProfileStore::validate(const Profile &profile, bool checkDuplicate) const
{
    auto fail = [this](const QString &message) {
        m_lastError = message;
        return false;
    };

    if (profile.id.isEmpty() || profile.id.size() > 128) {
        return fail(QStringLiteral("profile id is missing or too long"));
    }
    if (profile.name.isEmpty() || profile.name.size() > 256) {
        return fail(QStringLiteral("profile name is missing or too long"));
    }
    if (profile.configPath.isEmpty() || !QFileInfo(profile.configPath).isAbsolute()) {
        return fail(QStringLiteral("profile config path must be absolute"));
    }
    if (!isSupportedProtocol(profile.protocol)) {
        return fail(QStringLiteral("unsupported profile protocol"));
    }
    if (!profile.interfaceName.isEmpty()) {
        static const QRegularExpression interfacePattern(
                QStringLiteral("^[A-Za-z0-9_.-]{1,15}$"));
        if (!interfacePattern.match(profile.interfaceName).hasMatch()) {
            return fail(QStringLiteral("VPN interface name is invalid"));
        }
    }
    if (!profile.routingMode.isEmpty()
        && profile.routingMode != QStringLiteral("only-forward")
        && profile.routingMode != QStringLiteral("all-except")) {
        return fail(QStringLiteral("unsupported routing mode"));
    }
    if (profile.routingMode == QStringLiteral("all-except")
        && profile.serverRulesUrl.isEmpty()) {
        return fail(QStringLiteral("all-except requires a server routing policy URL"));
    }
    bool routesValid = false;
    const QStringList routes = amnezia::managedRoutePolicy::validatedManagedRoutes(
            profile.forwardRoutes, &routesValid);
    if (!routesValid || routes.size() != profile.forwardRoutes.size()) {
        return fail(QStringLiteral("forwardRoutes contains an invalid or duplicate route"));
    }
    if (profile.dnsServers.size() > 8 || profile.dnsDomains.size() > 8) {
        return fail(QStringLiteral("DNS metadata contains too many entries"));
    }
    for (const QString &server : profile.dnsServers) {
        QHostAddress address;
        if (server.isEmpty() || !address.setAddress(server)) {
            return fail(QStringLiteral("DNS server is not a valid IP address"));
        }
    }
    static const QRegularExpression dnsDomainPattern(
            QStringLiteral("^~?[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$") );
    for (const QString &domain : profile.dnsDomains) {
        if (domain.isEmpty() || domain.size() > 254
            || !dnsDomainPattern.match(domain).hasMatch()) {
            return fail(QStringLiteral("DNS routing domain is invalid"));
        }
    }
    if (!profile.dnsServers.isEmpty() && profile.dnsDomains.isEmpty()) {
        return fail(QStringLiteral("DNS servers require at least one routing domain"));
    }
    const auto validUrl = [](const QString &value) {
        if (value.isEmpty()) {
            return true;
        }
        const QUrl url(value, QUrl::StrictMode);
        return url.isValid() && (url.scheme() == QStringLiteral("http")
                                 || url.scheme() == QStringLiteral("https"))
                && !url.host().isEmpty() && url.userInfo().isEmpty()
                && url.fragment().isEmpty();
    };
    if (!validUrl(profile.serverRulesUrl)) {
        return fail(QStringLiteral("server rules URL is invalid"));
    }
    if (!validUrl(profile.updateManifestUrl)) {
        return fail(QStringLiteral("update manifest URL is invalid"));
    }
    if (!profile.updatePublicKeyPath.isEmpty()
        && (!QFileInfo(profile.updatePublicKeyPath).isAbsolute()
            || profile.updatePublicKeyPath.size() > 4096)) {
        return fail(QStringLiteral("update public key path is invalid"));
    }
    if (profile.autoUpdate
        && (profile.updateManifestUrl.isEmpty() || profile.updatePublicKeyPath.isEmpty())) {
        return fail(QStringLiteral("auto-update requires manifest URL and public key path"));
    }
    if (checkDuplicate && contains(profile.id)) {
        return fail(QStringLiteral("profile id already exists"));
    }
    return true;
}

void ProfileStore::setError(const QString &message) const
{
    m_lastError = message;
}

QString ProfileStore::defaultPath()
{
    QString stateDirectory = qEnvironmentVariable("XDG_STATE_HOME").trimmed();
    if (stateDirectory.isEmpty()) {
#ifdef Q_OS_UNIX
        stateDirectory = QDir::home().filePath(QStringLiteral(".local/state"));
#else
        stateDirectory = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
#endif
    }
    if (stateDirectory.isEmpty()) {
        stateDirectory = QDir::homePath();
    }
    return QDir(stateDirectory).filePath(QStringLiteral("amnezia/profiles.json"));
}

QString ProfileStore::normalizeProtocol(const QString &protocol)
{
    const QString value = protocol.trimmed().toLower();
    if (value == QStringLiteral("awg") || value == QStringLiteral("awg2")
        || value == QStringLiteral("amnezia-wg") || value == QStringLiteral("amneziawg")) {
        return QStringLiteral("amneziawg");
    }
    if (value == QStringLiteral("ss-xray")) {
        return QStringLiteral("ssxray");
    }
    return value;
}

bool ProfileStore::isSupportedProtocol(const QString &protocol)
{
    const QString normalized = normalizeProtocol(protocol);
    return normalized == QStringLiteral("wireguard")
        || normalized == QStringLiteral("amneziawg")
        || normalized == QStringLiteral("openvpn")
        || normalized == QStringLiteral("xray")
        || normalized == QStringLiteral("ssxray");
}

} // namespace amnezia::headless
